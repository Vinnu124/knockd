#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# integration.sh — end-to-end check of knockd against the real firewall.
#
# Starts the daemon, knocks at it over the loopback interface, and checks
# that iptables ends up in the expected state at each step.
#
#   sudo tests/integration.sh          # run from the repo root
#
# This touches the host's real iptables rules. It only ever works with
# port 2222 and a chain of its own, never port 22, and it removes
# everything it added on the way out — including if it fails partway.
# ──────────────────────────────────────────────────────────────────────

set -euo pipefail

CHAIN="KNOCKD"
PROT_PORT=2222
KNOCK_SEQ="7101,7102,7103"
ACCESS_TIMEOUT=5
BINARY="./knockd"
IPTABLES="/usr/sbin/iptables"

CONF=""
LOG=""
DAEMON_PID=""
DROP_RULE_ADDED=0
FAILURES=0

# ── Helpers ──────────────────────────────────────────────────────────

pass() { printf '  ok    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
info() { printf '%s\n' "$*"; }

# Invoked by the EXIT trap below, which shellcheck cannot follow.
# shellcheck disable=SC2329
cleanup() {
    local status=$?

    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi

    # Best effort: remove anything we or a failed daemon left behind.
    if [ "$DROP_RULE_ADDED" -eq 1 ]; then
        "$IPTABLES" -D INPUT -p tcp --dport "$PROT_PORT" -j DROP 2>/dev/null || true
    fi
    "$IPTABLES" -D INPUT -j "$CHAIN" 2>/dev/null || true
    "$IPTABLES" -F "$CHAIN" 2>/dev/null || true
    "$IPTABLES" -X "$CHAIN" 2>/dev/null || true

    [ -n "$CONF" ] && rm -f "$CONF"
    [ -n "$LOG" ] && rm -f "$LOG"

    exit "$status"
}
trap cleanup EXIT

# wait_until <seconds> <command...> — poll until the command succeeds.
wait_until() {
    local deadline=$(( $(date +%s) + $1 ))
    shift
    while [ "$(date +%s)" -le "$deadline" ]; do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# Passed to wait_until by name rather than called directly, so shellcheck
# does not see the call site.
# shellcheck disable=SC2329
chain_exists()   { "$IPTABLES" -S "$CHAIN"; }
jump_installed() { "$IPTABLES" -S INPUT | grep -q -- "-j $CHAIN"; }

grant_present() {
    "$IPTABLES" -S "$CHAIN" 2>/dev/null \
        | grep -q -- "-s 127.0.0.1/32 .*--dport $PROT_PORT -j ACCEPT"
}
grant_absent() { ! grant_present; }

drop_rule_present() {
    "$IPTABLES" -S INPUT | grep -q -- "-p tcp.*--dport $PROT_PORT -j DROP"
}

knock() {
    local ports="$1"
    ./knock_client.sh 127.0.0.1 -p "$ports" -d 0.3 >/dev/null 2>&1
}

dump_log() {
    info ""
    info "── daemon log ───────────────────────────────────────────"
    cat "$LOG" || true
    info "─────────────────────────────────────────────────────────"
}

# ── Preflight ────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    info "This test needs root: sudo tests/integration.sh"
    exit 1
fi
if [ ! -x "$BINARY" ]; then
    info "Build first: make"
    exit 1
fi
if [ ! -x "$IPTABLES" ]; then
    info "$IPTABLES not found"
    exit 1
fi
if ! command -v nc >/dev/null 2>&1 && ! command -v ncat >/dev/null 2>&1; then
    info "Need nc or ncat to send knocks"
    exit 1
fi
if "$IPTABLES" -S "$CHAIN" >/dev/null 2>&1; then
    info "A $CHAIN chain already exists — is knockd running? Stop it first."
    exit 1
fi

CONF="$(mktemp)"
LOG="$(mktemp)"
chmod 600 "$CONF"
cat > "$CONF" <<EOF
sequence = $KNOCK_SEQ
port = $PROT_PORT
timeout = $ACCESS_TIMEOUT
window = 15
max_clients = 16
log_level = 3
EOF

# ── Start ────────────────────────────────────────────────────────────

info ""
info "knockd integration test (port $PROT_PORT, sequence $KNOCK_SEQ)"
info ""

# A baseline DROP standing in for the operator's own rule. Shutdown must
# leave it alone: a daemon that removes it on the way out would open the
# protected port by stopping.
"$IPTABLES" -A INPUT -p tcp --dport "$PROT_PORT" -j DROP
DROP_RULE_ADDED=1

"$BINARY" -c "$CONF" > "$LOG" 2>&1 &
DAEMON_PID=$!

if ! wait_until 10 chain_exists; then
    fail "daemon did not create the $CHAIN chain"
    dump_log
    exit 1
fi
pass "created the $CHAIN chain"

if jump_installed; then
    pass "hooked INPUT into $CHAIN"
else
    fail "INPUT does not jump to $CHAIN"
fi

# ── A wrong order must not open anything ─────────────────────────────

knock "7102,7101,7103"
sleep 1
if grant_absent; then
    pass "an out-of-order sequence was rejected"
else
    fail "an out-of-order sequence opened the port"
fi

# ── The right order must open it ─────────────────────────────────────

knock "$KNOCK_SEQ"
if wait_until 10 grant_present; then
    pass "the correct sequence opened port $PROT_PORT"
else
    fail "the correct sequence did not open port $PROT_PORT"
    dump_log
fi

# ── And it must close again on its own ───────────────────────────────

if wait_until $((ACCESS_TIMEOUT + 10)) grant_absent; then
    pass "access expired after ${ACCESS_TIMEOUT}s"
else
    fail "access did not expire"
    dump_log
fi

# ── Shutdown must clean up after itself, and only after itself ───────

kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

if "$IPTABLES" -S "$CHAIN" >/dev/null 2>&1; then
    fail "the $CHAIN chain survived shutdown"
else
    pass "removed the $CHAIN chain on shutdown"
fi

if jump_installed; then
    fail "the INPUT jump to $CHAIN survived shutdown"
else
    pass "removed the INPUT jump on shutdown"
fi

# The regression that matters most: knockd used to delete this rule on
# shutdown, so stopping the daemon left the protected port wide open.
if drop_rule_present; then
    pass "left the operator's DROP rule in place"
else
    fail "shutdown removed the DROP rule — stopping knockd opened the port"
    DROP_RULE_ADDED=0
fi

info ""
if [ "$FAILURES" -eq 0 ]; then
    info "all integration checks passed"
else
    info "$FAILURES integration check(s) failed"
fi
exit "$FAILURES"
