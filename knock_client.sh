#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# knock_client.sh — send a knock sequence to a knockd server.
#
# Sends one TCP SYN (or UDP datagram) to each knock port in order, then
# optionally opens an SSH session.
#
# Needs nc or ncat. nmap is used only as a fallback and is not required.
# ──────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────
# These have to match the server's /etc/knockd.conf.
KNOCK_PORTS=(7000 8000 9000)
DELAY=0.5          # seconds between knocks
CONNECT_TIMEOUT=1  # seconds to wait for each knock to be answered
SSH_PORT=22

TARGET=""
DO_SSH=0
DO_UDP=0
SSH_USER="${USER:-$(id -un)}"

# ── Output helpers ───────────────────────────────────────────────────
if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

say()  { printf '%s\n' "$*"; }
warn() { printf '%s\n' "${YELLOW}$*${NC}" >&2; }
die()  { printf '%s\n' "${RED}$*${NC}" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $(basename "$0") <server> [options]

Options:
  -p, --ports <list>    Comma-separated knock ports (default: ${KNOCK_PORTS[*]})
  -d, --delay <secs>    Delay between knocks (default: $DELAY)
  -P, --ssh-port <port> Port the protected SSH service listens on (default: $SSH_PORT)
      --ssh [user]      Open an SSH session after knocking
      --udp             Send UDP datagrams instead of TCP SYNs
  -h, --help            Show this help

The port list and the order must match the server's configuration. A
wrong port does not just fail, it discards whatever progress the
sequence had made.

Examples:
  $(basename "$0") 203.0.113.9
  $(basename "$0") 203.0.113.9 -p 1111,2222,3333 -d 0.3
  $(basename "$0") 203.0.113.9 --ssh admin
EOF
}

# ── Arguments ────────────────────────────────────────────────────────
if [ "$#" -eq 0 ]; then
    usage
    exit 0
fi

case "$1" in
    -h|--help) usage; exit 0 ;;
    -*)        die "First argument must be the server address, not $1." ;;
    *)         TARGET="$1"; shift ;;
esac

while [ "$#" -gt 0 ]; do
    case "$1" in
        -p|--ports)
            [ "$#" -ge 2 ] || die "$1 needs a comma-separated list of ports."
            IFS=',' read -ra KNOCK_PORTS <<< "$2"
            shift 2
            ;;
        -d|--delay)
            [ "$#" -ge 2 ] || die "$1 needs a delay in seconds."
            DELAY="$2"
            shift 2
            ;;
        -P|--ssh-port)
            [ "$#" -ge 2 ] || die "$1 needs a port number."
            SSH_PORT="$2"
            shift 2
            ;;
        --ssh)
            DO_SSH=1
            shift
            # An optional username may follow, but not another option.
            if [ "$#" -ge 1 ] && [ "${1#-}" = "$1" ]; then
                SSH_USER="$1"
                shift
            fi
            ;;
        --udp)
            DO_UDP=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
done

# ── Validation ───────────────────────────────────────────────────────
[ "${#KNOCK_PORTS[@]}" -ge 2 ] || die "A knock sequence needs at least 2 ports."

for port in "${KNOCK_PORTS[@]}" "$SSH_PORT"; do
    case "$port" in
        ''|*[!0-9]*) die "Not a port number: '$port'" ;;
    esac
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        die "Port out of range: $port"
    fi
done

case "$DELAY" in
    ''|*[!0-9.]*) die "Not a delay in seconds: '$DELAY'" ;;
esac

# ── Pick a tool ──────────────────────────────────────────────────────
# nc and ncat both complete a connect(), so a closed port answers with an
# RST and the kernel has no reason to retransmit the SYN. nmap leaves the
# SYN unanswered, and the kernel's retransmit a second or so later arrives
# at the server as a second knock on the same port. knockd ignores an
# immediate repeat for exactly this reason, but nc is still the better tool
# and is the only one that can send UDP without root.
KNOCK_TOOL=""
for candidate in nc ncat; do
    if command -v "$candidate" >/dev/null 2>&1; then
        KNOCK_TOOL="$candidate"
        break
    fi
done

if [ -z "$KNOCK_TOOL" ]; then
    if command -v nmap >/dev/null 2>&1; then
        KNOCK_TOOL="nmap"
        warn "Using nmap: install nc (nmap-ncat) for more reliable knocking."
    else
        die "Need nc or ncat. Install with:
  sudo dnf install nmap-ncat   # Fedora/RHEL
  sudo apt install netcat-openbsd  # Debian/Ubuntu
  brew install netcat          # macOS"
    fi
fi

if [ "$DO_UDP" -eq 1 ] && [ "$KNOCK_TOOL" = "nmap" ]; then
    die "UDP knocking with nmap needs root. Install nc or ncat instead."
fi

PROTO_STR="TCP SYN"
if [ "$DO_UDP" -eq 1 ]; then
    PROTO_STR="UDP"
fi

# ── Send the sequence ────────────────────────────────────────────────
# Each knock is expected to go unanswered or be refused, so a non-zero
# exit from the tool is normal and is not treated as a failure. What
# matters is whether the server saw the packets, which only the server can
# say — check its log if a knock does not take effect.
send_knock() {
    local port="$1"

    case "$KNOCK_TOOL" in
        nc|ncat)
            if [ "$DO_UDP" -eq 1 ]; then
                printf 'knock\n' \
                    | "$KNOCK_TOOL" -u -w "$CONNECT_TIMEOUT" \
                                    "$TARGET" "$port" >/dev/null 2>&1 || true
            else
                "$KNOCK_TOOL" -w "$CONNECT_TIMEOUT" "$TARGET" "$port" \
                    </dev/null >/dev/null 2>&1 || true
            fi
            ;;
        nmap)
            nmap -Pn --host-timeout 1s --max-retries 0 \
                 -p "$port" "$TARGET" >/dev/null 2>&1 || true
            ;;
    esac
}

say ""
say "${BOLD}knocking ${TARGET}${NC}"
say "  tool      $KNOCK_TOOL ($PROTO_STR)"
say "  sequence  ${#KNOCK_PORTS[@]} ports, ${DELAY}s apart"
say ""

total="${#KNOCK_PORTS[@]}"
step=0
for port in "${KNOCK_PORTS[@]}"; do
    step=$((step + 1))
    printf '  %s[%d/%d]%s port %s' "$CYAN" "$step" "$total" "$NC" "$port"
    send_knock "$port"
    printf ' %ssent%s\n' "$GREEN" "$NC"

    if [ "$step" -lt "$total" ]; then
        sleep "$DELAY"
    fi
done

say ""
say "  ${GREEN}sequence sent${NC}"
say ""

# ── Connect ──────────────────────────────────────────────────────────
if [ "$DO_SSH" -eq 1 ]; then
    say "  connecting to ${SSH_USER}@${TARGET}..."
    say ""
    sleep 1  # let the server process the last knock
    if ssh -o ConnectTimeout=10 -p "$SSH_PORT" "${SSH_USER}@${TARGET}"; then
        say ""
        say "  ${GREEN}session ended${NC}"
    else
        say ""
        warn "SSH failed. Either the sequence was not accepted, the access
window had already closed, or sshd is not running on port $SSH_PORT.
Check the server: sudo journalctl -u knockd -n 20"
        exit 1
    fi
else
    say "  ${YELLOW}connect now — the window is short:${NC}"
    say ""
    if [ "$SSH_PORT" = "22" ]; then
        say "    ssh ${SSH_USER}@${TARGET}"
    else
        say "    ssh -p ${SSH_PORT} ${SSH_USER}@${TARGET}"
    fi
    say ""
fi
