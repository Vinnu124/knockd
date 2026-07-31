#!/bin/bash
# ──────────────────────────────────────────────────────────────────────
# knock_client.sh — Send a port knock sequence to a target server.
#
# This script sends TCP SYN packets to the configured knock ports
# in order, then optionally attempts an SSH connection.
#
# Usage:
#   ./knock_client.sh <target_ip>
#   ./knock_client.sh <target_ip> --ssh          # Also try SSH after
#   ./knock_client.sh <target_ip> --ssh user      # SSH as specific user
#
# Requirements:
#   - nmap (preferred) or ncat/nc must be installed
# ──────────────────────────────────────────────────────────────────────

set -e

# ── Configuration (must match the server's config.h) ─────────────────
KNOCK_PORTS=(7000 8000 9000)
DELAY=0.5  # seconds between knocks

# ── Colors for output ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ── Argument parsing ─────────────────────────────────────────────────
if [ -z "$1" ] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo -e "${RED}Usage: $0 <target_ip> [-p port1,port2...] [-d delay] [--ssh [user]] [--udp]${NC}"
    exit 1
fi

TARGET="$1"
DO_SSH=0
DO_UDP=0
SSH_USER="$USER"

shift
while [ "$#" -gt 0 ]; do
    case "$1" in
        -p|--ports)
            if [ -n "$2" ] && [[ "$2" != -* ]]; then
                IFS=',' read -ra KNOCK_PORTS <<< "$2"
                shift
            else
                echo -e "${RED}Error: -p requires a comma-separated list of ports.${NC}"
                exit 1
            fi
            ;;
        -d|--delay)
            if [ -n "$2" ] && [[ "$2" != -* ]]; then
                DELAY="$2"
                shift
            else
                echo -e "${RED}Error: -d requires a delay value in seconds.${NC}"
                exit 1
            fi
            ;;
        --ssh)
            DO_SSH=1
            if [ -n "$2" ] && [[ "$2" != -* ]]; then
                SSH_USER="$2"
                shift
            fi
            ;;
        --udp)
            DO_UDP=1
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
    shift
done

# ── Detect available knock tool ──────────────────────────────────────
KNOCK_TOOL=""
if [ "$DO_UDP" -eq 1 ]; then
    # UDP knocking requires nmap (nc/ncat can't send raw UDP probes easily)
    if command -v nmap &>/dev/null; then
        KNOCK_TOOL="nmap"
    else
        echo -e "${RED}Error: UDP knocking requires nmap. Install with:${NC}"
        echo "  sudo dnf install nmap   # Fedora/RHEL"
        echo "  brew install nmap       # macOS"
        exit 1
    fi
else
    # For TCP: prefer nc/ncat — they complete a connect() which gets an RST back
    # immediately (port closed), so the kernel has NO reason to retransmit the SYN.
    # nmap leaves the SYN unanswered (stealth scan), causing the OS to retransmit
    # the SYN up to 3 s later, which then arrives as a spurious second knock.
    if command -v nc &>/dev/null; then
        KNOCK_TOOL="nc"
    elif command -v ncat &>/dev/null; then
        KNOCK_TOOL="ncat"
    elif command -v nmap &>/dev/null; then
        KNOCK_TOOL="nmap"
    else
        echo -e "${RED}Error: No suitable tool found. Install nc or nmap:${NC}"
        echo "  sudo dnf install nmap   # Fedora/RHEL"
        echo "  brew install nmap       # macOS"
        exit 1
    fi
fi

if [ "$DO_UDP" -eq 1 ] && [ "$KNOCK_TOOL" != "nmap" ]; then
    echo -e "${RED}Error: UDP knocking currently requires 'nmap' to be installed.${NC}"
    exit 1
fi

PROTO_STR="TCP SYN"
if [ "$DO_UDP" -eq 1 ]; then
    PROTO_STR="UDP"
fi

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       PORT KNOCK CLIENT                  ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║  Target:  ${GREEN}${TARGET}${NC}"
echo -e "${CYAN}║  Tool:    ${GREEN}${KNOCK_TOOL}${NC}"
echo -e "${CYAN}║  Proto:   ${GREEN}${PROTO_STR}${NC}"
echo -e "${CYAN}║  Ports:   ${GREEN}${KNOCK_PORTS[*]}${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── Send knock sequence ──────────────────────────────────────────────
send_knock() {
    local port=$1

    case "$KNOCK_TOOL" in
        nmap)
            if [ "$DO_UDP" -eq 1 ]; then
                # Send a single UDP probe
                sudo nmap -sU -Pn --host-timeout 1s --max-retries 0 -p "$port" "$TARGET" &>/dev/null
            else
                # Send a single TCP SYN probe
                nmap -Pn --host-timeout 1s --max-retries 0 -p "$port" "$TARGET" &>/dev/null
            fi
            ;;
        ncat)
            ncat -w 1 "$TARGET" "$port" </dev/null &>/dev/null 2>&1 || true
            ;;
        nc)
            nc -z -w 1 "$TARGET" "$port" &>/dev/null 2>&1 || true
            ;;
    esac
}

KNOCK_FAILED=0
for i in "${!KNOCK_PORTS[@]}"; do
    port="${KNOCK_PORTS[$i]}"
    step=$((i + 1))
    total=${#KNOCK_PORTS[@]}

    echo -ne "  ${YELLOW}Knock ${step}/${total}:${NC} Sending to port ${GREEN}${port}${NC}..."
    send_knock "$port"
    if [ $? -ne 0 ] && [ "$KNOCK_TOOL" = "nmap" ]; then
        echo -e " ${RED}FAILED${NC}"
        KNOCK_FAILED=1
        break
    fi
    echo -e " ${GREEN}sent${NC}"

    # Delay between knocks (but not after the last one)
    if [ "$step" -lt "$total" ]; then
        sleep "$DELAY"
    fi
done

echo ""

if [ "$KNOCK_FAILED" -eq 1 ]; then
    echo -e "  ${RED}✗ Knock sequence failed. Check that the server is reachable.${NC}"
    echo ""
    exit 1
fi

echo -e "  ${GREEN}✓ All ${#KNOCK_PORTS[@]} knocks sent successfully!${NC}"
echo ""
echo -e "  ${CYAN}The server daemon will now verify the sequence.${NC}"
echo -e "  ${CYAN}If correct, port 22 will open for you for ${YELLOW}30 seconds${CYAN}.${NC}"
echo ""

# ── Optional SSH connection ──────────────────────────────────────────
if [ "$DO_SSH" -eq 1 ]; then
    echo -e "  ${CYAN}Connecting via SSH...${NC}"
    echo ""
    sleep 1  # Give the daemon a moment to process
    if ssh -o ConnectTimeout=10 "${SSH_USER}@${TARGET}"; then
        echo ""
        echo -e "  ${GREEN}✓ SSH session ended cleanly.${NC}"
    else
        echo ""
        echo -e "  ${RED}✗ SSH failed. The knock may not have completed in time, or SSH is not running on the server.${NC}"
        exit 1
    fi
else
    echo -e "  ${YELLOW}Run this now (you have ~30 seconds):${NC}"
    echo ""
    echo -e "    ${GREEN}ssh ${SSH_USER}@${TARGET}${NC}"
    echo ""
fi
