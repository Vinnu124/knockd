/*
 * config.h — Compile-time configuration for the port knocking daemon.
 *
 * NOTE: stdint.h is required here for uint16_t used in KNOCK_SEQUENCE.
 */

#include <stdint.h>

/*
 * Adjust these constants to customize the knock sequence, timeouts,
 * and protected port. Recompile after changes.
 */

#ifndef CONFIG_H
#define CONFIG_H

/* ── Knock Sequence ────────────────────────────────────────────────────
 * The secret sequence of TCP ports that must be "knocked" in order.
 * A client sends SYN packets to each port in this exact order.
 */
#define KNOCK_SEQ_LEN   3
static const uint16_t KNOCK_SEQUENCE[KNOCK_SEQ_LEN] = { 7000, 8000, 9000 };

/* ── Protected Service ─────────────────────────────────────────────────
 * The port that gets opened after a successful knock sequence.
 */
#define PROTECTED_PORT  22

/* ── Timing ────────────────────────────────────────────────────────────
 * ACCESS_TIMEOUT: Seconds before the opened port auto-closes.
 * KNOCK_WINDOW:   Max seconds allowed between consecutive knocks.
 *                 If a client takes longer, their progress resets.
 */
#define ACCESS_TIMEOUT  30
#define KNOCK_WINDOW    15

/* ── Capacity ──────────────────────────────────────────────────────────
 * Maximum number of client IPs tracked simultaneously.
 * When the table is full, the oldest stale entry is evicted.
 */
#define MAX_CLIENTS     64

/* ── Logging ───────────────────────────────────────────────────────────
 * LOG_LEVEL controls verbosity:
 *   0 = ERROR only
 *   1 = WARN + ERROR
 *   2 = INFO + WARN + ERROR
 *   3 = DEBUG (everything)
 */
#define LOG_LEVEL       2

/* ── Firewall Command ──────────────────────────────────────────────────
 * Path to the iptables binary. On Fedora with iptables-nft, this
 * is typically /usr/sbin/iptables (symlinked to iptables-nft).
 */
#define IPTABLES_PATH   "/usr/sbin/iptables"

#endif /* CONFIG_H */
