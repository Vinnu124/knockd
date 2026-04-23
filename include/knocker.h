/*
 * knocker.h — Per-IP knock sequence state machine.
 *
 * Tracks how far each client IP has progressed through the secret
 * knock sequence. Handles timeouts, wrong-port resets, and stale
 * entry cleanup.
 */

#ifndef KNOCKER_H
#define KNOCKER_H

#include <stdint.h>

/* Result of processing a knock attempt */
typedef enum {
    KNOCK_COMPLETE,      /* Sequence finished — open the port! */
    KNOCK_IN_PROGRESS,   /* Correct knock — advanced to next step */
    KNOCK_RESET          /* Wrong port or timeout — reset to step 0 */
} knock_result_t;

/*
 * Initialize the client tracking table.
 * Must be called once before any knocker_process() calls.
 */
void knocker_init(void);

/*
 * Process a knock attempt from a client.
 *
 *   src_ip:   Client IP (network byte order)
 *   dst_port: Port the SYN was sent to (host byte order)
 *
 * Returns:
 *   KNOCK_COMPLETE     — full sequence matched; trigger firewall open
 *   KNOCK_IN_PROGRESS  — correct step; waiting for next knock
 *   KNOCK_RESET        — wrong port or stale; progress reset
 */
knock_result_t knocker_process(uint32_t src_ip, uint16_t dst_port);

/*
 * Remove entries that haven't knocked within KNOCK_WINDOW seconds.
 * Call this periodically to prevent the table from filling up.
 */
void knocker_cleanup_stale(void);

#endif /* KNOCKER_H */
