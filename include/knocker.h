/*
 * knocker.h — Per-IP knock sequence state machine.
 *
 * Tracks how far each source address has progressed through the sequence,
 * and handles the ways progress can be lost: a wrong port, too long a gap
 * between knocks, or the table filling up.
 *
 * All functions are safe to call from any thread.
 */

#ifndef KNOCKER_H
#define KNOCKER_H

#include <stdint.h>

/* Outcome of one knock. */
typedef enum {
    KNOCK_COMPLETE,      /* sequence finished — grant access         */
    KNOCK_IN_PROGRESS,   /* accepted, or ignored as a duplicate      */
    KNOCK_RESET          /* wrong port, or not tracked at all        */
} knock_result_t;

/*
 * Allocate the client table. Call once, before starting any thread.
 * Returns 0 on success, -1 if the table could not be allocated.
 */
int knocker_init(void);

/*
 * Release the client table. Call once, after all threads have joined.
 */
void knocker_shutdown(void);

/*
 * Record one knock.
 *
 *   src_ip:   source IP, network byte order
 *   dst_port: the port that was knocked, host byte order
 *
 * Returns KNOCK_COMPLETE exactly once per completed sequence: the entry is
 * released at that point, so the client must send the whole sequence again
 * for another grant.
 */
knock_result_t knocker_process(uint32_t src_ip, uint16_t dst_port);

/*
 * Drop entries that have not knocked within KNOCK_WINDOW seconds. Call
 * periodically so abandoned sequences do not hold table slots.
 */
void knocker_cleanup_stale(void);

#endif /* KNOCKER_H */
