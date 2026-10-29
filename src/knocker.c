/*
 * knocker.c — Per-IP knock sequence state machine.
 *
 * A fixed-size table of client entries, one per address that is partway
 * through the sequence. Entries are small and bounded, and the table is
 * guarded by a single mutex: contention is irrelevant here because only
 * the processor thread calls in, and holding the lock across the logging
 * keeps the log in the same order as the state changes it describes.
 */

#include "knocker.h"
#include "config.h"
#include "logger.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Ignore a repeat of the port we just accepted, for this many seconds.
 *
 * The kernel retransmits an unanswered SYN after 1–3 seconds. That
 * retransmit arrives as a second knock on the same port, which without
 * this would count as an out-of-order knock and throw away the client's
 * progress. Sequences with a repeated port are rejected by
 * config_validate(), so this can never swallow a legitimate step.
 */
#define KNOCK_DEDUP_WINDOW 5

typedef struct {
    uint32_t ip;            /* client IP, network byte order        */
    int      current_step;  /* steps completed so far               */
    time_t   last_knock;    /* when the last knock was accepted     */
    uint16_t last_port;     /* which port that was, for dedup       */
    bool     active;        /* is this slot in use?                 */
} knock_client_t;

static knock_client_t *clients     = NULL;
static pthread_mutex_t table_lock  = PTHREAD_MUTEX_INITIALIZER;

/* ── Helpers ─────────────────────────────────────────────────────────── */

/*
 * Format an IP for a log line.
 *
 * The buffer is thread-local, so two threads cannot collide — but a single
 * log call must not use this twice, because the second call overwrites the
 * first result before printf sees either.
 */
static const char *ip_to_str(uint32_t ip)
{
    static _Thread_local char buf[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &ip, buf, sizeof(buf)) == NULL) {
        return "?";
    }
    return buf;
}

/* Find the entry for this IP, or NULL. Caller holds table_lock. */
static knock_client_t *find_client(uint32_t ip)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].ip == ip) {
            return &clients[i];
        }
    }
    return NULL;
}

/*
 * Claim a zeroed slot for a new client. Caller holds table_lock.
 *
 * A free slot is used if there is one. If the table is full, the oldest
 * entry is reused, but only once it is past KNOCK_WINDOW and therefore
 * worthless anyway: source addresses are trivially spoofable, so a flood
 * of first-port knocks must not be able to evict a real client that is
 * halfway through the sequence.
 *
 * Returns NULL if every entry is a live sequence.
 */
static knock_client_t *alloc_client(void)
{
    knock_client_t *oldest = NULL;
    time_t          now    = time(NULL);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            memset(&clients[i], 0, sizeof(clients[i]));
            return &clients[i];
        }
        if (oldest == NULL || clients[i].last_knock < oldest->last_knock) {
            oldest = &clients[i];
        }
    }

    if (oldest == NULL || (now - oldest->last_knock) <= KNOCK_WINDOW) {
        return NULL;
    }

    log_debug("Client table full — reusing the expired entry for %s",
              ip_to_str(oldest->ip));
    memset(oldest, 0, sizeof(*oldest));
    return oldest;
}

/*
 * The state machine itself. Caller holds table_lock.
 */
static knock_result_t process_locked(uint32_t src_ip, uint16_t dst_port)
{
    time_t          now = time(NULL);
    knock_client_t *c   = find_client(src_ip);

    if (c == NULL) {
        /*
         * An address we are not tracking. Only the first port of the
         * sequence starts an entry — anything else is background scan
         * noise and is not worth a table slot.
         */
        if (dst_port != KNOCK_SEQUENCE[0]) {
            log_debug("%s knocked port %u, which does not start the "
                      "sequence — ignored", ip_to_str(src_ip), dst_port);
            return KNOCK_RESET;
        }

        c = alloc_client();
        if (c == NULL) {
            log_warn("Client table is full of sequences in progress "
                     "— ignoring the knock from %s", ip_to_str(src_ip));
            return KNOCK_RESET;
        }
        c->ip     = src_ip;
        c->active = true;
        /*
         * last_port stays 0, which config_validate() guarantees is not in
         * the sequence, so the dedup check below cannot swallow this
         * client's first knock.
         */
    }

    if (dst_port == c->last_port &&
        (now - c->last_knock) <= KNOCK_DEDUP_WINDOW) {
        log_debug("%s repeated port %u within %ds — ignored as a "
                  "retransmit", ip_to_str(src_ip), dst_port,
                  KNOCK_DEDUP_WINDOW);
        return KNOCK_IN_PROGRESS;
    }

    if (c->current_step > 0 && (now - c->last_knock) > KNOCK_WINDOW) {
        log_info("%s left more than %ds between knocks — starting over",
                 ip_to_str(src_ip), KNOCK_WINDOW);
        c->current_step = 0;
    }

    if (dst_port == KNOCK_SEQUENCE[c->current_step]) {
        c->current_step++;
        c->last_knock = now;
        c->last_port  = dst_port;

        if (c->current_step >= KNOCK_SEQ_LEN) {
            /* Release the slot: another grant needs the whole sequence
             * again. */
            c->active = false;
            return KNOCK_COMPLETE;
        }

        /* The step number is safe to log; the port is the secret. */
        log_info("%s is at step %d of %d",
                 ip_to_str(src_ip), c->current_step, KNOCK_SEQ_LEN);
        return KNOCK_IN_PROGRESS;
    }

    /*
     * Wrong port. If it is the first port of the sequence, treat it as a
     * fresh attempt rather than a failure, so a client that lost its place
     * can simply knock again.
     *
     * last_port has to be updated here too. Leaving it pointing at the
     * previous step's port would make the dedup check above discard the
     * client's next legitimate knock, and the sequence would then fail on
     * the step after that.
     */
    if (dst_port == KNOCK_SEQUENCE[0]) {
        c->current_step = 1;
        c->last_knock   = now;
        c->last_port    = dst_port;
        log_debug("%s knocked out of order — restarted at step 1 of %d",
                  ip_to_str(src_ip), KNOCK_SEQ_LEN);
        return KNOCK_IN_PROGRESS;
    }

    log_debug("%s knocked port %u out of order — progress discarded",
              ip_to_str(src_ip), dst_port);
    c->active = false;
    return KNOCK_RESET;
}

/* ── Public API ──────────────────────────────────────────────────────── */

int knocker_init(void)
{
    clients = calloc((size_t)MAX_CLIENTS, sizeof(*clients));
    if (clients == NULL) {
        log_error("Could not allocate a client table for %d clients",
                  MAX_CLIENTS);
        return -1;
    }

    log_debug("Knock state machine ready (%d client slots)", MAX_CLIENTS);
    return 0;
}

void knocker_shutdown(void)
{
    free(clients);
    clients = NULL;
}

knock_result_t knocker_process(uint32_t src_ip, uint16_t dst_port)
{
    knock_result_t result;

    pthread_mutex_lock(&table_lock);
    result = process_locked(src_ip, dst_port);
    pthread_mutex_unlock(&table_lock);

    return result;
}

void knocker_cleanup_stale(void)
{
    time_t now     = time(NULL);
    int    cleaned = 0;

    pthread_mutex_lock(&table_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && (now - clients[i].last_knock) > KNOCK_WINDOW) {
            log_debug("Dropping the stale entry for %s",
                      ip_to_str(clients[i].ip));
            clients[i].active = false;
            cleaned++;
        }
    }
    pthread_mutex_unlock(&table_lock);

    if (cleaned > 0) {
        log_debug("Dropped %d stale client entries", cleaned);
    }
}
