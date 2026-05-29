/*
 * knocker.c — Per-IP knock sequence state machine.
 *
 * Maintains a fixed-size table of client IPs. For each incoming
 * SYN on a knock port, checks whether the client is progressing
 * through the secret sequence in order.
 *
 * Key design:
 *   - Fixed-size array (no malloc) — bounded memory, simple logic
 *   - Thread-safe: shared table access is serialized
 *   - Stale entries expire after KNOCK_WINDOW seconds
 *   - Wrong-order knocks immediately reset the client's progress
 */

#include "knocker.h"
#include "config.h"
#include "logger.h"

#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <omp.h>
#include <stdlib.h>
/* ── Per-client tracking entry ─────────────────────────────────────── */
/* Dedup window: ignore a repeated knock on the same port within this
 * many seconds. Prevents nmap's duplicate SYNs from resetting progress. */
#define KNOCK_DEDUP_WINDOW 5   /* kernel TCP SYN retransmits can arrive up to ~3s later */

typedef struct {
    uint32_t    ip;             /* Client IP (network byte order)     */
    int         current_step;   /* Steps completed (0 = no progress)  */
    time_t      last_knock;     /* Timestamp of last valid knock      */
    uint16_t    last_port;      /* Port of the last accepted knock     */
    bool        active;         /* Is this slot in use?               */
} knock_client_t;

/* Fixed-size client table */
static knock_client_t *clients = NULL;

/* ── Helpers ───────────────────────────────────────────────────────── */

/* Format an IP for logging (thread-local buffer to avoid races) */
static const char *ip_to_str(uint32_t ip)
{
    static char buf[INET_ADDRSTRLEN];
    #pragma omp threadprivate(buf)
    inet_ntop(AF_INET, &ip, buf, sizeof(buf));
    return buf;
}

/* Find an existing entry for this IP, or return NULL */
static knock_client_t *find_client(uint32_t ip)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].ip == ip) {
            return &clients[i];
        }
    }
    return NULL;
}

/* Find a free slot, or evict the oldest stale entry */
static knock_client_t *alloc_client(void)
{
    /* First pass: find an empty slot */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            return &clients[i];
        }
    }

    /* Table full — evict the entry with the oldest last_knock */
    knock_client_t *oldest = &clients[0];
    for (int i = 1; i < MAX_CLIENTS; i++) {
        if (clients[i].last_knock < oldest->last_knock) {
            oldest = &clients[i];
        }
    }

    log_warn("Client table full, evicting %s", ip_to_str(oldest->ip));
    oldest->active = false;
    return oldest;
}

/* ── Public API ────────────────────────────────────────────────────── */

void knocker_init(void)
{
    clients = calloc(MAX_CLIENTS, sizeof(knock_client_t));
    if (!clients) {
        log_error("Failed to allocate memory for knocker clients");
        exit(1);
    }
    log_info("Knock state machine initialized (capacity: %d clients)", MAX_CLIENTS);
}

knock_result_t knocker_process(uint32_t src_ip, uint16_t dst_port)
{
    knock_result_t result;

    /* Serialize access to the shared client table */
    #pragma omp critical(knocker_table)
    {
        time_t now = time(NULL);

        /* Find or create entry for this IP */
        knock_client_t *c = find_client(src_ip);

        if (c == NULL) {
            /* New IP — only accept if it's knocking the FIRST port */
            if (dst_port != KNOCK_SEQUENCE[0]) {
                log_debug("%s knocked port %u (not first port %u) — ignored",
                          ip_to_str(src_ip), dst_port, KNOCK_SEQUENCE[0]);
                result = KNOCK_RESET;
            } else {
                /* Allocate a new entry */
                c = alloc_client();
                c->ip           = src_ip;
                c->current_step = 0;
                c->last_knock   = now;
                c->active       = true;
                /* Fall through to the port check below */
                goto check_port;
            }
        } else {
            check_port:
            /* Deduplicate: ignore a repeat knock on the same port within
             * KNOCK_DEDUP_WINDOW seconds (handles nmap duplicate SYNs). */
            if (dst_port == c->last_port &&
                (now - c->last_knock) <= KNOCK_DEDUP_WINDOW) {
                log_debug("%s duplicate knock on port %u — ignored (dedup)",
                          ip_to_str(src_ip), dst_port);
                result = KNOCK_IN_PROGRESS;
                goto done;
            }

            /* Check for timeout between knocks */
            if (c->current_step > 0 && (now - c->last_knock) > KNOCK_WINDOW) {
                log_info("%s timed out (%.0fs since last knock) — resetting",
                         ip_to_str(src_ip), difftime(now, c->last_knock));
                c->current_step = 0;
            }

            /* Check if this knock matches the expected port */
            if (dst_port == KNOCK_SEQUENCE[c->current_step]) {
                c->current_step++;
                c->last_knock = now;
                c->last_port  = dst_port;   /* record for dedup */

                log_info("%s knocked port %u — step %d/%d",
                         ip_to_str(src_ip), dst_port,
                         c->current_step, KNOCK_SEQ_LEN);

                if (c->current_step >= KNOCK_SEQ_LEN) {
                    log_info("*** %s completed the knock sequence! ***",
                             ip_to_str(src_ip));
                    c->active = false;
                    result = KNOCK_COMPLETE;
                } else {
                    result = KNOCK_IN_PROGRESS;
                }
            } else {
                log_info("%s knocked port %u (expected %u) — resetting",
                         ip_to_str(src_ip), dst_port,
                         KNOCK_SEQUENCE[c->current_step]);

                if (dst_port == KNOCK_SEQUENCE[0]) {
                    c->current_step = 1;
                    c->last_knock   = now;
                    log_info("%s restarted sequence at step 1/%d",
                             ip_to_str(src_ip), KNOCK_SEQ_LEN);
                    result = KNOCK_IN_PROGRESS;
                } else {
                    c->active = false;
                    result = KNOCK_RESET;
                }
            }
        }
        done:;
    }

    return result;
}

void knocker_cleanup_stale(void)
{
    time_t now = time(NULL);
    int cleaned = 0;

    /* Scan each slot independently */
    #pragma omp parallel for reduction(+:cleaned) schedule(static)
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active &&
            (now - clients[i].last_knock) > KNOCK_WINDOW) {
            log_debug("Cleaning stale entry for %s",
                      ip_to_str(clients[i].ip));
            clients[i].active = false;
            cleaned++;
        }
    }

    if (cleaned > 0) {
        log_debug("Cleaned %d stale client entries", cleaned);
    }
}
