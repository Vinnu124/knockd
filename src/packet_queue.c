/*
 * packet_queue.c — Thread-safe ring buffer implementation.
 *
 * Fixed-size circular buffer synchronized with OpenMP locks.
 * The sniffer thread is the sole producer; the processor thread(s)
 * are consumers. Lock contention is minimal because the sniffer
 * only holds the lock briefly to enqueue, and consumers dequeue
 * in tight bursts.
 *
 * Design choices:
 *   - Ring buffer avoids malloc/free per packet
 *   - Power-of-2 capacity for fast modulo (bitwise AND)
 *   - OpenMP lock instead of pthread_mutex to keep the entire
 *     project consistently using the OpenMP threading model
 */

#include "packet_queue.h"
#include "logger.h"

#include <string.h>
#include <omp.h>

/* ── Ring buffer state ─────────────────────────────────────────────── */
static knock_event_t ring[QUEUE_CAPACITY];
static int head = 0;          /* Next write position (producer) */
static int tail = 0;          /* Next read position  (consumer) */
static int count = 0;         /* Current number of items        */
static omp_lock_t queue_lock; /* OpenMP lock for thread safety  */

/* ── Public API ────────────────────────────────────────────────────── */

void pktqueue_init(void)
{
    omp_init_lock(&queue_lock);
    head = tail = count = 0;
    memset(ring, 0, sizeof(ring));
    log_debug("Packet queue initialized (capacity: %d)", QUEUE_CAPACITY);
}

void pktqueue_destroy(void)
{
    omp_destroy_lock(&queue_lock);
    log_debug("Packet queue destroyed");
}

int pktqueue_push(const knock_event_t *event)
{
    int ret = -1;

    omp_set_lock(&queue_lock);
    {
        if (count < QUEUE_CAPACITY) {
            ring[head] = *event;
            head = (head + 1) & (QUEUE_CAPACITY - 1); /* fast modulo */
            count++;
            ret = 0;
        } else {
            /* Queue full — drop the packet and log a warning */
            log_warn("Packet queue full! Dropping knock event.");
        }
    }
    omp_unset_lock(&queue_lock);

    return ret;
}

int pktqueue_pop(knock_event_t *event)
{
    int ret = -1;

    omp_set_lock(&queue_lock);
    {
        if (count > 0) {
            *event = ring[tail];
            tail = (tail + 1) & (QUEUE_CAPACITY - 1);
            count--;
            ret = 0;
        }
    }
    omp_unset_lock(&queue_lock);

    return ret;
}

int pktqueue_size(void)
{
    int sz;
    omp_set_lock(&queue_lock);
    sz = count;
    omp_unset_lock(&queue_lock);
    return sz;
}
