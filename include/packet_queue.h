/*
 * packet_queue.h — Bounded queue between the capture and processor threads.
 *
 * The capture thread pushes knock events; the processor thread drains them.
 * A fixed-size ring buffer keeps memory bounded and avoids a malloc per
 * packet, and a condition variable lets the processor sleep until there is
 * something to do.
 *
 * All functions are safe to call from any thread.
 */

#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <stdint.h>

/* One captured knock. */
typedef struct {
    uint32_t src_ip;     /* source IP, network byte order      */
    uint16_t dst_port;   /* destination port, host byte order  */
} knock_event_t;

/* Capacity. Must be a power of two — the ring masks instead of dividing. */
#define QUEUE_CAPACITY 256

/*
 * Initialize the queue. Call once, before starting any thread.
 */
void pktqueue_init(void);

/*
 * Release the queue's resources. Call once, after all threads have joined.
 */
void pktqueue_destroy(void);

/*
 * Push an event. Returns 0 on success, -1 if the queue was full and the
 * event was dropped.
 */
int pktqueue_push(const knock_event_t *event);

/*
 * Take an event if one is waiting, without blocking.
 * Returns 0 on success, -1 if the queue is empty.
 */
int pktqueue_pop(knock_event_t *event);

/*
 * Take an event, waiting up to timeout_ms for one to arrive.
 * Returns 0 on success, -1 on timeout or if the queue is shutting down.
 */
int pktqueue_wait(knock_event_t *event, int timeout_ms);

/*
 * Wake every waiter so it can notice that the daemon is stopping.
 * Subsequent pktqueue_wait() calls return immediately once the queue is
 * drained.
 */
void pktqueue_shutdown(void);

#endif /* PACKET_QUEUE_H */
