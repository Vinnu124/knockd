/*
 * packet_queue.h — Thread-safe packet queue for producer-consumer pipeline.
 *
 * The sniffer thread pushes captured knock events into this queue,
 * and the processor thread(s) drain it. Uses OpenMP locks for
 * synchronization and a fixed-size ring buffer for bounded memory.
 */

#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include <stdint.h>

/* A single captured knock event */
typedef struct {
    uint32_t src_ip;     /* Source IP (network byte order) */
    uint16_t dst_port;   /* Destination port (host byte order) */
} knock_event_t;

/* Queue capacity — must be power of 2 for efficient modulo */
#define QUEUE_CAPACITY  256

/*
 * Initialize the packet queue. Must be called once at startup.
 */
void pktqueue_init(void);

/*
 * Destroy the packet queue. Called at shutdown.
 */
void pktqueue_destroy(void);

/*
 * Push a knock event into the queue (producer side).
 * Returns 0 on success, -1 if the queue is full (event is dropped).
 */
int pktqueue_push(const knock_event_t *event);

/*
 * Pop a knock event from the queue (consumer side).
 * Returns 0 on success, -1 if the queue is empty.
 */
int pktqueue_pop(knock_event_t *event);

/*
 * Returns the current number of events in the queue.
 */
int pktqueue_size(void);

#endif /* PACKET_QUEUE_H */
