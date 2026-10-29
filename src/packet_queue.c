/*
 * packet_queue.c — Bounded ring buffer with a condition variable.
 *
 * See packet_queue.h for the contract. Keeping the capture thread's work
 * down to "parse, push, go back to recvfrom()" matters: anything slow on
 * that path (fork/exec of iptables, in particular) would let the socket's
 * receive buffer overflow and silently lose knocks.
 */

#include "packet_queue.h"
#include "logger.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

/* Minimum gap between "queue full" reports. */
#define DROP_REPORT_INTERVAL 10

static knock_event_t ring[QUEUE_CAPACITY];
static int           head;           /* next write slot */
static int           tail;           /* next read slot  */
static int           count;
static int           shutting_down;

/* Dropped events not yet reported, and when we last reported. */
static unsigned long dropped;
static time_t        last_drop_report;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  not_empty;

/*
 * Fill ts with "now + timeout_ms" on the same clock pktqueue_init() gave
 * the condition variable.
 */
static void deadline_from_now(struct timespec *ts, int timeout_ms)
{
    if (clock_gettime(CLOCK_MONOTONIC, ts) != 0) {
        ts->tv_sec  = time(NULL);
        ts->tv_nsec = 0;
    }

    ts->tv_sec  += timeout_ms / 1000;
    ts->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec  += 1;
        ts->tv_nsec -= 1000000000L;
    }
}

/* ── Public API ──────────────────────────────────────────────────────── */

void pktqueue_init(void)
{
    pthread_condattr_t attr;

    head = tail = count = 0;
    shutting_down    = 0;
    dropped          = 0;
    last_drop_report = 0;
    memset(ring, 0, sizeof(ring));

    /*
     * Wait on the monotonic clock. With the default realtime clock, a
     * step in wall-clock time (ntp, a manual date change) would stretch or
     * collapse every pending timeout.
     */
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&not_empty, &attr);
    pthread_condattr_destroy(&attr);

    log_debug("Packet queue initialized (capacity %d)", QUEUE_CAPACITY);
}

void pktqueue_destroy(void)
{
    pthread_cond_destroy(&not_empty);
    log_debug("Packet queue destroyed");
}

int pktqueue_push(const knock_event_t *event)
{
    unsigned long to_report = 0;
    int           ret       = -1;

    pthread_mutex_lock(&lock);
    if (count < QUEUE_CAPACITY) {
        ring[head] = *event;
        head       = (head + 1) & (QUEUE_CAPACITY - 1);
        count++;
        ret = 0;
        pthread_cond_signal(&not_empty);
    } else {
        /*
         * Drop the event. A knock flood can produce these faster than we
         * could log them, so count them and report at most once every
         * DROP_REPORT_INTERVAL seconds — the log must not become the
         * amplifier for a flood.
         */
        time_t now = time(NULL);

        dropped++;
        if (now - last_drop_report >= DROP_REPORT_INTERVAL) {
            to_report        = dropped;
            dropped          = 0;
            last_drop_report = now;
        }
    }
    pthread_mutex_unlock(&lock);

    /* Log outside the lock: the capture thread should never wait on it. */
    if (to_report > 0) {
        log_warn("Packet queue full — dropped %lu knock event(s)", to_report);
    }

    return ret;
}

int pktqueue_pop(knock_event_t *event)
{
    int ret = -1;

    pthread_mutex_lock(&lock);
    if (count > 0) {
        *event = ring[tail];
        tail   = (tail + 1) & (QUEUE_CAPACITY - 1);
        count--;
        ret = 0;
    }
    pthread_mutex_unlock(&lock);

    return ret;
}

int pktqueue_wait(knock_event_t *event, int timeout_ms)
{
    struct timespec deadline;
    int             ret = -1;

    deadline_from_now(&deadline, timeout_ms);

    pthread_mutex_lock(&lock);
    while (count == 0 && !shutting_down) {
        if (pthread_cond_timedwait(&not_empty, &lock, &deadline) == ETIMEDOUT) {
            break;
        }
    }
    if (count > 0) {
        *event = ring[tail];
        tail   = (tail + 1) & (QUEUE_CAPACITY - 1);
        count--;
        ret = 0;
    }
    pthread_mutex_unlock(&lock);

    return ret;
}

void pktqueue_shutdown(void)
{
    pthread_mutex_lock(&lock);
    shutting_down = 1;
    pthread_cond_broadcast(&not_empty);
    pthread_mutex_unlock(&lock);
}
