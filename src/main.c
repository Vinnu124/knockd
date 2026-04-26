/*
 * main.c — Port Knocking Daemon entry point.
 *
 * Ties together the sniffer, state machine, and firewall manager.
 * Handles signal-based graceful shutdown, argument parsing, and
 * the main packet-processing pipeline.
 *
 * The daemon runs two threads in parallel:
 *   - A sniffer thread captures TCP SYN packets and pushes them
 *     into a shared ring buffer.
 *   - A processor thread drains the queue, runs the knock state
 *     machine, and triggers firewall operations.
 *
 * Usage:
 *   sudo ./knockd              # Run in foreground
 *   sudo ./knockd -v           # Verbose / debug logging
 */

#include "config.h"
#include "logger.h"
#include "sniffer.h"
#include "knocker.h"
#include "firewall.h"
#include "packet_queue.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <omp.h>

/* ── Globals for signal handler ────────────────────────────────────── */
static volatile sig_atomic_t g_running = 1;
static int g_sock_fd = -1;

/*
 * Signal handler for SIGINT (Ctrl+C) and SIGTERM.
 * Sets the running flag to 0 so both threads exit gracefully.
 */
static void signal_handler(int signum)
{
    (void)signum;
    g_running = 0;
}

/*
 * Print a banner showing the daemon configuration.
 */
static void print_banner(void)
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║          PORT KNOCKING DAEMON (knockd)              ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║                                                      ║\n");
    printf("║  Knock sequence:  ");
    for (int i = 0; i < KNOCK_SEQ_LEN; i++) {
        printf("%u", KNOCK_SEQUENCE[i]);
        if (i < KNOCK_SEQ_LEN - 1) printf(" → ");
    }
    printf("\n");
    printf("║  Protected port:  %d\n", PROTECTED_PORT);
    printf("║  Access timeout:  %d seconds\n", ACCESS_TIMEOUT);
    printf("║  Knock window:    %d seconds\n", KNOCK_WINDOW);
    printf("║  Max clients:     %d\n", MAX_CLIENTS);
    printf("║  OpenMP threads:  %d\n", omp_get_max_threads());
    printf("║                                                      ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\n");
}

static void print_usage(const char *progname)
{
    printf("Usage: sudo %s [OPTIONS]\n", progname);
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help       Show this help message\n");
    printf("  -f, --foreground Run in foreground (default)\n");
    printf("  -v, --verbose    Enable debug logging\n");
    printf("\n");
    printf("The daemon must be run as root (requires raw sockets + iptables).\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    int verbose = 0;

    /* ── Parse arguments ───────────────────────────────────────────── */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--foreground") == 0) {
            /* Already the default */
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* ── Check root privileges ─────────────────────────────────────── */
    if (geteuid() != 0) {
        fprintf(stderr, "Error: knockd must be run as root.\n");
        fprintf(stderr, "Try: sudo %s\n", argv[0]);
        return 1;
    }

    /* ── Initialize logger ─────────────────────────────────────────── */
    logger_init(0);

    if (verbose) {
        log_info("Verbose/debug logging enabled");
    }

    /* ── Print banner ──────────────────────────────────────────────── */
    print_banner();

    /* ── Install signal handlers ───────────────────────────────────── */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    log_info("Signal handlers installed (Ctrl+C or kill to stop)");

    /* ── Initialize components ─────────────────────────────────────── */
    knocker_init();
    pktqueue_init();

    g_sock_fd = sniffer_init();
    if (g_sock_fd < 0) {
        log_error("Failed to initialize sniffer — exiting");
        pktqueue_destroy();
        logger_close();
        return 1;
    }

    log_info("Listening for knock sequences...");
    log_info("Send TCP SYN to ports %u → %u → %u to open port %d",
             KNOCK_SEQUENCE[0], KNOCK_SEQUENCE[1], KNOCK_SEQUENCE[2],
             PROTECTED_PORT);

    /* ── Parallel pipeline: sniffer + processor ────────────────────── */

    #pragma omp parallel sections num_threads(2)
    {
        /* ── Sniffer: captures packets, pushes to queue ────────────── */
        #pragma omp section
        {
            log_info("[OMP] Sniffer running on thread %d", omp_get_thread_num());

            while (g_running) {
                uint32_t src_ip;
                uint16_t dst_port;

                int ret = sniffer_next_knock(g_sock_fd, &src_ip, &dst_port);

                if (ret < 0) {
                    if (!g_running) break;
                    continue;
                }

                knock_event_t evt = { .src_ip = src_ip, .dst_port = dst_port };
                log_info("[OMP] Thread %d pushing knock event to queue",
                         omp_get_thread_num());
                pktqueue_push(&evt);
            }

            log_info("[OMP] Sniffer thread %d exiting", omp_get_thread_num());
        }

        /* ── Processor: drains queue, runs state machine ───────────── */
        #pragma omp section
        {
            log_info("[OMP] Processor running on thread %d", omp_get_thread_num());

            time_t last_cleanup = time(NULL);

            while (g_running) {
                knock_event_t evt;

                /* Drain all available events from the queue */
                while (pktqueue_pop(&evt) == 0) {
                    log_info("[OMP] Thread %d processing knock event",
                             omp_get_thread_num());
                    knock_result_t result = knocker_process(evt.src_ip,
                                                            evt.dst_port);

                    if (result == KNOCK_COMPLETE) {
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &evt.src_ip, ip_str,
                                  sizeof(ip_str));
                        log_info("==> KNOCK SEQUENCE COMPLETE from %s!",
                                 ip_str);
                        log_info("==> Opening port %d for %s (auto-closes "
                                 "in %ds)",
                                 PROTECTED_PORT, ip_str, ACCESS_TIMEOUT);

                        /* Run firewall open as a task so multiple
                         * completions don't block each other */
                        uint32_t task_ip = evt.src_ip;
                        #pragma omp task firstprivate(task_ip)
                        {
                            log_info("[OMP] Firewall task running on thread %d",
                                     omp_get_thread_num());
                            if (firewall_open(task_ip) < 0) {
                                char tstr[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, &task_ip, tstr,
                                          sizeof(tstr));
                                log_error("Failed to open firewall for %s",
                                          tstr);
                            }
                        }
                    }
                }

                /* Periodically clean up stale client entries */
                time_t now = time(NULL);
                if (now - last_cleanup >= 5) {
                    knocker_cleanup_stale();
                    last_cleanup = now;
                }

                /* Brief sleep to avoid busy-waiting on an empty queue */
                usleep(10000);
            }

            #pragma omp taskwait
            log_info("[OMP] Processor thread %d exiting", omp_get_thread_num());
        }
    }

    /* ── Graceful shutdown ─────────────────────────────────────────── */
    log_info("Shutting down...");

    firewall_cleanup_all();
    sniffer_close(g_sock_fd);
    pktqueue_destroy();

    log_info("knockd stopped. Goodbye!");
    logger_close();

    return 0;
}
