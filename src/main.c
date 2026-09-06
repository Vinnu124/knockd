/*
 * main.c — Port Knocking Daemon entry point.
 *
 * Ties together the sniffer, state machine, and firewall manager.
 * Handles signal-based graceful shutdown, argument parsing, and
 * the main packet-processing pipeline.
 *
 * The daemon runs two threads in parallel:
 *   - A sniffer thread captures TCP SYN and UDP packets and pushes
 *     them into a shared ring buffer.
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
 * Format the configured knock sequence into buf as "7000 → 8000 → 9000".
 * Always NUL-terminates and truncates rather than overflowing. Returns buf
 * so it can be passed straight to a printf-style call.
 */
static const char *format_knock_sequence(char *buf, size_t buflen)
{
    size_t off = 0;

    if (buflen == 0) {
        return buf;
    }
    buf[0] = '\0';

    for (int i = 0; i < KNOCK_SEQ_LEN; i++) {
        int n = snprintf(buf + off, buflen - off, "%s%u",
                         (i == 0) ? "" : " → ", KNOCK_SEQUENCE[i]);
        if (n < 0 || (size_t)n >= buflen - off) {
            break;  /* truncated — stop cleanly */
        }
        off += (size_t)n;
    }
    return buf;
}

/*
 * Print a startup banner summarizing the active configuration.
 * Goes to stderr so it shares a stream with the log output (matters when
 * redirecting, or reading the daemon's output back from journald).
 */
static void print_banner(void)
{
    char seqbuf[128];

    fprintf(stderr,
        "\n"
        "  knockd — port knocking daemon\n"
        "  ─────────────────────────────\n"
        "\n"
        "    knock sequence   %s\n"
        "    protected port   %d\n"
        "    access window    %ds open, %ds between knocks\n"
        "    client table     %d slots\n"
        "\n",
        format_knock_sequence(seqbuf, sizeof(seqbuf)),
        PROTECTED_PORT, ACCESS_TIMEOUT, KNOCK_WINDOW, MAX_CLIENTS);
}

static void print_usage(const char *progname)
{
    printf("Usage: sudo %s [OPTIONS]\n", progname);
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help           Show this help message\n");
    printf("  -f, --foreground     Run in foreground (default)\n");
    printf("  -v, --verbose        Enable debug logging\n");
    printf("  -c, --config <file>  Path to config file (default: /etc/knockd.conf)\n");
    printf("\n");
    printf("The daemon must be run as root (requires raw sockets + iptables).\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    int         verbose     = 0;
    const char *config_file = "/etc/knockd.conf";  /* default path */

    /* ── Parse arguments ───────────────────────────────────────────── */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--foreground") == 0) {
            /* Already the default */
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a file path argument.\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
            config_file = argv[++i];
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

    /* ── Load Configuration ────────────────────────────────────────── */
    config_load(config_file);

    /*
     * A -v/--verbose flag on the command line overrides log_level from
     * the config file, so debugging a running daemon doesn't require a
     * config edit and restart. Applied after config_load() so it wins.
     */
    if (verbose) {
        LOG_LEVEL = LEVEL_DEBUG;
        log_info("Verbose/debug logging enabled (-v overrides config log_level)");
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

    log_debug("Signal handlers installed (SIGINT/SIGTERM stop the daemon)");

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

    char seqbuf[128];
    log_info("Listening — knock %s (TCP SYN or UDP) to open port %d",
             format_knock_sequence(seqbuf, sizeof(seqbuf)), PROTECTED_PORT);

    /* ── Parallel pipeline: sniffer + processor ────────────────────── */

    #pragma omp parallel sections num_threads(2)
    {
        /* ── Sniffer: captures packets, pushes to queue ────────────── */
        #pragma omp section
        {

            while (g_running) {
                uint32_t src_ip;
                uint16_t dst_port;

                int ret = sniffer_next_knock(g_sock_fd, &src_ip, &dst_port);

                if (ret < 0) {
                    if (!g_running) break;
                    continue;
                }
                knock_event_t evt = { .src_ip = src_ip, .dst_port = dst_port };
                pktqueue_push(&evt);
            }
        }

        /* ── Processor: drains queue, runs state machine ───────────── */
        #pragma omp section
        {

            time_t last_cleanup = time(NULL);

            while (g_running) {
                knock_event_t evt;

                /* Drain all available events from the queue */
                while (pktqueue_pop(&evt) == 0) {
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

                        /*
                         * Open the port synchronously. iptables returns in
                         * a few ms and completions are rare, so there is
                         * nothing to gain from offloading — and an OpenMP
                         * task generated inside this section is not
                         * guaranteed to run until the next taskwait, which
                         * only happens at shutdown.
                         */
                        if (firewall_open(evt.src_ip) < 0) {
                            log_error("Failed to open firewall for %s",
                                      ip_str);
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
