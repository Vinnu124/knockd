/*
 * main.c — knockd entry point.
 *
 * Wires the sniffer, the knock state machine and the firewall together.
 *
 * Two threads:
 *
 *   - the capture thread reads packets off a raw socket and pushes knock
 *     events into a bounded queue;
 *   - the main thread drains the queue, runs the state machine, opens the
 *     firewall for a completed sequence, and expires old grants.
 *
 * The split is what keeps the capture path short. Opening the firewall
 * means fork/exec of iptables, which takes milliseconds — long enough that
 * doing it inline would let the socket's receive buffer overflow and lose
 * knocks from everyone else while it ran.
 *
 * Usage:
 *   sudo ./knockd                      # foreground, config from /etc
 *   sudo ./knockd -c ./knockd.conf -v   # local config, debug logging
 */

#include "config.h"
#include "firewall.h"
#include "knocker.h"
#include "logger.h"
#include "packet_queue.h"
#include "sniffer.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * Longest the processor waits for a knock before looking around. It has to
 * wake up regularly even on an idle network to expire grants, drop stale
 * client entries and notice that the daemon is stopping.
 */
#define POLL_INTERVAL_MS 200

/* Seconds between sweeps for abandoned knock sequences. */
#define STALE_SCAN_INTERVAL 5

/* Cleared by the signal handler to bring both threads down. */
static volatile sig_atomic_t g_running = 1;

static void signal_handler(int signum)
{
    (void)signum;
    g_running = 0;
}

/*
 * Format the knock sequence into buf as "7000 -> 8000 -> 9000".
 * Truncates rather than overflowing, and always NUL-terminates. Returns
 * buf so it can be passed straight into a printf-style call.
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
                         (i == 0) ? "" : " -> ", KNOCK_SEQUENCE[i]);
        if (n < 0 || (size_t)n >= buflen - off) {
            break;  /* out of room — stop cleanly */
        }
        off += (size_t)n;
    }
    return buf;
}

/*
 * Print a startup summary.
 *
 * The sequence itself is withheld unless debug logging was asked for. It
 * is the shared secret, and stderr goes to the journal under systemd,
 * where it is readable by more people than /etc/knockd.conf is.
 */
static void print_banner(void)
{
    char seqbuf[160];

    if (LOG_LEVEL >= LEVEL_DEBUG) {
        format_knock_sequence(seqbuf, sizeof(seqbuf));
    } else {
        snprintf(seqbuf, sizeof(seqbuf),
                 "%d ports (hidden — run with -v to show them)",
                 KNOCK_SEQ_LEN);
    }

    fprintf(stderr,
        "\n"
        "  knockd %s\n"
        "  ---------------------------------\n"
        "\n"
        "    knock sequence   %s\n"
        "    protected port   %d\n"
        "    access window    %ds open, %ds allowed between knocks\n"
        "    client table     %d slots\n"
        "    capture on       %s\n"
        "\n",
        KNOCKD_VERSION, seqbuf, PROTECTED_PORT, ACCESS_TIMEOUT,
        KNOCK_WINDOW, MAX_CLIENTS,
        (KNOCK_INTERFACE[0] != '\0') ? KNOCK_INTERFACE : "every interface");
}

static void print_usage(const char *progname)
{
    printf("Usage: sudo %s [OPTIONS]\n", progname);
    printf("\n");
    printf("Options:\n");
    printf("  -c, --config <file>  Config file (default: %s)\n",
           DEFAULT_CONFIG_PATH);
    printf("  -v, --verbose        Debug logging; overrides log_level\n");
    printf("  -s, --syslog         Log to syslog instead of stderr\n");
    printf("  -V, --version        Print the version and exit\n");
    printf("  -h, --help           Print this help and exit\n");
    printf("\n");
    printf("knockd runs in the foreground and is meant to be supervised by\n");
    printf("systemd, which captures stderr into the journal. It needs root\n");
    printf("for the raw capture socket and for iptables.\n");
    printf("\n");
}

/*
 * The capture thread: raw socket in, queue out, and nothing slow in
 * between.
 */
static void *capture_thread(void *arg)
{
    int sock_fd = *(const int *)arg;

    while (g_running) {
        knock_event_t evt;
        int           rc;

        rc = sniffer_next_knock(sock_fd, &evt.src_ip, &evt.dst_port);
        if (rc == SNIFFER_OK) {
            pktqueue_push(&evt);
        } else if (rc == SNIFFER_ERROR) {
            log_error("Packet capture failed — stopping the daemon");
            g_running = 0;
            break;
        }
        /* SNIFFER_AGAIN: a receive timeout. Loop and re-check g_running. */
    }

    /* Wake the processor if it is waiting on an empty queue. */
    pktqueue_shutdown();
    return NULL;
}

/*
 * Handle one captured knock.
 */
static void process_event(const knock_event_t *evt)
{
    char ip_str[INET_ADDRSTRLEN];

    if (knocker_process(evt->src_ip, evt->dst_port) != KNOCK_COMPLETE) {
        return;
    }

    if (inet_ntop(AF_INET, &evt->src_ip, ip_str, sizeof(ip_str)) == NULL) {
        log_error("A sequence completed but its address could not be "
                  "formatted — ignoring it");
        return;
    }

    log_info("%s completed the knock sequence", ip_str);
    if (firewall_open(evt->src_ip) < 0) {
        log_error("%s completed the sequence but the firewall could not be "
                  "opened", ip_str);
    }
}

/*
 * The processor loop, which runs on the main thread until a signal
 * arrives.
 */
static void run_processor(void)
{
    time_t last_cleanup = time(NULL);

    while (g_running) {
        knock_event_t evt;
        time_t        now;

        if (pktqueue_wait(&evt, POLL_INTERVAL_MS) == 0) {
            /* Something arrived — handle it and anything queued behind
             * it before going back to sleep. */
            do {
                process_event(&evt);
            } while (pktqueue_pop(&evt) == 0);
        }

        firewall_tick();

        now = time(NULL);
        if (now - last_cleanup >= STALE_SCAN_INTERVAL) {
            knocker_cleanup_stale();
            last_cleanup = now;
        }
    }
}

int main(int argc, char *argv[])
{
    const char      *config_file     = DEFAULT_CONFIG_PATH;
    int              config_explicit = 0;
    int              verbose         = 0;
    int              use_syslog      = 0;
    int              sock_fd         = -1;
    int              exit_code       = 1;
    pthread_t        capture_tid;
    int              capture_started = 0;
    struct sigaction sa;

    /* ── Arguments ─────────────────────────────────────────────────── */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-V") == 0 ||
                   strcmp(argv[i], "--version") == 0) {
            printf("knockd %s\n", KNOCKD_VERSION);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 ||
                   strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-s") == 0 ||
                   strcmp(argv[i], "--syslog") == 0) {
            use_syslog = 1;
        } else if (strcmp(argv[i], "-c") == 0 ||
                   strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s needs a file path.\n", argv[i]);
                return 1;
            }
            config_file     = argv[++i];
            config_explicit = 1;
        } else {
            fprintf(stderr, "Error: unknown option '%s'.\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: knockd needs root for the raw capture "
                        "socket and for iptables.\n");
        fprintf(stderr, "Try: sudo %s\n", argv[0]);
        return 1;
    }

    logger_init(use_syslog);

    /*
     * A config file named on the command line has to exist. Carrying on
     * with the built-in defaults would mean running with the knock
     * sequence that is published in the README, which is no sequence at
     * all. The default path is treated more leniently, with a warning, so
     * a first run before the file is installed still works.
     */
    if (config_load(config_file) != 0 && config_explicit) {
        log_error("Could not read the config file given with -c (%s) "
                  "— refusing to start with the default knock sequence",
                  config_file);
        logger_close();
        return 1;
    }

    /* -v wins over log_level, so debugging a running daemon does not need
     * a config edit. Applied after config_load() for that reason. */
    if (verbose) {
        LOG_LEVEL = LEVEL_DEBUG;
        log_info("Debug logging enabled (-v overrides log_level)");
    }

    print_banner();

    /* ── Signals ───────────────────────────────────────────────────── */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* iptables runs in a child process; nothing here writes to a pipe or
     * socket, but SIGPIPE would be fatal by default if that ever changed. */
    signal(SIGPIPE, SIG_IGN);

    /* ── Start up ──────────────────────────────────────────────────── */
    pktqueue_init();

    if (knocker_init() != 0) {
        goto cleanup;
    }

    /*
     * Set the firewall up before capturing. Starting the other way round
     * would leave a window where knocks are accepted and silently fail to
     * open anything.
     */
    if (firewall_init() != 0) {
        goto cleanup;
    }

    sock_fd = sniffer_init();
    if (sock_fd < 0) {
        log_error("Could not start packet capture");
        goto cleanup;
    }

    if (pthread_create(&capture_tid, NULL, capture_thread, &sock_fd) != 0) {
        log_error("Could not start the capture thread");
        goto cleanup;
    }
    capture_started = 1;

    log_info("knockd %s is running — %d knock ports, protecting port %d",
             KNOCKD_VERSION, KNOCK_SEQ_LEN, PROTECTED_PORT);

    run_processor();

    exit_code = 0;

cleanup:
    log_info("Shutting down");

    g_running = 0;
    pktqueue_shutdown();
    if (capture_started) {
        pthread_join(capture_tid, NULL);
    }

    sniffer_close(sock_fd);
    firewall_shutdown();
    knocker_shutdown();
    pktqueue_destroy();

    log_info("knockd stopped");
    logger_close();

    return exit_code;
}
