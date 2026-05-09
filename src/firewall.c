/*
 * firewall.c — Dynamic iptables rule manager with auto-expiry.
 *
 * Opens/closes the protected port for specific IPs by forking
 * and exec'ing the iptables binary. Each open action spawns a
 * detached timer thread that removes the rule after ACCESS_TIMEOUT.
 *
 * Security:
 *   - IPs are validated through inet_ntop() (prevents injection)
 *   - Uses fork()/execv() instead of system() (no shell involved)
 *   - Tracks all added rules for cleanup on daemon exit
 */

#include "firewall.h"
#include "config.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <errno.h>

/* ── Active Rules Tracking ─────────────────────────────────────────── */

/* Track which IPs currently have open rules, for cleanup on exit */
typedef struct {
    uint32_t ip;
    int      active;
} active_rule_t;

static active_rule_t *active_rules = NULL;
static pthread_mutex_t rules_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── Helpers ───────────────────────────────────────────────────────── */

/* Safely convert IP to string (validated through inet_ntop) */
static int ip_to_safe_str(uint32_t ip, char *buf, size_t buflen)
{
    if (inet_ntop(AF_INET, &ip, buf, buflen) == NULL) {
        log_error("inet_ntop() failed — invalid IP");
        return -1;
    }
    return 0;
}

/*
 * Execute an iptables command using fork()/execv().
 * NO shell is involved — safe from injection attacks.
 *
 * action: "-I" (insert) or "-D" (delete)
 * ip_str: validated IP address string
 *
 * Returns: 0 on success, -1 on error.
 */
static int run_iptables(const char *action, const char *ip_str)
{
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", PROTECTED_PORT);

    log_debug("Executing: %s %s INPUT -s %s -p tcp --dport %s -j ACCEPT",
              IPTABLES_PATH, action, ip_str, port_str);

    pid_t pid = fork();

    if (pid < 0) {
        log_error("fork() failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* ── Child process: exec iptables ──────────────────────── */
        char *argv[] = {
            (char *)IPTABLES_PATH,
            (char *)action,       /* -I or -D */
            "INPUT",
            "-s", (char *)ip_str,
            "-p", "tcp",
            "--dport", port_str,
            "-j", "ACCEPT",
            NULL
        };

        execv(IPTABLES_PATH, argv);

        /* execv only returns on error */
        fprintf(stderr, "[knockd] execv(%s) failed: %s\n",
                IPTABLES_PATH, strerror(errno));
        _exit(127);
    }

    /* ── Parent process: wait for iptables to finish ───────────── */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        log_error("waitpid() failed: %s", strerror(errno));
        return -1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }

    log_error("iptables %s exited with status %d", action,
              WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return -1;
}

/* ── Expiry Timer Thread ───────────────────────────────────────────── */

typedef struct {
    uint32_t client_ip;
} expiry_arg_t;

static void *expiry_thread(void *arg)
{
    expiry_arg_t *ea = (expiry_arg_t *)arg;
    uint32_t ip = ea->client_ip;
    free(ea);

    char ip_str[INET_ADDRSTRLEN];
    ip_to_safe_str(ip, ip_str, sizeof(ip_str));

    log_info("Access timer started for %s (%d seconds)", ip_str, ACCESS_TIMEOUT);

    sleep(ACCESS_TIMEOUT);

    log_info("Access expired for %s — closing port %d", ip_str, PROTECTED_PORT);
    firewall_close(ip);

    return NULL;
}

/* ── Track active rules ────────────────────────────────────────────── */

static void track_rule_add(uint32_t ip)
{
    pthread_mutex_lock(&rules_mutex);
    if (!active_rules) {
        active_rules = calloc(MAX_CLIENTS, sizeof(active_rule_t));
    }
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!active_rules[i].active) {
            active_rules[i].ip     = ip;
            active_rules[i].active = 1;
            break;
        }
    }
    pthread_mutex_unlock(&rules_mutex);
}

static void track_rule_remove(uint32_t ip)
{
    pthread_mutex_lock(&rules_mutex);
    if (!active_rules) {
        pthread_mutex_unlock(&rules_mutex);
        return;
    }
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (active_rules[i].active && active_rules[i].ip == ip) {
            active_rules[i].active = 0;
            break;
        }
    }
    pthread_mutex_unlock(&rules_mutex);
}

/* ── Public API ────────────────────────────────────────────────────── */

int firewall_open(uint32_t client_ip)
{
    char ip_str[INET_ADDRSTRLEN];
    if (ip_to_safe_str(client_ip, ip_str, sizeof(ip_str)) < 0) {
        return -1;
    }

    log_info("Opening port %d for %s", PROTECTED_PORT, ip_str);

    if (run_iptables("-I", ip_str) < 0) {
        log_error("Failed to open port %d for %s", PROTECTED_PORT, ip_str);
        return -1;
    }

    /* Track the rule for cleanup */
    track_rule_add(client_ip);

    log_info("*** Port %d OPEN for %s (expires in %ds) ***",
             PROTECTED_PORT, ip_str, ACCESS_TIMEOUT);

    /* Spawn expiry timer thread */
    expiry_arg_t *ea = malloc(sizeof(expiry_arg_t));
    if (ea == NULL) {
        log_error("malloc() failed for expiry thread arg");
        return -1;
    }
    ea->client_ip = client_ip;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&tid, &attr, expiry_thread, ea) != 0) {
        log_error("Failed to create expiry thread: %s", strerror(errno));
        free(ea);
        /* Rule is still open, but won't auto-close. Log a warning. */
        log_warn("Rule for %s will NOT auto-expire!", ip_str);
    }

    pthread_attr_destroy(&attr);
    return 0;
}

int firewall_close(uint32_t client_ip)
{
    char ip_str[INET_ADDRSTRLEN];
    if (ip_to_safe_str(client_ip, ip_str, sizeof(ip_str)) < 0) {
        return -1;
    }

    log_info("Closing port %d for %s", PROTECTED_PORT, ip_str);

    int ret = run_iptables("-D", ip_str);

    /* Remove from tracking regardless of iptables result
     * (the rule might have been manually removed) */
    track_rule_remove(client_ip);

    if (ret == 0) {
        log_info("Port %d CLOSED for %s", PROTECTED_PORT, ip_str);
    }

    return ret;
}

void firewall_cleanup_all(void)
{
    log_info("Cleaning up all firewall rules added by knockd...");

    /*
     * Take a snapshot of active rules under the lock, then
     * release the lock and clean them up in parallel.
     * Each iptables -D call is independent per IP.
     */
    uint32_t *to_remove = malloc(MAX_CLIENTS * sizeof(uint32_t));
    if (!to_remove) return;
    int remove_count = 0;

    pthread_mutex_lock(&rules_mutex);
    if (active_rules) {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (active_rules[i].active) {
                to_remove[remove_count++] = active_rules[i].ip;
                active_rules[i].active = 0;
            }
        }
    }
    pthread_mutex_unlock(&rules_mutex);

    /* Parallel cleanup — each iptables call runs in its own thread */
    #pragma omp parallel for schedule(dynamic)
    for (int i = 0; i < remove_count; i++) {
        char ip_str[INET_ADDRSTRLEN];
        if (ip_to_safe_str(to_remove[i], ip_str, sizeof(ip_str)) == 0) {
            log_info("Removing rule for %s", ip_str);
            run_iptables("-D", ip_str);
        }
    }
    free(to_remove);

    log_info("Firewall cleanup complete (%d rules removed)", remove_count);

    /* Also remove the baseline DROP rule we used for testing */
    log_info("Removing baseline DROP rule for port %d...", PROTECTED_PORT);
    pid_t pid = fork();
    if (pid == 0) {
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", PROTECTED_PORT);
        char *argv[] = {
            (char *)IPTABLES_PATH,
            "-D", "INPUT",
            "-p", "tcp",
            "--dport", port_str,
            "-j", "DROP",
            NULL
        };
        execv(IPTABLES_PATH, argv);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            log_info("Baseline DROP rule removed successfully");
        } else {
            log_warn("Failed to remove baseline DROP rule (maybe it wasn't added?)");
        }
    }
}
