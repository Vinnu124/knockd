/*
 * firewall.c — iptables rule manager with time-limited grants.
 *
 * See firewall.h for the contract.
 *
 * Two things here are deliberate and worth not undoing:
 *
 *   - Rules go into knockd's own chain, never straight into INPUT. Deleting
 *     a rule by its specification removes whichever matching rule iptables
 *     finds first, so expiring a grant for 10.0.0.5 in INPUT could delete a
 *     permanent rule for 10.0.0.5 that the operator added by hand.
 *
 *   - Nothing here deletes a rule knockd did not add. Shutdown must leave
 *     the protected port closed; a daemon that opened it on the way out
 *     would be worse than no daemon at all.
 */

#include "firewall.h"
#include "config.h"
#include "logger.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Seconds iptables will wait for the xtables lock.
 *
 * Concurrent iptables invocations fail outright without this. Nothing in
 * knockd runs two at once, but other things on the host do — firewalld,
 * docker, fail2ban, an admin at a shell — and a failed delete means a
 * grant that never expires.
 */
#define IPTABLES_WAIT "5"

/* Grants closed in a single firewall_tick() pass; the rest wait for the
 * next one. Bounds the work done while nothing else runs. */
#define MAX_EXPIRY_PER_TICK 16

typedef struct {
    uint32_t ip;          /* network byte order         */
    time_t   expires_at;  /* when the grant runs out    */
    bool     active;
} grant_t;

static grant_t        *grants      = NULL;
static pthread_mutex_t grants_lock = PTHREAD_MUTEX_INITIALIZER;

/* Did knockd add the INPUT -> KNOCKD jump? If the operator put it in their
 * persistent ruleset we leave it alone on the way out. */
static bool g_added_jump = false;

/* ── Running iptables ────────────────────────────────────────────────── */

/*
 * Format an IP for use as an iptables argument.
 *
 * The address comes straight out of the packet header as a 32-bit value,
 * and inet_ntop() turns it into dotted quad, so there is no attacker-
 * supplied string anywhere in the argument list. Combined with execv()
 * below — no shell, no word splitting — there is nothing to inject into.
 */
static int ip_to_str(uint32_t ip, char *buf, size_t buflen)
{
    if (inet_ntop(AF_INET, &ip, buf, buflen) == NULL) {
        log_error("inet_ntop() failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * Run iptables and wait for it.
 *
 * fork() plus execv() rather than system(): no shell is started, so none
 * of the arguments can be read as shell syntax.
 *
 * quiet suppresses the log for commands that are expected to fail, such as
 * probing whether a chain already exists.
 *
 * Returns 0 if iptables exited successfully, -1 otherwise.
 */
static int run_iptables(char *const argv[], bool quiet)
{
    pid_t pid;
    int   status;

    if (LOG_LEVEL >= LEVEL_DEBUG) {
        char cmd[256];
        size_t off = 0;

        for (int i = 0; argv[i] != NULL && off < sizeof(cmd) - 1; i++) {
            int n = snprintf(cmd + off, sizeof(cmd) - off, "%s%s",
                             (i == 0) ? "" : " ", argv[i]);
            if (n < 0 || (size_t)n >= sizeof(cmd) - off) {
                break;
            }
            off += (size_t)n;
        }
        log_debug("Running: %s", cmd);
    }

    pid = fork();
    if (pid < 0) {
        log_error("fork() failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        execv(argv[0], argv);
        /* execv only returns on failure, and we are in the child, so
         * _exit() rather than exit(): no atexit handlers, no flushing the
         * parent's buffers twice. */
        _exit(127);
    }

    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            log_error("waitpid() failed: %s", strerror(errno));
            return -1;
        }
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }

    if (!quiet) {
        if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
            log_error("Could not execute %s — is iptables installed there?",
                      IPTABLES_PATH);
        } else if (WIFEXITED(status)) {
            log_error("%s exited with status %d",
                      IPTABLES_PATH, WEXITSTATUS(status));
        } else {
            log_error("%s was killed by signal %d", IPTABLES_PATH,
                      WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        }
    }
    return -1;
}

/*
 * Insert ("-I") or delete ("-D") the ACCEPT rule for one address in
 * knockd's chain.
 */
static int run_grant_rule(const char *action, const char *ip_str)
{
    char  port_str[8];
    char *argv[] = {
        IPTABLES_PATH,
        "-w", IPTABLES_WAIT,
        (char *)action,
        KNOCKD_CHAIN,
        "-s", (char *)ip_str,
        "-p", "tcp",
        "--dport", port_str,
        "-j", "ACCEPT",
        NULL
    };

    snprintf(port_str, sizeof(port_str), "%d", PROTECTED_PORT);
    return run_iptables(argv, false);
}

/* ── Grant table ─────────────────────────────────────────────────────── */

/* Caller holds grants_lock. */
static grant_t *find_grant(uint32_t ip)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (grants[i].active && grants[i].ip == ip) {
            return &grants[i];
        }
    }
    return NULL;
}

/* ── Public API ──────────────────────────────────────────────────────── */

int firewall_init(void)
{
    char *new_chain[]   = { IPTABLES_PATH, "-w", IPTABLES_WAIT,
                            "-N", KNOCKD_CHAIN, NULL };
    char *flush_chain[] = { IPTABLES_PATH, "-w", IPTABLES_WAIT,
                            "-F", KNOCKD_CHAIN, NULL };
    char *check_jump[]  = { IPTABLES_PATH, "-w", IPTABLES_WAIT,
                            "-C", "INPUT", "-j", KNOCKD_CHAIN, NULL };
    char *add_jump[]    = { IPTABLES_PATH, "-w", IPTABLES_WAIT,
                            "-I", "INPUT", "1", "-j", KNOCKD_CHAIN,
                            NULL };

    grants = calloc((size_t)MAX_CLIENTS, sizeof(*grants));
    if (grants == NULL) {
        log_error("Could not allocate a grant table for %d clients",
                  MAX_CLIENTS);
        return -1;
    }

    /*
     * Creating the chain fails if it already exists, which is the normal
     * case after a restart, so the result is ignored. The flush that
     * follows is what tells us the chain is really there — and it also
     * clears any grant left behind by a daemon that was killed.
     */
    run_iptables(new_chain, true);

    if (run_iptables(flush_chain, false) != 0) {
        log_error("Could not create or flush the %s chain. Check that "
                  "%s works and that we are root.",
                  KNOCKD_CHAIN, IPTABLES_PATH);
        free(grants);
        grants = NULL;
        return -1;
    }

    /*
     * Hook INPUT into the chain, at the top so a grant wins over the
     * operator's DROP. If the jump is already there (a persistent ruleset,
     * or a previous run that is still hooked up) leave it where it is.
     */
    if (run_iptables(check_jump, true) != 0) {
        if (run_iptables(add_jump, false) != 0) {
            log_error("Could not insert the INPUT jump to %s", KNOCKD_CHAIN);
            free(grants);
            grants = NULL;
            return -1;
        }
        g_added_jump = true;
        log_debug("Inserted INPUT -> %s at position 1", KNOCKD_CHAIN);
    } else {
        log_debug("INPUT already jumps to %s — leaving it in place",
                  KNOCKD_CHAIN);
    }

    log_info("Firewall ready — grants go into the %s chain", KNOCKD_CHAIN);
    return 0;
}

int firewall_open(uint32_t client_ip)
{
    char     ip_str[INET_ADDRSTRLEN];
    grant_t *slot = NULL;
    time_t   expires_at;
    bool     extended = false;

    if (grants == NULL) {
        log_error("firewall_open() before firewall_init()");
        return -1;
    }
    if (ip_to_str(client_ip, ip_str, sizeof(ip_str)) < 0) {
        return -1;
    }

    expires_at = time(NULL) + ACCESS_TIMEOUT;

    pthread_mutex_lock(&grants_lock);
    slot = find_grant(client_ip);
    if (slot != NULL) {
        /*
         * Already open: push the deadline out instead of inserting a
         * second identical rule. Without this, knocking repeatedly would
         * stack duplicate ACCEPT rules that each need their own delete.
         */
        slot->expires_at = expires_at;
        extended         = true;
    } else {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!grants[i].active) {
                slot = &grants[i];
                break;
            }
        }
        if (slot != NULL) {
            /* Reserve the slot before running iptables so a second
             * completed sequence for the same address cannot race into a
             * duplicate rule. */
            slot->ip         = client_ip;
            slot->expires_at = expires_at;
            slot->active     = true;
        }
    }
    pthread_mutex_unlock(&grants_lock);

    if (slot == NULL) {
        log_error("All %d grant slots are in use — refusing access for %s",
                  MAX_CLIENTS, ip_str);
        return -1;
    }

    if (extended) {
        log_info("Access for %s extended — now expires in %ds",
                 ip_str, ACCESS_TIMEOUT);
        return 0;
    }

    if (run_grant_rule("-I", ip_str) != 0) {
        log_error("Could not open port %d for %s", PROTECTED_PORT, ip_str);
        pthread_mutex_lock(&grants_lock);
        slot->active = false;
        pthread_mutex_unlock(&grants_lock);
        return -1;
    }

    log_info("Port %d is open for %s — closes in %ds",
             PROTECTED_PORT, ip_str, ACCESS_TIMEOUT);
    return 0;
}

int firewall_close(uint32_t client_ip)
{
    char     ip_str[INET_ADDRSTRLEN];
    grant_t *slot;
    bool     was_active = false;

    if (grants == NULL || ip_to_str(client_ip, ip_str, sizeof(ip_str)) < 0) {
        return -1;
    }

    pthread_mutex_lock(&grants_lock);
    slot = find_grant(client_ip);
    if (slot != NULL) {
        slot->active = false;
        was_active   = true;
    }
    pthread_mutex_unlock(&grants_lock);

    if (!was_active) {
        log_debug("No grant to close for %s", ip_str);
        return 0;
    }

    if (run_grant_rule("-D", ip_str) != 0) {
        log_warn("Could not remove the rule for %s — check %s -S %s",
                 ip_str, IPTABLES_PATH, KNOCKD_CHAIN);
        return -1;
    }

    log_info("Port %d is closed for %s", PROTECTED_PORT, ip_str);
    return 0;
}

void firewall_tick(void)
{
    uint32_t expired[MAX_EXPIRY_PER_TICK];
    int      count = 0;
    time_t   now;

    if (grants == NULL) {
        return;
    }
    now = time(NULL);

    pthread_mutex_lock(&grants_lock);
    for (int i = 0; i < MAX_CLIENTS && count < MAX_EXPIRY_PER_TICK; i++) {
        if (grants[i].active && now >= grants[i].expires_at) {
            expired[count++] = grants[i].ip;
            grants[i].active = false;
        }
    }
    pthread_mutex_unlock(&grants_lock);

    /* Run iptables outside the lock. */
    for (int i = 0; i < count; i++) {
        char ip_str[INET_ADDRSTRLEN];

        if (ip_to_str(expired[i], ip_str, sizeof(ip_str)) < 0) {
            continue;
        }
        log_info("Access has expired for %s — closing port %d",
                 ip_str, PROTECTED_PORT);
        if (run_grant_rule("-D", ip_str) != 0) {
            log_warn("Could not remove the expired rule for %s — check "
                     "%s -S %s", ip_str, IPTABLES_PATH, KNOCKD_CHAIN);
        }
    }
}

void firewall_shutdown(void)
{
    char *flush[]  = { IPTABLES_PATH, "-w", IPTABLES_WAIT,
                       "-F", KNOCKD_CHAIN, NULL };
    char *unhook[] = { IPTABLES_PATH, "-w", IPTABLES_WAIT,
                       "-D", "INPUT", "-j", KNOCKD_CHAIN, NULL };
    char *del[]    = { IPTABLES_PATH, "-w", IPTABLES_WAIT,
                       "-X", KNOCKD_CHAIN, NULL };

    if (grants == NULL) {
        return;  /* never initialized — nothing of ours is installed */
    }

    /*
     * Flushing the chain revokes every outstanding grant in one call. The
     * operator's own rules are in INPUT, not in here, so they survive:
     * stopping knockd closes the protected port rather than opening it.
     */
    if (run_iptables(flush, false) != 0) {
        log_warn("Could not flush the %s chain — grants may still be in "
                 "place. Check %s -S %s",
                 KNOCKD_CHAIN, IPTABLES_PATH, KNOCKD_CHAIN);
    }

    if (g_added_jump) {
        if (run_iptables(unhook, false) != 0) {
            log_warn("Could not remove the INPUT jump to %s", KNOCKD_CHAIN);
        } else {
            /* Only possible once nothing references the chain. */
            run_iptables(del, true);
        }
    }

    free(grants);
    grants = NULL;

    log_info("Removed the firewall rules knockd added");
}
