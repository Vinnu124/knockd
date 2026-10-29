/*
 * config.c — Config file parsing and validation.
 *
 * The format is one "key = value" per line, with # comments. Anything
 * missing, unparseable or out of range falls back to the built-in default
 * with a warning, so the daemon always starts with a usable configuration
 * rather than refusing to run over a typo.
 */

#include "config.h"
#include "logger.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* ── Defaults ────────────────────────────────────────────────────────── */
/*
 * Defined once so the initializers below, the reset logic in
 * config_validate() and knockd.conf.example cannot drift apart.
 */
#define DEFAULT_SEQUENCE_INIT   { 7000, 8000, 9000 }
#define DEFAULT_PROTECTED_PORT  22
#define DEFAULT_ACCESS_TIMEOUT  30
#define DEFAULT_KNOCK_WINDOW    15
#define DEFAULT_MAX_CLIENTS     64
#define DEFAULT_LOG_LEVEL       2

/* Values above these are almost certainly a mistake rather than intent. */
#define MAX_SANE_ACCESS_TIMEOUT 3600
#define MAX_SANE_CLIENTS        65536

static const uint16_t DEFAULT_SEQUENCE[] = DEFAULT_SEQUENCE_INIT;
#define DEFAULT_SEQ_LEN \
    ((int)(sizeof(DEFAULT_SEQUENCE) / sizeof(DEFAULT_SEQUENCE[0])))

int      KNOCK_SEQ_LEN                     = DEFAULT_SEQ_LEN;
uint16_t KNOCK_SEQUENCE[MAX_KNOCK_SEQ_LEN] = DEFAULT_SEQUENCE_INIT;

int  PROTECTED_PORT = DEFAULT_PROTECTED_PORT;
int  ACCESS_TIMEOUT = DEFAULT_ACCESS_TIMEOUT;
int  KNOCK_WINDOW   = DEFAULT_KNOCK_WINDOW;
int  MAX_CLIENTS    = DEFAULT_MAX_CLIENTS;
int  LOG_LEVEL      = DEFAULT_LOG_LEVEL;
char KNOCK_INTERFACE[IFNAME_MAX] = "";

/* ── Parsing helpers ─────────────────────────────────────────────────── */

/*
 * Restore the knock sequence and its length to the compiled-in default.
 */
static void reset_sequence_to_default(void)
{
    memcpy(KNOCK_SEQUENCE, DEFAULT_SEQUENCE, sizeof(DEFAULT_SEQUENCE));
    KNOCK_SEQ_LEN = DEFAULT_SEQ_LEN;
}

/*
 * Parse a strictly numeric value.
 *
 * Unlike atoi() this rejects an empty value, trailing garbage ("30s") and
 * anything outside int range, so a typo is reported instead of silently
 * becoming 0. On failure *out is left alone and the caller keeps its
 * default.
 *
 * Returns 0 on success, -1 on failure.
 */
static int parse_int(const char *key, const char *val, int *out)
{
    char *end = NULL;
    long  n;

    errno = 0;
    n = strtol(val, &end, 10);

    if (end == val || *end != '\0') {
        log_warn("Config: '%s' value \"%s\" is not a number — ignored",
                 key, val);
        return -1;
    }
    if (errno == ERANGE || n < INT_MIN || n > INT_MAX) {
        log_warn("Config: '%s' value \"%s\" is out of range — ignored",
                 key, val);
        return -1;
    }

    *out = (int)n;
    return 0;
}

/*
 * Parse a comma- or space-separated port list into KNOCK_SEQUENCE.
 *
 * Every entry must be a port in 1–65535, and one bad entry rejects the
 * whole list: a sequence is a shared secret, so listening on a
 * half-parsed version of it would be worse than falling back to the
 * default and saying so. Note that atoi() would have turned "70000" into
 * port 4464 without a word.
 *
 * Returns 0 on success, -1 if the list was rejected.
 */
static int parse_sequence(const char *val)
{
    uint16_t seq[MAX_KNOCK_SEQ_LEN];
    char     scratch[256];
    size_t   len   = strlen(val);
    int      count = 0;
    char    *tok;

    if (len >= sizeof(scratch)) {
        log_warn("Config: 'sequence' is too long to parse — rejected");
        return -1;
    }
    memcpy(scratch, val, len + 1);

    for (tok = strtok(scratch, ", \t"); tok != NULL;
         tok = strtok(NULL, ", \t")) {
        char *end = NULL;
        long  port;

        if (count >= MAX_KNOCK_SEQ_LEN) {
            log_warn("Config: 'sequence' has more than %d ports — rejected",
                     MAX_KNOCK_SEQ_LEN);
            return -1;
        }

        errno = 0;
        port  = strtol(tok, &end, 10);
        if (end == tok || *end != '\0' || errno == ERANGE ||
            port < 1 || port > 65535) {
            log_warn("Config: 'sequence' entry \"%s\" is not a port in "
                     "1–65535 — sequence rejected", tok);
            return -1;
        }
        seq[count++] = (uint16_t)port;
    }

    if (count == 0) {
        log_warn("Config: 'sequence' is empty — rejected");
        return -1;
    }

    memcpy(KNOCK_SEQUENCE, seq, (size_t)count * sizeof(seq[0]));
    KNOCK_SEQ_LEN = count;
    return 0;
}

/*
 * Copy an interface name into KNOCK_INTERFACE.
 *
 * Returns 0 on success, -1 if the name does not fit.
 */
static int parse_interface(const char *val)
{
    if (val[0] == '\0') {
        KNOCK_INTERFACE[0] = '\0';
        return 0;
    }
    if (strlen(val) >= sizeof(KNOCK_INTERFACE)) {
        log_warn("Config: 'interface' name \"%s\" is too long — ignored", val);
        return -1;
    }

    memcpy(KNOCK_INTERFACE, val, strlen(val) + 1);
    return 0;
}

/*
 * Warn if anyone but the owner can read the config file.
 *
 * The knock sequence is the whole secret, and the default install mode of
 * a config file is usually world-readable, so this is worth saying out
 * loud rather than assuming the operator checked.
 */
static void warn_if_world_readable(const char *filepath, FILE *f)
{
    struct stat st;

    if (fstat(fileno(f), &st) != 0) {
        return;
    }
    if (st.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
        log_warn("Config: %s is readable or writable by users other than "
                 "its owner (mode %04o) — it holds the knock sequence. "
                 "Run: chmod 600 %s",
                 filepath, (unsigned int)(st.st_mode & 07777), filepath);
    }
}

/* ── Validation ──────────────────────────────────────────────────────── */

/*
 * Check every field, resetting anything out of range or logically
 * inconsistent to its default and logging why.
 */
static void config_validate(void)
{
    int seq_ok   = 1;  /* the sequence survived validation            */
    int warnings = 0;  /* anything at all had to be reset or flagged  */

    /* ── Knock sequence ───────────────────────────────────────────── */
    if (KNOCK_SEQ_LEN < 2 || KNOCK_SEQ_LEN > MAX_KNOCK_SEQ_LEN) {
        log_warn("Config: 'sequence' must have 2–%d ports (got %d) "
                 "— using the default sequence",
                 MAX_KNOCK_SEQ_LEN, KNOCK_SEQ_LEN);
        seq_ok = 0;
    }

    for (int i = 0; seq_ok && i < KNOCK_SEQ_LEN; i++) {
        if (KNOCK_SEQUENCE[i] == 0) {
            log_warn("Config: knock port %d is 0 — using the default "
                     "sequence", i + 1);
            seq_ok = 0;
        }
    }

    /*
     * Duplicates are rejected because the daemon ignores a repeat of the
     * port it just accepted (see KNOCK_DEDUP_WINDOW in knocker.c). A
     * sequence like 7000,7000,9000 could therefore never be completed.
     */
    for (int i = 0; seq_ok && i < KNOCK_SEQ_LEN; i++) {
        for (int j = i + 1; j < KNOCK_SEQ_LEN; j++) {
            if (KNOCK_SEQUENCE[i] == KNOCK_SEQUENCE[j]) {
                log_warn("Config: 'sequence' repeats port %u at positions "
                         "%d and %d, which can never be completed "
                         "— using the default sequence",
                         KNOCK_SEQUENCE[i], i + 1, j + 1);
                seq_ok = 0;
                break;
            }
        }
    }

    if (!seq_ok) {
        reset_sequence_to_default();
        warnings++;
    }

    /* ── Protected port ───────────────────────────────────────────── */
    if (PROTECTED_PORT < 1 || PROTECTED_PORT > 65535) {
        log_warn("Config: 'port' %d is out of range (1–65535) — using %d",
                 PROTECTED_PORT, DEFAULT_PROTECTED_PORT);
        PROTECTED_PORT = DEFAULT_PROTECTED_PORT;
        warnings++;
    }

    for (int i = 0; i < KNOCK_SEQ_LEN; i++) {
        if ((int)KNOCK_SEQUENCE[i] == PROTECTED_PORT) {
            log_warn("Config: the protected port %d is also knock port %d. "
                     "Connecting to the protected port will count as a "
                     "knock — pick a sequence that does not include it.",
                     PROTECTED_PORT, i + 1);
            warnings++;
        }
    }

    /* ── Timing ───────────────────────────────────────────────────── */
    if (ACCESS_TIMEOUT <= 0) {
        log_warn("Config: 'timeout' must be greater than 0 (got %d) "
                 "— using %ds", ACCESS_TIMEOUT, DEFAULT_ACCESS_TIMEOUT);
        ACCESS_TIMEOUT = DEFAULT_ACCESS_TIMEOUT;
        warnings++;
    } else if (ACCESS_TIMEOUT > MAX_SANE_ACCESS_TIMEOUT) {
        log_warn("Config: 'timeout' of %ds keeps the port open for over an "
                 "hour after each knock — keeping the value, but check "
                 "that it is deliberate", ACCESS_TIMEOUT);
        warnings++;
    }

    if (KNOCK_WINDOW <= 0) {
        log_warn("Config: 'window' must be greater than 0 (got %d) "
                 "— using %ds", KNOCK_WINDOW, DEFAULT_KNOCK_WINDOW);
        KNOCK_WINDOW = DEFAULT_KNOCK_WINDOW;
        warnings++;
    }

    /* ── Capacity ─────────────────────────────────────────────────── */
    if (MAX_CLIENTS <= 0 || MAX_CLIENTS > MAX_SANE_CLIENTS) {
        log_warn("Config: 'max_clients' must be 1–%d (got %d) — using %d",
                 MAX_SANE_CLIENTS, MAX_CLIENTS, DEFAULT_MAX_CLIENTS);
        MAX_CLIENTS = DEFAULT_MAX_CLIENTS;
        warnings++;
    }

    /* ── Logging ──────────────────────────────────────────────────── */
    if (LOG_LEVEL < 0 || LOG_LEVEL > 3) {
        log_warn("Config: 'log_level' must be 0–3 (got %d) — using %d",
                 LOG_LEVEL, DEFAULT_LOG_LEVEL);
        LOG_LEVEL = DEFAULT_LOG_LEVEL;
        warnings++;
    }

    if (warnings == 0) {
        log_debug("Configuration validated");
    }
}

/* ── Public API ──────────────────────────────────────────────────────── */

int config_load(const char *filepath)
{
    char  line[256];
    FILE *f = fopen(filepath, "r");

    if (f == NULL) {
        log_warn("Could not open %s (%s) — falling back to the built-in "
                 "defaults, including the published default knock sequence",
                 filepath, strerror(errno));
        config_validate();
        return -1;
    }

    warn_if_world_readable(filepath, f);

    while (fgets(line, sizeof(line), f) != NULL) {
        char *ptr = line;
        char *eq;
        char *key;
        char *val;
        char *hash;
        char *end;

        while (*ptr == ' ' || *ptr == '\t') {
            ptr++;
        }
        if (*ptr == '#' || *ptr == '\n' || *ptr == '\r' || *ptr == '\0') {
            continue;
        }

        eq = strchr(ptr, '=');
        if (eq == NULL) {
            log_warn("Config: ignoring line without '=': %s", ptr);
            continue;
        }

        *eq = '\0';
        key = ptr;
        val = eq + 1;

        /* Trim the key's trailing whitespace. */
        end = key + strlen(key);
        while (end > key && (end[-1] == ' ' || end[-1] == '\t')) {
            *--end = '\0';
        }

        /* Drop a trailing comment, then trim whitespace from both ends of
         * the value. Without the trailing trim, "port = 22 " would be
         * rejected as non-numeric. */
        hash = strchr(val, '#');
        if (hash != NULL) {
            *hash = '\0';
        }
        val[strcspn(val, "\r\n")] = '\0';
        while (*val == ' ' || *val == '\t') {
            val++;
        }
        end = val + strlen(val);
        while (end > val && (end[-1] == ' ' || end[-1] == '\t')) {
            *--end = '\0';
        }

        if (strcmp(key, "sequence") == 0) {
            parse_sequence(val);
        } else if (strcmp(key, "port") == 0) {
            parse_int(key, val, &PROTECTED_PORT);
        } else if (strcmp(key, "timeout") == 0) {
            parse_int(key, val, &ACCESS_TIMEOUT);
        } else if (strcmp(key, "window") == 0) {
            parse_int(key, val, &KNOCK_WINDOW);
        } else if (strcmp(key, "max_clients") == 0) {
            parse_int(key, val, &MAX_CLIENTS);
        } else if (strcmp(key, "log_level") == 0) {
            parse_int(key, val, &LOG_LEVEL);
        } else if (strcmp(key, "interface") == 0) {
            parse_interface(val);
        } else {
            log_warn("Config: unknown key '%s' in %s — ignored",
                     key, filepath);
        }
    }

    if (ferror(f)) {
        log_warn("Error reading %s: %s", filepath, strerror(errno));
    }
    fclose(f);

    log_info("Configuration loaded from %s", filepath);
    config_validate();
    return 0;
}
