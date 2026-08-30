#include "config.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Default Values ──────────────────────────────────────────────────── */
/*
 * Fallback values, used when the config file is missing or unreadable,
 * omits a key, or supplies a value that config_validate() rejects as out
 * of range. Defined in one place so the initializers below, the reset
 * logic in config_validate(), and knockd.conf.example never drift apart.
 */
#define DEFAULT_SEQUENCE_INIT   { 7000, 8000, 9000 }
#define DEFAULT_PROTECTED_PORT  22
#define DEFAULT_ACCESS_TIMEOUT  30
#define DEFAULT_KNOCK_WINDOW    15
#define DEFAULT_MAX_CLIENTS     64
#define DEFAULT_LOG_LEVEL       2

static const uint16_t DEFAULT_SEQUENCE[] = DEFAULT_SEQUENCE_INIT;
#define DEFAULT_SEQ_LEN \
    ((int)(sizeof(DEFAULT_SEQUENCE) / sizeof(DEFAULT_SEQUENCE[0])))

int      KNOCK_SEQ_LEN                     = DEFAULT_SEQ_LEN;
uint16_t KNOCK_SEQUENCE[MAX_KNOCK_SEQ_LEN] = DEFAULT_SEQUENCE_INIT;

int PROTECTED_PORT = DEFAULT_PROTECTED_PORT;
int ACCESS_TIMEOUT = DEFAULT_ACCESS_TIMEOUT;
int KNOCK_WINDOW   = DEFAULT_KNOCK_WINDOW;
int MAX_CLIENTS    = DEFAULT_MAX_CLIENTS;
int LOG_LEVEL      = DEFAULT_LOG_LEVEL;

/*
 * Restore the knock sequence (and its length) to the compiled-in default.
 * Called by config_validate() whenever the configured sequence is unusable.
 */
static void reset_sequence_to_default(void)
{
    memcpy(KNOCK_SEQUENCE, DEFAULT_SEQUENCE, sizeof(DEFAULT_SEQUENCE));
    KNOCK_SEQ_LEN = DEFAULT_SEQ_LEN;
}

/*
 * Parse a comma-separated list of ports.
 */
static void parse_sequence(char *val)
{
    int count = 0;
    char *token = strtok(val, ", ");
    while (token != NULL && count < MAX_KNOCK_SEQ_LEN) {
        KNOCK_SEQUENCE[count++] = (uint16_t)atoi(token);
        token = strtok(NULL, ", ");
    }
    if (count > 0) {
        KNOCK_SEQ_LEN = count;
    }
}

/* ── Config Validation ───────────────────────────────────────────────── */

/*
 * Validate all configuration fields after loading.
 * Logs a warning and resets to the safe default for any field that is
 * out of range or logically inconsistent.
 */
static void config_validate(void)
{
    int ok = 1; /* track whether any warnings fired */

    /* ── Knock sequence ───────────────────────────────────────────── */
    if (KNOCK_SEQ_LEN < 2) {
        log_warn("Config: 'sequence' must have at least 2 ports (got %d) "
                 "— resetting to defaults (7000,8000,9000)", KNOCK_SEQ_LEN);
        reset_sequence_to_default();
        ok = 0;
    } else {
        /* Validate each port in the sequence */
        for (int i = 0; i < KNOCK_SEQ_LEN; i++) {
            if (KNOCK_SEQUENCE[i] < 1) {
                log_warn("Config: knock sequence port[%d]=%u is invalid "
                         "(must be 1–65535) — resetting to defaults",
                         i, KNOCK_SEQUENCE[i]);
                reset_sequence_to_default();
                ok = 0;
                break;
            }
        }

        /* Check for duplicate ports in the sequence */
        for (int i = 0; i < KNOCK_SEQ_LEN && ok; i++) {
            for (int j = i + 1; j < KNOCK_SEQ_LEN; j++) {
                if (KNOCK_SEQUENCE[i] == KNOCK_SEQUENCE[j]) {
                    log_warn("Config: knock sequence has duplicate port %u "
                             "at positions %d and %d — resetting to defaults",
                             KNOCK_SEQUENCE[i], i, j);
                    reset_sequence_to_default();
                    ok = 0;
                    break;
                }
            }
        }
    }

    /* ── Protected port ───────────────────────────────────────────── */
    if (PROTECTED_PORT < 1 || PROTECTED_PORT > 65535) {
        log_warn("Config: 'port' value %d is out of range (1–65535) "
                 "— resetting to default (22)", PROTECTED_PORT);
        PROTECTED_PORT = DEFAULT_PROTECTED_PORT;
        ok = 0;
    }

    /* Warn if the protected port collides with a knock port */
    for (int i = 0; i < KNOCK_SEQ_LEN; i++) {
        if ((int)KNOCK_SEQUENCE[i] == PROTECTED_PORT) {
            log_warn("Config: protected port %d is also in the knock "
                     "sequence (position %d) — this may cause issues",
                     PROTECTED_PORT, i);
            ok = 0;
        }
    }

    /* ── Access timeout ───────────────────────────────────────────── */
    if (ACCESS_TIMEOUT <= 0) {
        log_warn("Config: 'timeout' must be > 0 (got %d) "
                 "— resetting to default (30s)", ACCESS_TIMEOUT);
        ACCESS_TIMEOUT = DEFAULT_ACCESS_TIMEOUT;
        ok = 0;
    } else if (ACCESS_TIMEOUT > 3600) {
        log_warn("Config: 'timeout' of %ds is very large (max sensible is "
                 "3600s) — keeping value but double-check your config",
                 ACCESS_TIMEOUT);
    }

    /* ── Knock window ─────────────────────────────────────────────── */
    if (KNOCK_WINDOW <= 0) {
        log_warn("Config: 'window' must be > 0 (got %d) "
                 "— resetting to default (15s)", KNOCK_WINDOW);
        KNOCK_WINDOW = DEFAULT_KNOCK_WINDOW;
        ok = 0;
    } else if (KNOCK_WINDOW > ACCESS_TIMEOUT) {
        log_warn("Config: 'window' (%ds) is larger than 'timeout' (%ds) "
                 "— this is unusual, double-check your config",
                 KNOCK_WINDOW, ACCESS_TIMEOUT);
    }

    /* ── Max clients ──────────────────────────────────────────────── */
    if (MAX_CLIENTS <= 0) {
        log_warn("Config: 'max_clients' must be > 0 (got %d) "
                 "— resetting to default (64)", MAX_CLIENTS);
        MAX_CLIENTS = DEFAULT_MAX_CLIENTS;
        ok = 0;
    } else if (MAX_CLIENTS > 65536) {
        log_warn("Config: 'max_clients' of %d is unreasonably large "
                 "— resetting to default (64)", MAX_CLIENTS);
        MAX_CLIENTS = DEFAULT_MAX_CLIENTS;
        ok = 0;
    }

    /* ── Log level ────────────────────────────────────────────────── */
    if (LOG_LEVEL < 0 || LOG_LEVEL > 3) {
        log_warn("Config: 'log_level' must be 0–3 (got %d) "
                 "— resetting to default (2 = INFO)", LOG_LEVEL);
        LOG_LEVEL = DEFAULT_LOG_LEVEL;
        ok = 0;
    }

    if (ok) {
        log_info("Configuration validation passed — all values are sane");
    }
}

int config_load(const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f) {
        log_warn("Could not open config file %s, using defaults", filepath);
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *ptr = line;
        /* skip leading whitespace */
        while (*ptr == ' ' || *ptr == '\t') ptr++;

        /* skip comments and empty lines */
        if (*ptr == '#' || *ptr == '\n' || *ptr == '\r' || *ptr == '\0') {
            continue;
        }

        /* find the '=' */
        char *eq = strchr(ptr, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = ptr;
        char *val = eq + 1;

        /* trim trailing whitespace from key */
        char *k_end = key + strlen(key) - 1;
        while (k_end > key && (*k_end == ' ' || *k_end == '\t')) {
            *k_end = '\0';
            k_end--;
        }

        /* trim leading whitespace from val */
        while (*val == ' ' || *val == '\t') val++;

        /* trim trailing newlines from val */
        val[strcspn(val, "\r\n")] = 0;

        if (strcmp(key, "sequence") == 0) {
            parse_sequence(val);
        } else if (strcmp(key, "port") == 0) {
            PROTECTED_PORT = atoi(val);
        } else if (strcmp(key, "timeout") == 0) {
            ACCESS_TIMEOUT = atoi(val);
        } else if (strcmp(key, "window") == 0) {
            KNOCK_WINDOW = atoi(val);
        } else if (strcmp(key, "max_clients") == 0) {
            MAX_CLIENTS = atoi(val);
        } else if (strcmp(key, "log_level") == 0) {
            LOG_LEVEL = atoi(val);
        } else {
            /* Unknown key — warn the user so typos don't go unnoticed */
            log_warn("Config: unknown key '%s' in %s — ignored", key, filepath);
        }
    }

    fclose(f);
    log_info("Configuration loaded from %s", filepath);

    /* Validate all values and reset any that are out of range */
    config_validate();

    return 0;
}
