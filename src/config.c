#include "config.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Default Values ──────────────────────────────────────────────────── */

int KNOCK_SEQ_LEN = 3;
uint16_t KNOCK_SEQUENCE[MAX_KNOCK_SEQ_LEN] = { 7000, 8000, 9000 };

int PROTECTED_PORT = 22;
int ACCESS_TIMEOUT = 30;
int KNOCK_WINDOW = 15;
int MAX_CLIENTS = 64;
int LOG_LEVEL = 2;

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
        }
    }

    fclose(f);
    log_info("Configuration loaded from %s", filepath);
    return 0;
}
