#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#define MAX_KNOCK_SEQ_LEN 16

/* ── Global Configuration Variables ──────────────────────────────────── */

extern int KNOCK_SEQ_LEN;
extern uint16_t KNOCK_SEQUENCE[MAX_KNOCK_SEQ_LEN];

extern int PROTECTED_PORT;
extern int ACCESS_TIMEOUT;
extern int KNOCK_WINDOW;
extern int MAX_CLIENTS;
extern int LOG_LEVEL;

/* IPTABLES_PATH remains a macro as it's a fixed system path */
#define IPTABLES_PATH "/usr/sbin/iptables"

/*
 * Load configuration from a file (e.g. /etc/knockd.conf).
 * Uses default values if the file is missing or variables are unspecified.
 */
int config_load(const char *filepath);

#endif /* CONFIG_H */
