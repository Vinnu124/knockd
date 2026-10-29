/*
 * config.h — Runtime configuration.
 *
 * Every tunable lives in a global that config_load() fills in from the
 * config file and config_validate() sanity-checks. Values are read-only
 * once the threads start, so no locking is needed around them.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

/* Upper bound on how many ports a knock sequence may contain. */
#define MAX_KNOCK_SEQ_LEN 16

/* Buffer size for the optional capture interface name. */
#define IFNAME_MAX 32

/* Config file used when -c is not given. */
#define DEFAULT_CONFIG_PATH "/etc/knockd.conf"

/* Injected by the Makefile from `git describe`. */
#ifndef KNOCKD_VERSION
#define KNOCKD_VERSION "unknown"
#endif

/* ── Configuration ───────────────────────────────────────────────────── */

extern int      KNOCK_SEQ_LEN;
extern uint16_t KNOCK_SEQUENCE[MAX_KNOCK_SEQ_LEN];

extern int  PROTECTED_PORT;
extern int  ACCESS_TIMEOUT;
extern int  KNOCK_WINDOW;
extern int  MAX_CLIENTS;
extern int  LOG_LEVEL;
extern char KNOCK_INTERFACE[IFNAME_MAX];  /* "" captures on every interface */

/* Fixed system paths. */
#define IPTABLES_PATH "/usr/sbin/iptables"

/*
 * The iptables chain knockd creates and owns. Every rule the daemon adds
 * goes in here, which keeps it clear of whatever else INPUT contains:
 * expiring a grant can never delete a similar rule the operator wrote, and
 * cleaning up is a flush of a chain nothing else writes to.
 */
#define KNOCKD_CHAIN "KNOCKD"

/*
 * Read filepath, then validate every field, resetting anything missing,
 * unparseable or out of range to its built-in default.
 *
 * Returns 0 if the file was read, -1 if it could not be opened. Either way
 * the configuration is left in a usable, validated state.
 */
int config_load(const char *filepath);

#endif /* CONFIG_H */
