/*
 * logger.h — Logging interface for the port knocking daemon.
 *
 * Provides leveled logging (DEBUG, INFO, WARN, ERROR) that outputs
 * to stderr in foreground mode and to syslog in daemon mode.
 */

#ifndef LOGGER_H
#define LOGGER_H

typedef enum {
    LEVEL_ERROR = 0,
    LEVEL_WARN  = 1,
    LEVEL_INFO  = 2,
    LEVEL_DEBUG = 3
} log_level_t;

/*
 * Initialize the logger.
 *   use_syslog: if true, log to syslog; if false, log to stderr.
 */
void logger_init(int use_syslog);

/*
 * Shutdown the logger (closes syslog if open).
 */
void logger_close(void);

/*
 * Log a message at the given level. Uses printf-style formatting.
 * Messages below the configured LOG_LEVEL are silently dropped.
 */
void log_msg(log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* ── Convenience macros ──────────────────────────────────────────────── */
#define log_error(...)  log_msg(LEVEL_ERROR, __VA_ARGS__)
#define log_warn(...)   log_msg(LEVEL_WARN,  __VA_ARGS__)
#define log_info(...)   log_msg(LEVEL_INFO,  __VA_ARGS__)
#define log_debug(...)  log_msg(LEVEL_DEBUG, __VA_ARGS__)

#endif /* LOGGER_H */
