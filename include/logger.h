/*
 * logger.h — Leveled logging.
 *
 * Writes to stderr by default, or to syslog when logger_init() is told to.
 * Under systemd, stderr already ends up in the journal, so stderr is the
 * normal choice and syslog is there for running the daemon some other way.
 *
 * log_msg() is safe to call from any thread: each call emits one complete
 * line.
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
 *   use_syslog: non-zero to log to syslog, zero to log to stderr.
 */
void logger_init(int use_syslog);

/*
 * Shut the logger down (closes syslog if it was opened).
 */
void logger_close(void);

/*
 * Log one printf-style message. Messages above the configured LOG_LEVEL
 * are dropped. The message body is truncated past ~890 characters.
 */
void log_msg(log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* ── Convenience macros ──────────────────────────────────────────────── */
#define log_error(...)  log_msg(LEVEL_ERROR, __VA_ARGS__)
#define log_warn(...)   log_msg(LEVEL_WARN,  __VA_ARGS__)
#define log_info(...)   log_msg(LEVEL_INFO,  __VA_ARGS__)
#define log_debug(...)  log_msg(LEVEL_DEBUG, __VA_ARGS__)

#endif /* LOGGER_H */
