/*
 * logger.c — Leveled logging to stderr or syslog.
 *
 * Both threads log, so each line is formatted into a local buffer and
 * written with a single stdio call. Composing it with several fprintf()
 * calls would let two threads interleave halfway through a line.
 */

#include "logger.h"
#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

/* Longest message body we keep; anything longer is truncated. */
#define LOG_MSG_MAX  896
#define LOG_LINE_MAX 1024

static int g_use_syslog = 0;

/* Map our levels onto syslog priorities. */
static int level_to_syslog(log_level_t level)
{
    switch (level) {
        case LEVEL_ERROR: return LOG_ERR;
        case LEVEL_WARN:  return LOG_WARNING;
        case LEVEL_INFO:  return LOG_INFO;
        case LEVEL_DEBUG: return LOG_DEBUG;
        default:          return LOG_INFO;
    }
}

static const char *level_tag(log_level_t level)
{
    switch (level) {
        case LEVEL_ERROR: return "ERROR";
        case LEVEL_WARN:  return "WARN ";
        case LEVEL_INFO:  return "INFO ";
        case LEVEL_DEBUG: return "DEBUG";
        default:          return "?????";
    }
}

/* ── Public API ──────────────────────────────────────────────────────── */

void logger_init(int use_syslog)
{
    g_use_syslog = use_syslog;
    if (g_use_syslog) {
        openlog("knockd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }
}

void logger_close(void)
{
    if (g_use_syslog) {
        closelog();
        g_use_syslog = 0;
    }
}

void log_msg(log_level_t level, const char *fmt, ...)
{
    char      msg[LOG_MSG_MAX];
    char      line[LOG_LINE_MAX];
    char      timebuf[16];
    struct tm tm_buf;
    time_t    now;
    va_list   args;

    if ((int)level > LOG_LEVEL) {
        return;
    }

    va_start(args, fmt);

    if (g_use_syslog) {
        /* syslog adds its own timestamp, hostname and tag. */
        vsyslog(level_to_syslog(level), fmt, args);
        va_end(args);
        return;
    }

    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    now = time(NULL);
    if (localtime_r(&now, &tm_buf) != NULL) {
        strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tm_buf);
    } else {
        memcpy(timebuf, "--:--:--", sizeof("--:--:--"));
    }

    snprintf(line, sizeof(line), "[knockd %s %s] %s\n",
             timebuf, level_tag(level), msg);

    fputs(line, stderr);
    fflush(stderr);
}
