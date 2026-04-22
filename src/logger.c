/*
 * logger.c — Logging implementation.
 *
 * Supports dual-mode output: stderr (foreground) or syslog (daemon).
 * Messages are filtered by the compile-time LOG_LEVEL from config.h.
 *
 * _GNU_SOURCE is required to expose vsyslog() from syslog.h.
 */

#define _GNU_SOURCE

#include "logger.h"
#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>
#include <string.h>

/* ── State ─────────────────────────────────────────────────────────── */
static int g_use_syslog = 0;

/* Map our log levels to syslog priorities */
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

/* Human-readable level tags */
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

/* ── Public API ────────────────────────────────────────────────────── */

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
    }
}

void log_msg(log_level_t level, const char *fmt, ...)
{
    /* Filter by configured log level */
    if ((int)level > LOG_LEVEL) {
        return;
    }

    va_list args;
    va_start(args, fmt);

    if (g_use_syslog) {
        /* syslog handles timestamping and prefixing */
        vsyslog(level_to_syslog(level), fmt, args);
    } else {
        /* Stderr: add timestamp and level tag */
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char timebuf[20];
        strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm_info);

        fprintf(stderr, "[knockd %s %s] ", timebuf, level_tag(level));
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        fflush(stderr);
    }

    va_end(args);
}
