// SPDX-License-Identifier: GPL-2.0-only
// Structured logging (§10.12). See include/log.h.

#define _GNU_SOURCE

#include "log.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>

static int g_level = LOG_INFO;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

int log_parse_level(const char* s) {
    if (!s || !*s) return -1;
    if (strcasecmp(s, "debug") == 0) return LOG_DEBUG;
    if (strcasecmp(s, "info") == 0) return LOG_INFO;
    if (strcasecmp(s, "warn") == 0 || strcasecmp(s, "warning") == 0)
        return LOG_WARN;
    if (strcasecmp(s, "error") == 0 || strcasecmp(s, "err") == 0)
        return LOG_ERROR;
    char* end = NULL;
    long v = strtol(s, &end, 10);
    if (end && *end == '\0' && v >= LOG_DEBUG && v <= LOG_ERROR) return (int)v;
    return -1;
}

void log_set_level(int level) {
    if (level >= LOG_DEBUG && level <= LOG_ERROR) g_level = level;
}

int log_level(void) { return g_level; }

void log_init(void) {
    const char* e = getenv("SANDBOX_LOG_LEVEL");
    int l = log_parse_level(e);
    if (l >= 0) g_level = l;
}

static const char* level_name(int level) {
    switch (level) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_WARN:  return "WARN";
        case LOG_ERROR: return "ERROR";
        default:        return "INFO";
    }
}

void log_emitf(int level, const char* component, const char* event,
               const char* fmt, ...) {
    if (level < g_level) return;

    char extra[1024];
    extra[0] = '\0';
    if (fmt && *fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(extra, sizeof(extra), fmt, ap);
        va_end(ap);
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    gmtime_r(&tv.tv_sec, &tm);
    char ts[40];
    snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
             tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000));

    pthread_mutex_lock(&g_lock);
    fprintf(stderr,
            "{\"ts\":\"%s\",\"level\":\"%s\",\"component\":\"%s\","
            "\"event\":\"%s\"%s%s}\n",
            ts, level_name(level), component ? component : "",
            event ? event : "", extra[0] ? "," : "", extra);
    fflush(stderr);
    pthread_mutex_unlock(&g_lock);
}
