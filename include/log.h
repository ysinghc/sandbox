#ifndef LOG_H
#define LOG_H

// Structured logging (§10.12). One JSON object per line on stderr, which
// journald captures and rotates. Fields are standardised across components:
//
//   {"ts":"2026-10-17T12:34:56.789Z","level":"INFO","component":"ipc_server",
//    "event":"create","sandbox_id":7}
//
// Level filtering: LOG_DEBUG < LOG_INFO < LOG_WARN < LOG_ERROR. Configured via
// SANDBOX_LOG_LEVEL (name or number) or --log-level; default INFO.

#ifdef __cplusplus
extern "C" {
#endif

enum { LOG_DEBUG = 0, LOG_INFO = 1, LOG_WARN = 2, LOG_ERROR = 3 };

// Read SANDBOX_LOG_LEVEL (if set) and apply it. Call once at startup.
void log_init(void);

void log_set_level(int level);
int log_level(void);

// Parse "debug"|"info"|"warn"|"error" or "0".."3"; -1 if unrecognised.
int log_parse_level(const char* s);

// Emit one JSON line when `level` passes the threshold. `fmt` produces the
// trailing JSON fields (e.g. "\"sandbox_id\":%u") or "" for none.
void log_emitf(int level, const char* component, const char* event,
               const char* fmt, ...);

#define LOGF(level, comp, ev, ...) \
    log_emitf((level), (comp), (ev), __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // LOG_H
