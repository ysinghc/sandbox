// SPDX-License-Identifier: GPL-2.0-only
#ifndef LIBSANDBOX_H
#define LIBSANDBOX_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to a running sandbox
typedef struct sandbox_handle_t sandbox_handle_t;

// Configuration for sandbox creation
typedef struct {
    uint64_t memory_mib;        // Guest memory in MiB (e.g., 512)
    uint32_t vcpu_count;        // Number of vCPUs (e.g., 1)
    const char* template_name;  // Snapshot template to restore from (e.g., "python-agent")
    const char** env_vars;      // NULL-terminated array of "KEY=VALUE" strings
    uint32_t pool_wait_ms;      // Max time to wait if pool exhausted, 0 = fail immediately
    // #23: session key of the writable /workspace volume. NULL (or empty) gives
    // the sandbox an ephemeral workspace that dies with it, which is the old
    // behaviour. A non-empty key gives the sandbox a *persistent* volume: a
    // second sandbox created with the same key sees the files the first one
    // left, in any template built with a workspace. The volume outlives the
    // sandbox; it is deleted when its TTL expires.
    const char* session_key;
    // Lifetime of a session volume, in seconds, counted from its creation.
    // 0 selects the platform default (7 days); requests are clamped to the
    // platform maximum (default 30 days). Ignored when session_key is NULL.
    uint32_t ttl_seconds;
} sandbox_spec_t;

// Error codes
typedef enum {
    SANDBOX_OK = 0,
    SANDBOX_ERR_POOL_EXHAUSTED  = -1,  // Pool empty and wait timed out
    SANDBOX_ERR_INVALID_SPEC    = -2,  // Bad config (unknown template, invalid memory size)
    SANDBOX_ERR_DAEMON_UNREACHABLE = -3,
    SANDBOX_ERR_PERMISSION_DENIED  = -4,
    SANDBOX_ERR_INTERNAL           = -5,
    // #23/D5 renewal. -6: the session's deadline has passed and its volume is
    // gone; there is nothing left to renew (a new create with the same key starts
    // an empty volume). -7: the session has already reached the platform maximum
    // lifetime, so it cannot be extended further.
    SANDBOX_ERR_SESSION_EXPIRED    = -6,
    SANDBOX_ERR_SESSION_LIMIT      = -7,
    SANDBOX_ERR_SESSION_UNKNOWN    = -8,  // no volume for that session key
} sandbox_error_t;

// Initialize client connection to daemon
// Returns 0 on success, error code on failure
sandbox_error_t sandbox_init(const char* socket_path);

// Create a new sandbox from the specified template
// On success, returns SANDBOX_OK and writes handle to *out_handle
// On failure, returns error code
sandbox_error_t sandbox_create(const sandbox_spec_t* spec, sandbox_handle_t** out_handle);

// Pause vCPU execution (guest state frozen, memory preserved)
sandbox_error_t sandbox_pause(sandbox_handle_t* handle);

// Resume vCPU execution
sandbox_error_t sandbox_resume(sandbox_handle_t* handle);

// Destroy sandbox and reclaim resources
// After this call, handle is invalid
sandbox_error_t sandbox_destroy(sandbox_handle_t* handle);

// Query sandbox status
typedef struct {
    uint32_t sandbox_id;
    bool is_running;          // false if paused
    uint64_t uptime_ms;       // Time since vCPU resume
    uint64_t memory_rss_mib;  // Resident set size
    uint32_t page_faults;     // Cumulative uffd page faults served
} sandbox_status_t;

sandbox_error_t sandbox_inspect(sandbox_handle_t* handle, sandbox_status_t* out_status);

// Extend a session volume's deadline (#23/D5).
//
// `session_key` names the volume, not a sandbox: the volume outlives every VM,
// so the caller that wants to keep its data may have nothing running to name.
// `extra_seconds` is added to *now* (not to the previous deadline), which is what
// "this conversation is still active" means; 0 selects the platform default
// (7 days). The result is clamped so the session never exceeds the platform
// maximum (30 days by default) and is never shortened. On success
// `*out_expires_at` (may be NULL) is the resulting deadline in unix seconds.
//
// Returns SANDBOX_ERR_SESSION_EXPIRED if the deadline has passed (the volume is
// already gone), SANDBOX_ERR_SESSION_UNKNOWN if the key has no volume,
// SANDBOX_ERR_SESSION_LIMIT if it already sits at the platform maximum, and
// SANDBOX_ERR_INVALID_SPEC for a key the registry cannot accept.
sandbox_error_t sandbox_session_renew(const char* session_key,
                                      uint32_t extra_seconds,
                                      uint64_t* out_expires_at);

// Human-readable form of an error code, for logs and CLI output. Never NULL.
const char* sandbox_error_string(sandbox_error_t code);

// Disconnect from daemon (destroys all sandboxes owned by this session)
void sandbox_cleanup(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // LIBSANDBOX_H
