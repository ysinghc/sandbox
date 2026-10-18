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
} sandbox_spec_t;

// Error codes
typedef enum {
    SANDBOX_OK = 0,
    SANDBOX_ERR_POOL_EXHAUSTED  = -1,  // Pool empty and wait timed out
    SANDBOX_ERR_INVALID_SPEC    = -2,  // Bad config (unknown template, invalid memory size)
    SANDBOX_ERR_DAEMON_UNREACHABLE = -3,
    SANDBOX_ERR_PERMISSION_DENIED  = -4,
    SANDBOX_ERR_INTERNAL           = -5,
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

// Disconnect from daemon (destroys all sandboxes owned by this session)
void sandbox_cleanup(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // LIBSANDBOX_H
