// SPDX-License-Identifier: GPL-2.0-only
#ifndef LIBSANDBOX_H
#define LIBSANDBOX_H

#include <stddef.h>
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
    // #24 guest operations.
    SANDBOX_ERR_GUEST_UNAVAILABLE  = -9,   // agent unreachable or not ready; retryable
    SANDBOX_ERR_PATH_DENIED        = -10,  // outside /workspace, or not a plain absolute path
    SANDBOX_ERR_NOT_FOUND          = -11,
    SANDBOX_ERR_EXISTS             = -12,
    SANDBOX_ERR_TOO_LARGE          = -13,  // file, chunk or stdin over its limit
    SANDBOX_ERR_GUEST_IO           = -14,  // the guest's filesystem failed the operation
    SANDBOX_ERR_TIMEOUT            = -15,  // the host-side deadline expired
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

// ---------------------------------------------------------------------------
// Guest operations (#24): run commands and touch files inside a running sandbox.
//
// Every call needs the sandbox's handle (the daemon checks the session owns it)
// and may be made from several threads at once; they run concurrently and can
// take as long as the command does. File paths must be absolute and under
// /workspace: `..`, relative paths and symlinks that lead out are refused with
// SANDBOX_ERR_PATH_DENIED. (A command can of course read whatever the guest can;
// the confinement is for the file calls, not for exec.)
// ---------------------------------------------------------------------------

// Largest file the whole-file calls will move (the guest's own limit).
#define SANDBOX_MAX_FILE (4u * 1024u * 1024u)

typedef struct {
    // NULL-terminated. With `shell`, argv[0] is a script run by /bin/sh -c and
    // there must be no further elements; without it, argv is exec'd directly
    // (PATH is searched).
    const char* const* argv;
    bool shell;
    const char* cwd;                 // NULL: /workspace
    const char* const* env;          // NULL-terminated "KEY=VALUE", or NULL
    uint32_t timeout_ms;             // 0: 1 hour (also the maximum)
    // Agent-side cap on stdout+stderr combined; the command is killed when it is
    // exceeded and `output_truncated` is set. 0: 4 MiB.
    uint32_t max_output;
    const uint8_t* stdin_data;       // up to 64 KiB, then EOF
    size_t stdin_len;
} sandbox_exec_spec_t;

typedef struct {
    int exit_code;                   // -1 if the command was killed by a signal
    int term_signal;                 // that signal, else 0
    bool timed_out;                  // timeout_ms expired; the process group was killed
    bool output_truncated;           // the max_output cap killed it
    // The *head* of each stream: up to 32 KiB of stdout and 16 KiB of stderr fit
    // one reply. `*_total` is how much the command actually wrote, so a caller
    // can tell what was dropped. For more output, redirect to a file in
    // /workspace and read it back with sandbox_read_file.
    uint8_t* out;
    size_t out_len;
    uint64_t out_total;
    uint8_t* err;
    size_t err_len;
    uint64_t err_total;
} sandbox_exec_result_t;

// Run a command. Returns SANDBOX_OK whenever the command ran to completion --
// including a non-zero exit, a timeout or a kill; inspect the result for those.
// Any other code means it did not run (or the reply was lost).
sandbox_error_t sandbox_exec(sandbox_handle_t* handle, const sandbox_exec_spec_t* spec,
                             sandbox_exec_result_t* out);
void sandbox_exec_result_free(sandbox_exec_result_t* result);

// Read a whole file (up to SANDBOX_MAX_FILE) into a malloc'd buffer; free() it.
// SANDBOX_ERR_TOO_LARGE if the file is bigger.
sandbox_error_t sandbox_read_file(sandbox_handle_t* handle, const char* path,
                                  uint8_t** out_data, size_t* out_len);

#define SANDBOX_WRITE_APPEND  0x1u   // append instead of replacing
#define SANDBOX_WRITE_EXCL    0x2u   // fail with SANDBOX_ERR_EXISTS if present
#define SANDBOX_WRITE_PARENTS 0x4u   // create missing parent directories

// Write a whole file (up to SANDBOX_MAX_FILE). `mode` 0 means 0644. A file that
// fits one message (48 KiB) replaces the old one atomically; a larger one is
// sent in chunks (first chunk replaces, the rest append), so a failure partway
// can leave a partial file -- write to a temporary name and rename it with exec
// if that matters.
sandbox_error_t sandbox_write_file(sandbox_handle_t* handle, const char* path,
                                   const uint8_t* data, size_t len, uint32_t mode,
                                   uint32_t flags);

typedef struct {
    char name[256];
    uint8_t type;       // 0 other, 1 file, 2 dir, 3 symlink
    uint64_t size;
    int64_t mtime;
} sandbox_dirent_t;

// List a directory. `*out_entries` is malloc'd (free() it); `*out_truncated`
// (may be NULL) is set when the listing was cut to fit one reply.
sandbox_error_t sandbox_list_dir(sandbox_handle_t* handle, const char* path,
                                 sandbox_dirent_t** out_entries, size_t* out_count,
                                 bool* out_truncated);

typedef struct {
    uint8_t type;       // as sandbox_dirent_t.type
    uint64_t size;
    uint32_t mode;      // permission bits
    int64_t mtime;
} sandbox_fstat_t;

sandbox_error_t sandbox_stat(sandbox_handle_t* handle, const char* path,
                             sandbox_fstat_t* out);
// `mode` 0 means 0755. With `parents` this is `mkdir -p`.
sandbox_error_t sandbox_mkdir(sandbox_handle_t* handle, const char* path,
                              uint32_t mode, bool parents);
// Never removes the workspace root. `recursive` is required for a non-empty directory.
sandbox_error_t sandbox_remove(sandbox_handle_t* handle, const char* path,
                               bool recursive);

// Human-readable form of an error code, for logs and CLI output. Never NULL.
const char* sandbox_error_string(sandbox_error_t code);

// Disconnect from daemon (destroys all sandboxes owned by this session)
void sandbox_cleanup(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // LIBSANDBOX_H
