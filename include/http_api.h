// SPDX-License-Identifier: GPL-2.0-only
#ifndef HTTP_API_H
#define HTTP_API_H

// Control-plane HTTP API (#27). A separate, unprivileged process (sandbox-api)
// that speaks HTTP to assistants and their gateways and talks to the engine only
// through libsandbox, like any other client: it adds sessions, principals and a
// wire format, and no engine logic.
//
// The engine is reached through an ops table that production fills with the
// libsandbox functions and the tests fill with an in-memory fake, so everything
// above the engine -- auth, isolation, idempotency, framing, error mapping,
// streaming -- is testable without KVM.

#include <stdint.h>
#include <sys/types.h>

#include "libsandbox.h"

typedef struct {
    sandbox_error_t (*create)(const sandbox_spec_t*, sandbox_handle_t**);
    sandbox_error_t (*destroy)(sandbox_handle_t*);
    sandbox_error_t (*renew)(const char* session_key, uint32_t extra, uint64_t* expires_at);
    sandbox_error_t (*exec)(sandbox_handle_t*, const sandbox_exec_spec_t*, sandbox_exec_result_t*);
    void (*exec_free)(sandbox_exec_result_t*);
    sandbox_error_t (*read_file)(sandbox_handle_t*, const char*, uint8_t**, size_t*);
    sandbox_error_t (*write_file)(sandbox_handle_t*, const char*, const uint8_t*, size_t, uint32_t, uint32_t);
    sandbox_error_t (*list_dir)(sandbox_handle_t*, const char*, sandbox_dirent_t**, size_t*, bool*);
    sandbox_error_t (*stat)(sandbox_handle_t*, const char*, sandbox_fstat_t*);
    sandbox_error_t (*mkdir)(sandbox_handle_t*, const char*, uint32_t, bool);
    sandbox_error_t (*remove)(sandbox_handle_t*, const char*, bool);
} api_engine_ops_t;

extern const api_engine_ops_t api_engine_libsandbox;

typedef struct {
    // Listeners. At least one. A Unix socket identifies callers by peer uid; TCP
    // requires a bearer token, so it refuses to start without a token file.
    const char* unix_path;
    unsigned unix_mode;          // 0660 if 0
    const char* tcp_host;        // NULL: no TCP listener
    int tcp_port;                // 0 with tcp_host: pick a free port (tests)
    int allow_public_bind;       // tcp_host must be loopback unless set
    const char* tokens_path;     // principals file; NULL: none (Unix socket only)

    const char* default_template;   // "python-agent" if NULL
    uint64_t default_memory_mib;    // 256 if 0
    uint32_t default_vcpus;         // 1 if 0
    uint32_t default_ttl_seconds;   // 0: the engine's default
    unsigned max_running;           // sandboxes held at once (64): the engine caps a connection at 128
    unsigned max_sessions_total;    // 256
    unsigned max_sessions_default;  // per principal unless its entry says otherwise (16)
    unsigned idle_vm_seconds;       // reclaim a VM after this long idle (300); the workspace stays
    unsigned max_connections;       // 128
    uint32_t pool_wait_ms;          // how long a create may wait for a warm VM (0: the daemon's default)
    unsigned keepalive_seconds;     // SSE comment interval while a command runs (10)

    const api_engine_ops_t* engine;  // api_engine_libsandbox if NULL
} api_config_t;

typedef struct api_server api_server_t;

// Starts the listeners and the reaper; returns once they accept. NULL on error
// (message on stderr).
api_server_t* api_server_start(const api_config_t* cfg);
// The TCP port actually bound (0 if there is no TCP listener).
int api_server_tcp_port(const api_server_t* srv);
// Stops accepting, drops open connections, destroys every sandbox it holds.
void api_server_stop(api_server_t* srv);
// Sandboxes currently held (for tests and metrics).
unsigned api_server_running(const api_server_t* srv);
unsigned api_server_sessions(const api_server_t* srv);

#endif
