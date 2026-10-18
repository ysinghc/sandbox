// SPDX-License-Identifier: GPL-2.0-only
#ifndef IPC_SERVER_H
#define IPC_SERVER_H

#include "pool_manager.h"

// Engine IPC server (§2.3). SOCK_SEQPACKET Unix socket, length-prefixed
// protobuf; one persistent connection per client session. The daemon wires
// the live pool in before calling ipc_server_run().

int ipc_server_run(const char* socket_path);
int ipc_server_stop(void);

// Async-signal-safe variant for a SIGTERM/SIGINT handler: it only clears the
// run flag and wakes the event loop. Call ipc_server_stop() afterwards (from
// normal context) to join the broker-control thread.
void ipc_server_request_stop(void);

// Configure the server before ipc_server_run(). pool is borrowed (the daemon
// owns it). template_name (may be NULL) is the only snapshot a CreateRequest
// may name. allowed_services is a comma-separated host allowlist copied into
// each issued token (NULL/empty denies everything).
void ipc_server_set_pool(pool_manager_t* pool);
void ipc_server_set_template(const char* template_name);
void ipc_server_set_allowed_services(const char* csv);

// Phase 10.1: comma-separated allowlist of peer uids permitted to connect
// (SO_PEERCRED). NULL/empty accepts any uid (logged as a warning at startup).
void ipc_server_set_allowed_uids(const char* csv);

// Phase 11: default pool wait (ms) applied when a CreateRequest sends 0.
void ipc_server_set_default_pool_wait_ms(uint32_t ms);

// §10.8: Create worker pool size and per-session / per-uid concurrency caps.
// Non-positive arguments keep the built-in default.
void ipc_server_set_create_limits(int workers, int per_session, int per_uid);

// Engine-side half of §5.8: the credential broker validates session tokens
// over broker-control.sock. Runs in its own thread.
int ipc_server_start_broker_control(const char* socket_path);
void ipc_server_stop_broker_control(void);

// Test helpers: number of VMs currently tracked by the token registry.
int ipc_server_token_count(void);

#endif // IPC_SERVER_H
