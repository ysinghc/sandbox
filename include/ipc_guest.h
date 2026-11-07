// SPDX-License-Identifier: GPL-2.0-only
// ipc_guest.h -- #24: run one guest operation (exec / file op) for an IPC request.
#ifndef SANDBOX_IPC_GUEST_H
#define SANDBOX_IPC_GUEST_H

#include "ipc_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

// Execute the IPC_REQ_GUEST request `req` against the guest whose Firecracker
// vsock UDS is `uds_path`, and fill `resp` with the reply (an error response on
// any failure). It may block for as long as the operation's own deadline, so it
// belongs on a worker thread, never the IPC loop.
//
// It takes the UDS *path*, not a vm_handle_t, on purpose: the VM can be
// destroyed on the loop thread while a worker is mid-call, and a path is a value
// that cannot dangle (a vanished VM just makes the connect fail).
//
// The caller owns `resp` and frees it with ipc_response_clear().
void ipc_guest_execute(const char* uds_path, const ipc_request_t* req,
                       ipc_response_t* resp);

// Streaming exec (#34). Behaves like ipc_guest_execute, except a request with
// IPC_GF_STREAM (exec only; other ops ignore the sink) also invokes
// `on_chunk(is_stderr, data, n, ud)` for every output chunk while the command
// runs, and `resp` receives the terminal reply. Chunks are whole guest frames
// (at most GRPC_CHUNK bytes each); the terminal keeps the #24 shape (heads,
// totals, exit status). The sink runs on the caller's thread and must not
// block for long: while it runs, the guest's output waits.
typedef void (*ipc_guest_chunk_cb)(int is_stderr, const uint8_t* data,
                                  size_t n, void* ud);
void ipc_guest_execute_stream(const char* uds_path, const ipc_request_t* req,
                              ipc_guest_chunk_cb on_chunk, void* ud,
                              ipc_response_t* resp);

#ifdef __cplusplus
}
#endif

#endif  // SANDBOX_IPC_GUEST_H
