// SPDX-License-Identifier: GPL-2.0-only
#ifndef IPC_CODEC_H
#define IPC_CODEC_H

// C bridge over the generated C++ protobuf types (§2.3/§6.1). The engine is
// C, protobuf-c is not available, so the wire schema is implemented once in
// C++ (src/ipc_codec.cpp) and exposed here as plain C encode/decode calls.
// The generated header (sandbox.pb.h) is C++, so no C file includes it.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Request kinds — mirror proto ClientMessage's oneof.
typedef enum {
    IPC_REQ_CREATE = 1,
    IPC_REQ_DESTROY = 2,
    IPC_REQ_PAUSE = 3,
    IPC_REQ_RESUME = 4,
    IPC_REQ_INSPECT = 5,
    IPC_REQ_RENEW = 6,
} ipc_req_kind_t;

#define IPC_MAX_ENV 64
#define IPC_MAX_TEMPLATE 128
#define IPC_MAX_SESSION_KEY 128
#define IPC_TOKEN_HEX_LEN 64
#define IPC_MAX_ERRMSG 192

typedef struct {
    ipc_req_kind_t kind;

    // #12: echoed on the response. 0 = legacy, in-order replies.
    uint64_t request_id;

    // create
    uint64_t memory_mib;
    uint32_t vcpu_count;
    char template_name[IPC_MAX_TEMPLATE];
    uint32_t pool_wait_ms;
    char* env_vars[IPC_MAX_ENV + 1];  // NULL-terminated, owned by the struct
    int n_env;
    // #23: empty = ephemeral workspace. Non-empty = persistent session volume.
    char session_key[IPC_MAX_SESSION_KEY];
    uint32_t ttl_seconds;  // 0 = platform default

    // renew (#23/D5): seconds to add to session_key's deadline. 0 = default.
    uint32_t extra_seconds;

    // destroy/pause/resume/inspect
    uint32_t sandbox_id;
} ipc_request_t;

typedef struct {
    ipc_req_kind_t kind;  // selects which success oneof branch to emit
    uint64_t request_id;  // #12: echo of the request's id (0 = legacy)
    bool is_error;
    int32_t error_code;
    char error_message[IPC_MAX_ERRMSG];

    uint32_t sandbox_id;
    char session_token[IPC_TOKEN_HEX_LEN + 1];

    // inspect
    bool is_running;
    uint64_t uptime_ms;
    uint64_t memory_rss_mib;
    uint32_t page_faults;

    // renew (#23/D5): the session's deadline after the call, unix seconds.
    uint64_t expires_at;
} ipc_response_t;

void ipc_request_init(ipc_request_t* req);
void ipc_request_clear(ipc_request_t* req);

// Serialize/parse a bare protobuf message (no length prefix; see
// ipc_send_frame/ipc_recv_frame in ipc_internal.h). Return 0 on success.
int ipc_encode_request(const ipc_request_t* req, uint8_t* buf, size_t cap,
                       size_t* out_len);
int ipc_decode_request(const uint8_t* buf, size_t len, ipc_request_t* out);

int ipc_encode_response(const ipc_response_t* resp, uint8_t* buf, size_t cap,
                        size_t* out_len);
int ipc_decode_response(const uint8_t* buf, size_t len, ipc_response_t* out);

#ifdef __cplusplus
}
#endif

#endif // IPC_CODEC_H
