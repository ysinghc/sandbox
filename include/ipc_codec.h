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
    IPC_REQ_GUEST = 7,  // #24: exec / file ops; the op is in `guest_op`
} ipc_req_kind_t;

#define IPC_MAX_ENV 64
#define IPC_MAX_TEMPLATE 128
#define IPC_MAX_SESSION_KEY 128
#define IPC_TOKEN_HEX_LEN 64
#define IPC_MAX_ERRMSG 192

// #24 guest ops. Everything must fit one IPC frame (IPC_FRAME_MAX, 64 KiB).
#define IPC_MAX_PATH 4096
#define IPC_MAX_ARGV 256
#define IPC_GUEST_CHUNK (48u * 1024u)    // read/write payload per message
#define IPC_EXEC_OUT_KEEP (32u * 1024u)  // exec stdout head kept per reply
#define IPC_EXEC_ERR_KEEP (16u * 1024u)  // exec stderr head kept per reply
#define IPC_MAX_DIRENTS 512

enum {  // flag bits in ipc_request_t.guest_flags (mirror proto GuestRequest bools)
    IPC_GF_SHELL = 1,
    IPC_GF_APPEND = 2,
    IPC_GF_EXCL = 4,
    IPC_GF_PARENTS = 8,
    IPC_GF_RECURSIVE = 16,
};

typedef struct {
    char name[256];
    uint8_t type;
    uint64_t size;
    int64_t mtime;
} ipc_dirent_t;

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

    // #24 guest op (kind == IPC_REQ_GUEST). sandbox_id above names the target;
    // exec's environment reuses env_vars/n_env. The pointers are owned by the
    // struct (ipc_request_clear frees them); a consumer may steal them by
    // copying the pointer and NULLing it here.
    uint32_t guest_op;      // GRPC_OP_* (include/guest_rpc.h)
    uint32_t guest_flags;   // IPC_GF_*
    char path[IPC_MAX_PATH];
    char* argv[IPC_MAX_ARGV + 1];  // NULL-terminated
    int n_argv;
    uint8_t* data;          // exec stdin / write_file chunk
    size_t data_len;
    uint32_t timeout_ms;
    uint32_t max_output;
    uint64_t offset;
    uint32_t max_bytes;
    uint32_t mode;
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

    // #24 guest op (kind == IPC_REQ_GUEST; sandbox_id echoes the target). The
    // buffers are heap-owned: free them with ipc_response_clear(). Copying the
    // struct by value transfers ownership, it does not duplicate the buffers.
    int32_t exit_code;
    int32_t term_signal;
    bool timed_out;
    bool output_truncated;
    uint8_t* out;           // exec stdout head, or read_file data
    size_t out_len;
    uint8_t* err;           // exec stderr head
    size_t err_len;
    uint64_t out_total;
    uint64_t err_total;
    bool truncated;
    uint64_t size;
    ipc_dirent_t* entries;
    size_t n_entries;
    uint32_t ftype;
    uint32_t fmode;
    int64_t mtime;
} ipc_response_t;

// Free the heap buffers of a response (guest ops) and zero it. Safe on any
// response, including ones that never owned a buffer.
void ipc_response_clear(ipc_response_t* resp);

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
