// SPDX-License-Identifier: GPL-2.0-only
// guest_rpc.h -- #24: exec and file operations over the guest control channel.
//
// One header serves three consumers, so the wire format has a single source of
// truth: the guest agent (src/guest_rpc_server.c, built static into the rootfs
// image), the host client (src/guest_rpc_client.c, linked into the engine), and
// tests/test_guest_rpc.c, which runs the real server code over a socketpair.
// Everything here is freestanding libc: no protobuf, no engine headers.
//
// Transport: AF_VSOCK port GRPC_PORT in the guest, reached from the host via the
// per-VM Firecracker UDS ("CONNECT <port>\n" -> "OK <n>\n"). One request per
// connection; concurrency is more connections. Auth is the #10 rule applied at
// accept time: only a peer whose CID is the host's is served.
//
// Frame: u32le payload_len | u8 type | u8 flags(0) | payload. All integers are
// little-endian, strings are u32 length + bytes (no NUL).
//
//   host -> guest   GRPC_T_REQUEST   u8 version | u8 op | op body
//   guest -> host   GRPC_T_STDOUT / GRPC_T_STDERR   raw bytes (exec only)
//   guest -> host   GRPC_T_RESULT    u8 status | i32 errno | body
//
// On status != GRPC_OK the RESULT body is a single string (a human message).
#ifndef SANDBOX_GUEST_RPC_H
#define SANDBOX_GUEST_RPC_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define GRPC_PORT 5002
#define GRPC_VERSION 1

#define GRPC_HDR_LEN 6u
// Hard caps. They bound agent memory per connection; the request-level limits
// (output, file size) are checked against these too.
#define GRPC_MAX_FRAME (5u * 1024u * 1024u)
#define GRPC_MAX_FILE (4u * 1024u * 1024u)
#define GRPC_MAX_ARGS 1024u
#define GRPC_MAX_STDIN (64u * 1024u)
#define GRPC_MAX_OUTPUT_DEFAULT (4u * 1024u * 1024u)
#define GRPC_MAX_TIMEOUT_MS (3600u * 1000u)
#define GRPC_CHUNK 16384u

enum {
    GRPC_T_REQUEST = 1,
    GRPC_T_STDOUT = 0x10,
    GRPC_T_STDERR = 0x11,
    GRPC_T_RESULT = 0x12,
};

enum {
    GRPC_OP_EXEC = 1,
    GRPC_OP_READ_FILE = 2,
    GRPC_OP_WRITE_FILE = 3,
    GRPC_OP_LIST_DIR = 4,
    GRPC_OP_STAT = 5,
    GRPC_OP_MKDIR = 6,
    GRPC_OP_REMOVE = 7,
};

enum {
    GRPC_OK = 0,
    GRPC_E_BAD_REQUEST = 1,
    GRPC_E_DENIED = 2,       // path outside the workspace, or not absolute
    GRPC_E_NOT_FOUND = 3,
    GRPC_E_IO = 4,
    GRPC_E_TOO_LARGE = 5,
    GRPC_E_BAD_VERSION = 6,
    GRPC_E_BUSY = 7,         // connection limit
    GRPC_E_EXISTS = 8,
    GRPC_E_NOT_READY = 9,    // the workspace volume is not mounted yet
};

// Request flags (op-dependent).
#define GRPC_F_ALLOW_OUTSIDE 0x01u  // path policy off; host opt-in per request
#define GRPC_F_SHELL 0x02u          // exec: argv[0] is a /bin/sh -c script
#define GRPC_F_APPEND 0x04u         // write_file
#define GRPC_F_PARENTS 0x08u        // write_file / mkdir: create missing parents
#define GRPC_F_EXCL 0x10u           // write_file: fail if it exists
#define GRPC_F_RECURSIVE 0x20u      // remove

// Exec result flags.
#define GRPC_X_TIMED_OUT 0x01u
#define GRPC_X_TRUNCATED 0x02u  // output cap hit; the process group was killed

enum { GRPC_FT_OTHER = 0, GRPC_FT_FILE = 1, GRPC_FT_DIR = 2, GRPC_FT_LINK = 3 };

// ── byte codec ──────────────────────────────────────────────────────────────

typedef struct {
    uint8_t* p;
    size_t len, cap;
    int err;  // sticky: set when the buffer would overflow (then nothing is written)
} grpc_wr_t;

static inline void grpc_wr_init(grpc_wr_t* w, uint8_t* buf, size_t cap) {
    w->p = buf; w->len = 0; w->cap = cap; w->err = 0;
}
static inline void grpc_wr_raw(grpc_wr_t* w, const void* d, size_t n) {
    if (w->err || n > w->cap - w->len) { w->err = 1; return; }
    if (n) memcpy(w->p + w->len, d, n);
    w->len += n;
}
static inline void grpc_wr_u8(grpc_wr_t* w, uint8_t v) { grpc_wr_raw(w, &v, 1); }
static inline void grpc_wr_u32(grpc_wr_t* w, uint32_t v) {
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    grpc_wr_raw(w, b, 4);
}
static inline void grpc_wr_u64(grpc_wr_t* w, uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
    grpc_wr_raw(w, b, 8);  // one write, so an overflow leaves nothing behind
}
static inline void grpc_wr_str(grpc_wr_t* w, const char* s) {
    size_t n = s ? strlen(s) : 0;
    if (n > 0xffffffffu) { w->err = 1; return; }
    grpc_wr_u32(w, (uint32_t)n);
    grpc_wr_raw(w, s, n);
}

typedef struct {
    const uint8_t* p;
    size_t len, off;
    int err;  // sticky: a read past the end, or a malformed string
} grpc_rd_t;

static inline void grpc_rd_init(grpc_rd_t* r, const uint8_t* buf, size_t len) {
    r->p = buf; r->len = len; r->off = 0; r->err = 0;
}
static inline const uint8_t* grpc_rd_raw(grpc_rd_t* r, size_t n) {
    if (r->err || n > r->len - r->off) { r->err = 1; return NULL; }
    const uint8_t* q = r->p + r->off;
    r->off += n;
    return q;
}
static inline uint8_t grpc_rd_u8(grpc_rd_t* r) {
    const uint8_t* q = grpc_rd_raw(r, 1);
    return q ? q[0] : 0;
}
static inline uint32_t grpc_rd_u32(grpc_rd_t* r) {
    const uint8_t* q = grpc_rd_raw(r, 4);
    return q ? (uint32_t)q[0] | (uint32_t)q[1] << 8 | (uint32_t)q[2] << 16 |
                   (uint32_t)q[3] << 24
             : 0;
}
static inline uint64_t grpc_rd_u64(grpc_rd_t* r) {
    uint64_t lo = grpc_rd_u32(r);
    uint64_t hi = grpc_rd_u32(r);
    return lo | hi << 32;
}
// A string is returned as a pointer into the buffer plus its length. It is NOT
// NUL terminated; grpc_rd_cstr copies and rejects embedded NULs.
static inline const char* grpc_rd_str(grpc_rd_t* r, uint32_t* n) {
    uint32_t l = grpc_rd_u32(r);
    const uint8_t* q = grpc_rd_raw(r, l);
    if (n) *n = q ? l : 0;
    return (const char*)q;
}
// Copy a string into dst (NUL terminated). Fails (sets err) on overflow or an
// embedded NUL: a path or argv element with a NUL would be silently truncated by
// the kernel, which is exactly how a policy check and the syscall disagree.
static inline int grpc_rd_cstr(grpc_rd_t* r, char* dst, size_t cap) {
    uint32_t n;
    const char* s = grpc_rd_str(r, &n);
    if (!s || n >= cap || memchr(s, 0, n)) { r->err = 1; return -1; }
    memcpy(dst, s, n);
    dst[n] = '\0';
    return 0;
}

static inline void grpc_frame_hdr(uint8_t out[GRPC_HDR_LEN], uint8_t type, uint32_t len) {
    out[0] = (uint8_t)len; out[1] = (uint8_t)(len >> 8);
    out[2] = (uint8_t)(len >> 16); out[3] = (uint8_t)(len >> 24);
    out[4] = type; out[5] = 0;
}

// Parse a frame header. Returns 0 and fills type/len; -1 if `len` is over the cap
// or the reserved flags byte is non-zero (a future version must bump GRPC_VERSION
// rather than smuggle meaning into it).
static inline int grpc_frame_parse(const uint8_t h[GRPC_HDR_LEN], uint8_t* type, uint32_t* len) {
    uint32_t l = (uint32_t)h[0] | (uint32_t)h[1] << 8 | (uint32_t)h[2] << 16 |
                 (uint32_t)h[3] << 24;
    if (l > GRPC_MAX_FRAME || h[5] != 0) return -1;
    *type = h[4];
    *len = l;
    return 0;
}

// ── path policy (pure; tests/test_guest_rpc.c) ──────────────────────────────

// Lexical check: absolute, NUL-free, no "." / ".." components, no empty
// components beyond a single trailing slash. Writes the canonical form
// ("/a/b", never a trailing slash except "/") into `out`. Returns 0 or -1.
int grpc_path_canon(const char* path, char* out, size_t cap);

// 1 iff the canonical path is `root` or below it. `root` is canonical.
int grpc_path_within(const char* canon, const char* root);

// ── guest side ──────────────────────────────────────────────────────────────

typedef struct grpc_server grpc_server_t;

// `root` is the directory file ops are confined to ("/workspace" in the guest).
// `pre_op`, if set, runs before every operation and returns 0 when the root is
// usable (the agent mounts the workspace volume there); non-zero turns into
// GRPC_E_NOT_READY.
grpc_server_t* grpc_server_new(const char* root, int (*pre_op)(void));
void grpc_server_free(grpc_server_t* s);

// Hand an already-authenticated connected socket to the server (it takes
// ownership). Returns 0, or -1 when the connection limit is reached (the fd is
// then answered with GRPC_E_BUSY and closed).
int grpc_server_adopt(grpc_server_t* s, int fd);

// One non-blocking pass over every connection: read, dispatch, pump exec output,
// enforce timeouts, flush. Never sleeps. Returns the number of live connections.
int grpc_server_step(grpc_server_t* s);

// ── host side ───────────────────────────────────────────────────────────────

typedef struct {
    uint8_t status;       // GRPC_OK or GRPC_E_*
    int32_t err;          // guest errno, 0 if none
    uint8_t* body;        // malloc'd; the string message when status != GRPC_OK
    size_t body_len;
} grpc_reply_t;

void grpc_reply_free(grpc_reply_t* r);

// Called for each streamed exec chunk; `is_stderr` distinguishes the pipes.
typedef void (*grpc_chunk_cb)(int is_stderr, const uint8_t* data, size_t n, void* ud);

// Connect to a Firecracker hybrid-vsock UDS and open `port`. Returns a connected
// fd or -1 with errno set. Retries the handshake until `deadline_ms` (the guest
// may not have re-announced its listener yet after a restore).
int grpc_connect_uds(const char* uds_path, unsigned port, int deadline_ms);

// Send `req` (a complete GRPC_T_REQUEST payload) on `fd` and read frames until a
// RESULT. `deadline_ms` bounds the whole call; on expiry the connection is
// closed, which the guest treats as cancellation (it kills the exec's process
// group). Returns 0 with `out` filled, or -1 with errno (ETIMEDOUT, EPROTO, ...).
// Closes `fd`.
int grpc_call_fd(int fd, const uint8_t* req, size_t req_len, grpc_chunk_cb cb,
                 void* ud, int deadline_ms, grpc_reply_t* out);

typedef struct {
    const char* cwd;                 // NULL: the workspace
    const char* const* argv;         // argv[argc]; with GRPC_F_SHELL argv[0] is the script
    uint32_t argc;
    const char* const* env;          // "KEY=VALUE", may be NULL
    uint32_t envc;
    const uint8_t* stdin_data;       // up to GRPC_MAX_STDIN, then EOF
    size_t stdin_len;
    uint32_t timeout_ms;             // 0: GRPC_MAX_TIMEOUT_MS
    uint32_t max_output;             // 0: GRPC_MAX_OUTPUT_DEFAULT; total of stdout+stderr
    uint32_t flags;                  // GRPC_F_SHELL | GRPC_F_ALLOW_OUTSIDE
} grpc_exec_req_t;

typedef struct {
    int32_t exit_code;               // -1 when killed by a signal
    int32_t term_signal;
    uint32_t flags;                  // GRPC_X_*
} grpc_exec_res_t;

// Typed calls. Return 0 on success, a positive GRPC_E_* when the guest refused
// or failed (message in `*msg` if non-NULL, copied, up to msg_cap), or -1 for a
// transport failure (errno set).
int grpc_exec(int fd, const grpc_exec_req_t* rq, grpc_chunk_cb cb, void* ud,
              int deadline_ms, grpc_exec_res_t* res, char* msg, size_t msg_cap);
int grpc_read_file(int fd, const char* path, uint64_t offset, uint32_t max_bytes,
                   int deadline_ms, uint8_t** data, size_t* len, int* truncated,
                   char* msg, size_t msg_cap);
int grpc_write_file(int fd, const char* path, const uint8_t* data, size_t len,
                    uint32_t mode, uint32_t flags, int deadline_ms, char* msg,
                    size_t msg_cap);
typedef struct {
    char name[256];
    uint8_t type;
    uint64_t size;
    int64_t mtime;
} grpc_dirent_t;
// Entries are malloc'd into *out (free() it); *truncated is set if the guest cut
// the listing at its frame budget.
int grpc_list_dir(int fd, const char* path, uint32_t flags, int deadline_ms,
                  grpc_dirent_t** out, size_t* n, int* truncated, char* msg,
                  size_t msg_cap);
typedef struct {
    uint8_t type;
    uint64_t size;
    uint32_t mode;
    int64_t mtime;
} grpc_stat_t;
int grpc_stat(int fd, const char* path, uint32_t flags, int deadline_ms,
              grpc_stat_t* st, char* msg, size_t msg_cap);
int grpc_mkdir(int fd, const char* path, uint32_t mode, uint32_t flags,
               int deadline_ms, char* msg, size_t msg_cap);
int grpc_remove(int fd, const char* path, uint32_t flags, int deadline_ms,
                char* msg, size_t msg_cap);

#endif  // SANDBOX_GUEST_RPC_H
