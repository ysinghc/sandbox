// SPDX-License-Identifier: GPL-2.0-only
// privsep.h -- #9: the daemon<->helper boundary.
//
// The long-running daemon (User=sandboxd, zero capabilities) cannot create
// taps, nftables rules, device nodes, bind mounts, chroots, uid transitions,
// or cgroup entries, nor kill or reap VMMs. All of that lives in
// `sandbox-privileged`, a small root helper that speaks this protocol over a
// SOCK_SEQPACKET unix socket and allows exactly one peer uid (the daemon's).
//
// Shape of every record (request and reply share the framing):
//
//   offset  size  field
//   0       1     version (must be PRIVSEP_VERSION)
//   1       1     op (request) or status (reply)
//   2       2     reserved, must be zero
//   4       4     body length in bytes, little-endian
//   8       n     body
//
// Bodies are NUL-terminated strings and little-endian integers, parsed
// strictly: short reads, lying lengths, missing terminators and trailing
// garbage are all refused. Requests:
//
//   HELLO     {version u8}                       -> {version u8}
//   NET_UP    {vm_id NUL}                        -> {tap NUL, host_ip u32, guest_ip u32}
//   NET_DOWN  {vm_id NUL}                        -> {}
//   SPAWN     {vm_id NUL, uid u32, gid u32, flags u32,
//              kernel NUL, rootfs NUL, vmstate NUL, mem NUL,
//              workspace NUL, outdir NUL, serial NUL}
//                                                    -> {pid s32}
//   POLL      {vm_id NUL}                        -> {state u8, pad[3],
//                                                  status s32, termsig s32,
//                                                  jail_step s32}
//   TEARDOWN  {vm_id NUL}                        -> {}
//   SWEEP     {min_age_s u32}                    -> {swept u32}
//
// Replies carry a status byte instead of the op. A nonzero status carries a
// two-integer body {errno s32, jail_step s32}; jail_step is nonzero only when
// a spawn died in the pre-exec jail sequence (steps 1-16, see jailer.c).
//
// What the wire deliberately cannot express: tap names (derived from vm_id),
// argv (constructed from flag bits), the Firecracker binary path (helper
// constant), cgroup paths (derived), or any uid 0 / daemon-uid identity. The
// validators below are the allowlist; the helper enforces them on receipt and
// the daemon applies them before sending.
#ifndef SANDBOX_PRIVSEP_H
#define SANDBOX_PRIVSEP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PRIVSEP_VERSION 1
#define PRIVSEP_MAX_MSG 65536u
#define PRIVSEP_HEADER_LEN 8u
#define PRIVSEP_VM_ID_MAX 32u
#define PRIVSEP_MAX_PATH 4096u
#define PRIVSEP_MAX_CHILDREN 128u
#define PRIVSEP_DEFAULT_SOCK "/run/sandbox-privileged/helper.sock"

typedef enum {
    PRIVSEP_OP_HELLO = 1,
    PRIVSEP_OP_NET_UP = 2,
    PRIVSEP_OP_NET_DOWN = 3,
    PRIVSEP_OP_SPAWN = 4,
    PRIVSEP_OP_POLL = 5,
    PRIVSEP_OP_TEARDOWN = 6,
    PRIVSEP_OP_SWEEP = 7,
} privsep_op_t;

typedef enum {
    PRIVSEP_OK = 0,
    PRIVSEP_ERR_REQUEST = 1,    // validation failed; the request was not run
    PRIVSEP_ERR_NOT_FOUND = 2,  // no such VM
    PRIVSEP_ERR_FAILED = 3,     // ran and failed; errno follows
    PRIVSEP_ERR_BUSY = 4,       // child table full
} privsep_status_t;

// SPAWN flag bits. Production passes mount_devices=true always, so only the
// two genuinely varying bits travel; anything else is refused.
enum {
    PRIVSEP_SPAWN_SECCOMP = 1u,  // install the seccomp filter
    PRIVSEP_SPAWN_PCI = 2u,      // pass --enable-pci to Firecracker
};

// POLL states.
enum {
    PRIVSEP_POLL_RUNNING = 0,
    PRIVSEP_POLL_EXITED = 1,
};

static inline void privsep_put_u32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static inline uint32_t privsep_get_u32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

// Encode one record. Returns 0 on success, -1 when the body is oversize or
// the buffer too small.
static inline int privsep_encode(uint8_t version, uint8_t op_or_status,
                                 const uint8_t* body, uint32_t body_len,
                                 uint8_t* out, size_t out_cap, size_t* out_len) {
    if (body_len > PRIVSEP_MAX_MSG - PRIVSEP_HEADER_LEN) return -1;
    if (out_cap < (size_t)body_len + PRIVSEP_HEADER_LEN) return -1;
    out[0] = version;
    out[1] = op_or_status;
    out[2] = out[3] = 0;
    privsep_put_u32(out + 4, body_len);
    if (body_len) memcpy(out + PRIVSEP_HEADER_LEN, body, body_len);
    *out_len = (size_t)body_len + PRIVSEP_HEADER_LEN;
    return 0;
}

// Decode one record. Framing is checked (exact length, version, zero
// reserved, body length matching the record); the op/status byte is NOT
// range-checked here because requests and replies share the framing with
// different ranges -- callers apply privsep_op_ok / privsep_status_ok.
static inline int privsep_decode(const uint8_t* msg, size_t msg_len,
                                 uint8_t* version, uint8_t* op_or_status,
                                 const uint8_t** body, uint32_t* body_len) {
    if (!msg || msg_len < PRIVSEP_HEADER_LEN || msg_len > PRIVSEP_MAX_MSG)
        return -1;
    uint32_t n = privsep_get_u32(msg + 4);
    if (n > PRIVSEP_MAX_MSG - PRIVSEP_HEADER_LEN) return -1;
    if ((size_t)n + PRIVSEP_HEADER_LEN != msg_len) return -1;
    if (msg[0] != PRIVSEP_VERSION) return -1;
    if (msg[2] != 0 || msg[3] != 0) return -1;
    *version = msg[0];
    *op_or_status = msg[1];
    *body = msg + PRIVSEP_HEADER_LEN;
    *body_len = n;
    return 0;
}

static inline bool privsep_op_ok(uint8_t op) {
    return op >= PRIVSEP_OP_HELLO && op <= PRIVSEP_OP_SWEEP;
}

static inline bool privsep_status_ok(uint8_t st) {
    return st <= PRIVSEP_ERR_BUSY;
}

// VM ids name taps, jail dirs, and cgroup leaves, so the charset is the same
// discipline as template names (plus '.'), bounded, and never empty. Bare
// "." and ".." are refused outright: "<root>/.." would escape the jail,
// cgroup, and tap namespaces the id is allowed to name.
static inline bool privsep_vm_id_ok(const char* id) {
    if (!id || !*id) return false;
    if (!strcmp(id, ".") || !strcmp(id, "..")) return false;
    size_t n = 0;
    for (const char* p = id; *p; p++) {
        char c = *p;
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) return false;
        if (++n > PRIVSEP_VM_ID_MAX) return false;
    }
    return true;
}

// The tap name derives from a valid vm id; it never arrives on the wire, so a
// caller cannot aim tap operations at someone else's device.
static inline int privsep_tap_name(const char* vm_id, char* out, size_t cap) {
    if (!privsep_vm_id_ok(vm_id) || !out || cap < PRIVSEP_VM_ID_MAX + 5)
        return -1;
    size_t n = strlen(vm_id);
    memcpy(out, "tap-", 4);
    memcpy(out + 4, vm_id, n + 1);
    return 0;
}

// The jailed identity must be unprivileged and must not be the daemon itself:
// an escape from the jail must not land on the daemon's uid or gid.
static inline bool privsep_jail_ids_ok(uint32_t uid, uint32_t gid,
                                       uint32_t daemon_uid,
                                       uint32_t daemon_gid) {
    if (uid == 0 || gid == 0) return false;
    if (uid > 65535u || gid > 65535u) return false;
    if (uid == daemon_uid || gid == daemon_gid) return false;
    return true;
}

// Absolute paths only, no empty/dot/dot-dot components, no trailing slash,
// printable ASCII only, and strictly under one of the roots (a root itself is
// refused). The helper's roots are its own startup flags, not wire data.
static inline bool privsep_path_ok(const char* path, const char* const* roots,
                                   size_t nroots) {
    if (!path || !roots || !nroots) return false;
    size_t len = strlen(path);
    if (!len || len > PRIVSEP_MAX_PATH) return false;
    if (path[0] != '/' || path[len - 1] == '/') return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)path[i];
        if (c < 0x20 || c > 0x7E) return false;
    }
    // Component scan: every component between slashes must be non-empty and
    // must not be "." or "..".
    size_t start = 1;
    for (size_t i = 1; i <= len; i++) {
        if (i == len || path[i] == '/') {
            size_t clen = i - start;
            if (!clen) return false;
            if (clen == 1 && path[start] == '.') return false;
            if (clen == 2 && path[start] == '.' && path[start + 1] == '.')
                return false;
            start = i + 1;
        }
    }
    for (size_t r = 0; r < nroots; r++) {
        size_t rl = strlen(roots[r]);
        if (len > rl && !memcmp(path, roots[r], rl) && path[rl] == '/')
            return true;
    }
    return false;
}

static inline bool privsep_spawn_flags_ok(uint32_t flags) {
    return (flags & ~(PRIVSEP_SPAWN_SECCOMP | PRIVSEP_SPAWN_PCI)) == 0;
}

// ---- daemon-side client (src/privsep_client.c) ------------------------------
//
// Every call validates its arguments with the shared validators before
// sending (defense in depth; the helper re-validates on receipt). Errors:
// 0 on success, -1 with errno set. A FAILED status surfaces the server's
// errno; NOT_FOUND becomes ENOENT; REQUEST/BUSY become EINVAL/EAGAIN (the
// former is always a client bug); transport failures become EIO, ETIMEDOUT,
// or ECONNRESET. SPAWN additionally reports the jail step (1-16) when the
// child died before exec, else 0.

// Connect to the helper. No retry here; the daemon retries at startup.
int privsep_connect(const char* sock_path);

// One RPC with a deadline. Returns 0 with the reply status and body; -1 with
// errno=ETIMEDOUT/ECONNRESET/EBADMSG/EIO on transport failure. Never blocks
// past timeout_ms.
int privsep_rpc(int fd, uint8_t op, const uint8_t* req, uint32_t req_len,
                uint8_t* reply, uint32_t reply_cap, uint32_t* reply_len,
                uint8_t* status, int timeout_ms);

int privsep_hello(int fd);
int privsep_net_up(int fd, const char* vm_id, char* tap, size_t tap_cap,
                   uint32_t* host_ip, uint32_t* guest_ip);
int privsep_net_down(int fd, const char* vm_id);

typedef struct {
    const char* vm_id;
    uint32_t jailer_uid;
    uint32_t jailer_gid;
    uint32_t flags;  // PRIVSEP_SPAWN_* bits
    const char* kernel;     // under snapshot_root, or NULL/"" to skip
    const char* rootfs;     // under snapshot_root, or NULL/"" to skip
    const char* vmstate;    // under snapshot_root, or NULL/"" to skip
    const char* mem;        // under snapshot_root, or NULL/"" to skip
    const char* workspace;  // under workspace_root, or NULL/"" to skip
    const char* outdir;     // under snapshot_root, or NULL/"" to skip
    const char* serial;     // under jail_root, or NULL/"" to skip
} privsep_spawn_args_t;

int privsep_spawn(int fd, const privsep_spawn_args_t* args,
                  const char* snapshot_root, const char* workspace_root,
                  const char* jail_root, pid_t* pid, int* jail_step);
int privsep_poll(int fd, const char* vm_id, int* state, int* status,
                 int* termsig, int* jail_step);
int privsep_teardown(int fd, const char* vm_id);
int privsep_sweep(int fd, uint32_t min_age_s, uint32_t* swept);

#ifdef __cplusplus
}
#endif

#endif  // SANDBOX_PRIVSEP_H
