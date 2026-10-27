// SPDX-License-Identifier: GPL-2.0-only
// ipc_guest.c -- #24: one IPC guest request -> one guest RPC -> one IPC reply.
//
// The IPC frame is 64 KiB, so this layer is where the guest's larger limits are
// squeezed into it: exec output is the head of each stream plus the true byte
// counts (the caller learns what was dropped), reads and writes are one chunk
// per message (libsandbox loops), and a directory listing stops at a byte
// budget and says so. Nothing here may produce a response that does not encode,
// because a reply that cannot be sent is a request that never returns.
#define _GNU_SOURCE

#include "ipc_guest.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "guest_rpc.h"
#include "libsandbox.h"

#define CONNECT_MS 5000
#define FILE_OP_MS 30000
#define EXEC_MARGIN_MS 15000  // host deadline sits this far past the exec's own
#define DIR_BUDGET (40u * 1024u)

static void fail(ipc_response_t* r, const ipc_request_t* q, sandbox_error_t code,
                 const char* msg) {
    ipc_response_clear(r);
    r->request_id = q->request_id;
    r->kind = IPC_REQ_GUEST;
    r->sandbox_id = q->sandbox_id;
    r->is_error = true;
    r->error_code = code;
    snprintf(r->error_message, sizeof(r->error_message), "%s", msg ? msg : "");
}

static sandbox_error_t map_status(int st) {
    switch (st) {
    case GRPC_E_BAD_REQUEST: return SANDBOX_ERR_INVALID_SPEC;
    case GRPC_E_DENIED: return SANDBOX_ERR_PATH_DENIED;
    case GRPC_E_NOT_FOUND: return SANDBOX_ERR_NOT_FOUND;
    case GRPC_E_IO: return SANDBOX_ERR_GUEST_IO;
    case GRPC_E_TOO_LARGE: return SANDBOX_ERR_TOO_LARGE;
    case GRPC_E_EXISTS: return SANDBOX_ERR_EXISTS;
    case GRPC_E_BUSY:
    case GRPC_E_NOT_READY: return SANDBOX_ERR_GUEST_UNAVAILABLE;  // retryable
    default: return SANDBOX_ERR_INTERNAL;
    }
}

// Fold a typed-call result (0 ok, >0 guest status, -1 transport) into `r`.
// Returns 0 when the call succeeded and the caller should fill the reply.
static int settle(int rc, int saved_errno, const char* msg, ipc_response_t* r,
                  const ipc_request_t* q) {
    if (rc == 0) return 0;
    if (rc > 0) {
        fail(r, q, map_status(rc), msg[0] ? msg : "guest refused the request");
        return -1;
    }
    sandbox_error_t code = saved_errno == ETIMEDOUT ? SANDBOX_ERR_TIMEOUT
                                                    : SANDBOX_ERR_GUEST_UNAVAILABLE;
    char m[IPC_MAX_ERRMSG];
    snprintf(m, sizeof(m), "guest call failed: %s", strerror(saved_errno));
    fail(r, q, code, m);
    return -1;
}

typedef struct {
    uint8_t *out, *err;
    size_t out_len, err_len;
    uint64_t out_total, err_total;
} collect_t;

static void on_chunk(int is_err, const uint8_t* d, size_t n, void* ud) {
    collect_t* c = ud;
    uint8_t** buf = is_err ? &c->err : &c->out;
    size_t* len = is_err ? &c->err_len : &c->out_len;
    uint64_t* total = is_err ? &c->err_total : &c->out_total;
    size_t keep = is_err ? IPC_EXEC_ERR_KEEP : IPC_EXEC_OUT_KEEP;
    *total += n;
    if (*len >= keep) return;  // the head is full; keep counting
    size_t take = n < keep - *len ? n : keep - *len;
    if (!*buf && !(*buf = malloc(keep))) return;
    memcpy(*buf + *len, d, take);
    *len += take;
}

static void do_exec(const char* uds, const ipc_request_t* q, ipc_response_t* r) {
    if (q->n_argv < 1 || ((q->guest_flags & IPC_GF_SHELL) && q->n_argv != 1)) {
        return fail(r, q, SANDBOX_ERR_INVALID_SPEC, "exec needs argv (one script with shell)");
    }
    if (q->data_len > GRPC_MAX_STDIN) {
        return fail(r, q, SANDBOX_ERR_TOO_LARGE, "stdin over 64 KiB");
    }
    int fd = grpc_connect_uds(uds, GRPC_PORT, CONNECT_MS);
    if (fd < 0) {
        int e = errno;
        settle(-1, e, "", r, q);
        return;
    }
    grpc_exec_req_t g;
    memset(&g, 0, sizeof(g));
    g.cwd = q->path[0] ? q->path : NULL;
    g.argv = (const char* const*)q->argv;
    g.argc = (uint32_t)q->n_argv;
    g.env = (const char* const*)q->env_vars;
    g.envc = (uint32_t)q->n_env;
    g.stdin_data = q->data;
    g.stdin_len = q->data_len;
    g.timeout_ms = q->timeout_ms;
    g.max_output = q->max_output;
    g.flags = (q->guest_flags & IPC_GF_SHELL) ? GRPC_F_SHELL : 0;

    uint32_t own = q->timeout_ms ? q->timeout_ms : GRPC_MAX_TIMEOUT_MS;
    if (own > GRPC_MAX_TIMEOUT_MS) own = GRPC_MAX_TIMEOUT_MS;
    collect_t c;
    memset(&c, 0, sizeof(c));
    grpc_exec_res_t res;
    char msg[IPC_MAX_ERRMSG] = "";
    int rc = grpc_exec(fd, &g, on_chunk, &c, (int)(own + EXEC_MARGIN_MS), &res, msg, sizeof(msg));
    int e = errno;
    if (settle(rc, e, msg, r, q) < 0) { free(c.out); free(c.err); return; }
    r->exit_code = res.exit_code;
    r->term_signal = res.term_signal;
    r->timed_out = (res.flags & GRPC_X_TIMED_OUT) != 0;
    r->output_truncated = (res.flags & GRPC_X_TRUNCATED) != 0;
    r->out = c.out; r->out_len = c.out_len; r->out_total = c.out_total;
    r->err = c.err; r->err_len = c.err_len; r->err_total = c.err_total;
}

static void do_read(const char* uds, const ipc_request_t* q, ipc_response_t* r) {
    uint32_t max = q->max_bytes ? q->max_bytes : IPC_GUEST_CHUNK;
    if (max > IPC_GUEST_CHUNK) max = IPC_GUEST_CHUNK;  // one frame; the caller loops
    int fd = grpc_connect_uds(uds, GRPC_PORT, CONNECT_MS);
    if (fd < 0) { int e = errno; settle(-1, e, "", r, q); return; }
    uint8_t* d = NULL; size_t n = 0; int tr = 0;
    char msg[IPC_MAX_ERRMSG] = "";
    int rc = grpc_read_file(fd, q->path, q->offset, max, FILE_OP_MS, &d, &n, &tr, msg, sizeof(msg));
    int e = errno;
    if (settle(rc, e, msg, r, q) < 0) return;
    r->out = n ? d : (free(d), NULL);
    r->out_len = n;
    r->truncated = tr != 0;
}

static void do_write(const char* uds, const ipc_request_t* q, ipc_response_t* r) {
    if (q->data_len > IPC_GUEST_CHUNK) {
        return fail(r, q, SANDBOX_ERR_TOO_LARGE, "write chunk over the frame budget");
    }
    int fd = grpc_connect_uds(uds, GRPC_PORT, CONNECT_MS);
    if (fd < 0) { int e = errno; settle(-1, e, "", r, q); return; }
    uint32_t fl = ((q->guest_flags & IPC_GF_APPEND) ? GRPC_F_APPEND : 0) |
                  ((q->guest_flags & IPC_GF_EXCL) ? GRPC_F_EXCL : 0) |
                  ((q->guest_flags & IPC_GF_PARENTS) ? GRPC_F_PARENTS : 0);
    char msg[IPC_MAX_ERRMSG] = "";
    int rc = grpc_write_file(fd, q->path, q->data, q->data_len, q->mode ? q->mode : 0644, fl,
                             FILE_OP_MS, msg, sizeof(msg));
    int e = errno;
    settle(rc, e, msg, r, q);
}

static void do_list(const char* uds, const ipc_request_t* q, ipc_response_t* r) {
    int fd = grpc_connect_uds(uds, GRPC_PORT, CONNECT_MS);
    if (fd < 0) { int e = errno; settle(-1, e, "", r, q); return; }
    grpc_dirent_t* ent = NULL; size_t n = 0; int tr = 0;
    char msg[IPC_MAX_ERRMSG] = "";
    int rc = grpc_list_dir(fd, q->path, 0, FILE_OP_MS, &ent, &n, &tr, msg, sizeof(msg));
    int e = errno;
    if (settle(rc, e, msg, r, q) < 0) return;
    // Fit the frame: a byte budget on names, and a hard entry cap.
    size_t keep = 0, bytes = 0;
    while (keep < n && keep < IPC_MAX_DIRENTS) {
        size_t cost = strlen(ent[keep].name) + 24;
        if (bytes + cost > DIR_BUDGET) break;
        bytes += cost;
        keep++;
    }
    if (keep < n) tr = 1;
    r->entries = keep ? calloc(keep, sizeof(ipc_dirent_t)) : NULL;
    if (keep && !r->entries) { free(ent); return fail(r, q, SANDBOX_ERR_INTERNAL, "out of memory"); }
    for (size_t i = 0; i < keep; i++) {
        memcpy(r->entries[i].name, ent[i].name, sizeof(r->entries[i].name));
        r->entries[i].type = ent[i].type;
        r->entries[i].size = ent[i].size;
        r->entries[i].mtime = ent[i].mtime;
    }
    r->n_entries = keep;
    r->truncated = tr != 0;
    free(ent);
}

static void do_stat(const char* uds, const ipc_request_t* q, ipc_response_t* r) {
    int fd = grpc_connect_uds(uds, GRPC_PORT, CONNECT_MS);
    if (fd < 0) { int e = errno; settle(-1, e, "", r, q); return; }
    grpc_stat_t st;
    char msg[IPC_MAX_ERRMSG] = "";
    int rc = grpc_stat(fd, q->path, 0, FILE_OP_MS, &st, msg, sizeof(msg));
    int e = errno;
    if (settle(rc, e, msg, r, q) < 0) return;
    r->ftype = st.type;
    r->size = st.size;
    r->fmode = st.mode;
    r->mtime = st.mtime;
}

static void do_simple(const char* uds, const ipc_request_t* q, ipc_response_t* r, int op) {
    int fd = grpc_connect_uds(uds, GRPC_PORT, CONNECT_MS);
    if (fd < 0) { int e = errno; settle(-1, e, "", r, q); return; }
    char msg[IPC_MAX_ERRMSG] = "";
    int rc;
    if (op == GRPC_OP_MKDIR) {
        rc = grpc_mkdir(fd, q->path, q->mode, (q->guest_flags & IPC_GF_PARENTS) ? GRPC_F_PARENTS : 0,
                        FILE_OP_MS, msg, sizeof(msg));
    } else {
        rc = grpc_remove(fd, q->path, (q->guest_flags & IPC_GF_RECURSIVE) ? GRPC_F_RECURSIVE : 0,
                         FILE_OP_MS, msg, sizeof(msg));
    }
    int e = errno;
    settle(rc, e, msg, r, q);
}

void ipc_guest_execute(const char* uds_path, const ipc_request_t* q, ipc_response_t* r) {
    memset(r, 0, sizeof(*r));
    r->request_id = q->request_id;
    r->kind = IPC_REQ_GUEST;
    r->sandbox_id = q->sandbox_id;
    if (!uds_path || !*uds_path) {
        return fail(r, q, SANDBOX_ERR_GUEST_UNAVAILABLE, "sandbox has no guest channel");
    }
    int op = (int)q->guest_op;
    if (op != GRPC_OP_EXEC && !q->path[0]) {
        return fail(r, q, SANDBOX_ERR_INVALID_SPEC, "a path is required");
    }
    switch (op) {
    case GRPC_OP_EXEC: do_exec(uds_path, q, r); break;
    case GRPC_OP_READ_FILE: do_read(uds_path, q, r); break;
    case GRPC_OP_WRITE_FILE: do_write(uds_path, q, r); break;
    case GRPC_OP_LIST_DIR: do_list(uds_path, q, r); break;
    case GRPC_OP_STAT: do_stat(uds_path, q, r); break;
    case GRPC_OP_MKDIR:
    case GRPC_OP_REMOVE: do_simple(uds_path, q, r, op); break;
    default: fail(r, q, SANDBOX_ERR_INVALID_SPEC, "unknown guest operation");
    }
}
