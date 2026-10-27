// SPDX-License-Identifier: GPL-2.0-only
// guest_rpc_client.c -- #24 host side of the exec / file RPC (wire format and
// semantics: include/guest_rpc.h).
//
// Blocking, one request per connection, every call bounded by a deadline. A
// deadline expiry closes the connection, which the guest reads as cancellation
// and answers by killing the exec's process group -- so a host-side timeout
// cannot leave a runaway process behind.
#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "guest_rpc.h"

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void grpc_reply_free(grpc_reply_t* r) {
    if (!r) return;
    free(r->body);
    memset(r, 0, sizeof(*r));
}

// Wait for `events` on fd until the absolute deadline. 0 ready, -1 errno set.
static int wait_fd(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t left = deadline - mono_ms();
        if (left <= 0) { errno = ETIMEDOUT; return -1; }
        struct pollfd p = { .fd = fd, .events = events };
        int n = poll(&p, 1, left > 1000000 ? 1000000 : (int)left);
        if (n > 0) return 0;
        if (n < 0 && errno != EINTR) return -1;
    }
}

static int write_all(int fd, const void* b, size_t n, int64_t deadline) {
    const uint8_t* p = b;
    while (n) {
        if (wait_fd(fd, POLLOUT, deadline) < 0) return -1;
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int read_all(int fd, void* b, size_t n, int64_t deadline) {
    uint8_t* p = b;
    while (n) {
        if (wait_fd(fd, POLLIN, deadline) < 0) return -1;
        ssize_t r = read(fd, p, n);
        if (r < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (r == 0) { errno = ECONNRESET; return -1; }
        if (r < 0) return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

int grpc_connect_uds(const char* uds_path, unsigned port, int deadline_ms) {
    struct sockaddr_un addr;
    if (!uds_path || strlen(uds_path) >= sizeof(addr.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int64_t deadline = mono_ms() + deadline_ms;
    int last = ECONNREFUSED;
    do {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return -1;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strcpy(addr.sun_path, uds_path);
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char hs[48];
            int n = snprintf(hs, sizeof(hs), "CONNECT %u\n", port);
            char line[64];
            size_t got = 0;
            int ok = write_all(fd, hs, (size_t)n, deadline) == 0;
            // Read the one-line reply a byte at a time: anything after the
            // newline already belongs to the guest's first frame.
            while (ok && got < sizeof(line) - 1) {
                if (read_all(fd, line + got, 1, deadline) < 0) { ok = 0; break; }
                if (line[got++] == '\n') break;
            }
            if (ok && got >= 3 && !memcmp(line, "OK ", 3)) return fd;
            last = ok ? EPROTO : errno;
        } else {
            last = errno;
        }
        close(fd);
        // The guest may not have re-announced its listener after a restore yet.
        struct timespec nap = { 0, 50 * 1000000L };
        nanosleep(&nap, NULL);
    } while (mono_ms() < deadline);
    errno = last == ECONNREFUSED || last == ENOENT ? last : ETIMEDOUT;
    return -1;
}

int grpc_call_fd(int fd, const uint8_t* req, size_t req_len, grpc_chunk_cb cb,
                 void* ud, int deadline_ms, grpc_reply_t* out) {
    int64_t deadline = mono_ms() + deadline_ms;
    int rc = -1;
    uint8_t* payload = NULL;
    memset(out, 0, sizeof(*out));
    if (req_len > GRPC_MAX_FRAME) { errno = EMSGSIZE; goto done; }

    uint8_t h[GRPC_HDR_LEN];
    grpc_frame_hdr(h, GRPC_T_REQUEST, (uint32_t)req_len);
    if (write_all(fd, h, sizeof(h), deadline) < 0 ||
        write_all(fd, req, req_len, deadline) < 0)
        goto done;

    for (;;) {
        uint8_t type;
        uint32_t len;
        if (read_all(fd, h, sizeof(h), deadline) < 0) goto done;
        if (grpc_frame_parse(h, &type, &len) < 0) { errno = EPROTO; goto done; }
        payload = malloc(len ? len : 1);
        if (!payload) { errno = ENOMEM; goto done; }
        if (len && read_all(fd, payload, len, deadline) < 0) goto done;

        if (type == GRPC_T_STDOUT || type == GRPC_T_STDERR) {
            if (cb) cb(type == GRPC_T_STDERR, payload, len, ud);
        } else if (type == GRPC_T_RESULT) {
            grpc_rd_t r;
            grpc_rd_init(&r, payload, len);
            uint8_t st = grpc_rd_u8(&r);
            int32_t err = (int32_t)grpc_rd_u32(&r);
            if (r.err) { errno = EPROTO; goto done; }
            out->status = st;
            out->err = err;
            out->body_len = len - r.off;
            out->body = malloc(out->body_len ? out->body_len : 1);
            if (!out->body) { errno = ENOMEM; goto done; }
            memcpy(out->body, payload + r.off, out->body_len);
            rc = 0;
            goto done;
        } else {
            errno = EPROTO;
            goto done;
        }
        free(payload);
        payload = NULL;
    }
done:;
    int saved = errno;
    free(payload);
    close(fd);
    errno = saved;
    return rc;
}

// ── typed calls ─────────────────────────────────────────────────────────────

typedef struct { uint8_t* b; grpc_wr_t w; } req_t;

static int req_begin(req_t* q, uint8_t op, uint32_t flags, size_t cap) {
    q->b = malloc(cap + 16);
    if (!q->b) { errno = ENOMEM; return -1; }
    grpc_wr_init(&q->w, q->b, cap + 16);
    grpc_wr_u8(&q->w, GRPC_VERSION);
    grpc_wr_u8(&q->w, op);
    grpc_wr_u32(&q->w, flags);
    return 0;
}

// Run the request and fold a guest-side failure into the return value.
static int run(int fd, req_t* q, grpc_chunk_cb cb, void* ud, int deadline_ms,
               grpc_reply_t* rp, char* msg, size_t msg_cap) {
    if (msg && msg_cap) msg[0] = '\0';
    if (q->w.err) { close(fd); free(q->b); errno = EMSGSIZE; return -1; }
    int rc = grpc_call_fd(fd, q->b, q->w.len, cb, ud, deadline_ms, rp);
    free(q->b);
    if (rc < 0) return -1;
    if (rp->status == GRPC_OK) return 0;
    if (msg && msg_cap) {
        grpc_rd_t r;
        grpc_rd_init(&r, rp->body, rp->body_len);
        uint32_t n;
        const char* s = grpc_rd_str(&r, &n);
        if (s) {
            if (n >= msg_cap) n = (uint32_t)msg_cap - 1;
            memcpy(msg, s, n);
            msg[n] = '\0';
        }
    }
    int st = rp->status;
    grpc_reply_free(rp);
    return st;
}

int grpc_exec(int fd, const grpc_exec_req_t* rq, grpc_chunk_cb cb, void* ud,
              int deadline_ms, grpc_exec_res_t* res, char* msg, size_t msg_cap) {
    size_t cap = 64 + (rq->cwd ? strlen(rq->cwd) : 0) + rq->stdin_len;
    for (uint32_t i = 0; i < rq->argc; i++) cap += 4 + strlen(rq->argv[i]);
    for (uint32_t i = 0; i < rq->envc; i++) cap += 4 + strlen(rq->env[i]);
    req_t q;
    if (req_begin(&q, GRPC_OP_EXEC, rq->flags, cap) < 0) { close(fd); return -1; }
    grpc_wr_str(&q.w, rq->cwd ? rq->cwd : "");
    grpc_wr_u32(&q.w, rq->argc);
    for (uint32_t i = 0; i < rq->argc; i++) grpc_wr_str(&q.w, rq->argv[i]);
    grpc_wr_u32(&q.w, rq->envc);
    for (uint32_t i = 0; i < rq->envc; i++) grpc_wr_str(&q.w, rq->env[i]);
    grpc_wr_u32(&q.w, rq->timeout_ms);
    grpc_wr_u32(&q.w, rq->max_output);
    grpc_wr_u32(&q.w, (uint32_t)rq->stdin_len);
    grpc_wr_raw(&q.w, rq->stdin_data, rq->stdin_len);

    // The guest enforces timeout_ms itself; the host deadline is the backstop
    // for a wedged guest, so it sits a margin above it.
    grpc_reply_t rp;
    int rc = run(fd, &q, cb, ud, deadline_ms, &rp, msg, msg_cap);
    if (rc) return rc;
    grpc_rd_t r;
    grpc_rd_init(&r, rp.body, rp.body_len);
    res->exit_code = (int32_t)grpc_rd_u32(&r);
    res->term_signal = (int32_t)grpc_rd_u32(&r);
    res->flags = grpc_rd_u32(&r);
    int bad = r.err;
    grpc_reply_free(&rp);
    if (bad) { errno = EPROTO; return -1; }
    return 0;
}

int grpc_read_file(int fd, const char* path, uint64_t offset, uint32_t max_bytes,
                   int deadline_ms, uint8_t** data, size_t* len, int* truncated,
                   char* msg, size_t msg_cap) {
    req_t q;
    if (req_begin(&q, GRPC_OP_READ_FILE, 0, strlen(path) + 32) < 0) { close(fd); return -1; }
    grpc_wr_str(&q.w, path);
    grpc_wr_u64(&q.w, offset);
    grpc_wr_u32(&q.w, max_bytes);
    grpc_reply_t rp;
    int rc = run(fd, &q, NULL, NULL, deadline_ms, &rp, msg, msg_cap);
    if (rc) return rc;
    grpc_rd_t r;
    grpc_rd_init(&r, rp.body, rp.body_len);
    int tr = grpc_rd_u8(&r);
    (void)grpc_rd_u64(&r);  // total file size
    uint32_t n = grpc_rd_u32(&r);
    const uint8_t* d = grpc_rd_raw(&r, n);
    if (r.err || !d) { grpc_reply_free(&rp); errno = EPROTO; return -1; }
    *data = malloc(n ? n : 1);
    if (!*data) { grpc_reply_free(&rp); errno = ENOMEM; return -1; }
    memcpy(*data, d, n);
    *len = n;
    if (truncated) *truncated = tr;
    grpc_reply_free(&rp);
    return 0;
}

int grpc_write_file(int fd, const char* path, const uint8_t* data, size_t len,
                    uint32_t mode, uint32_t flags, int deadline_ms, char* msg,
                    size_t msg_cap) {
    if (len > GRPC_MAX_FILE) { close(fd); if (msg && msg_cap) snprintf(msg, msg_cap, "file over the size limit"); return GRPC_E_TOO_LARGE; }
    req_t q;
    if (req_begin(&q, GRPC_OP_WRITE_FILE, flags, strlen(path) + len + 32) < 0) { close(fd); return -1; }
    grpc_wr_str(&q.w, path);
    grpc_wr_u32(&q.w, mode);
    grpc_wr_u32(&q.w, (uint32_t)len);
    grpc_wr_raw(&q.w, data, len);
    grpc_reply_t rp;
    int rc = run(fd, &q, NULL, NULL, deadline_ms, &rp, msg, msg_cap);
    if (rc) return rc;
    grpc_reply_free(&rp);
    return 0;
}

int grpc_list_dir(int fd, const char* path, uint32_t flags, int deadline_ms,
                  grpc_dirent_t** out, size_t* n, int* truncated, char* msg,
                  size_t msg_cap) {
    req_t q;
    if (req_begin(&q, GRPC_OP_LIST_DIR, flags, strlen(path) + 8) < 0) { close(fd); return -1; }
    grpc_wr_str(&q.w, path);
    grpc_reply_t rp;
    int rc = run(fd, &q, NULL, NULL, deadline_ms, &rp, msg, msg_cap);
    if (rc) return rc;
    grpc_rd_t r;
    grpc_rd_init(&r, rp.body, rp.body_len);
    int tr = grpc_rd_u8(&r);
    uint32_t count = grpc_rd_u32(&r);
    // Each entry is at least 4+1+8+8 bytes, so a count the body cannot hold is
    // a lie, not an allocation request.
    if (r.err || (uint64_t)count * 21u > rp.body_len) {
        grpc_reply_free(&rp);
        errno = EPROTO;
        return -1;
    }
    grpc_dirent_t* e = calloc(count ? count : 1, sizeof(*e));
    if (!e) { grpc_reply_free(&rp); errno = ENOMEM; return -1; }
    for (uint32_t i = 0; i < count; i++) {
        uint32_t nl;
        const char* nm = grpc_rd_str(&r, &nl);
        e[i].type = grpc_rd_u8(&r);
        e[i].size = grpc_rd_u64(&r);
        e[i].mtime = (int64_t)grpc_rd_u64(&r);
        if (r.err || !nm || nl >= sizeof(e[i].name)) {
            free(e);
            grpc_reply_free(&rp);
            errno = EPROTO;
            return -1;
        }
        memcpy(e[i].name, nm, nl);
        e[i].name[nl] = '\0';
    }
    *out = e;
    *n = count;
    if (truncated) *truncated = tr;
    grpc_reply_free(&rp);
    return 0;
}

int grpc_stat(int fd, const char* path, uint32_t flags, int deadline_ms,
              grpc_stat_t* st, char* msg, size_t msg_cap) {
    req_t q;
    if (req_begin(&q, GRPC_OP_STAT, flags, strlen(path) + 8) < 0) { close(fd); return -1; }
    grpc_wr_str(&q.w, path);
    grpc_reply_t rp;
    int rc = run(fd, &q, NULL, NULL, deadline_ms, &rp, msg, msg_cap);
    if (rc) return rc;
    grpc_rd_t r;
    grpc_rd_init(&r, rp.body, rp.body_len);
    st->type = grpc_rd_u8(&r);
    st->size = grpc_rd_u64(&r);
    st->mode = grpc_rd_u32(&r);
    st->mtime = (int64_t)grpc_rd_u64(&r);
    int bad = r.err;
    grpc_reply_free(&rp);
    if (bad) { errno = EPROTO; return -1; }
    return 0;
}

int grpc_mkdir(int fd, const char* path, uint32_t mode, uint32_t flags,
               int deadline_ms, char* msg, size_t msg_cap) {
    req_t q;
    if (req_begin(&q, GRPC_OP_MKDIR, flags, strlen(path) + 16) < 0) { close(fd); return -1; }
    grpc_wr_str(&q.w, path);
    grpc_wr_u32(&q.w, mode);
    grpc_reply_t rp;
    int rc = run(fd, &q, NULL, NULL, deadline_ms, &rp, msg, msg_cap);
    if (rc) return rc;
    grpc_reply_free(&rp);
    return 0;
}

int grpc_remove(int fd, const char* path, uint32_t flags, int deadline_ms,
                char* msg, size_t msg_cap) {
    req_t q;
    if (req_begin(&q, GRPC_OP_REMOVE, flags, strlen(path) + 8) < 0) { close(fd); return -1; }
    grpc_wr_str(&q.w, path);
    grpc_reply_t rp;
    int rc = run(fd, &q, NULL, NULL, deadline_ms, &rp, msg, msg_cap);
    if (rc) return rc;
    grpc_reply_free(&rp);
    return 0;
}
