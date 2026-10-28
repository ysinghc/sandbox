// SPDX-License-Identifier: GPL-2.0-only
// guest_rpc_server.c -- #24 guest side of the exec / file RPC (see
// include/guest_rpc.h for the wire format).
//
// Single-threaded and non-blocking by construction: the guest agent's main loop
// is a zero-timeout busy poll (scripts/sandbox-agent.c explains why timers are
// not usable after a restore), so this module exposes one step() that the loop
// calls, and never sleeps, blocks on a pipe or waits on a timer. Deadlines are
// compared against CLOCK_MONOTONIC on every step.
//
// It is the guest's PID 1 (the init execs the agent), so step() also reaps every
// orphan; exec children are matched by pid and everything else is discarded.
#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "guest_rpc.h"

#define MAX_CONNS 16
#define REQ_TIMEOUT_MS 10000        // a connection must deliver its request by then
#define QUEUE_HIGH (1u << 20)       // stop reading exec pipes above this backlog
#define MAX_INFLIGHT_IN (16u << 20) // request bytes buffered across all connections
#define DEFAULT_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

typedef struct {
    int fd;  // -1: free
    uint64_t born_ms;
    uint8_t hdr[GRPC_HDR_LEN];
    size_t hdr_got;
    uint8_t* in;
    uint32_t in_len, in_got;
    uint8_t in_type;
    int dispatched;
    int closing;  // close once the output queue is flushed

    uint8_t* out;
    size_t out_len, out_off, out_cap;

    int exec;
    pid_t pid;
    int reaped, wstatus;
    int fo, fe, fi;
    uint8_t* sin;
    size_t sin_len, sin_off;
    uint64_t deadline_ms, out_total, out_max;
    uint32_t xflags;
    int killed;
} conn_t;

struct grpc_server {
    char root[PATH_MAX];       // canonical, as the host names it
    char root_real[PATH_MAX];  // realpath(root); what resolved paths are checked against
    int (*pre_op)(void);
    conn_t c[MAX_CONNS];
    size_t in_bytes;
    unsigned tmp_seq;
    char** benv;   // base environment, owned
    int n_benv;
};

static uint64_t now_ms(void) {
    // The syscall, not clock_gettime(3): see the vDSO note in sandbox-agent.c.
    struct timespec ts;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

// ── output queue ────────────────────────────────────────────────────────────

static int q_append(conn_t* c, const void* d, size_t n) {
    if (n > c->out_cap - c->out_len) {
        // Compact first, then grow.
        if (c->out_off) {
            memmove(c->out, c->out + c->out_off, c->out_len - c->out_off);
            c->out_len -= c->out_off;
            c->out_off = 0;
        }
        if (n > c->out_cap - c->out_len) {
            size_t cap = c->out_cap ? c->out_cap : 4096;
            while (cap < c->out_len + n) cap *= 2;
            uint8_t* p = realloc(c->out, cap);
            if (!p) return -1;
            c->out = p;
            c->out_cap = cap;
        }
    }
    memcpy(c->out + c->out_len, d, n);
    c->out_len += n;
    return 0;
}

static int q_frame(conn_t* c, uint8_t type, const void* d, size_t n) {
    uint8_t h[GRPC_HDR_LEN];
    grpc_frame_hdr(h, type, (uint32_t)n);
    if (q_append(c, h, sizeof(h)) < 0) return -1;
    return n ? q_append(c, d, n) : 0;
}

static void q_result(conn_t* c, int status, int err, const void* body, size_t n) {
    uint8_t pre[5] = { (uint8_t)status, (uint8_t)err, (uint8_t)(err >> 8),
                       (uint8_t)(err >> 16), (uint8_t)(err >> 24) };
    uint8_t h[GRPC_HDR_LEN];
    grpc_frame_hdr(h, GRPC_T_RESULT, (uint32_t)(sizeof(pre) + n));
    q_append(c, h, sizeof(h));
    q_append(c, pre, sizeof(pre));
    if (n) q_append(c, body, n);
    c->closing = 1;
}

static void q_error(conn_t* c, int status, int err, const char* msg) {
    uint8_t b[256];
    grpc_wr_t w;
    grpc_wr_init(&w, b, sizeof(b));
    grpc_wr_str(&w, msg);
    if (w.err) { w.len = 0; w.err = 0; grpc_wr_str(&w, "error"); }
    q_result(c, status, err, b, w.len);
}

static int errno_status(int e) {
    switch (e) {
    case ENOENT: case ENOTDIR: return GRPC_E_NOT_FOUND;
    case EEXIST: return GRPC_E_EXISTS;
    case EACCES: case EPERM: return GRPC_E_DENIED;
    case EFBIG: return GRPC_E_TOO_LARGE;
    default: return GRPC_E_IO;
    }
}

static void q_errno(conn_t* c, const char* what) {
    int e = errno;
    char m[160];
    snprintf(m, sizeof(m), "%s: %s", what, strerror(e));
    q_error(c, errno_status(e), e, m);
}

// ── connection lifecycle ────────────────────────────────────────────────────

static void kill_group(conn_t* c) {
    if (c->exec && !c->reaped && c->pid > 0) kill(-c->pid, SIGKILL);
}

static void conn_close(grpc_server_t* s, conn_t* c) {
    if (c->exec && !c->reaped && c->pid > 0) {
        // The host went away (or the request is being abandoned): cancellation.
        // SIGKILL cannot be blocked, so this wait is bounded by the kernel.
        kill(-c->pid, SIGKILL);
        waitpid(c->pid, NULL, 0);
    }
    if (c->fo >= 0) close(c->fo);
    if (c->fe >= 0) close(c->fe);
    if (c->fi >= 0) close(c->fi);
    if (c->fd >= 0) close(c->fd);
    s->in_bytes -= c->in_len;
    free(c->in);
    free(c->out);
    free(c->sin);
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->fo = c->fe = c->fi = -1;
}

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

grpc_server_t* grpc_server_new(const char* root, int (*pre_op)(void)) {
    grpc_server_t* s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    if (grpc_path_canon(root, s->root, sizeof(s->root)) < 0 ||
        !realpath(s->root, s->root_real)) {
        // The root may not exist yet in the guest (the volume is mounted lazily);
        // fall back to the canonical name, and re-resolve once pre_op succeeds.
        snprintf(s->root_real, sizeof(s->root_real), "%s", s->root);
    }
    s->pre_op = pre_op;
    for (int i = 0; i < MAX_CONNS; i++) {
        s->c[i].fd = -1;
        s->c[i].fo = s->c[i].fe = s->c[i].fi = -1;
    }
    // A closed exec stdin pipe or a vanished host must be an error return, never
    // a signal that kills PID 1. Exec children get SIG_DFL back before exec.
    signal(SIGPIPE, SIG_IGN);
    return s;
}

static void benv_clear(grpc_server_t* s) {
    for (int i = 0; i < s->n_benv; i++) free(s->benv[i]);
    free(s->benv);
    s->benv = NULL;
    s->n_benv = 0;
}

int grpc_server_set_base_env(grpc_server_t* s, const char* payload, size_t len) {
    if (!s) return 0;
    benv_clear(s);
    if (!payload || !len) return 0;
    char** v = calloc(GRPC_BASE_ENV_MAX, sizeof(char*));
    if (!v) return 0;
    int n = 0;
    for (size_t i = 0; i < len && n < GRPC_BASE_ENV_MAX;) {
        size_t j = i;
        while (j < len && payload[j] != '\n' && payload[j] != '\0') j++;
        size_t ll = j - i;
        const char* eq = memchr(payload + i, '=', ll);
        bool ok = eq && eq > payload + i;
        // KEY must look like an environment variable name: a stray "bad key=1"
        // would otherwise be handed to execve as-is.
        for (const char* k = payload + i; ok && k < eq; k++)
            if (!(isalnum((unsigned char)*k) || *k == '_')) ok = false;
        if (ok && isdigit((unsigned char)payload[i])) ok = false;
        // Engine control verbs share the channel with env; never a variable.
        if (ok && ll >= 16 && !memcmp(payload + i, "SANDBOX_CONTROL=", 16)) ok = false;
        if (ok) {
            char* e = malloc(ll + 1);
            if (!e) break;
            memcpy(e, payload + i, ll);
            e[ll] = '\0';
            v[n++] = e;
        }
        i = j + 1;
    }
    if (n == 0) {
        free(v);
        return 0;
    }
    s->benv = v;
    s->n_benv = n;
    return n;
}

void grpc_server_free(grpc_server_t* s) {
    if (!s) return;
    benv_clear(s);
    for (int i = 0; i < MAX_CONNS; i++)
        if (s->c[i].fd >= 0 || s->c[i].exec) conn_close(s, &s->c[i]);
    free(s);
}

int grpc_server_adopt(grpc_server_t* s, int fd) {
    set_nonblock(fd);
    for (int i = 0; i < MAX_CONNS; i++) {
        conn_t* c = &s->c[i];
        if (c->fd >= 0) continue;
        memset(c, 0, sizeof(*c));
        c->fd = fd;
        c->fo = c->fe = c->fi = -1;
        c->born_ms = now_ms();
        return 0;
    }
    // Over the limit: say so rather than leave the host waiting.
    conn_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.fd = -1;
    q_error(&tmp, GRPC_E_BUSY, 0, "too many connections");
    if (tmp.out) {
        ssize_t w = send(fd, tmp.out, tmp.out_len, MSG_NOSIGNAL | MSG_DONTWAIT);
        (void)w;
    }
    free(tmp.out);
    close(fd);
    return -1;
}

// ── path resolution ─────────────────────────────────────────────────────────

static int real_within(const grpc_server_t* s, const char* real) {
    return grpc_path_within(real, s->root_real);
}

static void split_path(const char* canon, char* dir, size_t dcap, const char** base) {
    snprintf(dir, dcap, "%s", canon);
    char* sl = strrchr(dir, '/');
    *base = sl + 1;
    if (sl == dir) dir[1] = '\0'; else *sl = '\0';
}

// Create every missing directory above `canon` (not `canon` itself), checking
// after each step that the real location is still under the root.
static int make_parents(const grpc_server_t* s, const char* canon) {
    char dir[PATH_MAX];
    const char* base;
    split_path(canon, dir, sizeof(dir), &base);
    size_t rl = strlen(s->root);
    size_t dl = strlen(dir);
    for (size_t i = rl + 1; i <= dl; i++) {
        if (dir[i] != '/' && dir[i] != '\0') continue;
        char saved = dir[i];
        dir[i] = '\0';
        struct stat st;
        if (lstat(dir, &st) != 0) {
            if (errno != ENOENT || mkdir(dir, 0755) != 0) return -1;
        }
        char real[PATH_MAX];
        if (!realpath(dir, real) || !real_within(s, real)) { errno = EACCES; return -1; }
        dir[i] = saved;
    }
    return 0;
}

// Map a request path to one safe to hand to a syscall. 0 or a GRPC_E_* code.
// `follow`: resolve a symlink in the final component too (read, list); without
// it the final component is the link itself (stat, remove, write replaces it).
static int resolve(grpc_server_t* s, const char* raw, uint32_t flags, int follow,
                   char* out, size_t cap, char* msg, size_t mcap) {
    char canon[PATH_MAX];
    if (grpc_path_canon(raw, canon, sizeof(canon)) < 0) {
        snprintf(msg, mcap, "path must be absolute with no '.' or '..' components");
        return GRPC_E_DENIED;
    }
    if (flags & GRPC_F_ALLOW_OUTSIDE) {
        snprintf(out, cap, "%s", canon);
        return 0;
    }
    if (!grpc_path_within(canon, s->root)) {
        snprintf(msg, mcap, "path is outside %s", s->root);
        return GRPC_E_DENIED;
    }
    if (strcmp(canon, s->root) == 0) {
        snprintf(out, cap, "%s", s->root_real);
        return 0;
    }
    if ((flags & GRPC_F_PARENTS) && make_parents(s, canon) < 0) {
        int e = errno;
        snprintf(msg, mcap, "create parents: %s", strerror(e));
        return errno_status(e);
    }
    char dir[PATH_MAX], rdir[PATH_MAX];
    const char* base;
    split_path(canon, dir, sizeof(dir), &base);
    if (!realpath(dir, rdir)) {
        int e = errno;
        snprintf(msg, mcap, "%.100s: %s", dir, strerror(e));
        return errno_status(e);
    }
    if (!real_within(s, rdir)) {
        snprintf(msg, mcap, "path escapes %s via a symlink", s->root);
        return GRPC_E_DENIED;
    }
    char joined[PATH_MAX];
    int n = snprintf(joined, sizeof(joined), "%s%s%s", rdir,
                     strcmp(rdir, "/") == 0 ? "" : "/", base);
    if (n < 0 || (size_t)n >= sizeof(joined)) {
        snprintf(msg, mcap, "path too long");
        return GRPC_E_BAD_REQUEST;
    }
    if (follow) {
        char rfull[PATH_MAX];
        if (realpath(joined, rfull)) {
            if (!real_within(s, rfull)) {
                snprintf(msg, mcap, "path escapes %s via a symlink", s->root);
                return GRPC_E_DENIED;
            }
            snprintf(out, cap, "%s", rfull);
            return 0;
        }
        // Does not exist (yet): fine for callers that create it.
    }
    snprintf(out, cap, "%s", joined);
    return 0;
}

// ── file operations ─────────────────────────────────────────────────────────

static int ftype(mode_t m) {
    if (S_ISREG(m)) return GRPC_FT_FILE;
    if (S_ISDIR(m)) return GRPC_FT_DIR;
    if (S_ISLNK(m)) return GRPC_FT_LINK;
    return GRPC_FT_OTHER;
}

static void op_read(grpc_server_t* s, conn_t* c, grpc_rd_t* r, uint32_t flags) {
    char path[PATH_MAX], real[PATH_MAX], msg[160];
    grpc_rd_cstr(r, path, sizeof(path));
    uint64_t off = grpc_rd_u64(r);
    uint32_t max = grpc_rd_u32(r);
    if (r->err) return q_error(c, GRPC_E_BAD_REQUEST, 0, "malformed read_file");
    if (max == 0) max = GRPC_MAX_FILE;
    if (max > GRPC_MAX_FILE) return q_error(c, GRPC_E_TOO_LARGE, 0, "max_bytes over the file limit");
    int st = resolve(s, path, flags, 1, real, sizeof(real), msg, sizeof(msg));
    if (st) return q_error(c, st, 0, msg);
    int fd = open(real, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return q_errno(c, "open");
    struct stat sb;
    if (fstat(fd, &sb) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return q_errno(c, "fstat");
    }
    if (!S_ISREG(sb.st_mode)) {
        close(fd);
        errno = EISDIR;
        return q_errno(c, "not a regular file");
    }
    uint8_t* buf = malloc(13 + (size_t)max);
    if (!buf) { close(fd); errno = ENOMEM; return q_errno(c, "read"); }
    size_t got = 0;
    int rerr = 0;
    while (got < max) {
        ssize_t n = pread(fd, buf + 13 + got, max - got, (off_t)(off + got));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { rerr = errno; break; }
        if (n == 0) break;
        got += (size_t)n;
    }
    close(fd);
    if (rerr) { free(buf); errno = rerr; return q_errno(c, "read"); }
    grpc_wr_t w;
    grpc_wr_init(&w, buf, 13);
    grpc_wr_u8(&w, off + got < (uint64_t)sb.st_size);  // truncated
    grpc_wr_u64(&w, (uint64_t)sb.st_size);
    grpc_wr_u32(&w, (uint32_t)got);
    q_result(c, GRPC_OK, 0, buf, 13 + got);
    free(buf);
}

static void op_write(grpc_server_t* s, conn_t* c, grpc_rd_t* r, uint32_t flags) {
    char path[PATH_MAX], real[PATH_MAX], msg[160];
    grpc_rd_cstr(r, path, sizeof(path));
    uint32_t mode = grpc_rd_u32(r);
    uint32_t n;
    const uint8_t* data = (const uint8_t*)grpc_rd_str(r, &n);
    if (r->err) return q_error(c, GRPC_E_BAD_REQUEST, 0, "malformed write_file");
    if (n > GRPC_MAX_FILE) return q_error(c, GRPC_E_TOO_LARGE, 0, "file over the size limit");
    mode &= 07777;
    int st = resolve(s, path, flags, 0, real, sizeof(real), msg, sizeof(msg));
    if (st) return q_error(c, st, 0, msg);
    if (strcmp(real, s->root_real) == 0) return q_error(c, GRPC_E_DENIED, EISDIR, "path is the root");

    int fd;
    char tmp[PATH_MAX + 32];
    int use_tmp = !(flags & (GRPC_F_APPEND | GRPC_F_EXCL));
    if (use_tmp) {
        // Overwrite atomically: a reader (or a crash) sees the old file or the
        // new one, never half of it. The temp name lives beside the target so
        // rename() stays on one filesystem.
        snprintf(tmp, sizeof(tmp), "%s.sbtmp.%d.%u", real, (int)getpid(), s->tmp_seq++);
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    } else {
        int oflags = O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC |
                     ((flags & GRPC_F_APPEND) ? O_APPEND : 0) |
                     ((flags & GRPC_F_EXCL) ? O_EXCL : 0);
        fd = open(real, oflags, mode);
    }
    if (fd < 0) return q_errno(c, "open");
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, data + done, n - done);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) break;
        done += (size_t)w;
    }
    int werr = done < n ? (errno ? errno : EIO) : 0;
    if (use_tmp) fchmod(fd, mode);
    if (close(fd) != 0 && !werr) werr = errno;
    if (werr) {
        if (use_tmp) unlink(tmp);
        errno = werr;
        return q_errno(c, "write");
    }
    if (use_tmp && rename(tmp, real) != 0) {
        int e = errno;
        unlink(tmp);
        errno = e;
        return q_errno(c, "rename");
    }
    uint8_t b[8];
    grpc_wr_t w;
    grpc_wr_init(&w, b, sizeof(b));
    grpc_wr_u64(&w, n);
    q_result(c, GRPC_OK, 0, b, w.len);
}

static void op_list(grpc_server_t* s, conn_t* c, grpc_rd_t* r, uint32_t flags) {
    char path[PATH_MAX], real[PATH_MAX], msg[160];
    grpc_rd_cstr(r, path, sizeof(path));
    if (r->err) return q_error(c, GRPC_E_BAD_REQUEST, 0, "malformed list_dir");
    int st = resolve(s, path, flags, 1, real, sizeof(real), msg, sizeof(msg));
    if (st) return q_error(c, st, 0, msg);
    DIR* d = opendir(real);
    if (!d) return q_errno(c, "opendir");
    size_t cap = GRPC_MAX_FRAME - 64;
    uint8_t* buf = malloc(cap);
    if (!buf) { closedir(d); errno = ENOMEM; return q_errno(c, "list"); }
    grpc_wr_t w;
    grpc_wr_init(&w, buf, cap);
    grpc_wr_raw(&w, "\0\0\0\0\0", 5);  // truncated u8 + count u32, patched below
    uint32_t count = 0;
    int truncated = 0;
    struct dirent* de;
    int dfd = dirfd(d);
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        struct stat sb;
        if (fstatat(dfd, de->d_name, &sb, AT_SYMLINK_NOFOLLOW) != 0) continue;
        size_t mark = w.len;
        grpc_wr_str(&w, de->d_name);
        grpc_wr_u8(&w, (uint8_t)ftype(sb.st_mode));
        grpc_wr_u64(&w, (uint64_t)sb.st_size);
        grpc_wr_u64(&w, (uint64_t)sb.st_mtime);
        if (w.err) { w.len = mark; truncated = 1; break; }
        count++;
    }
    closedir(d);
    buf[0] = (uint8_t)truncated;
    buf[1] = (uint8_t)count; buf[2] = (uint8_t)(count >> 8);
    buf[3] = (uint8_t)(count >> 16); buf[4] = (uint8_t)(count >> 24);
    q_result(c, GRPC_OK, 0, buf, w.len);
    free(buf);
}

static void op_stat(grpc_server_t* s, conn_t* c, grpc_rd_t* r, uint32_t flags) {
    char path[PATH_MAX], real[PATH_MAX], msg[160];
    grpc_rd_cstr(r, path, sizeof(path));
    if (r->err) return q_error(c, GRPC_E_BAD_REQUEST, 0, "malformed stat");
    int st = resolve(s, path, flags, 0, real, sizeof(real), msg, sizeof(msg));
    if (st) return q_error(c, st, 0, msg);
    struct stat sb;
    if (lstat(real, &sb) != 0) return q_errno(c, "stat");
    uint8_t b[32];
    grpc_wr_t w;
    grpc_wr_init(&w, b, sizeof(b));
    grpc_wr_u8(&w, (uint8_t)ftype(sb.st_mode));
    grpc_wr_u64(&w, (uint64_t)sb.st_size);
    grpc_wr_u32(&w, (uint32_t)(sb.st_mode & 07777));
    grpc_wr_u64(&w, (uint64_t)sb.st_mtime);
    q_result(c, GRPC_OK, 0, b, w.len);
}

static void op_mkdir(grpc_server_t* s, conn_t* c, grpc_rd_t* r, uint32_t flags) {
    char path[PATH_MAX], real[PATH_MAX], msg[160];
    grpc_rd_cstr(r, path, sizeof(path));
    uint32_t mode = grpc_rd_u32(r) & 07777;
    if (r->err) return q_error(c, GRPC_E_BAD_REQUEST, 0, "malformed mkdir");
    int st = resolve(s, path, flags, 0, real, sizeof(real), msg, sizeof(msg));
    if (st) return q_error(c, st, 0, msg);
    if (mkdir(real, mode ? mode : 0755) != 0) {
        struct stat sb;
        // `mkdir -p` semantics: an existing directory is success.
        if (errno == EEXIST && (flags & GRPC_F_PARENTS) && lstat(real, &sb) == 0 &&
            S_ISDIR(sb.st_mode)) {
            return q_result(c, GRPC_OK, 0, NULL, 0);
        }
        return q_errno(c, "mkdir");
    }
    q_result(c, GRPC_OK, 0, NULL, 0);
}

static int rm_cb(const char* p, const struct stat* sb, int type, struct FTW* f) {
    (void)sb; (void)f;
    return (type == FTW_DP || type == FTW_D) ? rmdir(p) : unlink(p);
}

static void op_remove(grpc_server_t* s, conn_t* c, grpc_rd_t* r, uint32_t flags) {
    char path[PATH_MAX], real[PATH_MAX], msg[160];
    grpc_rd_cstr(r, path, sizeof(path));
    if (r->err) return q_error(c, GRPC_E_BAD_REQUEST, 0, "malformed remove");
    int st = resolve(s, path, flags, 0, real, sizeof(real), msg, sizeof(msg));
    if (st) return q_error(c, st, 0, msg);
    if (!(flags & GRPC_F_ALLOW_OUTSIDE) && strcmp(real, s->root_real) == 0)
        return q_error(c, GRPC_E_DENIED, 0, "refusing to remove the workspace root");
    if (strcmp(real, "/") == 0) return q_error(c, GRPC_E_DENIED, 0, "refusing to remove /");
    struct stat sb;
    if (lstat(real, &sb) != 0) return q_errno(c, "stat");
    int rc;
    if (S_ISDIR(sb.st_mode)) {
        rc = (flags & GRPC_F_RECURSIVE) ? nftw(real, rm_cb, 16, FTW_DEPTH | FTW_PHYS)
                                        : rmdir(real);
    } else {
        rc = unlink(real);
    }
    if (rc != 0) return q_errno(c, "remove");
    q_result(c, GRPC_OK, 0, NULL, 0);
}

// ── exec ────────────────────────────────────────────────────────────────────

static void op_exec(grpc_server_t* s, conn_t* c, grpc_rd_t* r, uint32_t flags) {
    char cwd[PATH_MAX], msg[160];
    uint32_t cl;
    const char* cs = grpc_rd_str(r, &cl);
    uint32_t argc = grpc_rd_u32(r);
    if (r->err || !cs || cl >= PATH_MAX || memchr(cs, 0, cl))
        return q_error(c, GRPC_E_BAD_REQUEST, 0, "malformed exec");
    if (argc == 0 || argc > GRPC_MAX_ARGS)
        return q_error(c, GRPC_E_BAD_REQUEST, 0, "argc out of range");

    // One arena for argv + env: every string is NUL-terminated in place, and any
    // string that already contains a NUL is refused (it would be silently cut).
    size_t cap = r->len + 64;
    char* arena = malloc(cap);
    char** vec = calloc((size_t)argc + 8 + GRPC_MAX_ARGS + (size_t)s->n_benv, sizeof(char*));
    if (!arena || !vec) { free(arena); free(vec); errno = ENOMEM; return q_errno(c, "exec"); }
    size_t ao = 0;
    uint32_t nargv = 0, nenv = 0;
    char** argv = vec;
    char** envp = vec + argc + 4;  // argv needs up to 4 slots in shell mode
    int shell = (flags & GRPC_F_SHELL) != 0;
    for (uint32_t i = 0; i < argc && !r->err; i++) {
        uint32_t n;
        const char* a = grpc_rd_str(r, &n);
        if (!a || memchr(a, 0, n)) { r->err = 1; break; }
        memcpy(arena + ao, a, n);
        arena[ao + n] = '\0';
        argv[nargv++] = arena + ao;
        ao += n + 1;
    }
    uint32_t envc = grpc_rd_u32(r);
    if (envc > GRPC_MAX_ARGS) r->err = 1;
    int have_path = 0, have_home = 0;
    for (uint32_t i = 0; i < envc && !r->err; i++) {
        uint32_t n;
        const char* e = grpc_rd_str(r, &n);
        if (!e || memchr(e, 0, n) || !memchr(e, '=', n)) { r->err = 1; break; }
        memcpy(arena + ao, e, n);
        arena[ao + n] = '\0';
        if (n >= 5 && !strncmp(e, "PATH=", 5)) have_path = 1;
        if (n >= 5 && !strncmp(e, "HOME=", 5)) have_home = 1;
        envp[nenv++] = arena + ao;
        ao += n + 1;
    }
    // The sandbox's base environment fills in whatever the request did not set
    // itself. The strings live in the server and outlive the exec (the child
    // inherits a copy of them).
    for (int i = 0; i < s->n_benv && !r->err; i++) {
        const char* b = s->benv[i];
        size_t kl = (size_t)(strchr(b, '=') - b) + 1;  // "KEY="
        bool shadowed = false;
        for (uint32_t j = 0; j < nenv; j++)
            if (!strncmp(envp[j], b, kl)) { shadowed = true; break; }
        if (shadowed) continue;
        if (!strncmp(b, "PATH=", 5)) have_path = 1;
        if (!strncmp(b, "HOME=", 5)) have_home = 1;
        envp[nenv++] = (char*)b;
    }
    uint32_t timeout = grpc_rd_u32(r);
    uint32_t maxout = grpc_rd_u32(r);
    uint32_t sl;
    const uint8_t* sdat = (const uint8_t*)grpc_rd_str(r, &sl);
    if (r->err || sl > GRPC_MAX_STDIN || r->off != r->len) {
        free(arena); free(vec);
        return q_error(c, GRPC_E_BAD_REQUEST, 0, "malformed exec");
    }
    if (shell) {
        if (argc != 1) {
            free(arena); free(vec);
            return q_error(c, GRPC_E_BAD_REQUEST, 0, "shell exec takes exactly one script");
        }
        char* script = argv[0];
        argv[0] = (char*)"/bin/sh";
        argv[1] = (char*)"-c";
        argv[2] = script;
        argv[3] = NULL;
    } else {
        argv[nargv] = NULL;
    }
    static const char path_default[] = "PATH=" DEFAULT_PATH;
    if (!have_path) envp[nenv++] = (char*)path_default;
    char home[PATH_MAX + 8];
    if (!have_home) {
        snprintf(home, sizeof(home), "HOME=%s", s->root);
        envp[nenv++] = home;
    }
    envp[nenv] = NULL;

    // Working directory: the workspace unless the request names one.
    if (cl == 0) {
        snprintf(cwd, sizeof(cwd), "%s", s->root_real);
    } else {
        char raw[PATH_MAX];
        memcpy(raw, cs, cl);
        raw[cl] = '\0';
        int st = resolve(s, raw, flags, 1, cwd, sizeof(cwd), msg, sizeof(msg));
        if (st) { free(arena); free(vec); return q_error(c, st, 0, msg); }
    }
    if (timeout == 0 || timeout > GRPC_MAX_TIMEOUT_MS) timeout = GRPC_MAX_TIMEOUT_MS;
    if (maxout == 0) maxout = GRPC_MAX_OUTPUT_DEFAULT;

    int pi[2], po[2], pe[2];
    if (pipe2(pi, O_CLOEXEC) != 0) goto fail_nopipes;
    if (pipe2(po, O_CLOEXEC) != 0) { close(pi[0]); close(pi[1]); goto fail_nopipes; }
    if (pipe2(pe, O_CLOEXEC) != 0) {
        close(pi[0]); close(pi[1]); close(po[0]); close(po[1]);
        goto fail_nopipes;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pi[0]); close(pi[1]); close(po[0]); close(po[1]); close(pe[0]); close(pe[1]);
        goto fail_nopipes;
    }
    if (pid == 0) {
        // Own session and process group, so a timeout or cancel takes the whole
        // tree down with one kill(-pid).
        setsid();
        signal(SIGPIPE, SIG_DFL);
        dup2(pi[0], 0);
        dup2(po[1], 1);
        dup2(pe[1], 2);
        if (chdir(cwd) != 0) {
            static const char m[] = "sandbox-agent: cannot enter the working directory\n";
            ssize_t w = write(2, m, sizeof(m) - 1);
            (void)w;
            _exit(126);
        }
        environ = envp;
        execvp(argv[0], argv);
        static const char m[] = "sandbox-agent: exec failed\n";
        ssize_t w = write(2, m, sizeof(m) - 1);
        (void)w;
        _exit(127);
    }
    close(pi[0]); close(po[1]); close(pe[1]);
    free(arena);
    free(vec);
    c->exec = 1;
    c->pid = pid;
    c->fi = pi[1]; c->fo = po[0]; c->fe = pe[0];
    set_nonblock(c->fi); set_nonblock(c->fo); set_nonblock(c->fe);
    if (sl) {
        c->sin = malloc(sl);
        if (c->sin) { memcpy(c->sin, sdat, sl); c->sin_len = sl; }
    }
    if (!c->sin_len) { close(c->fi); c->fi = -1; }
    c->deadline_ms = now_ms() + timeout;
    c->out_max = maxout;
    return;

fail_nopipes:
    free(arena);
    free(vec);
    q_errno(c, "exec");
}

static void exec_finish(conn_t* c) {
    uint8_t b[12];
    grpc_wr_t w;
    grpc_wr_init(&w, b, sizeof(b));
    int32_t code = -1, sig = 0;
    if (WIFEXITED(c->wstatus)) code = WEXITSTATUS(c->wstatus);
    else if (WIFSIGNALED(c->wstatus)) sig = WTERMSIG(c->wstatus);
    grpc_wr_u32(&w, (uint32_t)code);
    grpc_wr_u32(&w, (uint32_t)sig);
    grpc_wr_u32(&w, c->xflags);
    if (c->fo >= 0) close(c->fo);
    if (c->fe >= 0) close(c->fe);
    if (c->fi >= 0) close(c->fi);
    c->fo = c->fe = c->fi = -1;
    c->exec = 0;
    q_result(c, GRPC_OK, 0, b, w.len);
}

// Read what is available from one exec pipe into stream frames. `drain` ignores
// the queue backlog (used once the child has exited so nothing is left behind).
static void pump_pipe(conn_t* c, int* fdp, uint8_t type, int drain) {
    uint8_t buf[GRPC_CHUNK];
    for (int i = 0; *fdp >= 0 && i < 64; i++) {
        if (!drain && c->out_len - c->out_off > QUEUE_HIGH) return;  // backpressure
        ssize_t n = read(*fdp, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == EAGAIN) return;
        if (n <= 0) { close(*fdp); *fdp = -1; return; }
        uint64_t room = c->out_max > c->out_total ? c->out_max - c->out_total : 0;
        if ((uint64_t)n > room) {
            n = (ssize_t)room;
            c->xflags |= GRPC_X_TRUNCATED;
        }
        if (n > 0) {
            q_frame(c, type, buf, (size_t)n);
            c->out_total += (uint64_t)n;
        }
        if (c->xflags & GRPC_X_TRUNCATED) {
            kill_group(c);
            c->killed = 1;
            return;
        }
    }
}

static void exec_pump(conn_t* c, uint64_t now) {
    if (c->fi >= 0) {
        if (c->sin_off < c->sin_len) {
            ssize_t w = write(c->fi, c->sin + c->sin_off, c->sin_len - c->sin_off);
            if (w > 0) c->sin_off += (size_t)w;
            else if (w < 0 && errno != EAGAIN && errno != EINTR) c->sin_off = c->sin_len;
        }
        if (c->sin_off >= c->sin_len) { close(c->fi); c->fi = -1; }
    }
    if (!(c->xflags & GRPC_X_TRUNCATED)) {
        pump_pipe(c, &c->fo, GRPC_T_STDOUT, 0);
        pump_pipe(c, &c->fe, GRPC_T_STDERR, 0);
    }
    if (!c->killed && now >= c->deadline_ms) {
        c->xflags |= GRPC_X_TIMED_OUT;
        kill_group(c);
        c->killed = 1;
    }
    if (c->reaped) {
        // The child is gone, so anything it wrote is already in the pipes. A
        // background grandchild may still hold them open; do not wait for it.
        if (!(c->xflags & GRPC_X_TRUNCATED)) {
            pump_pipe(c, &c->fo, GRPC_T_STDOUT, 1);
            pump_pipe(c, &c->fe, GRPC_T_STDERR, 1);
        }
        exec_finish(c);
    }
}

// ── dispatch + I/O ──────────────────────────────────────────────────────────

static void dispatch(grpc_server_t* s, conn_t* c) {
    grpc_rd_t r;
    grpc_rd_init(&r, c->in, c->in_len);
    if (c->in_type != GRPC_T_REQUEST) return q_error(c, GRPC_E_BAD_REQUEST, 0, "expected a request frame");
    uint8_t ver = grpc_rd_u8(&r);
    uint8_t op = grpc_rd_u8(&r);
    uint32_t flags = grpc_rd_u32(&r);
    if (r.err) return q_error(c, GRPC_E_BAD_REQUEST, 0, "short request");
    if (ver != GRPC_VERSION) return q_error(c, GRPC_E_BAD_VERSION, 0, "unsupported protocol version");
    if (s->pre_op && s->pre_op() != 0)
        return q_error(c, GRPC_E_NOT_READY, 0, "workspace is not mounted");
    if (!realpath(s->root, s->root_real)) snprintf(s->root_real, sizeof(s->root_real), "%s", s->root);
    switch (op) {
    case GRPC_OP_EXEC: op_exec(s, c, &r, flags); break;
    case GRPC_OP_READ_FILE: op_read(s, c, &r, flags); break;
    case GRPC_OP_WRITE_FILE: op_write(s, c, &r, flags); break;
    case GRPC_OP_LIST_DIR: op_list(s, c, &r, flags); break;
    case GRPC_OP_STAT: op_stat(s, c, &r, flags); break;
    case GRPC_OP_MKDIR: op_mkdir(s, c, &r, flags); break;
    case GRPC_OP_REMOVE: op_remove(s, c, &r, flags); break;
    default: q_error(c, GRPC_E_BAD_REQUEST, 0, "unknown operation");
    }
}

// Returns 0 to keep the connection, -1 to drop it now.
static int conn_read(grpc_server_t* s, conn_t* c) {
    while (!c->dispatched) {
        if (c->hdr_got < GRPC_HDR_LEN) {
            ssize_t n = read(c->fd, c->hdr + c->hdr_got, GRPC_HDR_LEN - c->hdr_got);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && errno == EAGAIN) return 0;
            if (n <= 0) return -1;
            c->hdr_got += (size_t)n;
            if (c->hdr_got < GRPC_HDR_LEN) continue;
            uint32_t len;
            if (grpc_frame_parse(c->hdr, &c->in_type, &len) < 0) {
                q_error(c, GRPC_E_BAD_REQUEST, 0, "bad frame header");
                c->dispatched = 1;
                return 0;
            }
            if (len > 0) {
                if (s->in_bytes + len > MAX_INFLIGHT_IN || !(c->in = malloc(len))) {
                    free(c->in); c->in = NULL;
                    q_error(c, GRPC_E_BUSY, 0, "request buffer limit");
                    c->dispatched = 1;
                    return 0;
                }
                s->in_bytes += len;
            }
            c->in_len = len;
        }
        if (c->in_got < c->in_len) {
            ssize_t n = read(c->fd, c->in + c->in_got, c->in_len - c->in_got);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && errno == EAGAIN) return 0;
            if (n <= 0) return -1;
            c->in_got += (uint32_t)n;
        }
        if (c->in_got == c->in_len) {
            c->dispatched = 1;
            dispatch(s, c);
        }
    }
    return 0;
}

static int conn_flush(conn_t* c) {
    while (c->out_off < c->out_len) {
        ssize_t n = send(c->fd, c->out + c->out_off, c->out_len - c->out_off,
                         MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (n <= 0) return -1;
        c->out_off += (size_t)n;
    }
    c->out_off = c->out_len = 0;
    return 0;
}

static void reap_children(grpc_server_t* s) {
    int st;
    pid_t p;
    while ((p = waitpid(-1, &st, WNOHANG)) > 0) {
        for (int i = 0; i < MAX_CONNS; i++) {
            conn_t* c = &s->c[i];
            if (c->exec && c->pid == p) { c->reaped = 1; c->wstatus = st; }
        }
    }
}

int grpc_server_step(grpc_server_t* s) {
    uint64_t now = now_ms();
    reap_children(s);
    int live = 0;
    for (int i = 0; i < MAX_CONNS; i++) {
        conn_t* c = &s->c[i];
        if (c->fd < 0) continue;
        int drop = 0;
        if (!c->dispatched) {
            if (now - c->born_ms > REQ_TIMEOUT_MS) drop = 1;
            else if (conn_read(s, c) < 0) drop = 1;
        } else if (c->exec) {
            // After the request the host sends nothing and does not half-close.
            // Any readability means it closed (or misbehaved): cancel the exec.
            char tmp;
            ssize_t n = recv(c->fd, &tmp, 1, MSG_PEEK | MSG_DONTWAIT);
            if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR) || n > 0) drop = 1;
        }
        if (!drop && c->exec) exec_pump(c, now);
        if (!drop && conn_flush(c) < 0) drop = 1;
        if (!drop && c->closing && c->out_off == c->out_len && !c->exec) drop = 1;
        if (drop) { conn_close(s, c); continue; }
        live++;
    }
    return live;
}
