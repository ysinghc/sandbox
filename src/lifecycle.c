// SPDX-License-Identifier: GPL-2.0-only
// Lifecycle: the daemon-side live-VM registry plus the client-side libsandbox
// C API (§3.1). The client speaks the §2.3 IPC protocol (SEQPACKET +
// length-prefixed protobuf) through ipc_codec.

#include "lifecycle.h"

#include "ipc_codec.h"
#include "ipc_internal.h"
#include "libsandbox.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Live-VM registry (daemon). Mutated only by the IPC loop thread; reads are
// lock-protected. The returned pointer is borrowed (valid until the matching
// lifecycle_remove, which the same thread performs after vmm_destroy).
// ---------------------------------------------------------------------------

typedef struct lc_entry {
    vm_handle_t* vm;
    struct lc_entry* next;
} lc_entry_t;

static pthread_mutex_t g_lc_lock = PTHREAD_MUTEX_INITIALIZER;
static lc_entry_t* g_lc_list = NULL;
static int g_lc_count = 0;

int lifecycle_track(vm_handle_t* vm) {
    if (!vm) return -1;
    lc_entry_t* e = calloc(1, sizeof(*e));
    if (!e) return -1;
    e->vm = vm;
    pthread_mutex_lock(&g_lc_lock);
    e->next = g_lc_list;
    g_lc_list = e;
    g_lc_count++;
    pthread_mutex_unlock(&g_lc_lock);
    return 0;
}

int lifecycle_remove(uint32_t sandbox_id) {
    pthread_mutex_lock(&g_lc_lock);
    lc_entry_t** pp = &g_lc_list;
    while (*pp) {
        if ((*pp)->vm && (*pp)->vm->sandbox_id == sandbox_id) {
            lc_entry_t* dead = *pp;
            *pp = dead->next;
            free(dead);
            g_lc_count--;
            pthread_mutex_unlock(&g_lc_lock);
            return 0;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&g_lc_lock);
    return -1;
}

vm_handle_t* lifecycle_get(uint32_t sandbox_id) {
    vm_handle_t* vm = NULL;
    pthread_mutex_lock(&g_lc_lock);
    for (lc_entry_t* e = g_lc_list; e; e = e->next) {
        if (e->vm && e->vm->sandbox_id == sandbox_id) {
            vm = e->vm;
            break;
        }
    }
    pthread_mutex_unlock(&g_lc_lock);
    return vm;
}

int lifecycle_count(void) {
    int n;
    pthread_mutex_lock(&g_lc_lock);
    n = g_lc_count;
    pthread_mutex_unlock(&g_lc_lock);
    return n;
}

// ---------------------------------------------------------------------------
// Client API (§3.1)
// ---------------------------------------------------------------------------

struct sandbox_handle_t {
    uint32_t sandbox_id;
    char token[IPC_TOKEN_HEX_LEN + 1];
};

// ---------------------------------------------------------------------------
// Client transport (#12)
//
// One connection per process, usable from several threads at once: every
// request carries a correlation id, a reader thread matches the reply and wakes
// the caller. Without this, "create several sandboxes in parallel" would be a
// polite lie -- the daemon would have to serialise them to keep replies in
// order, which is exactly what the old protocol forced.
//
// A transport failure is latched in `dead` and wakes every waiter, so a broken
// connection fails calls instead of hanging them.
// ---------------------------------------------------------------------------

typedef struct c_waiter {
    uint64_t rid;
    ipc_response_t resp;
    bool done;
    struct c_waiter* next;
} c_waiter_t;

static struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int fd;
    pthread_t reader;
    bool reader_started;
    int gen;               // bumped per connection; stale readers see it
    sandbox_error_t dead;  // SANDBOX_OK while the connection is usable
    uint64_t next_rid;
    c_waiter_t* waiters;
} c = { .mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER,
        .fd = -1, .dead = SANDBOX_OK, .next_rid = 1 };

// Caller holds c.mu.
static void client_fail(sandbox_error_t why) {
    if (c.dead == SANDBOX_OK) c.dead = why;
    pthread_cond_broadcast(&c.cv);
}

static void* client_reader(void* arg) {
    int gen = (int)(intptr_t)arg;
    for (;;) {
        uint8_t buf[IPC_FRAME_MAX];
        size_t n = 0;
        pthread_mutex_lock(&c.mu);
        if (gen != c.gen || c.fd < 0) {
            pthread_mutex_unlock(&c.mu);
            return NULL;
        }
        int fd = c.fd;
        pthread_mutex_unlock(&c.mu);

        if (ipc_recv_frame(fd, buf, sizeof(buf), &n) < 0) {
            pthread_mutex_lock(&c.mu);
            if (gen == c.gen) client_fail(SANDBOX_ERR_DAEMON_UNREACHABLE);
            pthread_mutex_unlock(&c.mu);
            return NULL;
        }
        ipc_response_t resp;
        if (ipc_decode_response(buf, n, &resp) < 0) {
            pthread_mutex_lock(&c.mu);
            if (gen == c.gen) client_fail(SANDBOX_ERR_INTERNAL);
            pthread_mutex_unlock(&c.mu);
            return NULL;
        }

        pthread_mutex_lock(&c.mu);
        if (gen != c.gen) {  // connection was replaced while we read
            pthread_mutex_unlock(&c.mu);
            return NULL;
        }
        bool matched = false;
        for (c_waiter_t* w = c.waiters; w; w = w->next) {
            if (w->rid == resp.request_id) {
                w->resp = resp;  // ownership of any buffers moves with it
                w->done = true;
                matched = true;
                pthread_cond_broadcast(&c.cv);
                break;
            }
        }
        pthread_mutex_unlock(&c.mu);
        if (!matched) ipc_response_clear(&resp);  // nobody is waiting: do not leak
    }
}

// Send one request and wait for the reply carrying its id.
static sandbox_error_t client_roundtrip(ipc_request_t* req,
                                        ipc_response_t* resp) {
    uint8_t buf[IPC_FRAME_MAX];
    size_t n = 0;

    pthread_mutex_lock(&c.mu);
    if (c.dead != SANDBOX_OK || c.fd < 0) {
        sandbox_error_t rc = c.dead != SANDBOX_OK ? c.dead
                                                  : SANDBOX_ERR_DAEMON_UNREACHABLE;
        pthread_mutex_unlock(&c.mu);
        return rc;
    }
    // 0 is reserved for "legacy, in-order" callers; never hand it out.
    uint64_t rid = c.next_rid++;
    if (rid == 0) rid = c.next_rid++;
    req->request_id = rid;

    // A request that does not fit one frame is the caller's mistake, not a
    // transport failure: refuse it without poisoning the shared connection.
    if (ipc_encode_request(req, buf, sizeof(buf), &n) < 0) {
        pthread_mutex_unlock(&c.mu);
        return SANDBOX_ERR_INVALID_SPEC;
    }

    // Register before sending: a fast daemon may answer before send() returns.
    c_waiter_t w;
    memset(&w, 0, sizeof(w));
    w.rid = rid;
    w.next = c.waiters;
    c.waiters = &w;

    if (ipc_send_frame(c.fd, buf, n) < 0) {
        c.waiters = w.next;
        client_fail(SANDBOX_ERR_DAEMON_UNREACHABLE);
        sandbox_error_t rc = c.dead;
        pthread_mutex_unlock(&c.mu);
        return rc;
    }

    while (!w.done && c.dead == SANDBOX_OK)
        pthread_cond_wait(&c.cv, &c.mu);

    sandbox_error_t rc = c.dead;
    for (c_waiter_t** pp = &c.waiters; *pp; pp = &(*pp)->next) {
        if (*pp == &w) {
            *pp = w.next;
            break;
        }
    }
    if (rc == SANDBOX_OK) {
        if (!w.done || w.resp.request_id != rid) {
            rc = SANDBOX_ERR_INTERNAL;  // protocol invariant broken
        } else {
            *resp = w.resp;
        }
    }
    pthread_mutex_unlock(&c.mu);
    return rc;
}

// Fill a request with the id of a simple (destroy/pause/resume/inspect) op.
static void req_by_id(ipc_request_t* req, ipc_req_kind_t kind, uint32_t id) {
    ipc_request_init(req);
    req->kind = kind;
    req->sandbox_id = id;
}

sandbox_error_t sandbox_init(const char* socket_path) {
    if (!socket_path || !*socket_path) return SANDBOX_ERR_DAEMON_UNREACHABLE;
    sandbox_cleanup();  // drop a previous connection, reader included
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return SANDBOX_ERR_INTERNAL;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        close(fd);
        return SANDBOX_ERR_DAEMON_UNREACHABLE;
    }
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return SANDBOX_ERR_DAEMON_UNREACHABLE;
    }

    pthread_mutex_lock(&c.mu);
    c.fd = fd;
    c.dead = SANDBOX_OK;
    int gen = ++c.gen;
    if (pthread_create(&c.reader, NULL, client_reader, (void*)(intptr_t)gen) != 0) {
        close(fd);
        c.fd = -1;
        pthread_mutex_unlock(&c.mu);
        return SANDBOX_ERR_INTERNAL;
    }
    c.reader_started = true;
    pthread_mutex_unlock(&c.mu);
    return SANDBOX_OK;
}

sandbox_error_t sandbox_create(const sandbox_spec_t* spec,
                               sandbox_handle_t** out_handle) {
    if (out_handle) *out_handle = NULL;
    if (!spec || !out_handle) return SANDBOX_ERR_INVALID_SPEC;

    ipc_request_t req;
    ipc_request_init(&req);
    req.kind = IPC_REQ_CREATE;
    req.memory_mib = spec->memory_mib;
    req.vcpu_count = spec->vcpu_count;
    snprintf(req.template_name, sizeof(req.template_name), "%s",
             spec->template_name ? spec->template_name : "");
    req.pool_wait_ms = spec->pool_wait_ms;
    // #23: session workspace. Empty key keeps the ephemeral (pool) path.
    snprintf(req.session_key, sizeof(req.session_key), "%s",
             spec->session_key ? spec->session_key : "");
    req.ttl_seconds = spec->ttl_seconds;
    for (int i = 0; spec->env_vars && spec->env_vars[i] && i < IPC_MAX_ENV; i++) {
        req.env_vars[i] = strdup(spec->env_vars[i]);
        if (!req.env_vars[i]) break;
        req.n_env++;
    }

    ipc_response_t resp;
    sandbox_error_t rc = client_roundtrip(&req, &resp);
    ipc_request_clear(&req);
    if (rc != SANDBOX_OK) return rc;
    if (resp.is_error) return (sandbox_error_t)resp.error_code;

    sandbox_handle_t* h = calloc(1, sizeof(*h));
    if (!h) return SANDBOX_ERR_INTERNAL;
    h->sandbox_id = resp.sandbox_id;
    snprintf(h->token, sizeof(h->token), "%s", resp.session_token);
    *out_handle = h;
    return SANDBOX_OK;
}

static sandbox_error_t simple_op(sandbox_handle_t* handle, ipc_req_kind_t kind,
                                 ipc_response_t* out) {
    if (!handle) return SANDBOX_ERR_INVALID_SPEC;
    ipc_request_t req;
    req_by_id(&req, kind, handle->sandbox_id);
    ipc_response_t resp;
    sandbox_error_t rc = client_roundtrip(&req, &resp);
    if (rc != SANDBOX_OK) return rc;
    if (resp.is_error) return (sandbox_error_t)resp.error_code;
    if (out) *out = resp;
    return SANDBOX_OK;
}

sandbox_error_t sandbox_pause(sandbox_handle_t* handle) {
    return simple_op(handle, IPC_REQ_PAUSE, NULL);
}

sandbox_error_t sandbox_resume(sandbox_handle_t* handle) {
    return simple_op(handle, IPC_REQ_RESUME, NULL);
}

sandbox_error_t sandbox_destroy(sandbox_handle_t* handle) {
    if (!handle) return SANDBOX_ERR_INVALID_SPEC;
    sandbox_error_t rc = simple_op(handle, IPC_REQ_DESTROY, NULL);
    free(handle);
    return rc;
}

sandbox_error_t sandbox_inspect(sandbox_handle_t* handle,
                                sandbox_status_t* out_status) {
    if (!out_status) return SANDBOX_ERR_INVALID_SPEC;
    ipc_response_t resp;
    sandbox_error_t rc = simple_op(handle, IPC_REQ_INSPECT, &resp);
    if (rc != SANDBOX_OK) return rc;
    out_status->sandbox_id = resp.sandbox_id;
    out_status->is_running = resp.is_running;
    out_status->uptime_ms = resp.uptime_ms;
    out_status->memory_rss_mib = resp.memory_rss_mib;
    out_status->page_faults = resp.page_faults;
    return SANDBOX_OK;
}

sandbox_error_t sandbox_session_renew(const char* session_key,
                                      uint32_t extra_seconds,
                                      uint64_t* out_expires_at) {
    if (!session_key || !*session_key) return SANDBOX_ERR_INVALID_SPEC;
    ipc_request_t req;
    ipc_request_init(&req);
    req.kind = IPC_REQ_RENEW;
    snprintf(req.session_key, sizeof(req.session_key), "%s", session_key);
    req.extra_seconds = extra_seconds;

    ipc_response_t resp;
    sandbox_error_t rc = client_roundtrip(&req, &resp);
    ipc_request_clear(&req);
    if (rc != SANDBOX_OK) return rc;
    if (resp.is_error) return (sandbox_error_t)resp.error_code;
    if (out_expires_at) *out_expires_at = resp.expires_at;
    return SANDBOX_OK;
}

// ---------------------------------------------------------------------------
// Guest operations (#24)
// ---------------------------------------------------------------------------

// Run one guest request. On SANDBOX_OK `*resp` owns its buffers (the caller
// clears it); on any error it owns nothing.
static sandbox_error_t guest_call(sandbox_handle_t* handle, ipc_request_t* req,
                                  ipc_response_t* resp) {
    if (!handle) return SANDBOX_ERR_INVALID_SPEC;
    req->kind = IPC_REQ_GUEST;
    req->sandbox_id = handle->sandbox_id;
    sandbox_error_t rc = client_roundtrip(req, resp);
    if (rc != SANDBOX_OK) return rc;
    if (resp->is_error) {
        sandbox_error_t e = (sandbox_error_t)resp->error_code;
        ipc_response_clear(resp);
        return e;
    }
    return SANDBOX_OK;
}

static bool set_path(ipc_request_t* req, const char* path) {
    if (!path || strlen(path) >= sizeof(req->path)) return false;
    snprintf(req->path, sizeof(req->path), "%s", path);
    return true;
}

sandbox_error_t sandbox_exec(sandbox_handle_t* handle, const sandbox_exec_spec_t* spec,
                             sandbox_exec_result_t* out) {
    if (!out) return SANDBOX_ERR_INVALID_SPEC;
    memset(out, 0, sizeof(*out));
    if (!handle || !spec || !spec->argv || !spec->argv[0]) return SANDBOX_ERR_INVALID_SPEC;
    ipc_request_t req;
    ipc_request_init(&req);
    req.guest_op = 1;  // GRPC_OP_EXEC
    if (spec->cwd && !set_path(&req, spec->cwd)) return SANDBOX_ERR_INVALID_SPEC;
    for (int i = 0; spec->argv[i]; i++) {
        if (req.n_argv >= IPC_MAX_ARGV) { ipc_request_clear(&req); return SANDBOX_ERR_INVALID_SPEC; }
        req.argv[req.n_argv] = strdup(spec->argv[i]);
        if (!req.argv[req.n_argv]) { ipc_request_clear(&req); return SANDBOX_ERR_INTERNAL; }
        req.n_argv++;
    }
    for (int i = 0; spec->env && spec->env[i]; i++) {
        if (req.n_env >= IPC_MAX_ENV) { ipc_request_clear(&req); return SANDBOX_ERR_INVALID_SPEC; }
        req.env_vars[req.n_env] = strdup(spec->env[i]);
        if (!req.env_vars[req.n_env]) { ipc_request_clear(&req); return SANDBOX_ERR_INTERNAL; }
        req.n_env++;
    }
    if (spec->stdin_len) {
        req.data = malloc(spec->stdin_len);
        if (!req.data) { ipc_request_clear(&req); return SANDBOX_ERR_INTERNAL; }
        memcpy(req.data, spec->stdin_data, spec->stdin_len);
        req.data_len = spec->stdin_len;
    }
    req.timeout_ms = spec->timeout_ms;
    req.max_output = spec->max_output;
    req.guest_flags = spec->shell ? IPC_GF_SHELL : 0;

    ipc_response_t resp;
    sandbox_error_t rc = guest_call(handle, &req, &resp);
    ipc_request_clear(&req);
    if (rc != SANDBOX_OK) return rc;
    out->exit_code = resp.exit_code;
    out->term_signal = resp.term_signal;
    out->timed_out = resp.timed_out;
    out->output_truncated = resp.output_truncated;
    out->out = resp.out; out->out_len = resp.out_len; out->out_total = resp.out_total;
    out->err = resp.err; out->err_len = resp.err_len; out->err_total = resp.err_total;
    resp.out = resp.err = NULL;  // moved into `out`
    ipc_response_clear(&resp);
    return SANDBOX_OK;
}

void sandbox_exec_result_free(sandbox_exec_result_t* r) {
    if (!r) return;
    free(r->out);
    free(r->err);
    memset(r, 0, sizeof(*r));
}

sandbox_error_t sandbox_read_file(sandbox_handle_t* handle, const char* path,
                                  uint8_t** out_data, size_t* out_len) {
    if (out_data) *out_data = NULL;
    if (out_len) *out_len = 0;
    if (!handle || !path || !out_data || !out_len) return SANDBOX_ERR_INVALID_SPEC;
    uint8_t* buf = NULL;
    size_t have = 0;
    for (;;) {
        ipc_request_t req;
        ipc_request_init(&req);
        req.guest_op = 2;  // GRPC_OP_READ_FILE
        if (!set_path(&req, path)) { free(buf); return SANDBOX_ERR_INVALID_SPEC; }
        req.offset = have;
        req.max_bytes = IPC_GUEST_CHUNK;
        ipc_response_t resp;
        sandbox_error_t rc = guest_call(handle, &req, &resp);
        ipc_request_clear(&req);
        if (rc != SANDBOX_OK) { free(buf); return rc; }
        if (have + resp.out_len > SANDBOX_MAX_FILE) {
            ipc_response_clear(&resp);
            free(buf);
            return SANDBOX_ERR_TOO_LARGE;
        }
        uint8_t* nb = realloc(buf, have + resp.out_len + 1);
        if (!nb) { ipc_response_clear(&resp); free(buf); return SANDBOX_ERR_INTERNAL; }
        buf = nb;
        if (resp.out_len) memcpy(buf + have, resp.out, resp.out_len);
        have += resp.out_len;
        bool more = resp.truncated && resp.out_len > 0;
        ipc_response_clear(&resp);
        if (!more) break;
    }
    *out_data = buf;
    *out_len = have;
    return SANDBOX_OK;
}

sandbox_error_t sandbox_write_file(sandbox_handle_t* handle, const char* path,
                                   const uint8_t* data, size_t len, uint32_t mode,
                                   uint32_t flags) {
    if (!handle || !path || (len && !data)) return SANDBOX_ERR_INVALID_SPEC;
    if (len > SANDBOX_MAX_FILE) return SANDBOX_ERR_TOO_LARGE;
    size_t off = 0;
    bool first = true;
    do {
        size_t n = len - off < IPC_GUEST_CHUNK ? len - off : IPC_GUEST_CHUNK;
        ipc_request_t req;
        ipc_request_init(&req);
        req.guest_op = 3;  // GRPC_OP_WRITE_FILE
        if (!set_path(&req, path)) return SANDBOX_ERR_INVALID_SPEC;
        req.mode = mode;
        if (n) {
            req.data = malloc(n);
            if (!req.data) return SANDBOX_ERR_INTERNAL;
            memcpy(req.data, data + off, n);
            req.data_len = n;
        }
        // Later chunks append; EXCL only guards the first, which creates it.
        bool append = (flags & SANDBOX_WRITE_APPEND) || !first;
        req.guest_flags = (append ? IPC_GF_APPEND : 0) |
                          ((flags & SANDBOX_WRITE_EXCL) && first ? IPC_GF_EXCL : 0) |
                          ((flags & SANDBOX_WRITE_PARENTS) ? IPC_GF_PARENTS : 0);
        ipc_response_t resp;
        sandbox_error_t rc = guest_call(handle, &req, &resp);
        ipc_request_clear(&req);
        if (rc != SANDBOX_OK) return rc;
        ipc_response_clear(&resp);
        off += n;
        first = false;
    } while (off < len);
    return SANDBOX_OK;
}

sandbox_error_t sandbox_list_dir(sandbox_handle_t* handle, const char* path,
                                 sandbox_dirent_t** out_entries, size_t* out_count,
                                 bool* out_truncated) {
    if (out_entries) *out_entries = NULL;
    if (out_count) *out_count = 0;
    if (out_truncated) *out_truncated = false;
    if (!handle || !path || !out_entries || !out_count) return SANDBOX_ERR_INVALID_SPEC;
    ipc_request_t req;
    ipc_request_init(&req);
    req.guest_op = 4;  // GRPC_OP_LIST_DIR
    if (!set_path(&req, path)) return SANDBOX_ERR_INVALID_SPEC;
    ipc_response_t resp;
    sandbox_error_t rc = guest_call(handle, &req, &resp);
    ipc_request_clear(&req);
    if (rc != SANDBOX_OK) return rc;
    sandbox_dirent_t* e = calloc(resp.n_entries ? resp.n_entries : 1, sizeof(*e));
    if (!e) { ipc_response_clear(&resp); return SANDBOX_ERR_INTERNAL; }
    for (size_t i = 0; i < resp.n_entries; i++) {
        memcpy(e[i].name, resp.entries[i].name, sizeof(e[i].name));
        e[i].type = resp.entries[i].type;
        e[i].size = resp.entries[i].size;
        e[i].mtime = resp.entries[i].mtime;
    }
    *out_entries = e;
    *out_count = resp.n_entries;
    if (out_truncated) *out_truncated = resp.truncated;
    ipc_response_clear(&resp);
    return SANDBOX_OK;
}

sandbox_error_t sandbox_stat(sandbox_handle_t* handle, const char* path,
                             sandbox_fstat_t* out) {
    if (!handle || !path || !out) return SANDBOX_ERR_INVALID_SPEC;
    ipc_request_t req;
    ipc_request_init(&req);
    req.guest_op = 5;  // GRPC_OP_STAT
    if (!set_path(&req, path)) return SANDBOX_ERR_INVALID_SPEC;
    ipc_response_t resp;
    sandbox_error_t rc = guest_call(handle, &req, &resp);
    ipc_request_clear(&req);
    if (rc != SANDBOX_OK) return rc;
    out->type = (uint8_t)resp.ftype;
    out->size = resp.size;
    out->mode = resp.fmode;
    out->mtime = resp.mtime;
    ipc_response_clear(&resp);
    return SANDBOX_OK;
}

sandbox_error_t sandbox_mkdir(sandbox_handle_t* handle, const char* path,
                              uint32_t mode, bool parents) {
    if (!handle || !path) return SANDBOX_ERR_INVALID_SPEC;
    ipc_request_t req;
    ipc_request_init(&req);
    req.guest_op = 6;  // GRPC_OP_MKDIR
    if (!set_path(&req, path)) return SANDBOX_ERR_INVALID_SPEC;
    req.mode = mode;
    req.guest_flags = parents ? IPC_GF_PARENTS : 0;
    ipc_response_t resp;
    sandbox_error_t rc = guest_call(handle, &req, &resp);
    ipc_request_clear(&req);
    if (rc == SANDBOX_OK) ipc_response_clear(&resp);
    return rc;
}

sandbox_error_t sandbox_remove(sandbox_handle_t* handle, const char* path,
                               bool recursive) {
    if (!handle || !path) return SANDBOX_ERR_INVALID_SPEC;
    ipc_request_t req;
    ipc_request_init(&req);
    req.guest_op = 7;  // GRPC_OP_REMOVE
    if (!set_path(&req, path)) return SANDBOX_ERR_INVALID_SPEC;
    req.guest_flags = recursive ? IPC_GF_RECURSIVE : 0;
    ipc_response_t resp;
    sandbox_error_t rc = guest_call(handle, &req, &resp);
    ipc_request_clear(&req);
    if (rc == SANDBOX_OK) ipc_response_clear(&resp);
    return rc;
}

void sandbox_cleanup(void) {
    pthread_t reader;
    bool join = false;
    pthread_mutex_lock(&c.mu);
    if (c.fd >= 0) {
        int fd = c.fd;
        c.fd = -1;
        c.gen++;  // orphan the reader: anything it still reads is not ours
        client_fail(SANDBOX_ERR_DAEMON_UNREACHABLE);
        shutdown(fd, SHUT_RDWR);  // wakes a reader blocked in recv
        close(fd);
        join = c.reader_started;
        reader = c.reader;
        c.reader_started = false;
    }
    pthread_mutex_unlock(&c.mu);
    // Join outside the lock: the reader needs it to finish.
    if (join) pthread_join(reader, NULL);
}

sandbox_handle_t* lifecycle_test_handle(uint32_t sandbox_id) {
    sandbox_handle_t* h = calloc(1, sizeof(*h));
    if (h) h->sandbox_id = sandbox_id;
    return h;
}

const char* sandbox_handle_token(const sandbox_handle_t* handle) {
    return handle ? handle->token : NULL;
}

const char* sandbox_error_string(sandbox_error_t code) {
    switch (code) {
        case SANDBOX_OK: return "ok";
        case SANDBOX_ERR_POOL_EXHAUSTED: return "pool exhausted";
        case SANDBOX_ERR_INVALID_SPEC: return "invalid spec";
        case SANDBOX_ERR_DAEMON_UNREACHABLE: return "daemon unreachable";
        case SANDBOX_ERR_PERMISSION_DENIED: return "permission denied";
        case SANDBOX_ERR_INTERNAL: return "internal error";
        case SANDBOX_ERR_SESSION_EXPIRED: return "session expired";
        case SANDBOX_ERR_SESSION_LIMIT: return "session at platform maximum lifetime";
        case SANDBOX_ERR_SESSION_UNKNOWN: return "unknown session";
        case SANDBOX_ERR_GUEST_UNAVAILABLE: return "guest agent unavailable";
        case SANDBOX_ERR_PATH_DENIED: return "path denied";
        case SANDBOX_ERR_NOT_FOUND: return "not found";
        case SANDBOX_ERR_EXISTS: return "already exists";
        case SANDBOX_ERR_TOO_LARGE: return "too large";
        case SANDBOX_ERR_GUEST_IO: return "guest I/O error";
        case SANDBOX_ERR_TIMEOUT: return "timed out";
        default: return "unknown error";
    }
}
