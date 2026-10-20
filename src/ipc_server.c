// SPDX-License-Identifier: GPL-2.0-only
// Engine IPC server (§2.3) + engine-side session-token authority (§5.8).
//
// SOCK_SEQPACKET Unix socket, length-prefixed protobuf. One persistent
// connection per client session (epoll loop). A session owns every sandbox it
// created; disconnecting reclaims them. Creating a sandbox also mints a
// 256-bit session token recorded in a process-wide registry that the
// broker-control thread (see below) validates for the credential broker.
//
// Single-threaded event loop: a Create blocks the loop for the duration of the
// pool restore (~100 ms warm-slow / ~1 s cold). Acceptable at this scale; see
// SYSTEM DESIGN.md §15.9.

#define _GNU_SOURCE

#include "ipc_server.h"

#include "broker.h"       // broker-control wire constants (§5.8)
#include "ipc_codec.h"
#include "ipc_internal.h"
#include "lifecycle.h"
#include "log.h"
#include "pool_manager.h"
#include "telemetry.h"
#include "vmm_manager.h"
#include "workspace.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define IPC_MAX_SESSIONS 64
#define IPC_MAX_OWNED 128
#define IPC_MAX_PIDFDS 256
#define IPC_MAX_ALLOWED_UIDS 64
#define TOKEN_MAX_SERVICES 64

// §10.8 async Create: the epoll loop must never block on a pool restore.
// Create requests are copied into a job, handed to a small worker pool, and the
// loop completes them from the result queue on an eventfd wakeup. Per-session
// serialization (one dispatched job at a time, FIFO) preserves response order.
#define IPC_CREATE_WORKERS 4
#define IPC_CREATE_QUEUE_MAX 16  // outstanding creates per session
#define IPC_CREATE_UID_MAX 64    // outstanding creates per peer uid

// epoll data.u64 tag: low byte = kind, upper bits = payload (fd or table index).
enum { EP_LISTEN = 1, EP_WAKE = 2, EP_CLIENT = 3, EP_PIDFD = 4 };

// One in-flight (or queued) Create. Copied off the wire request so the loop can
// return to epoll immediately; env values are strdup'd (the request is cleared).
typedef struct create_job {
    int session_fd;
    uint64_t session_epoch;
    uid_t uid;
    uint64_t memory_mib;
    uint32_t vcpu_count;
    uint32_t pool_wait_ms;
    char template_name[IPC_MAX_TEMPLATE];
    // #23: empty = ephemeral workspace (warm-pool path). Non-empty = persistent
    // session volume, which forces a dedicated restore (see create_worker_fn).
    char session_key[IPC_MAX_SESSION_KEY];
    uint32_t ttl_seconds;
    char* env[IPC_MAX_ENV + 1];  // NULL-terminated
    struct create_job* next;
} create_job_t;

// A finished job, posted by a worker and consumed by the loop thread.
typedef struct create_result {
    create_job_t* job;
    sandbox_error_t code;   // SANDBOX_OK on success
    vm_handle_t* vm;        // owned by the loop thread on receipt
    char token[IPC_TOKEN_HEX_LEN + 1];
    struct create_result* next;
} create_result_t;

typedef struct {
    int fd;
    uid_t uid;  // peer uid from SO_PEERCRED (Phase 10.1); for logging/quotas
    uint64_t epoch;  // distinguishes reused fd slots across disconnects
    uint32_t owned[IPC_MAX_OWNED];
    int n_owned;

    // §10.8: per-session Create FIFO. cq_head is only dispatched when the
    // previous job's result has been consumed (cq_active), so a single session's
    // responses stay in request order.
    create_job_t* cq_head;
    create_job_t* cq_tail;
    int n_outstanding;  // queued + active
    bool cq_active;
} session_t;

typedef struct token_entry {
    uint8_t token[32];
    uint32_t sandbox_id;
    char* services[TOKEN_MAX_SERVICES + 1];  // NULL-terminated
    struct token_entry* next;
} token_entry_t;

static struct {
    pool_manager_t* pool;
    char template_name[IPC_MAX_TEMPLATE];
    char* allowed[TOKEN_MAX_SERVICES + 1];
    int n_allowed;

    // Phase 10.1: SO_PEERCRED allowlist. Empty => any peer uid is accepted
    // (backward compatible; a warning is logged at startup). Non-empty => only
    // the listed uids may connect.
    uid_t allowed_uids[IPC_MAX_ALLOWED_UIDS];
    int n_allowed_uids;

    // Phase 11: default pool_wait_ms applied when a CreateRequest sends 0.
    uint32_t default_pool_wait_ms;

    int listen_fd;
    int epfd;
    int wake_fd;
    volatile sig_atomic_t running;

    int bc_listen_fd;
    int bc_wake_fd;
    pthread_t bc_thread;
    volatile sig_atomic_t bc_running;
    bool bc_started;
    char bc_path[108];

    session_t sessions[IPC_MAX_SESSIONS];

    // pidfd -> sandbox tracking for VMM crash detection (§4.2). Only handed-out
    // VMs are tracked; warm-pool VMs are only destroyed internally.
    struct {
        int pidfd;
        int session_fd;
        uint32_t sandbox_id;
    } vms[IPC_MAX_PIDFDS];

    pthread_mutex_t tok_lock;
    token_entry_t* tokens;

    // §10.8 async Create machinery.
    pthread_mutex_t q_lock;
    pthread_cond_t q_cond;
    create_job_t* q_head;
    create_job_t* q_tail;
    int q_len;
    bool q_stop;
    pthread_mutex_t r_lock;
    create_result_t* r_head;
    create_result_t* r_tail;
    pthread_t workers[IPC_CREATE_WORKERS];
    int n_workers;
    int create_workers_cfg;   // desired worker count (default IPC_CREATE_WORKERS)
    int per_session_max;      // default IPC_CREATE_QUEUE_MAX
    int per_uid_max;          // default IPC_CREATE_UID_MAX
    uint64_t session_epoch;   // bumped per accepted connection
    struct { uid_t uid; int n; } uid_inflight[IPC_MAX_ALLOWED_UIDS];
} g = { .listen_fd = -1, .epfd = -1, .wake_fd = -1, .bc_listen_fd = -1,
        .bc_wake_fd = -1, .tok_lock = PTHREAD_MUTEX_INITIALIZER,
        .q_lock = PTHREAD_MUTEX_INITIALIZER,
        .q_cond = PTHREAD_COND_INITIALIZER,
        .r_lock = PTHREAD_MUTEX_INITIALIZER,
        .create_workers_cfg = IPC_CREATE_WORKERS,
        .per_session_max = IPC_CREATE_QUEUE_MAX,
        .per_uid_max = IPC_CREATE_UID_MAX };

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int read_full(int fd, void* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, (char*)buf + off, n - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

static int write_full(int fd, const void* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, (const char*)buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static uint64_t read_rss_mib(int pid) {
    if (pid <= 0) return 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    char line[256];
    uint64_t kib = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%lu", &kib);
            break;
        }
    }
    fclose(f);
    return kib / 1024;
}

// ---------------------------------------------------------------------------
// Phase 10.1: peer-uid allowlist (SO_PEERCRED). An empty list accepts any uid
// (logged at startup); otherwise only listed uids may open a session.
// ---------------------------------------------------------------------------

static bool uid_allowed(uid_t uid) {
    if (g.n_allowed_uids == 0) return true;
    for (int i = 0; i < g.n_allowed_uids; i++) {
        if (g.allowed_uids[i] == uid) return true;
    }
    return false;
}

// Phase 10.5: names that flow into tap device names or filesystem paths must be
// constrained to [A-Za-z0-9_-] (max 20) so they cannot carry shell
// metacharacters into network_manager's nft commands or leak path traversal.
static bool valid_name(const char* s) {
    if (!s || !*s) return false;
    size_t n = 0;
    for (; s[n]; n++) {
        char c = s[n];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-')) {
            return false;
        }
    }
    return n <= 20;
}

// ---------------------------------------------------------------------------
// session token registry (shared by the IPC loop and the broker-control thread)
// ---------------------------------------------------------------------------

static void token_free_locked(token_entry_t* e) {
    for (int i = 0; e->services[i]; i++) free(e->services[i]);
    free(e);
}

static token_entry_t* token_find_locked(const uint8_t token[32]) {
    for (token_entry_t* e = g.tokens; e; e = e->next) {
        if (memcmp(e->token, token, 32) == 0) return e;
    }
    return NULL;
}

static void hex_encode(const uint8_t* in, size_t n, char* out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hx[in[i] >> 4];
        out[2 * i + 1] = hx[in[i] & 0xf];
    }
    out[2 * n] = '\0';
}

// Mint a token for sandbox_id; writes 64 lowercase hex chars to out_hex.
// Returns 0 on success.
static int token_issue(uint32_t sandbox_id, char out_hex[IPC_TOKEN_HEX_LEN + 1]) {
    token_entry_t* e = calloc(1, sizeof(*e));
    if (!e) return -1;
    if (getrandom(e->token, sizeof(e->token), 0) != (ssize_t)sizeof(e->token)) {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0 || read_full(fd, e->token, sizeof(e->token)) < 0) {
            if (fd >= 0) close(fd);
            free(e);
            return -1;
        }
        close(fd);
    }
    e->sandbox_id = sandbox_id;
    pthread_mutex_lock(&g.tok_lock);
    for (int i = 0; i < g.n_allowed; i++) e->services[i] = strdup(g.allowed[i]);
    e->next = g.tokens;
    g.tokens = e;
    pthread_mutex_unlock(&g.tok_lock);
    hex_encode(e->token, sizeof(e->token), out_hex);
    return 0;
}

static void token_revoke(uint32_t sandbox_id) {
    pthread_mutex_lock(&g.tok_lock);
    token_entry_t** pp = &g.tokens;
    while (*pp) {
        token_entry_t* e = *pp;
        if (e->sandbox_id == sandbox_id) {
            *pp = e->next;
            token_free_locked(e);
        } else {
            pp = &e->next;
        }
    }
    pthread_mutex_unlock(&g.tok_lock);
}

int ipc_server_token_count(void) {
    int n = 0;
    pthread_mutex_lock(&g.tok_lock);
    for (token_entry_t* e = g.tokens; e; e = e->next) n++;
    pthread_mutex_unlock(&g.tok_lock);
    return n;
}

// ---------------------------------------------------------------------------
// session table (touched only by the IPC loop thread)
// ---------------------------------------------------------------------------

static session_t* session_find(int fd) {
    for (int i = 0; i < IPC_MAX_SESSIONS; i++) {
        if (g.sessions[i].fd == fd) return &g.sessions[i];
    }
    return NULL;
}

static session_t* session_alloc(int fd) {
    for (int i = 0; i < IPC_MAX_SESSIONS; i++) {
        if (g.sessions[i].fd < 0) {
            memset(&g.sessions[i], 0, sizeof(g.sessions[i]));
            g.sessions[i].fd = fd;
            g.sessions[i].epoch = ++g.session_epoch;
            return &g.sessions[i];
        }
    }
    return NULL;
}

// §10.8 per-uid outstanding-create accounting (loop-thread only).
static int uid_inflight_get(uid_t uid) {
    for (int i = 0; i < IPC_MAX_ALLOWED_UIDS; i++) {
        if (g.uid_inflight[i].n && g.uid_inflight[i].uid == uid)
            return g.uid_inflight[i].n;
    }
    return 0;
}

static void uid_inflight_add(uid_t uid, int delta) {
    for (int i = 0; i < IPC_MAX_ALLOWED_UIDS; i++) {
        if (g.uid_inflight[i].n && g.uid_inflight[i].uid == uid) {
            g.uid_inflight[i].n += delta;
            if (g.uid_inflight[i].n <= 0) {
                g.uid_inflight[i].n = 0;
                g.uid_inflight[i].uid = 0;
            }
            return;
        }
    }
    if (delta <= 0) return;
    for (int i = 0; i < IPC_MAX_ALLOWED_UIDS; i++) {
        if (g.uid_inflight[i].n == 0) {
            g.uid_inflight[i].uid = uid;
            g.uid_inflight[i].n = delta;
            return;
        }
    }
}

static bool session_owns(const session_t* s, uint32_t id) {
    for (int i = 0; i < s->n_owned; i++) {
        if (s->owned[i] == id) return true;
    }
    return false;
}

static void session_own(session_t* s, uint32_t id) {
    if (s->n_owned < IPC_MAX_OWNED) s->owned[s->n_owned++] = id;
}

static void session_disown(session_t* s, uint32_t id) {
    for (int i = 0; i < s->n_owned; i++) {
        if (s->owned[i] == id) {
            s->owned[i] = s->owned[--s->n_owned];
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// pidfd crash tracking (§4.2). pidfd_open() + epoll lets the event loop notice
// a VMM dying (crash or seccomp SIGSYS) without polling. Only the IPC loop
// thread touches this table.
// ---------------------------------------------------------------------------

static int pidfd_track(pid_t pid, int session_fd, uint32_t sandbox_id) {
    if (pid <= 0 || g.epfd < 0) return -1;
    int idx = -1;
    for (int i = 0; i < IPC_MAX_PIDFDS; i++) {
        if (g.vms[i].pidfd < 0) { idx = i; break; }
    }
    if (idx < 0) return -1;
    int pfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pfd < 0) return -1;
    int fl = fcntl(pfd, F_GETFD);
    if (fl >= 0) fcntl(pfd, F_SETFD, fl | FD_CLOEXEC);
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.u64 = ((uint64_t)idx << 8) | EP_PIDFD;
    if (epoll_ctl(g.epfd, EPOLL_CTL_ADD, pfd, &ev) < 0) {
        close(pfd);
        return -1;
    }
    g.vms[idx].pidfd = pfd;
    g.vms[idx].session_fd = session_fd;
    g.vms[idx].sandbox_id = sandbox_id;
    return 0;
}

// Stop watching a sandbox's VMM (normal destroy path). Safe if untracked.
static void pidfd_untrack(uint32_t sandbox_id) {
    for (int i = 0; i < IPC_MAX_PIDFDS; i++) {
        if (g.vms[i].pidfd >= 0 && g.vms[i].sandbox_id == sandbox_id) {
            if (g.epfd >= 0) epoll_ctl(g.epfd, EPOLL_CTL_DEL, g.vms[i].pidfd, NULL);
            close(g.vms[i].pidfd);
            g.vms[i].pidfd = -1;
            g.vms[i].session_fd = -1;
            g.vms[i].sandbox_id = 0;
        }
    }
}

// The VMM exited: reap it, bump the crash metric, and reclaim engine-side
// state so a later inspect/destroy reports the sandbox is gone.
static void pidfd_handle(int idx) {
    if (idx < 0 || idx >= IPC_MAX_PIDFDS || g.vms[idx].pidfd < 0) return;
    int pfd = g.vms[idx].pidfd;
    int sfd = g.vms[idx].session_fd;
    uint32_t id = g.vms[idx].sandbox_id;

    // Reap the dead child (idempotent w.r.t. vmm_destroy's own waitpid).
    siginfo_t si;
    while (waitid(P_PIDFD, (id_t)pfd, &si, WEXITED | WNOHANG) < 0 &&
           errno == EINTR) {
    }
    epoll_ctl(g.epfd, EPOLL_CTL_DEL, pfd, NULL);
    close(pfd);
    g.vms[idx].pidfd = -1;
    g.vms[idx].session_fd = -1;
    g.vms[idx].sandbox_id = 0;

    telemetry_vmm_crash();
    LOGF(LOG_WARN, "ipc_server", "vmm_crash", "\"sandbox_id\":%u", id);

    vm_handle_t* vm = lifecycle_get(id);
    if (vm) {
        vmm_destroy(vm);
        lifecycle_remove(id);
    }
    token_revoke(id);
    session_t* s = session_find(sfd);
    if (s) session_disown(s, id);
}

// ---------------------------------------------------------------------------
// message handling
// ---------------------------------------------------------------------------

static void send_response(int fd, const ipc_response_t* resp) {
    uint8_t buf[IPC_FRAME_MAX];
    size_t n = 0;
    if (ipc_encode_response(resp, buf, sizeof(buf), &n) < 0) {
        fprintf(stderr, "[ipc] failed to encode response\n");
        return;
    }
    if (ipc_send_frame(fd, buf, n) < 0) {
        fprintf(stderr, "[ipc] failed to send response: %s\n", strerror(errno));
    }
}

static void reply_error(int fd, sandbox_error_t code, const char* msg) {
    ipc_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.is_error = true;
    resp.error_code = code;
    snprintf(resp.error_message, sizeof(resp.error_message), "%s", msg ? msg : "");
    send_response(fd, &resp);
}

// ---------------------------------------------------------------------------
// §10.8 async Create: job/result queues + worker pool
// ---------------------------------------------------------------------------

static void free_job(create_job_t* j) {
    if (!j) return;
    for (int i = 0; j->env[i]; i++) free(j->env[i]);
    free(j);
}

static create_job_t* build_job(const ipc_request_t* req, session_t* s) {
    create_job_t* j = calloc(1, sizeof(*j));
    if (!j) return NULL;
    j->session_fd = s->fd;
    j->session_epoch = s->epoch;
    j->uid = s->uid;
    j->memory_mib = req->memory_mib ? req->memory_mib : 128;
    j->vcpu_count = req->vcpu_count ? req->vcpu_count : 1;
    j->pool_wait_ms = req->pool_wait_ms ? req->pool_wait_ms
                                        : g.default_pool_wait_ms;
    snprintf(j->template_name, sizeof(j->template_name), "%s", g.template_name);
    // #23
    snprintf(j->session_key, sizeof(j->session_key), "%s", req->session_key);
    j->ttl_seconds = req->ttl_seconds;
    int n = 0;
    for (int i = 0; i < req->n_env && i < IPC_MAX_ENV; i++) {
        if (!req->env_vars[i]) break;
        j->env[n] = strdup(req->env_vars[i]);
        if (!j->env[n]) { free_job(j); return NULL; }
        n++;
    }
    j->env[n] = NULL;
    return j;
}

// #23: create with a persistent session workspace. Deliberately not the pool
// path: a warm VM's workspace is bound before the request arrives, and
// Firecracker cannot swap a block device after restore, so the volume has to be
// decided (and cloned) first. Costs one restore, measured well inside budget.
static sandbox_error_t session_provision(const create_job_t* job,
                                         vm_handle_t** out_vm) {
    *out_vm = NULL;
    char base[PATH_MAX];
    workspace_base_path(g.template_name, base, sizeof(base));
    struct stat st;
    if (stat(base, &st) < 0) {
        fprintf(stderr, "[ipc_server] template %s has no workspace base image (%s); "
                        "rebuild the template to use session_key\n",
                g.template_name, base);
        return SANDBOX_ERR_INVALID_SPEC;
    }

    // One VM per session volume: two would write the same blocks through
    // separate page caches and destroy each other's files. Take the lease before
    // touching the image; vmm_destroy releases it.
    if (workspace_lease(job->session_key) < 0) {
        fprintf(stderr, "[ipc_server] session %s is already in use (errno=%d)\n",
                job->session_key, errno);
        return SANDBOX_ERR_INVALID_SPEC;
    }

    workspace_meta_t meta;
    if (workspace_ensure(job->session_key, job->uid, 0, job->ttl_seconds, base,
                         &meta) < 0) {
        fprintf(stderr, "[ipc_server] cannot prepare workspace for session %s: %s\n",
                job->session_key, strerror(errno));
        workspace_release(job->session_key);
        return SANDBOX_ERR_INTERNAL;
    }
    fprintf(stderr,
            "[ipc_server] session %s volume %s owner=%u ttl=%llds expires=%lld\n",
            job->session_key, meta.id, (unsigned)meta.owner_uid,
            (long long)(meta.expires_at - meta.created_at),
            (long long)meta.expires_at);

    char image[PATH_MAX];
    workspace_paths(job->session_key, NULL, 0, image, sizeof(image));
    vm_handle_t* vm = restore_vm_with_workspace(image);
    if (!vm) {
        workspace_release(job->session_key);
        return SANDBOX_ERR_POOL_EXHAUSTED;
    }
    snprintf(vm->session_key, sizeof(vm->session_key), "%s", job->session_key);
    *out_vm = vm;
    return SANDBOX_OK;
}

// A pool restore + env inject + token mint. Runs off the epoll loop; the only
// shared mutation is the token registry (token_lock) and the result queue.
static void* create_worker_fn(void* arg) {    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g.q_lock);
        while (!g.q_stop && !g.q_head)
            pthread_cond_wait(&g.q_cond, &g.q_lock);
        if (g.q_stop && !g.q_head) {
            pthread_mutex_unlock(&g.q_lock);
            break;
        }
        create_job_t* job = g.q_head;
        g.q_head = job->next;
        if (!g.q_head) g.q_tail = NULL;
        g.q_len--;
        pthread_mutex_unlock(&g.q_lock);

        create_result_t* r = calloc(1, sizeof(*r));
        if (!r) { free_job(job); continue; }  // OOM: drop the request
        r->job = job;
        r->code = SANDBOX_ERR_INTERNAL;

        sandbox_spec_t spec;
        memset(&spec, 0, sizeof(spec));
        spec.memory_mib = job->memory_mib;
        spec.vcpu_count = job->vcpu_count;
        spec.template_name = job->template_name;
        spec.env_vars = (const char**)job->env;
        spec.pool_wait_ms = job->pool_wait_ms;

        uint64_t t0 = now_ms();
        vm_handle_t* vm = NULL;
        sandbox_error_t err;
        if (job->session_key[0]) {
            // #23: a session-backed create needs its workspace bound *before*
            // Firecracker loads the snapshot, so it cannot be served from the
            // warm pool (a pool member's volume is already mounted). Clone the
            // session's volume, then restore directly. Costs a restore, not a
            // wait: still ~50 ms against a 250 ms budget.
            err = session_provision(job, &vm);
        } else {
            err = pool_provision(g.pool, &spec, &vm);
        }
        telemetry_provision_latency(now_ms() - t0);
        if (err != SANDBOX_OK || !vm) {
            r->code = (err != SANDBOX_OK) ? err : SANDBOX_ERR_INTERNAL;
            telemetry_pool_exhausted();
        } else {
            if (job->env[0]) {
                if (vmm_inject_env(vm, (const char* const*)job->env) == 0) {
                    LOGF(LOG_DEBUG, "ipc_server", "env_injected",
                         "\"sandbox_id\":%u", vm->sandbox_id);
                } else {
                    LOGF(LOG_WARN, "ipc_server", "env_inject_failed",
                         "\"sandbox_id\":%u", vm->sandbox_id);
                }
            }
            if (token_issue(vm->sandbox_id, r->token) < 0) {
                r->code = SANDBOX_ERR_INTERNAL;  // loop destroys vm
                r->vm = vm;
            } else {
                r->code = SANDBOX_OK;
                r->vm = vm;
            }
        }

        pthread_mutex_lock(&g.r_lock);
        if (g.r_tail) g.r_tail->next = r;
        else g.r_head = r;
        g.r_tail = r;
        pthread_mutex_unlock(&g.r_lock);
        uint64_t one = 1;
        ssize_t w = write(g.wake_fd, &one, sizeof(one));
        (void)w;
    }
    return NULL;
}

// Hand the head of a session's Create FIFO to the worker pool (loop thread).
static void dispatch_cq_head(session_t* s) {
    create_job_t* j = s->cq_head;
    if (!j) { s->cq_active = false; return; }
    s->cq_head = j->next;
    if (!s->cq_head) s->cq_tail = NULL;
    j->next = NULL;
    s->cq_active = true;
    pthread_mutex_lock(&g.q_lock);
    if (g.q_tail) g.q_tail->next = j;
    else g.q_head = j;
    g.q_tail = j;
    g.q_len++;
    pthread_cond_signal(&g.q_cond);
    pthread_mutex_unlock(&g.q_lock);
}

// Validate and enqueue a Create. Replies immediately only on rejection.
static void submit_create(int fd, session_t* s, const ipc_request_t* req) {
    if (req->template_name[0] && !valid_name(req->template_name)) {
        reply_error(fd, SANDBOX_ERR_INVALID_SPEC, "invalid template name");
        return;
    }
    if (g.template_name[0] && req->template_name[0] &&
        strcmp(req->template_name, g.template_name) != 0) {
        reply_error(fd, SANDBOX_ERR_INVALID_SPEC, "unknown template");
        return;
    }
    if (!g.pool) {
        reply_error(fd, SANDBOX_ERR_INTERNAL, "pool not configured");
        return;
    }
    // §10.8 rate limiting: bound outstanding creates per session and per uid.
    if (s->n_outstanding >= g.per_session_max) {
        reply_error(fd, SANDBOX_ERR_POOL_EXHAUSTED, "too many concurrent creates");
        return;
    }
    if (uid_inflight_get(s->uid) >= g.per_uid_max) {
        reply_error(fd, SANDBOX_ERR_POOL_EXHAUSTED, "uid create limit reached");
        return;
    }
    create_job_t* j = build_job(req, s);
    if (!j) {
        reply_error(fd, SANDBOX_ERR_INTERNAL, "out of memory");
        return;
    }
    if (s->cq_tail) s->cq_tail->next = j;
    else s->cq_head = j;
    s->cq_tail = j;
    s->n_outstanding++;
    uid_inflight_add(s->uid, +1);
    if (!s->cq_active) dispatch_cq_head(s);
}

// Consume a finished job (loop thread): track + reply + dispatch the next.
static void complete_result(create_result_t* r) {
    create_job_t* job = r->job;
    session_t* s = session_find(job->session_fd);
    if (s && s->epoch != job->session_epoch) s = NULL;  // fd was reused
    uid_inflight_add(job->uid, -1);

    if (!s) {
        // Client disconnected while the create was in flight: reclaim.
        if (r->vm) {
            if (r->code == SANDBOX_OK) token_revoke(r->vm->sandbox_id);
            vmm_destroy(r->vm);
        }
        free_job(job);
        return;
    }

    s->cq_active = false;
    if (s->n_outstanding > 0) s->n_outstanding--;

    if (r->code != SANDBOX_OK || !r->vm) {
        if (r->vm) vmm_destroy(r->vm);
        reply_error(s->fd, r->code != SANDBOX_OK ? r->code : SANDBOX_ERR_INTERNAL,
                    "pool provision failed");
    } else {
        vm_handle_t* vm = r->vm;
        lifecycle_track(vm);
        session_own(s, vm->sandbox_id);
        if (pidfd_track(vm->vmm_pid, s->fd, vm->sandbox_id) < 0) {
            fprintf(stderr, "[ipc] pidfd_track failed for sandbox %u\n",
                    vm->sandbox_id);
        }
        ipc_response_t resp;
        memset(&resp, 0, sizeof(resp));
        resp.kind = IPC_REQ_CREATE;
        resp.sandbox_id = vm->sandbox_id;
        snprintf(resp.session_token, sizeof(resp.session_token), "%s", r->token);
        LOGF(LOG_INFO, "ipc_server", "create", "\"sandbox_id\":%u",
             vm->sandbox_id);
        send_response(s->fd, &resp);
    }
    free_job(job);
    if (!g.q_stop && s->cq_head) dispatch_cq_head(s);
}

// Drain the worker result queue (loop thread, on EP_WAKE).
static void drain_results(void) {
    pthread_mutex_lock(&g.r_lock);
    create_result_t* r = g.r_head;
    g.r_head = g.r_tail = NULL;
    pthread_mutex_unlock(&g.r_lock);
    while (r) {
        create_result_t* next = r->next;
        complete_result(r);
        free(r);
        r = next;
    }
}

static int start_create_workers(void) {
    int want = g.create_workers_cfg;
    if (want < 1) want = 1;
    if (want > IPC_CREATE_WORKERS) want = IPC_CREATE_WORKERS;
    for (int i = 0; i < want; i++) {
        if (pthread_create(&g.workers[i], NULL, create_worker_fn, NULL) != 0) {
            fprintf(stderr, "[ipc] failed to start create worker %d\n", i);
            break;
        }
        g.n_workers++;
    }
    return g.n_workers > 0 ? 0 : -1;
}

static void stop_create_workers(void) {
    pthread_mutex_lock(&g.q_lock);
    g.q_stop = true;
    pthread_cond_broadcast(&g.q_cond);
    pthread_mutex_unlock(&g.q_lock);
    for (int i = 0; i < g.n_workers; i++) pthread_join(g.workers[i], NULL);
    g.n_workers = 0;
    g.q_stop = false;
}

static void handle_destroy(int fd, session_t* s, uint32_t id) {
    if (!session_owns(s, id)) {
        reply_error(fd, SANDBOX_ERR_PERMISSION_DENIED, "not owned by session");
        return;
    }
    vm_handle_t* vm = lifecycle_get(id);
    if (vm) vmm_destroy(vm);
    pidfd_untrack(id);
    lifecycle_remove(id);
    token_revoke(id);
    session_disown(s, id);
    ipc_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.kind = IPC_REQ_DESTROY;
    resp.sandbox_id = id;
    send_response(fd, &resp);
}

static void handle_pause_resume(int fd, session_t* s, uint32_t id, bool pause) {
    if (!session_owns(s, id)) {
        reply_error(fd, SANDBOX_ERR_PERMISSION_DENIED, "not owned by session");
        return;
    }
    vm_handle_t* vm = lifecycle_get(id);
    if (!vm) {
        reply_error(fd, SANDBOX_ERR_INTERNAL, "sandbox gone");
        return;
    }
    int rc = pause ? vmm_pause_vcpus(vm) : vmm_resume_vcpus(vm);
    if (rc != 0) {
        reply_error(fd, SANDBOX_ERR_INTERNAL,
                    pause ? "pause failed" : "resume failed");
        return;
    }
    ipc_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.kind = pause ? IPC_REQ_PAUSE : IPC_REQ_RESUME;
    resp.sandbox_id = id;
    send_response(fd, &resp);
}

static void handle_inspect(int fd, session_t* s, uint32_t id) {
    if (!session_owns(s, id)) {
        reply_error(fd, SANDBOX_ERR_PERMISSION_DENIED, "not owned by session");
        return;
    }
    vm_handle_t* vm = lifecycle_get(id);
    if (!vm) {
        reply_error(fd, SANDBOX_ERR_INTERNAL, "sandbox gone");
        return;
    }
    char state[32] = {0};
    vmm_state(vm, state, sizeof(state));
    ipc_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.kind = IPC_REQ_INSPECT;
    resp.sandbox_id = id;
    resp.is_running = (strcmp(state, "Running") == 0);
    uint64_t now = now_ms();
    resp.uptime_ms = (vm->resume_time_ms && now > vm->resume_time_ms)
                         ? now - vm->resume_time_ms
                         : 0;
    resp.memory_rss_mib = read_rss_mib(vm->vmm_pid);
    resp.page_faults = vm->page_faults;
    send_response(fd, &resp);
}

// #23/D5: extend a session volume's deadline.
//
// Keyed by session_key, not by sandbox id, on purpose: the volume outlives every
// VM, so the caller that wants to keep it may have nothing running to name. The
// workspace layer owns the policy (absolute deadline from creation, clamped to
// the platform maximum, never shortened); this handler only maps its refusals
// onto errors the caller can act on.
static void handle_renew(int fd, const ipc_request_t* req) {
    workspace_meta_t m;
    if (workspace_renew(req->session_key, req->extra_seconds, (int64_t)time(NULL),
                        &m) < 0) {
        switch (errno) {
            case ESTALE:
                reply_error(fd, SANDBOX_ERR_SESSION_EXPIRED,
                            "session expired; its volume is already gone");
                break;
            case ERANGE:
                reply_error(fd, SANDBOX_ERR_SESSION_LIMIT,
                            "session has reached the platform maximum lifetime");
                break;
            case EINVAL:
                reply_error(fd, SANDBOX_ERR_INVALID_SPEC, "invalid session key");
                break;
            case ENOENT:
                reply_error(fd, SANDBOX_ERR_SESSION_UNKNOWN,
                            "no such session");
                break;
            default:
                reply_error(fd, SANDBOX_ERR_INTERNAL, "cannot renew session");
                break;
        }
        return;
    }
    ipc_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.kind = IPC_REQ_RENEW;
    resp.expires_at = (uint64_t)m.expires_at;
    send_response(fd, &resp);
}

static void handle_message(int fd, session_t* s, const uint8_t* payload,
                           size_t len) {
    ipc_request_t req;
    if (ipc_decode_request(payload, len, &req) < 0) {
        reply_error(fd, SANDBOX_ERR_INVALID_SPEC, "malformed request");
        return;
    }
    switch (req.kind) {
        case IPC_REQ_CREATE:  submit_create(fd, s, &req); break;
        case IPC_REQ_DESTROY: handle_destroy(fd, s, req.sandbox_id); break;
        case IPC_REQ_PAUSE:   handle_pause_resume(fd, s, req.sandbox_id, true); break;
        case IPC_REQ_RESUME:  handle_pause_resume(fd, s, req.sandbox_id, false); break;
        case IPC_REQ_INSPECT: handle_inspect(fd, s, req.sandbox_id); break;
        case IPC_REQ_RENEW:   handle_renew(fd, &req); break;
        default:              reply_error(fd, SANDBOX_ERR_INVALID_SPEC, "unknown op"); break;
    }
    ipc_request_clear(&req);
}

// Destroy everything a session owns; used on disconnect and shutdown.
static void drop_session(session_t* s) {
    if (s->fd < 0) return;
    for (int i = 0; i < s->n_owned; i++) {
        uint32_t id = s->owned[i];
        vm_handle_t* vm = lifecycle_get(id);
        if (vm) {
            vmm_destroy(vm);
            lifecycle_remove(id);
        }
        pidfd_untrack(id);
        token_revoke(id);
    }
    // §10.8: drop Create requests this session queued but never dispatched. The
    // active job (if any) is owned by the worker/result path, which reclaims it
    // when it finds no such session.
    while (s->cq_head) {
        create_job_t* j = s->cq_head;
        s->cq_head = j->next;
        uid_inflight_add(j->uid, -1);
        free_job(j);
    }
    s->cq_tail = NULL;
    s->n_outstanding = 0;
    s->cq_active = false;
    if (g.epfd >= 0) {
        epoll_ctl(g.epfd, EPOLL_CTL_DEL, s->fd, NULL);
    }
    close(s->fd);
    s->fd = -1;
    s->n_owned = 0;
}

// ---------------------------------------------------------------------------
// engine IPC loop
// ---------------------------------------------------------------------------

static int make_seqpacket_listener(const char* path) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    unlink(path);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(fd, 64) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    chmod(path, 0660);
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    return fd;
}

static void accept_clients(int lfd) {
    for (;;) {
        int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            return;  // EAGAIN or real error
        }
        // Phase 10.1: authenticate the peer before it can reach the pool.
        struct ucred cred;
        socklen_t clen = sizeof(cred);
        if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) < 0) {
            close(cfd);
            continue;
        }
        if (!uid_allowed(cred.uid)) {
            LOGF(LOG_WARN, "ipc_server", "peer_rejected",
                 "\"uid\":%d,\"pid\":%d", (int)cred.uid, (int)cred.pid);
            close(cfd);
            continue;
        }
        session_t* s = session_alloc(cfd);
        if (!s) {
            fprintf(stderr, "[ipc] session table full; rejecting client\n");
            close(cfd);
            continue;
        }
        s->uid = cred.uid;
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.u64 = ((uint64_t)cfd << 8) | EP_CLIENT;
        if (epoll_ctl(g.epfd, EPOLL_CTL_ADD, cfd, &ev) < 0) {
            close(cfd);
            s->fd = -1;
            continue;
        }
    }
}

int ipc_server_run(const char* socket_path) {
    if (!socket_path) return -1;
    for (int i = 0; i < IPC_MAX_SESSIONS; i++) g.sessions[i].fd = -1;
    memset(g.uid_inflight, 0, sizeof(g.uid_inflight));
    for (int i = 0; i < IPC_MAX_PIDFDS; i++) {
        g.vms[i].pidfd = -1;
        g.vms[i].session_fd = -1;
        g.vms[i].sandbox_id = 0;
    }

    g.listen_fd = make_seqpacket_listener(socket_path);
    if (g.listen_fd < 0) {
        fprintf(stderr, "[ipc] listen %s: %s\n", socket_path, strerror(errno));
        return -1;
    }
    g.epfd = epoll_create1(EPOLL_CLOEXEC);
    g.wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (g.epfd < 0 || g.wake_fd < 0) {
        fprintf(stderr, "[ipc] epoll/eventfd: %s\n", strerror(errno));
        close(g.listen_fd);
        g.listen_fd = -1;
        return -1;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.u64 = EP_LISTEN;
    epoll_ctl(g.epfd, EPOLL_CTL_ADD, g.listen_fd, &ev);
    ev.data.u64 = EP_WAKE;
    epoll_ctl(g.epfd, EPOLL_CTL_ADD, g.wake_fd, &ev);

    fprintf(stderr, "[ipc] listening on %s (template %s)\n", socket_path,
            g.template_name[0] ? g.template_name : "<none>");
    if (g.n_allowed_uids == 0) {
        LOGF(LOG_WARN, "ipc_server", "peer_auth",
             "\"mode\":\"any_uid\",\"warning\":\"no allowed_uids configured\"");
    } else {
        LOGF(LOG_INFO, "ipc_server", "peer_auth",
             "\"mode\":\"allowlist\",\"count\":%d", g.n_allowed_uids);
    }

    uint8_t* payload = malloc(IPC_FRAME_MAX);
    if (!payload) {
        close(g.listen_fd);
        close(g.wake_fd);
        close(g.epfd);
        g.listen_fd = g.wake_fd = g.epfd = -1;
        return -1;
    }

    // §10.8: start the Create worker pool before accepting connections.
    if (start_create_workers() < 0) {
        fprintf(stderr, "[ipc] no create workers; refusing to serve\n");
        free(payload);
        close(g.listen_fd);
        close(g.wake_fd);
        close(g.epfd);
        g.listen_fd = g.wake_fd = g.epfd = -1;
        unlink(socket_path);
        return -1;
    }

    g.running = 1;
    struct epoll_event evs[64];
    while (g.running) {
        int n = epoll_wait(g.epfd, evs, 64, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; i++) {
            uint64_t tag = evs[i].data.u64;
            int kind = (int)(tag & 0xff);
            if (kind == EP_WAKE) {
                uint64_t v;
                if (read(g.wake_fd, &v, sizeof(v)) < 0) { /* drained */ }
                drain_results();  // §10.8: completed Creates
                continue;
            }
            if (kind == EP_LISTEN) {
                accept_clients(g.listen_fd);
                continue;
            }
            if (kind == EP_PIDFD) {
                pidfd_handle((int)(tag >> 8));
                continue;
            }
            int fd = (int)(tag >> 8);
            session_t* s = session_find(fd);
            if (!s) continue;
            size_t plen = 0;
            if (ipc_recv_frame(fd, payload, IPC_FRAME_MAX, &plen) < 0) {
                drop_session(s);
                continue;
            }
            handle_message(fd, s, payload, plen);
        }
    }

    free(payload);
    // §10.8: stop workers, then drain whatever results they produced before
    // reclaiming sessions (dispatch is suppressed once q_stop is set).
    stop_create_workers();
    drain_results();
    // Reclaim all sessions.
    for (int i = 0; i < IPC_MAX_SESSIONS; i++) drop_session(&g.sessions[i]);
    close(g.listen_fd);
    close(g.wake_fd);
    close(g.epfd);
    g.listen_fd = g.wake_fd = g.epfd = -1;
    unlink(socket_path);
    return 0;
}

int ipc_server_stop(void) {
    ipc_server_request_stop();
    ipc_server_stop_broker_control();
    return 0;
}

void ipc_server_request_stop(void) {
    g.running = 0;
    if (g.wake_fd >= 0) {
        uint64_t one = 1;
        ssize_t w = write(g.wake_fd, &one, sizeof(one));
        (void)w;
    }
}

void ipc_server_set_pool(pool_manager_t* pool) { g.pool = pool; }

void ipc_server_set_template(const char* template_name) {
    snprintf(g.template_name, sizeof(g.template_name), "%s",
             template_name ? template_name : "");
}

void ipc_server_set_allowed_uids(const char* csv) {
    g.n_allowed_uids = 0;
    if (!csv || !*csv) return;
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", csv);
    char* save = NULL;
    for (char* tok = strtok_r(tmp, ",", &save);
         tok && g.n_allowed_uids < IPC_MAX_ALLOWED_UIDS;
         tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ') tok++;
        char* end = tok + strlen(tok);
        while (end > tok && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';
        if (!*tok) continue;
        g.allowed_uids[g.n_allowed_uids++] = (uid_t)strtoul(tok, NULL, 10);
    }
}

void ipc_server_set_allowed_services(const char* csv) {
    for (int i = 0; i < g.n_allowed; i++) free(g.allowed[i]);
    g.n_allowed = 0;
    g.allowed[0] = NULL;
    if (!csv || !*csv) return;
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", csv);
    char* save = NULL;
    for (char* tok = strtok_r(tmp, ",", &save); tok && g.n_allowed < TOKEN_MAX_SERVICES;
         tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ') tok++;
        char* end = tok + strlen(tok);
        while (end > tok && (end[-1] == ' ')) *--end = '\0';
        if (!*tok) continue;
        g.allowed[g.n_allowed++] = strdup(tok);
    }
    g.allowed[g.n_allowed] = NULL;
}

void ipc_server_set_default_pool_wait_ms(uint32_t ms) {
    g.default_pool_wait_ms = ms;
}

// §10.8: tune the Create worker pool / per-session / per-uid concurrency caps.
// Non-positive arguments leave the corresponding default in place.
void ipc_server_set_create_limits(int workers, int per_session, int per_uid) {
    if (workers > 0) g.create_workers_cfg = workers;
    if (per_session > 0) g.per_session_max = per_session;
    if (per_uid > 0) g.per_uid_max = per_uid;
}

// ---------------------------------------------------------------------------
// broker-control server (§5.8): the credential broker validates tokens here.
// ---------------------------------------------------------------------------

static void bc_handle_conn(int fd) {
    uint8_t req[BROKER_VALIDATE_REQ_LEN];
    for (;;) {
        if (read_full(fd, req, sizeof(req)) < 0) return;
        if (req[0] != BROKER_MSG_VALIDATE_TOKEN) return;

        uint8_t rbuf[4096];
        size_t off = 0;
        bool found = false;
        uint32_t sid = 0;

        pthread_mutex_lock(&g.tok_lock);
        token_entry_t* e = token_find_locked(req + 1);
        if (e) {
            found = true;
            sid = e->sandbox_id;
            int n = 0;
            while (e->services[n]) n++;
            rbuf[off++] = 0;  // status OK
            rbuf[off++] = (uint8_t)(sid >> 24);
            rbuf[off++] = (uint8_t)(sid >> 16);
            rbuf[off++] = (uint8_t)(sid >> 8);
            rbuf[off++] = (uint8_t)sid;
            rbuf[off++] = (uint8_t)(n >> 8);
            rbuf[off++] = (uint8_t)n;
            for (int i = 0; i < n; i++) {
                size_t len = strlen(e->services[i]);
                if (len > 255) len = 255;
                rbuf[off++] = (uint8_t)len;
                memcpy(rbuf + off, e->services[i], len);
                off += len;
            }
        }
        pthread_mutex_unlock(&g.tok_lock);

        if (!found) {
            uint8_t status = 1;  // invalid
            if (write_full(fd, &status, 1) < 0) return;
            continue;
        }
        if (write_full(fd, rbuf, off) < 0) return;
    }
}

static void* bc_thread_fn(void* arg) {
    (void)arg;
    int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0) {
        fprintf(stderr, "[broker-control] socket: %s\n", strerror(errno));
        return NULL;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(g.bc_path) >= sizeof(addr.sun_path)) {
        close(lfd);
        return NULL;
    }
    strncpy(addr.sun_path, g.bc_path, sizeof(addr.sun_path) - 1);
    unlink(g.bc_path);
    if (bind(lfd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(lfd, 32) < 0) {
        fprintf(stderr, "[broker-control] bind %s: %s\n", g.bc_path, strerror(errno));
        close(lfd);
        return NULL;
    }
    chmod(g.bc_path, 0660);
    g.bc_listen_fd = lfd;
    g.bc_wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    fprintf(stderr, "[broker-control] listening on %s\n", g.bc_path);

    g.bc_running = 1;
    while (g.bc_running) {
        struct pollfd pfd = { .fd = lfd, .events = POLLIN };
        int pr = poll(&pfd, 1, 200);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) continue;
        int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) continue;
        bc_handle_conn(cfd);
        close(cfd);
    }
    close(lfd);
    unlink(g.bc_path);
    g.bc_listen_fd = -1;
    return NULL;
}

int ipc_server_start_broker_control(const char* socket_path) {
    if (!socket_path || g.bc_started) return -1;
    snprintf(g.bc_path, sizeof(g.bc_path), "%s", socket_path);
    if (pthread_create(&g.bc_thread, NULL, bc_thread_fn, NULL) != 0) {
        return -1;
    }
    g.bc_started = true;
    return 0;
}

void ipc_server_stop_broker_control(void) {
    if (!g.bc_started) return;
    g.bc_running = 0;
    if (g.bc_wake_fd >= 0) {
        uint64_t one = 1;
        ssize_t w = write(g.bc_wake_fd, &one, sizeof(one));
        (void)w;
    }
    pthread_join(g.bc_thread, NULL);
    if (g.bc_wake_fd >= 0) {
        close(g.bc_wake_fd);
        g.bc_wake_fd = -1;
    }
    g.bc_started = false;
}
