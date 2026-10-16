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
#include "pool_manager.h"
#include "telemetry.h"
#include "vmm_manager.h"

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
#define TOKEN_MAX_SERVICES 64

// epoll data.u64 tag: low byte = kind, upper bits = payload (fd or table index).
enum { EP_LISTEN = 1, EP_WAKE = 2, EP_CLIENT = 3, EP_PIDFD = 4 };

typedef struct {
    int fd;
    uint32_t owned[IPC_MAX_OWNED];
    int n_owned;
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
} g = { .listen_fd = -1, .epfd = -1, .wake_fd = -1, .bc_listen_fd = -1,
        .bc_wake_fd = -1, .tok_lock = PTHREAD_MUTEX_INITIALIZER };

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
            return &g.sessions[i];
        }
    }
    return NULL;
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
    fprintf(stderr,
            "{\"component\":\"ipc_server\",\"event\":\"vmm_crash\","
            "\"sandbox_id\":%u}\n",
            id);

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

static void handle_create(int fd, session_t* s, const ipc_request_t* req) {
    if (g.template_name[0] && req->template_name[0] &&
        strcmp(req->template_name, g.template_name) != 0) {
        reply_error(fd, SANDBOX_ERR_INVALID_SPEC, "unknown template");
        return;
    }
    if (!g.pool) {
        reply_error(fd, SANDBOX_ERR_INTERNAL, "pool not configured");
        return;
    }

    sandbox_spec_t spec;
    memset(&spec, 0, sizeof(spec));
    spec.memory_mib = req->memory_mib ? req->memory_mib : 128;
    spec.vcpu_count = req->vcpu_count ? req->vcpu_count : 1;
    spec.template_name = g.template_name;
    spec.env_vars = (const char**)req->env_vars;
    spec.pool_wait_ms = req->pool_wait_ms;

    uint64_t t0 = now_ms();
    vm_handle_t* vm = NULL;
    sandbox_error_t err = pool_provision(g.pool, &spec, &vm);
    telemetry_provision_latency(now_ms() - t0);

    if (err != SANDBOX_OK || !vm) {
        reply_error(fd, err != SANDBOX_OK ? err : SANDBOX_ERR_INTERNAL,
                    "pool provision failed");
        telemetry_pool_exhausted();
        return;
    }

    lifecycle_track(vm);
    session_own(s, vm->sandbox_id);
    if (pidfd_track(vm->vmm_pid, fd, vm->sandbox_id) < 0) {
        // Crash detection degraded but the sandbox is still usable.
        fprintf(stderr, "[ipc] pidfd_track failed for sandbox %u\n",
                vm->sandbox_id);
    }

    // Per-VM env injection (Phase 9b): best-effort delivery to the guest agent.
    if (req->env_vars[0]) {
        if (vmm_inject_env(vm, (const char* const*)req->env_vars) == 0) {
            fprintf(stderr,
                    "{\"component\":\"ipc_server\",\"event\":\"env_injected\","
                    "\"sandbox_id\":%u}\n",
                    vm->sandbox_id);
        } else {
            fprintf(stderr,
                    "{\"component\":\"ipc_server\",\"event\":\"env_inject_failed\","
                    "\"sandbox_id\":%u}\n",
                    vm->sandbox_id);
        }
    }

    ipc_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.kind = IPC_REQ_CREATE;
    resp.sandbox_id = vm->sandbox_id;
    if (token_issue(vm->sandbox_id, resp.session_token) < 0) {
        // Roll back: the sandbox exists but has no usable token.
        lifecycle_remove(vm->sandbox_id);
        session_disown(s, vm->sandbox_id);
        vmm_destroy(vm);
        reply_error(fd, SANDBOX_ERR_INTERNAL, "token generation failed");
        return;
    }
    fprintf(stderr,
            "{\"component\":\"ipc_server\",\"event\":\"create\",\"sandbox_id\":%u}"
            "\n",
            vm->sandbox_id);
    send_response(fd, &resp);
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

static void handle_message(int fd, session_t* s, const uint8_t* payload,
                           size_t len) {
    ipc_request_t req;
    if (ipc_decode_request(payload, len, &req) < 0) {
        reply_error(fd, SANDBOX_ERR_INVALID_SPEC, "malformed request");
        return;
    }
    switch (req.kind) {
        case IPC_REQ_CREATE:  handle_create(fd, s, &req); break;
        case IPC_REQ_DESTROY: handle_destroy(fd, s, req.sandbox_id); break;
        case IPC_REQ_PAUSE:   handle_pause_resume(fd, s, req.sandbox_id, true); break;
        case IPC_REQ_RESUME:  handle_pause_resume(fd, s, req.sandbox_id, false); break;
        case IPC_REQ_INSPECT: handle_inspect(fd, s, req.sandbox_id); break;
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
        session_t* s = session_alloc(cfd);
        if (!s) {
            fprintf(stderr, "[ipc] session table full; rejecting client\n");
            close(cfd);
            continue;
        }
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

    uint8_t* payload = malloc(IPC_FRAME_MAX);
    if (!payload) {
        close(g.listen_fd);
        close(g.wake_fd);
        close(g.epfd);
        g.listen_fd = g.wake_fd = g.epfd = -1;
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
