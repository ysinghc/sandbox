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

static int g_client_fd = -1;

static sandbox_error_t client_roundtrip(const ipc_request_t* req,
                                        ipc_response_t* resp) {
    if (g_client_fd < 0) return SANDBOX_ERR_DAEMON_UNREACHABLE;
    uint8_t buf[IPC_FRAME_MAX];
    size_t n = 0;
    if (ipc_encode_request(req, buf, sizeof(buf), &n) < 0) {
        return SANDBOX_ERR_INTERNAL;
    }
    if (ipc_send_frame(g_client_fd, buf, n) < 0) {
        return SANDBOX_ERR_DAEMON_UNREACHABLE;
    }
    if (ipc_recv_frame(g_client_fd, buf, sizeof(buf), &n) < 0) {
        return SANDBOX_ERR_DAEMON_UNREACHABLE;
    }
    if (ipc_decode_response(buf, n, resp) < 0) return SANDBOX_ERR_INTERNAL;
    return SANDBOX_OK;
}

// Fill a request with the id of a simple (destroy/pause/resume/inspect) op.
static void req_by_id(ipc_request_t* req, ipc_req_kind_t kind, uint32_t id) {
    ipc_request_init(req);
    req->kind = kind;
    req->sandbox_id = id;
}

sandbox_error_t sandbox_init(const char* socket_path) {
    if (!socket_path || !*socket_path) return SANDBOX_ERR_DAEMON_UNREACHABLE;
    if (g_client_fd >= 0) {
        close(g_client_fd);
        g_client_fd = -1;
    }
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
    g_client_fd = fd;
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

void sandbox_cleanup(void) {
    if (g_client_fd >= 0) {
        close(g_client_fd);
        g_client_fd = -1;
    }
}

const char* sandbox_handle_token(const sandbox_handle_t* handle) {
    return handle ? handle->token : NULL;
}
