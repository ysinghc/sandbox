// SPDX-License-Identifier: GPL-2.0-only
// Session table and VM lifecycle for the control-plane API (#27).
//
// A session is a persistent workspace plus a VM that comes and goes. The workspace
// belongs to the engine (a volume keyed by `engine_key`, which outlives every VM
// until its TTL); the VM is provisioned the first time it is needed, reclaimed
// after it has been idle for a while, and provisioned again on the next request.
// Restoring a template is fast enough that "idle" costs the user nothing, and an
// assistant that goes quiet for an hour does not hold a VM for it.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api_internal.h"
#include "log.h"
#include "sha256.h"

static void hexn(const uint8_t d[32], size_t n, char* out) {
    char h[65];
    sha256_hex(d, h);
    memcpy(out, h, n);
    out[n] = '\0';
}

// Ids and engine keys are derived from (owner, key), so the same principal and
// key always name the same session and the same workspace -- across API
// restarts, which is what makes a session deterministic -- and two principals
// can never collide on a key. The engine key is an opaque hash: nothing that
// reaches the engine's socket can be steered at someone else's volume by name.
static void hash_parts(const char* domain, const char* owner, const char* key, uint8_t out[32]) {
    // domain \0 owner \0 key: the separators keep ("ab","c") and ("a","bc") apart.
    // Every input is length-bounded by its caller, so the buffer is on the stack:
    // there is no failure path that could hash to a constant and make every
    // session the same session.
    uint8_t buf[320];
    size_t dl = strlen(domain), ol = strlen(owner), kl = strlen(key);
    if (dl + ol + kl + 2 > sizeof(buf)) abort();
    memcpy(buf, domain, dl);
    buf[dl] = 0;
    memcpy(buf + dl + 1, owner, ol);
    buf[dl + 1 + ol] = 0;
    memcpy(buf + dl + 2 + ol, key, kl);
    sha256(buf, dl + ol + kl + 2, out);
}

void sess_make_id(const char* owner, const char* key, char id[32], char engine_key[80]) {
    uint8_t d[32];
    hash_parts("sandbox-api/session", owner, key, d);
    memcpy(id, "ses_", 4);
    hexn(d, 24, id + 4);
    hash_parts("sandbox-api/workspace", owner, key, d);
    memcpy(engine_key, "api-", 4);
    hexn(d, 48, engine_key + 4);
}

static void free_strv(char** v) {
    if (!v) return;
    for (char** p = v; *p; p++) free(*p);
    free(v);
}

void sess_free_fields(api_session_t* x) {
    free_strv(x->egress);
    free_strv(x->env);
    x->egress = x->env = NULL;
}

static void sess_free(api_session_t* x) {
    sess_free_fields(x);
    pthread_mutex_destroy(&x->mu);
    pthread_cond_destroy(&x->cv);
    free(x);
}

api_session_t* sess_find(struct api_server* s, const char* id, const char* owner) {
    api_session_t* hit = NULL;
    pthread_mutex_lock(&s->mu);
    for (api_session_t* x = s->sessions; x; x = x->next) {
        if (!x->removed && !strcmp(x->id, id) && !strcmp(x->owner, owner)) {
            x->refs++;
            hit = x;
            break;
        }
    }
    pthread_mutex_unlock(&s->mu);
    return hit;
}

void sess_unref(struct api_server* s, api_session_t* x) {
    pthread_mutex_lock(&s->mu);
    int dead = (--x->refs == 0 && x->removed);
    pthread_mutex_unlock(&s->mu);
    if (dead) sess_free(x);
}

unsigned sess_count_owner(struct api_server* s, const char* owner) {
    unsigned n = 0;
    pthread_mutex_lock(&s->mu);
    for (api_session_t* x = s->sessions; x; x = x->next)
        if (!x->removed && !strcmp(x->owner, owner)) n++;
    pthread_mutex_unlock(&s->mu);
    return n;
}

// Called with x->mu held and no operation in flight.
void sess_destroy_vm_locked(struct api_server* s, api_session_t* x) {
    if (!x->h) return;
    s->eng->destroy(x->h);
    x->h = NULL;
    pthread_mutex_lock(&s->mu);
    if (s->n_running) s->n_running--;
    pthread_mutex_unlock(&s->mu);
}

// Free a slot by reclaiming the longest-idle VM of some other session. Uses
// trylock only: the caller holds its own session's lock, and two sessions each
// waiting on the other's would deadlock.
static int evict_lru(struct api_server* s, api_session_t* except) {
    api_session_t* held[256];
    size_t n = 0;
    pthread_mutex_lock(&s->mu);
    for (api_session_t* x = s->sessions; x && n < 256; x = x->next)
        if (!x->removed && x != except) { x->refs++; held[n++] = x; }
    pthread_mutex_unlock(&s->mu);
    api_session_t* best = NULL;
    for (size_t i = 0; i < n; i++)
        if (held[i]->h && held[i]->inflight == 0 &&
            (!best || held[i]->last_active < best->last_active))
            best = held[i];
    int freed = 0;
    if (best && pthread_mutex_trylock(&best->mu) == 0) {
        if (best->h && best->inflight == 0 && !best->closing) {
            sess_destroy_vm_locked(s, best);
            freed = 1;
            LOGF(LOG_INFO, "http_api", "vm_evicted", "\"session\":\"%s\"", best->id);
        }
        pthread_mutex_unlock(&best->mu);
    }
    for (size_t i = 0; i < n; i++) sess_unref(s, held[i]);
    return freed;
}

static void note_engine_rc(struct api_server* s, sandbox_error_t rc) {
    if (rc != SANDBOX_ERR_DAEMON_UNREACHABLE) return;
    time_t now = time(NULL);
    pthread_mutex_lock(&s->mu);
    if (now - s->engine_err_since > 10) { s->engine_err_since = now; s->engine_errs = 0; }
    int n = ++s->engine_errs;
    pthread_mutex_unlock(&s->mu);
    // libsandbox holds one connection for the life of the process. If the daemon
    // restarted it is gone for good, so fail fast and let the supervisor restart
    // us; sessions come back by key, with their workspaces.
    if (n >= 3 && !__atomic_load_n(&s->stopping, __ATOMIC_ACQUIRE)) {
        LOGF(LOG_ERROR, "http_api", "engine_lost", "\"errors\":%d", n);
        fprintf(stderr, "sandbox-api: the engine connection is lost; exiting for a restart\n");
        _exit(75);
    }
}

sandbox_error_t sess_acquire(struct api_server* s, api_session_t* x, sandbox_handle_t** out) {
    pthread_mutex_lock(&x->mu);
    if (x->closing || x->removed) {
        pthread_mutex_unlock(&x->mu);
        return SANDBOX_ERR_SESSION_UNKNOWN;
    }
    if (!x->h) {
        pthread_mutex_lock(&s->mu);
        int full = s->n_running >= s->cfg.max_running;
        pthread_mutex_unlock(&s->mu);
        if (full) {
            evict_lru(s, x);
            pthread_mutex_lock(&s->mu);
            full = s->n_running >= s->cfg.max_running;
            if (!full) s->n_running++;
            pthread_mutex_unlock(&s->mu);
            if (full) {
                pthread_mutex_unlock(&x->mu);
                return SANDBOX_ERR_POOL_EXHAUSTED;
            }
        } else {
            pthread_mutex_lock(&s->mu);
            s->n_running++;  // reserve before the slow part, so the cap holds
            pthread_mutex_unlock(&s->mu);
        }
        sandbox_spec_t spec = {
            .memory_mib = x->memory_mib,
            .vcpu_count = x->vcpus,
            .template_name = x->template_name,
            .pool_wait_ms = s->cfg.pool_wait_ms,
            .env_vars = (const char**)x->env,
            .session_key = x->engine_key,
            .ttl_seconds = x->ttl_seconds,
            .egress_allow = (const char**)x->egress,
            .egress_deny_all = x->egress_deny_all,
        };
        sandbox_handle_t* h = NULL;
        sandbox_error_t rc = s->eng->create(&spec, &h);
        if (rc != SANDBOX_OK) {
            pthread_mutex_lock(&s->mu);
            if (s->n_running) s->n_running--;
            pthread_mutex_unlock(&s->mu);
            pthread_mutex_unlock(&x->mu);
            note_engine_rc(s, rc);
            return rc;
        }
        x->h = h;
    }
    x->inflight++;
    *out = x->h;
    pthread_mutex_unlock(&x->mu);
    return SANDBOX_OK;
}

void sess_release(struct api_server* s, api_session_t* x) {
    (void)s;
    pthread_mutex_lock(&x->mu);
    x->inflight--;
    x->last_active = time(NULL);
    pthread_cond_broadcast(&x->cv);
    pthread_mutex_unlock(&x->mu);
}

static void unlink_session(struct api_server* s, api_session_t* x) {
    pthread_mutex_lock(&s->mu);
    for (api_session_t** pp = &s->sessions; *pp; pp = &(*pp)->next) {
        if (*pp == x) { *pp = x->next; break; }
    }
    if (s->n_sessions) s->n_sessions--;
    x->removed = true;
    x->refs--;  // the table's own reference
    int dead = (x->refs == 0);
    pthread_mutex_unlock(&s->mu);
    if (dead) sess_free(x);
}

// Tear a session down: refuse new work, wait for what is running, reclaim the VM,
// forget the record. The caller holds a reference. `wait_s` bounds the wait.
void sess_close(struct api_server* s, api_session_t* x, int wait_s) {
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += wait_s;
    pthread_mutex_lock(&x->mu);
    x->closing = true;
    while (x->inflight > 0 && pthread_cond_timedwait(&x->cv, &x->mu, &dl) == 0) {}
    sess_destroy_vm_locked(s, x);
    pthread_mutex_unlock(&x->mu);
    unlink_session(s, x);
}

void sess_reap_once(struct api_server* s) {
    api_session_t* held[512];
    size_t n = 0;
    pthread_mutex_lock(&s->mu);
    for (api_session_t* x = s->sessions; x && n < 512; x = x->next)
        if (!x->removed) { x->refs++; held[n++] = x; }
    pthread_mutex_unlock(&s->mu);
    time_t now = time(NULL);
    for (size_t i = 0; i < n; i++) {
        api_session_t* x = held[i];
        int expire = 0;
        if (pthread_mutex_trylock(&x->mu) == 0) {
            if (x->inflight == 0 && !x->closing) {
                if (x->expires_at && now > x->expires_at) {
                    expire = 1;
                } else if (x->h && s->cfg.idle_vm_seconds &&
                           now - x->last_active > (time_t)s->cfg.idle_vm_seconds) {
                    sess_destroy_vm_locked(s, x);
                    LOGF(LOG_INFO, "http_api", "vm_idle_reclaimed", "\"session\":\"%s\"", x->id);
                }
            }
            pthread_mutex_unlock(&x->mu);
        }
        if (expire) {
            LOGF(LOG_INFO, "http_api", "session_expired", "\"session\":\"%s\"", x->id);
            sess_close(s, x, 5);
        }
        sess_unref(s, x);
    }
}

void sess_shutdown_all(struct api_server* s) {
    for (;;) {
        api_session_t* x = NULL;
        pthread_mutex_lock(&s->mu);
        for (api_session_t* y = s->sessions; y; y = y->next)
            if (!y->removed) { y->refs++; x = y; break; }
        pthread_mutex_unlock(&s->mu);
        if (!x) return;
        sess_close(s, x, 5);
        sess_unref(s, x);
    }
}
