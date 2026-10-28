// SPDX-License-Identifier: GPL-2.0-only
#ifndef HTTP_API_INTERNAL_H
#define HTTP_API_INTERNAL_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "broker.h"     // http_request_t and the header helpers
#include "http_api.h"
#include "json.h"

// ---- principals ------------------------------------------------------------

typedef struct api_principal {
    char name[64];
    uint8_t token_hash[32];   // SHA-256 of the bearer token
    bool has_token;
    unsigned max_sessions;    // 0: the server default
    char** templates;         // NULL-terminated allow-list; NULL: any
    struct api_principal* next;
} api_principal_t;

typedef struct api_auth api_auth_t;
// A file of "[name]" sections with token_sha256 / max_sessions / templates keys.
// NULL path gives an empty set. Refuses a file others can read.
api_auth_t* auth_load(const char* path, char* err, size_t errcap);
void auth_free(api_auth_t* a);
size_t auth_count_tokens(const api_auth_t* a);
// The principal owning this bearer token (compared in constant time), or NULL.
const api_principal_t* auth_by_token(const api_auth_t* a, const char* token);
// A Unix-socket caller: "uid:N", with limits from a "[uid:N]" section if present.
void auth_for_uid(const api_auth_t* a, uid_t uid, api_principal_t* out);

// ---- sessions --------------------------------------------------------------

typedef struct api_session {
    char id[32];              // "ses_" + 24 hex, derived from owner + key
    char key[132];
    char engine_key[80];      // the engine's workspace session key: opaque, owner-bound
    char owner[64];
    char template_name[64];
    uint64_t memory_mib;
    uint32_t vcpus;
    uint32_t ttl_seconds;
    char** egress;            // NULL-terminated, may be NULL
    bool egress_deny_all;
    char** env;               // NULL-terminated "K=V", may be NULL
    time_t created, last_active, expires_at;

    sandbox_handle_t* h;      // the VM, or NULL while idle
    int inflight;
    bool closing;
    bool removed;             // out of the table; freed when refs reaches 0
    int refs;                 // table reference + handlers holding it

    pthread_mutex_t mu;
    pthread_cond_t cv;
    struct api_session* next;
} api_session_t;

// ---- the server ------------------------------------------------------------

#define API_MAX_IDEM 128
typedef struct {
    int state;                // 0 free, 1 running, 2 done
    char owner[64], sid[32], key[132];
    uint8_t body_sha[32];
    int status;
    char* body;
    size_t len;
    time_t when;
} api_idem_t;

struct api_server {
    api_config_t cfg;
    char default_template[64];
    api_auth_t* auth;
    const api_engine_ops_t* eng;

    int unix_fd, tcp_fd;
    int tcp_port;
    int wake[2];              // pipe: stop signal for the poll loops
    volatile int stopping;

    pthread_mutex_t mu;       // sessions, connections, idempotency
    api_session_t* sessions;
    unsigned n_sessions, n_running;
    int* conn_fds;
    unsigned n_conns;
    pthread_cond_t conns_cv;
    api_idem_t idem[API_MAX_IDEM];

    pthread_t t_accept[2], t_reaper;
    int accept_started[2];
    int reaper_started;
    int engine_errs;
    time_t engine_err_since;
};

// sessions.c
api_session_t* sess_find(struct api_server* s, const char* id, const char* owner);  // takes a ref
void sess_unref(struct api_server* s, api_session_t* x);
void sess_make_id(const char* owner, const char* key, char id[32], char engine_key[80]);
// Provision the VM if the session is idle and count the caller as in flight.
sandbox_error_t sess_acquire(struct api_server* s, api_session_t* x, sandbox_handle_t** h);
void sess_release(struct api_server* s, api_session_t* x);
// Refuse new work, wait up to wait_s for what is running, reclaim the VM and
// forget the session. The caller holds its own reference.
void sess_close(struct api_server* s, api_session_t* x, int wait_s);
void sess_destroy_vm_locked(struct api_server* s, api_session_t* x);
void sess_free_fields(api_session_t* x);
void sess_reap_once(struct api_server* s);
void sess_shutdown_all(struct api_server* s);
unsigned sess_count_owner(struct api_server* s, const char* owner);

#endif
