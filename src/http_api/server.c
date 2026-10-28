// SPDX-License-Identifier: GPL-2.0-only
// Control-plane HTTP API server (#27): listeners, HTTP/1.1 framing, routing and
// the handlers. Everything that touches the engine goes through api_engine_ops_t.
//
// Isolation rule, enforced in exactly one place (sess_find): a session is
// addressed by id *and* owner, so another principal's id is indistinguishable
// from one that does not exist (404, never 403).

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "api_internal.h"
#include "log.h"
#include "sha256.h"

#define MAX_JSON_BODY (1024 * 1024)
#define MAX_PATH_QUERY 4096
#define STREAM_CHUNK 8192
#define IDEM_TTL_S 600
#define MAX_ENV_VARS 64

// ---- request context -------------------------------------------------------

typedef struct {
    struct api_server* srv;
    int fd;
    bool is_unix;
    uid_t uid;
} conn_t;

typedef struct {
    conn_t* c;
    http_request_t* req;
    char path[HTTP_MAX_TARGET];
    char* query;
    char rid[72];
    char who[64];
    const api_principal_t* principal;
    api_principal_t uid_principal;
    uint8_t* body;
    size_t body_len;
    int keepalive;
    int status;
    struct timespec t0;
} rq_t;

static const char* reason(int s) {
    switch (s) {
    case 100: return "Continue";
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 410: return "Gone";
    case 411: return "Length Required";
    case 413: return "Payload Too Large";
    case 415: return "Unsupported Media Type";
    case 422: return "Unprocessable Entity";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    default: return "Status";
    }
}

static int write_all(int fd, const void* p, size_t n) {
    const char* c = p;
    while (n) {
        ssize_t w = send(fd, c, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        c += w;
        n -= (size_t)w;
    }
    return 0;
}

static void send_head(rq_t* r, int status, const char* ctype, long long len, const char* extra) {
    char h[1024];
    int n = snprintf(h, sizeof(h),
                     "HTTP/1.1 %d %s\r\nX-Request-Id: %s\r\nCache-Control: no-store\r\n"
                     "X-Content-Type-Options: nosniff\r\n",
                     status, reason(status), r->rid);
    if (ctype) n += snprintf(h + n, sizeof(h) - (size_t)n, "Content-Type: %s\r\n", ctype);
    if (len >= 0) n += snprintf(h + n, sizeof(h) - (size_t)n, "Content-Length: %lld\r\n", len);
    if (extra) n += snprintf(h + n, sizeof(h) - (size_t)n, "%s", extra);
    n += snprintf(h + n, sizeof(h) - (size_t)n, "Connection: %s\r\n\r\n", r->keepalive ? "keep-alive" : "close");
    r->status = status;
    if (write_all(r->c->fd, h, (size_t)n) < 0) r->keepalive = 0;
}

static void respond(rq_t* r, int status, const char* ctype, const void* body, size_t len, const char* extra) {
    send_head(r, status, ctype, (long long)len, extra);
    if (len && write_all(r->c->fd, body, len) < 0) r->keepalive = 0;
}

static void respond_json(rq_t* r, int status, jbuf_t* b, const char* extra) {
    if (b->oom) {
        r->keepalive = 0;
        respond(r, 500, "application/json", "{\"error\":{\"code\":\"internal\",\"message\":\"out of memory\"}}", 62, NULL);
    } else {
        respond(r, status, "application/json", b->p ? b->p : "", b->len, extra);
    }
    jb_free(b);
}

static void respond_error(rq_t* r, int status, const char* code, const char* msg) {
    jbuf_t b;
    jb_init(&b);
    jb_raw(&b, "{\"error\":{\"code\":");
    jb_cstr(&b, code);
    jb_raw(&b, ",\"message\":");
    jb_cstr(&b, msg);
    jb_fmt(&b, "},\"request_id\":\"%s\"}", r->rid);
    const char* extra = NULL;
    if (status == 401) extra = "WWW-Authenticate: Bearer realm=\"sandbox\"\r\n";
    else if (status == 503 || status == 429) extra = "Retry-After: 1\r\n";
    respond_json(r, status, &b, extra);
}

// The engine's error codes, as HTTP. The mapping is part of the API contract
// (docs/API.md): a client decides whether to retry, fix its request or give up
// from the status and the stable `code`.
static void map_err(sandbox_error_t e, int* status, const char** code) {
    switch (e) {
    case SANDBOX_ERR_POOL_EXHAUSTED: *status = 503; *code = "capacity"; break;
    case SANDBOX_ERR_INVALID_SPEC: *status = 400; *code = "invalid_spec"; break;
    case SANDBOX_ERR_DAEMON_UNREACHABLE: *status = 503; *code = "engine_unavailable"; break;
    case SANDBOX_ERR_PERMISSION_DENIED: *status = 502; *code = "engine_denied"; break;
    case SANDBOX_ERR_SESSION_EXPIRED: *status = 410; *code = "session_expired"; break;
    case SANDBOX_ERR_SESSION_LIMIT: *status = 409; *code = "session_at_maximum_lifetime"; break;
    case SANDBOX_ERR_SESSION_UNKNOWN: *status = 404; *code = "session_not_found"; break;
    case SANDBOX_ERR_GUEST_UNAVAILABLE: *status = 503; *code = "guest_unavailable"; break;
    case SANDBOX_ERR_PATH_DENIED: *status = 400; *code = "path_denied"; break;
    case SANDBOX_ERR_NOT_FOUND: *status = 404; *code = "not_found"; break;
    case SANDBOX_ERR_EXISTS: *status = 409; *code = "exists"; break;
    case SANDBOX_ERR_TOO_LARGE: *status = 413; *code = "too_large"; break;
    case SANDBOX_ERR_GUEST_IO: *status = 502; *code = "guest_io"; break;
    case SANDBOX_ERR_TIMEOUT: *status = 504; *code = "timeout"; break;
    default: *status = 500; *code = "internal"; break;
    }
}

static void respond_engine_error(rq_t* r, sandbox_error_t e) {
    int st;
    const char* code;
    map_err(e, &st, &code);
    respond_error(r, st, code, sandbox_error_string(e));
}

// ---- query strings ---------------------------------------------------------

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Value of `name` in the query string, percent-decoded. 1 found, 0 absent, -1 bad.
static int qget(const rq_t* r, const char* name, char* out, size_t cap) {
    if (!r->query) return 0;
    size_t nl = strlen(name);
    const char* p = r->query;
    while (*p) {
        const char* end = strchr(p, '&');
        size_t seg = end ? (size_t)(end - p) : strlen(p);
        if (seg > nl && !strncmp(p, name, nl) && p[nl] == '=') {
            const char* v = p + nl + 1;
            size_t vl = seg - nl - 1, o = 0;
            for (size_t i = 0; i < vl; i++) {
                char c = v[i];
                if (c == '%') {
                    int a = i + 1 < vl ? hexv(v[i + 1]) : -1, b = i + 2 < vl ? hexv(v[i + 2]) : -1;
                    if (a < 0 || b < 0) return -1;
                    c = (char)(a * 16 + b);
                    if (c == '\0') return -1;  // a NUL would end the path early in C
                    i += 2;
                } else if (c == '+') {
                    c = ' ';
                }
                if (o + 1 >= cap) return -1;
                out[o++] = c;
            }
            out[o] = '\0';
            return 1;
        }
        if (!end) break;
        p = end + 1;
    }
    return 0;
}

static int qflag(const rq_t* r, const char* name) {
    char v[16];
    if (qget(r, name, v, sizeof(v)) != 1) return 0;
    return !strcmp(v, "1") || !strcmp(v, "true");
}

// ---- session JSON ----------------------------------------------------------

static void jb_session(jbuf_t* b, api_session_t* x) {
    pthread_mutex_lock(&x->mu);
    const char* state = x->closing ? "closing" : (x->h ? "ready" : "idle");
    jb_raw(b, "{\"id\":");
    jb_cstr(b, x->id);
    jb_raw(b, ",\"key\":");
    jb_cstr(b, x->key);
    jb_raw(b, ",\"state\":");
    jb_cstr(b, state);
    jb_raw(b, ",\"template\":");
    jb_cstr(b, x->template_name);
    jb_fmt(b, ",\"memory_mib\":%llu,\"vcpus\":%u,\"created_at\":%lld,\"last_active_at\":%lld,\"expires_at\":%lld",
           (unsigned long long)x->memory_mib, x->vcpus, (long long)x->created, (long long)x->last_active,
           (long long)x->expires_at);
    jb_raw(b, ",\"workspace\":\"/workspace\",\"egress\":");
    if (x->egress_deny_all) {
        jb_raw(b, "{\"deny_all\":true}");
    } else if (x->egress) {
        jb_raw(b, "{\"allow\":[");
        for (char** e = x->egress; *e; e++) {
            if (e != x->egress) jb_raw(b, ",");
            jb_cstr(b, *e);
        }
        jb_raw(b, "]}");
    } else {
        jb_raw(b, "{\"allow\":null}");  // the daemon-wide policy
    }
    jb_raw(b, "}");
    pthread_mutex_unlock(&x->mu);
}

// ---- body parsing helpers --------------------------------------------------

static int body_json(rq_t* r, jv_t** out) {
    char err[96];
    if (r->body_len == 0) {
        respond_error(r, 400, "invalid_json", "a JSON body is required");
        return -1;
    }
    const char* ct = http_get_header(r->req, "Content-Type");
    if (ct && !strcasestr(ct, "json")) {
        respond_error(r, 415, "unsupported_media_type", "Content-Type must be application/json");
        return -1;
    }
    jv_t* v = json_parse((const char*)r->body, r->body_len, err, sizeof(err));
    if (!v) {
        respond_error(r, 400, "invalid_json", err);
        return -1;
    }
    if (v->type != J_OBJ) {
        json_free(v);
        respond_error(r, 400, "invalid_json", "the body must be a JSON object");
        return -1;
    }
    *out = v;
    return 0;
}

// Reject members the endpoint does not know: a misspelt "ttl" must not be a
// silently ignored default.
static int only_fields(rq_t* r, const jv_t* o, const char* const* allowed) {
    for (size_t i = 0; i < o->n; i++) {
        int ok = 0;
        for (const char* const* a = allowed; *a; a++)
            if (!strcmp(o->keys[i], *a)) ok = 1;
        if (!ok) {
            char m[160];
            snprintf(m, sizeof(m), "unknown field \"%.60s\"", o->keys[i]);
            respond_error(r, 400, "unknown_field", m);
            return -1;
        }
    }
    return 0;
}

static int bad_type(rq_t* r, const char* field, const char* want) {
    char m[160];
    snprintf(m, sizeof(m), "\"%s\" must be %s", field, want);
    respond_error(r, 400, "invalid_field", m);
    return -1;
}

static int name_chars(const char* s, size_t max, const char* extra) {
    size_t n = strlen(s);
    if (n == 0 || n > max) return 0;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && !strchr(extra, s[i])) return 0;
    return 1;
}

static void free_strv(char** v) {
    if (!v) return;
    for (char** p = v; *p; p++) free(*p);
    free(v);
}

// ---- idempotency -----------------------------------------------------------

enum { IDEM_PROCEED, IDEM_REPLAY, IDEM_BUSY, IDEM_MISMATCH };

static int idem_begin(struct api_server* s, const char* owner, const char* sid, const char* key,
                      const uint8_t sha[32], int* slot, int* status, char** body, size_t* len) {
    time_t now = time(NULL);
    int rc = IDEM_PROCEED;
    *slot = -1;
    pthread_mutex_lock(&s->mu);
    int free_i = -1, old_i = -1;
    for (int i = 0; i < API_MAX_IDEM; i++) {
        api_idem_t* e = &s->idem[i];
        if (e->state == 2 && now - e->when > IDEM_TTL_S) { free(e->body); memset(e, 0, sizeof(*e)); }
        if (e->state == 0) { if (free_i < 0) free_i = i; continue; }
        if (!strcmp(e->owner, owner) && !strcmp(e->sid, sid) && !strcmp(e->key, key)) {
            if (memcmp(e->body_sha, sha, 32) != 0) rc = IDEM_MISMATCH;
            else if (e->state == 1) rc = IDEM_BUSY;
            else {
                rc = IDEM_REPLAY;
                *status = e->status;
                *len = e->len;
                *body = malloc(e->len + 1);
                if (*body) { memcpy(*body, e->body, e->len); (*body)[e->len] = '\0'; }
                else rc = IDEM_PROCEED;  // cannot replay: run it again rather than fail
            }
            pthread_mutex_unlock(&s->mu);
            return rc;
        }
        if (e->state == 2 && (old_i < 0 || e->when < s->idem[old_i].when)) old_i = i;
    }
    int use = free_i >= 0 ? free_i : old_i;
    if (use >= 0) {
        api_idem_t* e = &s->idem[use];
        free(e->body);
        memset(e, 0, sizeof(*e));
        e->state = 1;
        e->when = now;
        snprintf(e->owner, sizeof(e->owner), "%s", owner);
        snprintf(e->sid, sizeof(e->sid), "%s", sid);
        snprintf(e->key, sizeof(e->key), "%s", key);
        memcpy(e->body_sha, sha, 32);
        *slot = use;
    }
    pthread_mutex_unlock(&s->mu);
    return rc;
}

static void idem_finish(struct api_server* s, int slot, int status, const char* body, size_t len) {
    if (slot < 0) return;
    pthread_mutex_lock(&s->mu);
    api_idem_t* e = &s->idem[slot];
    // A server-side failure is a retryable outcome, not an answer to remember.
    if (status >= 500 || !(e->body = malloc(len + 1))) {
        memset(e, 0, sizeof(*e));
    } else {
        memcpy(e->body, body, len);
        e->body[len] = '\0';
        e->len = len;
        e->status = status;
        e->state = 2;
        e->when = time(NULL);
    }
    pthread_mutex_unlock(&s->mu);
}

// ---- handlers --------------------------------------------------------------

static void h_health(rq_t* r) {
    const char* b = "{\"status\":\"ok\"}";
    respond(r, 200, "application/json", b, strlen(b), NULL);
}

static void rand_hex(char* out, size_t nbytes) {
    uint8_t b[32];
    if (nbytes > sizeof(b)) nbytes = sizeof(b);
    if (getrandom(b, nbytes, 0) != (ssize_t)nbytes) memset(b, 0, nbytes);  // never hit; refuse below
    static const char* H = "0123456789abcdef";
    for (size_t i = 0; i < nbytes; i++) { out[i * 2] = H[b[i] >> 4]; out[i * 2 + 1] = H[b[i] & 15]; }
    out[nbytes * 2] = '\0';
}

static int template_allowed(const api_principal_t* p, const char* t) {
    if (!p->templates) return 1;
    for (char** a = p->templates; *a; a++)
        if (!strcmp(*a, t)) return 1;
    return 0;
}

static void h_create(rq_t* r) {
    struct api_server* s = r->c->srv;
    static const char* const fields[] = { "key", "template", "memory_mib", "vcpus", "ttl_seconds",
                                          "env", "egress_allow", "egress_deny_all", NULL };
    jv_t* v = NULL;
    if (body_json(r, &v) < 0) return;
    if (only_fields(r, v, fields) < 0) { json_free(v); return; }

    const char *key = NULL, *tmpl = NULL;
    int64_t mem = 0, vcpus = 0, ttl = 0;
    bool deny = false;
    if (json_get_str(v, "key", &key) < 0) { bad_type(r, "key", "a string"); goto out; }
    if (key && !name_chars(key, 128, "._:@-")) {
        respond_error(r, 400, "invalid_field", "\"key\" must be 1-128 characters of A-Z a-z 0-9 . _ : @ -");
        goto out;
    }
    if (json_get_str(v, "template", &tmpl) < 0) { bad_type(r, "template", "a string"); goto out; }
    if (tmpl && !name_chars(tmpl, 63, "._-")) { bad_type(r, "template", "a template name"); goto out; }
    if (json_get_int(v, "memory_mib", &mem) < 0 || (mem != 0 && (mem < 64 || mem > 8192))) { bad_type(r, "memory_mib", "an integer from 64 to 8192"); goto out; }
    if (json_get_int(v, "vcpus", &vcpus) < 0 || (vcpus != 0 && (vcpus < 1 || vcpus > 8))) { bad_type(r, "vcpus", "an integer from 1 to 8"); goto out; }
    if (json_get_int(v, "ttl_seconds", &ttl) < 0 || ttl < 0 || ttl > 30 * 86400) { bad_type(r, "ttl_seconds", "an integer from 0 to 2592000"); goto out; }
    if (json_get_bool(v, "egress_deny_all", &deny) < 0) { bad_type(r, "egress_deny_all", "a boolean"); goto out; }

    char** egress = NULL;
    char** env = NULL;
    const jv_t* ea = json_get(v, "egress_allow");
    if (ea && ea->type != J_NULL) {
        if (ea->type != J_ARR || ea->n > 16) { bad_type(r, "egress_allow", "an array of at most 16 strings"); goto out; }
        if (deny && ea->n) { respond_error(r, 400, "invalid_field", "egress_deny_all cannot be combined with egress_allow"); goto out; }
        if (ea->n) {
            egress = calloc(ea->n + 1, sizeof(*egress));
            for (size_t i = 0; egress && i < ea->n; i++) {
                const jv_t* e = ea->items[i];
                if (e->type != J_STR || e->slen == 0 || e->slen > 255 || strlen(e->s) != e->slen) {
                    free_strv(egress);
                    bad_type(r, "egress_allow", "an array of host strings");
                    goto out;
                }
                egress[i] = strdup(e->s);
            }
        }
    }
    const jv_t* ev = json_get(v, "env");
    if (ev && ev->type != J_NULL) {
        if (ev->type != J_OBJ || ev->n > MAX_ENV_VARS) { free_strv(egress); bad_type(r, "env", "an object of at most 64 string values"); goto out; }
        env = calloc(ev->n + 1, sizeof(*env));
        size_t total = 0;
        for (size_t i = 0; env && i < ev->n; i++) {
            const char* k = ev->keys[i];
            const jv_t* val = ev->items[i];
            int ok = val->type == J_STR && strlen(val->s) == val->slen && strlen(k) <= 64 &&
                     (isalpha((unsigned char)k[0]) || k[0] == '_');
            for (const char* c = k; ok && *c; c++) if (!isalnum((unsigned char)*c) && *c != '_') ok = 0;
            total += strlen(k) + (val->s ? val->slen : 0) + 2;
            if (!ok || total > 16384) { free_strv(egress); free_strv(env); bad_type(r, "env", "an object of NAME: string, at most 16 KiB in all"); goto out; }
            size_t n = strlen(k) + val->slen + 2;
            env[i] = malloc(n);
            if (env[i]) snprintf(env[i], n, "%s=%s", k, val->s);
        }
    }

    // Everything past here may fail for reasons the caller can act on.
    char keybuf[132];
    if (key) snprintf(keybuf, sizeof(keybuf), "%s", key);
    else { memcpy(keybuf, "auto-", 5); rand_hex(keybuf + 5, 16); }
    const char* template_name = tmpl ? tmpl : s->default_template;
    if (!template_allowed(r->principal, template_name)) {
        free_strv(egress); free_strv(env);
        respond_error(r, 403, "template_not_allowed", "this principal may not use that template");
        goto out;
    }
    api_session_t* x = calloc(1, sizeof(*x));
    if (!x) { free_strv(egress); free_strv(env); respond_error(r, 500, "internal", "out of memory"); goto out; }
    sess_make_id(r->who, keybuf, x->id, x->engine_key);

    api_session_t* existing = sess_find(s, x->id, r->who);
    if (existing) {
        // Idempotent attach: the same principal and key name the same session.
        // What differs is an error rather than a silent ignore.
        int differs = (tmpl && strcmp(tmpl, existing->template_name)) ||
                      (mem && (uint64_t)mem != existing->memory_mib) ||
                      (vcpus && (uint32_t)vcpus != existing->vcpus);
        free_strv(egress); free_strv(env); free(x);
        if (differs) {
            sess_unref(s, existing);
            respond_error(r, 409, "session_exists", "a session with this key exists with different resources");
            goto out;
        }
        jbuf_t b; jb_init(&b); jb_session(&b, existing);
        sess_unref(s, existing);
        respond_json(r, 200, &b, NULL);
        goto out;
    }

    unsigned limit = r->principal->max_sessions ? r->principal->max_sessions : s->cfg.max_sessions_default;
    pthread_mutex_lock(&s->mu);
    int too_many_total = s->n_sessions >= s->cfg.max_sessions_total;
    pthread_mutex_unlock(&s->mu);
    if (sess_count_owner(s, r->who) >= limit || too_many_total) {
        free_strv(egress); free_strv(env); free(x);
        respond_error(r, 429, "too_many_sessions", too_many_total ? "the server is at its session limit" : "this principal is at its session limit");
        goto out;
    }

    snprintf(x->key, sizeof(x->key), "%s", keybuf);
    snprintf(x->owner, sizeof(x->owner), "%s", r->who);
    snprintf(x->template_name, sizeof(x->template_name), "%s", template_name);
    x->memory_mib = mem ? (uint64_t)mem : s->cfg.default_memory_mib;
    x->vcpus = vcpus ? (uint32_t)vcpus : s->cfg.default_vcpus;
    x->ttl_seconds = ttl ? (uint32_t)ttl : s->cfg.default_ttl_seconds;
    x->egress = egress;
    x->egress_deny_all = deny;
    x->env = env;
    x->created = x->last_active = time(NULL);
    x->refs = 2;  // the table's and this handler's
    pthread_mutex_init(&x->mu, NULL);
    pthread_cond_init(&x->cv, NULL);

    pthread_mutex_lock(&s->mu);
    x->next = s->sessions;
    s->sessions = x;
    s->n_sessions++;
    pthread_mutex_unlock(&s->mu);

    // Provision now rather than on first use: an assistant that creates a session
    // is about to use it, and a template that cannot be restored should fail here.
    sandbox_handle_t* h = NULL;
    sandbox_error_t er = sess_acquire(s, x, &h);
    if (er != SANDBOX_OK) {
        sess_close(s, x, 1);
        sess_unref(s, x);
        respond_engine_error(r, er);
        goto out;
    }
    sess_release(s, x);
    // Learn the real deadline: the engine clamps the ttl and owns the clock.
    uint64_t exp = 0;
    if (s->eng->renew(x->engine_key, x->ttl_seconds, &exp) == SANDBOX_OK) x->expires_at = (time_t)exp;
    else x->expires_at = x->ttl_seconds ? x->created + x->ttl_seconds : 0;
    LOGF(LOG_INFO, "http_api", "session_created", "\"rid\":\"%s\",\"principal\":\"%s\",\"session\":\"%s\"", r->rid, r->who, x->id);
    jbuf_t b;
    jb_init(&b);
    jb_session(&b, x);
    sess_unref(s, x);
    respond_json(r, 201, &b, NULL);
out:
    json_free(v);
}

static void h_list(rq_t* r) {
    struct api_server* s = r->c->srv;
    api_session_t* held[512];
    size_t n = 0;
    pthread_mutex_lock(&s->mu);
    for (api_session_t* x = s->sessions; x && n < 512; x = x->next)
        if (!x->removed && !strcmp(x->owner, r->who)) { x->refs++; held[n++] = x; }
    pthread_mutex_unlock(&s->mu);
    jbuf_t b;
    jb_init(&b);
    jb_raw(&b, "{\"sessions\":[");
    for (size_t i = 0; i < n; i++) {
        if (i) jb_raw(&b, ",");
        jb_session(&b, held[i]);
        sess_unref(s, held[i]);
    }
    jb_raw(&b, "]}");
    respond_json(r, 200, &b, NULL);
}

static void h_get(rq_t* r, api_session_t* x) {
    jbuf_t b;
    jb_init(&b);
    jb_session(&b, x);
    respond_json(r, 200, &b, NULL);
}

static void h_delete(rq_t* r, api_session_t* x) {
    // The workspace volume is not touched: it lives out its ttl, so the same key
    // reattaches to the same files. The engine has no "delete volume" call.
    sess_close(r->c->srv, x, 30);
    LOGF(LOG_INFO, "http_api", "session_deleted", "\"rid\":\"%s\",\"principal\":\"%s\",\"session\":\"%s\"", r->rid, r->who, x->id);
    respond(r, 204, NULL, NULL, 0, NULL);
}

static void h_renew(rq_t* r, api_session_t* x) {
    static const char* const fields[] = { "ttl_seconds", NULL };
    jv_t* v = NULL;
    int64_t ttl = 0;
    if (r->body_len) {
        if (body_json(r, &v) < 0) return;
        if (only_fields(r, v, fields) < 0 ||
            json_get_int(v, "ttl_seconds", &ttl) < 0 || ttl < 0 || ttl > 30 * 86400) {
            if (!r->status) bad_type(r, "ttl_seconds", "an integer from 0 to 2592000");
            json_free(v);
            return;
        }
        json_free(v);
    }
    uint64_t exp = 0;
    sandbox_error_t er = r->c->srv->eng->renew(x->engine_key, (uint32_t)ttl, &exp);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); return; }
    pthread_mutex_lock(&x->mu);
    x->expires_at = (time_t)exp;
    pthread_mutex_unlock(&x->mu);
    jbuf_t b;
    jb_init(&b);
    jb_session(&b, x);
    respond_json(r, 200, &b, NULL);
}

// ---- exec ------------------------------------------------------------------

typedef struct {
    struct api_server* srv;
    sandbox_handle_t* h;
    sandbox_exec_spec_t spec;
    sandbox_exec_result_t res;
    sandbox_error_t rc;
    int done;
    long long ms;
    pthread_mutex_t mu;
    pthread_cond_t cv;
} exec_job_t;

static long long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void* exec_thread(void* a) {
    exec_job_t* j = a;
    long long t0 = mono_ms();
    j->rc = j->srv->eng->exec(j->h, &j->spec, &j->res);
    pthread_mutex_lock(&j->mu);
    j->ms = mono_ms() - t0;
    j->done = 1;
    pthread_cond_broadcast(&j->cv);
    pthread_mutex_unlock(&j->mu);
    return NULL;
}

static void jb_stream_text(jbuf_t* b, const uint8_t* d, size_t n, bool b64) {
    if (b64) jb_b64(b, d, n);
    else jb_str(b, (const char*)d, n);
}

static void jb_exec_result(jbuf_t* b, const exec_job_t* j, bool b64) {
    const sandbox_exec_result_t* e = &j->res;
    jb_fmt(b, "{\"exit_code\":%d,\"term_signal\":%d,\"timed_out\":%s,\"output_truncated\":%s,\"duration_ms\":%lld,",
           e->exit_code, e->term_signal, e->timed_out ? "true" : "false",
           e->output_truncated ? "true" : "false", j->ms);
    jb_raw(b, "\"stdout\":");
    jb_stream_text(b, e->out, e->out_len, b64);
    jb_raw(b, ",\"stderr\":");
    jb_stream_text(b, e->err, e->err_len, b64);
    // The engine returns the head of each stream; the totals say what was dropped.
    jb_fmt(b, ",\"stdout_bytes\":%llu,\"stderr_bytes\":%llu,\"stdout_returned\":%zu,\"stderr_returned\":%zu,\"encoding\":\"%s\"}",
           (unsigned long long)e->out_total, (unsigned long long)e->err_total, e->out_len, e->err_len,
           b64 ? "base64" : "utf8");
}

static void sse_event(rq_t* r, const char* ev, const char* data) {
    char head[96];
    int n = snprintf(head, sizeof(head), "event: %s\ndata: ", ev);
    if (write_all(r->c->fd, head, (size_t)n) < 0 || write_all(r->c->fd, data, strlen(data)) < 0 ||
        write_all(r->c->fd, "\n\n", 2) < 0)
        r->keepalive = 0;
}

static void sse_stream(rq_t* r, const char* ev, const uint8_t* d, size_t n, bool b64) {
    size_t off = 0;
    while (off < n) {
        size_t len = n - off < STREAM_CHUNK ? n - off : STREAM_CHUNK;
        if (!b64 && off + len < n)  // do not split a UTF-8 sequence across events
            for (int back = 0; back < 3 && len > 1 && (d[off + len] & 0xC0) == 0x80; back++) len--;
        jbuf_t b;
        jb_init(&b);
        jb_raw(&b, "{\"data\":");
        jb_stream_text(&b, d + off, len, b64);
        jb_fmt(&b, ",\"encoding\":\"%s\"}", b64 ? "base64" : "utf8");
        if (!b.oom) sse_event(r, ev, b.p);
        jb_free(&b);
        off += len;
    }
}

static void h_exec(rq_t* r, api_session_t* x) {
    struct api_server* s = r->c->srv;
    static const char* const fields[] = { "command", "argv", "cwd", "env", "timeout_ms", "max_output",
                                          "stdin", "stdin_base64", "output_encoding", "stream", NULL };
    jv_t* v = NULL;
    char** argv = NULL;
    char** env = NULL;
    uint8_t* in = NULL;
    int slot = -1;
    if (body_json(r, &v) < 0) return;
    if (only_fields(r, v, fields) < 0) goto out;

    const char *command = NULL, *cwd = NULL, *enc = NULL, *stdin_s = NULL, *stdin_b = NULL;
    int64_t timeout = 0, maxout = 0;
    bool stream = false;
    if (json_get_str(v, "command", &command) < 0) { bad_type(r, "command", "a string"); goto out; }
    if (json_get_str(v, "cwd", &cwd) < 0) { bad_type(r, "cwd", "a string"); goto out; }
    if (json_get_str(v, "output_encoding", &enc) < 0 || (enc && strcmp(enc, "utf8") && strcmp(enc, "base64"))) { bad_type(r, "output_encoding", "\"utf8\" or \"base64\""); goto out; }
    if (json_get_str(v, "stdin", &stdin_s) < 0) { bad_type(r, "stdin", "a string"); goto out; }
    if (json_get_str(v, "stdin_base64", &stdin_b) < 0) { bad_type(r, "stdin_base64", "a string"); goto out; }
    if (json_get_int(v, "timeout_ms", &timeout) < 0 || timeout < 0 || timeout > 3600000) { bad_type(r, "timeout_ms", "an integer from 0 to 3600000"); goto out; }
    if (json_get_int(v, "max_output", &maxout) < 0 || maxout < 0 || maxout > 4 * 1024 * 1024) { bad_type(r, "max_output", "an integer from 0 to 4194304"); goto out; }
    if (json_get_bool(v, "stream", &stream) < 0) { bad_type(r, "stream", "a boolean"); goto out; }
    const char* accept = http_get_header(r->req, "Accept");
    if (accept && strstr(accept, "text/event-stream")) stream = true;
    bool b64 = enc && !strcmp(enc, "base64");

    const jv_t* av = json_get(v, "argv");
    if ((command != NULL) == (av && av->type != J_NULL)) {
        respond_error(r, 400, "invalid_field", "give exactly one of \"command\" (a shell script) or \"argv\" (an array)");
        goto out;
    }
    if (command) {
        argv = calloc(2, sizeof(*argv));
        if (!argv || !(argv[0] = strdup(command)) || strlen(command) == 0) { respond_error(r, 400, "invalid_field", "\"command\" must not be empty"); goto out; }
    } else {
        if (av->type != J_ARR || av->n == 0 || av->n > 256) { bad_type(r, "argv", "a non-empty array of strings"); goto out; }
        argv = calloc(av->n + 1, sizeof(*argv));
        for (size_t i = 0; argv && i < av->n; i++) {
            const jv_t* e = av->items[i];
            if (e->type != J_STR || strlen(e->s) != e->slen || (i == 0 && e->slen == 0)) { bad_type(r, "argv", "an array of strings"); goto out; }
            argv[i] = strdup(e->s);
        }
    }
    const jv_t* ev = json_get(v, "env");
    if (ev && ev->type != J_NULL) {
        if (ev->type != J_OBJ || ev->n > MAX_ENV_VARS) { bad_type(r, "env", "an object of at most 64 string values"); goto out; }
        env = calloc(ev->n + 1, sizeof(*env));
        for (size_t i = 0; env && i < ev->n; i++) {
            const char* k = ev->keys[i];
            const jv_t* val = ev->items[i];
            int ok = val->type == J_STR && strlen(val->s) == val->slen && strlen(k) <= 64 && (isalpha((unsigned char)k[0]) || k[0] == '_');
            for (const char* c = k; ok && *c; c++) if (!isalnum((unsigned char)*c) && *c != '_') ok = 0;
            if (!ok) { bad_type(r, "env", "an object of NAME: string"); goto out; }
            size_t n = strlen(k) + val->slen + 2;
            env[i] = malloc(n);
            if (env[i]) snprintf(env[i], n, "%s=%s", k, val->s);
        }
    }
    size_t in_len = 0;
    if (stdin_s && stdin_b) { respond_error(r, 400, "invalid_field", "give \"stdin\" or \"stdin_base64\", not both"); goto out; }
    if (stdin_s) { in_len = strlen(stdin_s); in = (uint8_t*)strdup(stdin_s); }
    if (stdin_b) {
        size_t bl = strlen(stdin_b);
        in = malloc(bl / 4 * 3 + 3);
        ssize_t d = in ? b64_decode(stdin_b, bl, in) : -1;
        if (d < 0) { bad_type(r, "stdin_base64", "valid base64"); goto out; }
        in_len = (size_t)d;
    }
    if (in_len > 64 * 1024) { respond_error(r, 413, "too_large", "stdin is limited to 64 KiB"); goto out; }

    // Idempotency-Key: a retry of the same request returns the first answer
    // instead of running the command twice. Not offered for streams (nothing to
    // replay into an event stream).
    const char* ik = http_get_header(r->req, "Idempotency-Key");
    if (ik && !stream) {
        if (!name_chars(ik, 128, "._:@-=+/")) { respond_error(r, 400, "invalid_header", "Idempotency-Key must be 1-128 plain characters"); goto out; }
        uint8_t sha[32];
        sha256(r->body, r->body_len, sha);
        int st = 0; char* rb = NULL; size_t rl = 0;
        int ir = idem_begin(s, r->who, x->id, ik, sha, &slot, &st, &rb, &rl);
        if (ir == IDEM_REPLAY) {
            respond(r, st, "application/json", rb, rl, "Idempotent-Replay: true\r\n");
            free(rb);
            goto out;
        }
        if (ir == IDEM_BUSY) { respond_error(r, 409, "request_in_progress", "a request with this Idempotency-Key is still running"); goto out; }
        if (ir == IDEM_MISMATCH) { respond_error(r, 422, "idempotency_key_reused", "this Idempotency-Key was used with a different request"); goto out; }
    }

    sandbox_handle_t* h = NULL;
    sandbox_error_t er = sess_acquire(s, x, &h);
    if (er != SANDBOX_OK) {
        if (slot >= 0) idem_finish(s, slot, 503, "", 0);
        respond_engine_error(r, er);
        goto out;
    }
    exec_job_t j;
    memset(&j, 0, sizeof(j));
    pthread_mutex_init(&j.mu, NULL);
    pthread_cond_init(&j.cv, NULL);
    j.srv = s;
    j.h = h;
    j.spec = (sandbox_exec_spec_t){ .argv = (const char* const*)argv, .shell = command != NULL, .cwd = cwd,
                                    .env = (const char* const*)env, .timeout_ms = (uint32_t)timeout,
                                    .max_output = (uint32_t)maxout, .stdin_data = in, .stdin_len = in_len };

    if (!stream) {
        exec_thread(&j);
    } else {
        pthread_t t;
        if (pthread_create(&t, NULL, exec_thread, &j) != 0) {
            sess_release(s, x);
            respond_error(r, 503, "capacity", "cannot start the command");
            goto out;
        }
        // The engine returns a command's output when the command ends, so what
        // streams is the lifecycle -- started, output, exit -- plus keepalives so
        // a long command does not look like a dead connection to a proxy.
        r->keepalive = 0;
        send_head(r, 200, "text/event-stream", -1, "X-Accel-Buffering: no\r\n");
        char d[200];
        snprintf(d, sizeof(d), "{\"session\":\"%s\",\"request_id\":\"%s\"}", x->id, r->rid);
        sse_event(r, "started", d);
        pthread_mutex_lock(&j.mu);
        while (!j.done) {
            struct timespec dl;
            clock_gettime(CLOCK_REALTIME, &dl);
            dl.tv_sec += s->cfg.keepalive_seconds;
            if (pthread_cond_timedwait(&j.cv, &j.mu, &dl) != 0 && !j.done) {
                if (write_all(r->c->fd, ": keepalive\n\n", 13) < 0) break;  // client left; still join below
            }
        }
        pthread_mutex_unlock(&j.mu);
        pthread_join(t, NULL);
        if (j.rc == SANDBOX_OK) {
            sse_stream(r, "stdout", j.res.out, j.res.out_len, b64);
            sse_stream(r, "stderr", j.res.err, j.res.err_len, b64);
            // The final event carries the totals without re-sending the output.
            jbuf_t e;
            jb_init(&e);
            jb_fmt(&e, "{\"exit_code\":%d,\"term_signal\":%d,\"timed_out\":%s,\"output_truncated\":%s,\"duration_ms\":%lld,\"stdout_bytes\":%llu,\"stderr_bytes\":%llu}",
                   j.res.exit_code, j.res.term_signal, j.res.timed_out ? "true" : "false",
                   j.res.output_truncated ? "true" : "false", j.ms, (unsigned long long)j.res.out_total,
                   (unsigned long long)j.res.err_total);
            if (!e.oom) sse_event(r, "exit", e.p);
            jb_free(&e);
            s->eng->exec_free(&j.res);
        } else {
            int st; const char* code;
            map_err(j.rc, &st, &code);
            jbuf_t b;
            jb_init(&b);
            jb_raw(&b, "{\"code\":");
            jb_cstr(&b, code);
            jb_raw(&b, ",\"message\":");
            jb_cstr(&b, sandbox_error_string(j.rc));
            jb_raw(&b, "}");
            if (!b.oom) sse_event(r, "error", b.p);
            jb_free(&b);
        }
        sess_release(s, x);
        pthread_mutex_destroy(&j.mu);
        pthread_cond_destroy(&j.cv);
        goto out;
    }

    sess_release(s, x);
    if (j.rc != SANDBOX_OK) {
        if (slot >= 0) idem_finish(s, slot, 500, "", 0);
        respond_engine_error(r, j.rc);
    } else {
        jbuf_t b;
        jb_init(&b);
        jb_exec_result(&b, &j, b64);
        s->eng->exec_free(&j.res);
        if (slot >= 0 && !b.oom) idem_finish(s, slot, 200, b.p, b.len);
        respond_json(r, 200, &b, NULL);
    }
    pthread_mutex_destroy(&j.mu);
    pthread_cond_destroy(&j.cv);
    json_free(v);
    free_strv(argv);
    free_strv(env);
    free(in);
    return;
out:
    if (slot >= 0 && s->idem[slot].state == 1) idem_finish(s, slot, 500, "", 0);
    json_free(v);
    free_strv(argv);
    free_strv(env);
    free(in);
}

// ---- files -----------------------------------------------------------------

static int need_path(rq_t* r, char* path, size_t cap) {
    int q = qget(r, "path", path, cap);
    if (q != 1 || path[0] == '\0') {
        respond_error(r, 400, "invalid_field", "the \"path\" query parameter is required (absolute, under /workspace)");
        return -1;
    }
    return 0;
}

static void h_file_get(rq_t* r, api_session_t* x) {
    char path[MAX_PATH_QUERY];
    if (need_path(r, path, sizeof(path)) < 0) return;
    sandbox_handle_t* h;
    sandbox_error_t er = sess_acquire(r->c->srv, x, &h);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); return; }
    uint8_t* data = NULL;
    size_t len = 0;
    er = r->c->srv->eng->read_file(h, path, &data, &len);
    sess_release(r->c->srv, x);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); return; }
    respond(r, 200, "application/octet-stream", data, len, "Content-Disposition: attachment\r\n");
    free(data);
}

static void h_file_put(rq_t* r, api_session_t* x) {
    char path[MAX_PATH_QUERY], mode[16];
    if (need_path(r, path, sizeof(path)) < 0) return;
    uint32_t flags = 0, m = 0;
    if (qflag(r, "append")) flags |= SANDBOX_WRITE_APPEND;
    if (qflag(r, "exclusive")) flags |= SANDBOX_WRITE_EXCL;
    if (qflag(r, "parents")) flags |= SANDBOX_WRITE_PARENTS;
    int q = qget(r, "mode", mode, sizeof(mode));
    if (q < 0 || (q == 1 && (strlen(mode) == 0 || strspn(mode, "01234567") != strlen(mode) || (m = (uint32_t)strtoul(mode, NULL, 8)) > 0777))) {
        respond_error(r, 400, "invalid_field", "\"mode\" must be octal permission bits, e.g. 644");
        return;
    }
    sandbox_handle_t* h;
    sandbox_error_t er = sess_acquire(r->c->srv, x, &h);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); return; }
    er = r->c->srv->eng->write_file(h, path, r->body, r->body_len, m, flags);
    sess_release(r->c->srv, x);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); return; }
    jbuf_t b;
    jb_init(&b);
    jb_raw(&b, "{\"path\":");
    jb_cstr(&b, path);
    jb_fmt(&b, ",\"bytes\":%zu}", r->body_len);
    respond_json(r, 200, &b, NULL);
}

static void h_file_delete(rq_t* r, api_session_t* x) {
    char path[MAX_PATH_QUERY];
    if (need_path(r, path, sizeof(path)) < 0) return;
    sandbox_handle_t* h;
    sandbox_error_t er = sess_acquire(r->c->srv, x, &h);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); return; }
    er = r->c->srv->eng->remove(h, path, qflag(r, "recursive"));
    sess_release(r->c->srv, x);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); return; }
    respond(r, 204, NULL, NULL, 0, NULL);
}

static const char* type_name(unsigned t) {
    return t == 1 ? "file" : t == 2 ? "dir" : t == 3 ? "symlink" : "other";
}

static void h_stat(rq_t* r, api_session_t* x) {
    char path[MAX_PATH_QUERY];
    if (need_path(r, path, sizeof(path)) < 0) return;
    sandbox_handle_t* h;
    sandbox_error_t er = sess_acquire(r->c->srv, x, &h);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); return; }
    sandbox_fstat_t st;
    er = r->c->srv->eng->stat(h, path, &st);
    sess_release(r->c->srv, x);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); return; }
    jbuf_t b;
    jb_init(&b);
    jb_raw(&b, "{\"path\":");
    jb_cstr(&b, path);
    jb_fmt(&b, ",\"type\":\"%s\",\"size\":%llu,\"mode\":\"%o\",\"mtime\":%lld}", type_name(st.type),
           (unsigned long long)st.size, st.mode & 07777, (long long)st.mtime);
    respond_json(r, 200, &b, NULL);
}

static void h_ls(rq_t* r, api_session_t* x) {
    char path[MAX_PATH_QUERY];
    if (need_path(r, path, sizeof(path)) < 0) return;
    sandbox_handle_t* h;
    sandbox_error_t er = sess_acquire(r->c->srv, x, &h);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); return; }
    sandbox_dirent_t* ents = NULL;
    size_t n = 0;
    bool trunc = false;
    er = r->c->srv->eng->list_dir(h, path, &ents, &n, &trunc);
    sess_release(r->c->srv, x);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); return; }
    jbuf_t b;
    jb_init(&b);
    jb_raw(&b, "{\"path\":");
    jb_cstr(&b, path);
    jb_raw(&b, ",\"entries\":[");
    for (size_t i = 0; i < n; i++) {
        if (i) jb_raw(&b, ",");
        jb_raw(&b, "{\"name\":");
        jb_cstr(&b, ents[i].name);
        jb_fmt(&b, ",\"type\":\"%s\",\"size\":%llu,\"mtime\":%lld}", type_name(ents[i].type),
               (unsigned long long)ents[i].size, (long long)ents[i].mtime);
    }
    jb_fmt(&b, "],\"truncated\":%s}", trunc ? "true" : "false");
    free(ents);
    respond_json(r, 200, &b, NULL);
}

static void h_mkdir(rq_t* r, api_session_t* x) {
    static const char* const fields[] = { "path", "parents", "mode", NULL };
    jv_t* v = NULL;
    if (body_json(r, &v) < 0) return;
    const char* path = NULL;
    bool parents = false;
    int64_t mode = 0;
    if (only_fields(r, v, fields) < 0) goto out;
    if (json_get_str(v, "path", &path) != 0 || !*path) { bad_type(r, "path", "a path string"); goto out; }
    if (json_get_bool(v, "parents", &parents) < 0) { bad_type(r, "parents", "a boolean"); goto out; }
    if (json_get_int(v, "mode", &mode) < 0 || mode < 0 || mode > 0777) { bad_type(r, "mode", "an integer of permission bits (e.g. 493 for 0755)"); goto out; }
    sandbox_handle_t* h;
    sandbox_error_t er = sess_acquire(r->c->srv, x, &h);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); goto out; }
    er = r->c->srv->eng->mkdir(h, path, (uint32_t)mode, parents);
    sess_release(r->c->srv, x);
    if (er != SANDBOX_OK) { respond_engine_error(r, er); goto out; }
    respond(r, 204, NULL, NULL, 0, NULL);
out:
    json_free(v);
}

// ---- routing ---------------------------------------------------------------

static void method_not_allowed(rq_t* r, const char* allow) {
    char h[96];
    snprintf(h, sizeof(h), "Allow: %s\r\n", allow);
    jbuf_t b;
    jb_init(&b);
    jb_fmt(&b, "{\"error\":{\"code\":\"method_not_allowed\",\"message\":\"allowed: %s\"},\"request_id\":\"%s\"}", allow, r->rid);
    respond_json(r, 405, &b, h);
}

static void route(rq_t* r) {
    const char* m = r->req->method;
    char* path = r->path;
    if (strncmp(path, "/v1/", 4) != 0) { respond_error(r, 404, "not_found", "no such route"); return; }
    path += 3;  // "/..."

    if (!strcmp(path, "/health")) {
        if (strcmp(m, "GET")) { method_not_allowed(r, "GET"); return; }
        h_health(r);
        return;
    }
    if (!strcmp(path, "/sessions")) {
        if (!strcmp(m, "POST")) h_create(r);
        else if (!strcmp(m, "GET")) h_list(r);
        else method_not_allowed(r, "GET, POST");
        return;
    }
    if (strncmp(path, "/sessions/", 10) != 0) { respond_error(r, 404, "not_found", "no such route"); return; }
    char* id = path + 10;
    char* sub = strchr(id, '/');
    if (sub) *sub++ = '\0';
    struct api_server* s = r->c->srv;
    if (!*id || strlen(id) > 31) { respond_error(r, 404, "session_not_found", "no such session"); return; }

    api_session_t* x = sess_find(s, id, r->who);
    if (!x) { respond_error(r, 404, "session_not_found", "no such session"); return; }
    if (!sub) {
        if (!strcmp(m, "GET")) h_get(r, x);
        else if (!strcmp(m, "DELETE")) h_delete(r, x);
        else method_not_allowed(r, "GET, DELETE");
    } else if (!strcmp(sub, "exec")) {
        if (strcmp(m, "POST")) method_not_allowed(r, "POST"); else h_exec(r, x);
    } else if (!strcmp(sub, "renew")) {
        if (strcmp(m, "POST")) method_not_allowed(r, "POST"); else h_renew(r, x);
    } else if (!strcmp(sub, "files")) {
        if (!strcmp(m, "GET")) h_file_get(r, x);
        else if (!strcmp(m, "PUT")) h_file_put(r, x);
        else if (!strcmp(m, "DELETE")) h_file_delete(r, x);
        else method_not_allowed(r, "GET, PUT, DELETE");
    } else if (!strcmp(sub, "stat")) {
        if (strcmp(m, "GET")) method_not_allowed(r, "GET"); else h_stat(r, x);
    } else if (!strcmp(sub, "ls")) {
        if (strcmp(m, "GET")) method_not_allowed(r, "GET"); else h_ls(r, x);
    } else if (!strcmp(sub, "mkdir")) {
        if (strcmp(m, "POST")) method_not_allowed(r, "POST"); else h_mkdir(r, x);
    } else {
        respond_error(r, 404, "not_found", "no such route");
    }
    sess_unref(s, x);
}

// ---- connections -----------------------------------------------------------

static int valid_rid(const char* s) {
    size_t n = strlen(s);
    if (n == 0 || n > 64) return 0;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && !strchr("._-", s[i])) return 0;
    return 1;
}

static int read_body(rq_t* r, size_t max) {
    const char* te = http_get_header(r->req, "Transfer-Encoding");
    if (te) {
        r->keepalive = 0;
        respond_error(r, 501, "chunked_unsupported", "send a Content-Length instead of chunked encoding");
        return -1;
    }
    // Two different Content-Length headers is a smuggling attempt, not a request.
    const char* cl = NULL;
    for (size_t i = 0; i < r->req->nheaders; i++) {
        if (strcasecmp(r->req->headers[i].name, "Content-Length")) continue;
        if (cl && strcmp(cl, r->req->headers[i].value)) {
            r->keepalive = 0;
            respond_error(r, 400, "bad_request", "conflicting Content-Length headers");
            return -1;
        }
        cl = r->req->headers[i].value;
    }
    if (!cl) return 0;
    char* e;
    errno = 0;
    unsigned long long n = strtoull(cl, &e, 10);
    if (*cl == '\0' || *e || errno || !isdigit((unsigned char)*cl)) {
        r->keepalive = 0;
        respond_error(r, 400, "bad_request", "invalid Content-Length");
        return -1;
    }
    if (n > max) {
        r->keepalive = 0;
        respond_error(r, 413, "too_large", "the request body is too large for this endpoint");
        return -1;
    }
    const char* ex = http_get_header(r->req, "Expect");
    if (ex && !strcasecmp(ex, "100-continue") && n) write_all(r->c->fd, "HTTP/1.1 100 Continue\r\n\r\n", 25);
    r->body = malloc(n + 1);
    if (!r->body) { r->keepalive = 0; respond_error(r, 500, "internal", "out of memory"); return -1; }
    size_t got = 0;
    while (got < n) {
        ssize_t k = recv(r->c->fd, r->body + got, n - got, 0);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) { r->keepalive = 0; return -1; }  // short body: drop the connection
        got += (size_t)k;
    }
    r->body[n] = '\0';
    r->body_len = n;
    return 0;
}

static void authenticate(rq_t* r) {
    if (r->c->is_unix) {
        auth_for_uid(r->c->srv->auth, r->c->uid, &r->uid_principal);
        r->principal = &r->uid_principal;
        snprintf(r->who, sizeof(r->who), "%s", r->uid_principal.name);
        return;
    }
    const char* a = http_get_header(r->req, "Authorization");
    if (a && !strncasecmp(a, "Bearer ", 7)) {
        const api_principal_t* p = auth_by_token(r->c->srv->auth, a + 7);
        if (p) {
            r->principal = p;
            snprintf(r->who, sizeof(r->who), "%s", p->name);
        }
    }
}

static void serve_conn(conn_t* c) {
    struct api_server* s = c->srv;
    struct timeval tv = { .tv_sec = 30 };
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    http_request_t* req = malloc(sizeof(*req));
    if (!req) return;
    while (!__atomic_load_n(&s->stopping, __ATOMIC_ACQUIRE)) {
        rq_t r;
        memset(&r, 0, sizeof(r));
        r.c = c;
        r.req = req;
        r.keepalive = 1;
        if (http_parse_headers(c->fd, req) < 0) break;
        clock_gettime(CLOCK_MONOTONIC, &r.t0);
        const char* rid = http_get_header(req, "X-Request-Id");
        if (rid && valid_rid(rid)) snprintf(r.rid, sizeof(r.rid), "%s", rid);
        else { memcpy(r.rid, "req_", 4); rand_hex(r.rid + 4, 8); }
        const char* conn_h = http_get_header(req, "Connection");
        if ((conn_h && !strcasecmp(conn_h, "close")) || strcmp(req->version, "HTTP/1.1") != 0) r.keepalive = 0;

        snprintf(r.path, sizeof(r.path), "%s", req->target);
        r.query = strchr(r.path, '?');
        if (r.query) *r.query++ = '\0';

        int is_health = !strcmp(r.path, "/v1/health");
        if (!is_health) authenticate(&r);
        if (!is_health && !r.principal) {
            respond_error(&r, 401, "unauthorized", "a valid bearer token is required");
            r.keepalive = 0;  // the body (if any) was not read
        } else {
            size_t max = MAX_JSON_BODY;
            size_t pl = strlen(r.path);
            if (!strcmp(req->method, "PUT") && pl >= 6 && !strcmp(r.path + pl - 6, "/files")) max = SANDBOX_MAX_FILE;
            if (read_body(&r, max) == 0) route(&r);
        }
        long long ms = (long long)((mono_ms() - ((long long)r.t0.tv_sec * 1000 + r.t0.tv_nsec / 1000000)));
        LOGF(LOG_INFO, "http_api", "request", "\"rid\":\"%s\",\"principal\":\"%s\",\"method\":\"%s\",\"path\":\"%.80s\",\"status\":%d,\"ms\":%lld",
             r.rid, r.principal ? r.who : "-", req->method, r.path, r.status, ms);
        free(r.body);
        if (!r.keepalive) break;
    }
    free(req);
}

typedef struct {
    conn_t c;
} conn_arg_t;

static void conn_unregister(struct api_server* s, int fd) {
    pthread_mutex_lock(&s->mu);
    for (unsigned i = 0; i < s->n_conns; i++) {
        if (s->conn_fds[i] == fd) { s->conn_fds[i] = s->conn_fds[--s->n_conns]; break; }
    }
    pthread_cond_broadcast(&s->conns_cv);
    pthread_mutex_unlock(&s->mu);
}

static void* conn_thread(void* a) {
    conn_arg_t* ca = a;
    serve_conn(&ca->c);
    conn_unregister(ca->c.srv, ca->c.fd);
    close(ca->c.fd);
    free(ca);
    return NULL;
}

typedef struct {
    struct api_server* srv;
    int which;  // 0 unix, 1 tcp
} accept_arg_t;

static void* accept_thread(void* a) {
    accept_arg_t* aa = a;
    struct api_server* s = aa->srv;
    int lfd = aa->which == 0 ? s->unix_fd : s->tcp_fd;
    bool is_unix = aa->which == 0;
    free(aa);
    while (!__atomic_load_n(&s->stopping, __ATOMIC_ACQUIRE)) {
        struct pollfd p[2] = { { .fd = lfd, .events = POLLIN }, { .fd = s->wake[0], .events = POLLIN } };
        if (poll(p, 2, -1) < 0) { if (errno == EINTR) continue; break; }
        if (p[1].revents) break;
        if (!(p[0].revents & POLLIN)) continue;
        int fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) continue;
        conn_arg_t* ca = calloc(1, sizeof(*ca));
        if (!ca) { close(fd); continue; }
        ca->c.srv = s;
        ca->c.fd = fd;
        ca->c.is_unix = is_unix;
        ca->c.uid = (uid_t)-1;
        if (is_unix) {
            struct ucred cred;
            socklen_t cl = sizeof(cred);
            if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cl) < 0) { close(fd); free(ca); continue; }
            ca->c.uid = cred.uid;
        } else {
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        }
        pthread_mutex_lock(&s->mu);
        int full = s->n_conns >= s->cfg.max_connections;
        if (!full) s->conn_fds[s->n_conns++] = fd;
        pthread_mutex_unlock(&s->mu);
        if (full) {
            static const char busy[] = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(fd, busy, sizeof(busy) - 1, MSG_NOSIGNAL);
            close(fd);
            free(ca);
            continue;
        }
        pthread_t t;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &at, conn_thread, ca) != 0) {
            conn_unregister(s, fd);
            close(fd);
            free(ca);
        }
        pthread_attr_destroy(&at);
    }
    return NULL;
}

static void* reaper_thread(void* a) {
    struct api_server* s = a;
    while (!__atomic_load_n(&s->stopping, __ATOMIC_ACQUIRE)) {
        struct pollfd p = { .fd = s->wake[0], .events = POLLIN };
        if (poll(&p, 1, 1000) > 0) break;
        sess_reap_once(s);
        pthread_mutex_lock(&s->mu);  // expire finished idempotency records
        time_t now = time(NULL);
        for (int i = 0; i < API_MAX_IDEM; i++)
            if (s->idem[i].state == 2 && now - s->idem[i].when > IDEM_TTL_S) { free(s->idem[i].body); memset(&s->idem[i], 0, sizeof(s->idem[i])); }
        pthread_mutex_unlock(&s->mu);
    }
    return NULL;
}

// ---- start / stop ----------------------------------------------------------

static int is_loopback(const char* host) {
    struct in_addr a4;
    struct in6_addr a6;
    if (!strcmp(host, "localhost")) return 1;
    if (inet_pton(AF_INET, host, &a4) == 1) return (ntohl(a4.s_addr) >> 24) == 127;
    if (inet_pton(AF_INET6, host, &a6) == 1) return IN6_IS_ADDR_LOOPBACK(&a6);
    return 0;
}

static int listen_unix(struct api_server* s) {
    const char* path = s->cfg.unix_path;
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    if (strlen(path) >= sizeof(a.sun_path)) { fprintf(stderr, "sandbox-api: socket path too long\n"); return -1; }
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) { fprintf(stderr, "sandbox-api: %s exists and is not a socket\n", path); return -1; }
        unlink(path);  // a stale socket from a previous run
    }
    strcpy(a.sun_path, path);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    mode_t old = umask(0177);  // created 0600, widened below
    int rc = bind(fd, (struct sockaddr*)&a, sizeof(a));
    umask(old);
    if (rc < 0 || chmod(path, s->cfg.unix_mode ? s->cfg.unix_mode : 0660) < 0 || listen(fd, 64) < 0) {
        fprintf(stderr, "sandbox-api: %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    s->unix_fd = fd;
    return 0;
}

static int listen_tcp(struct api_server* s) {
    const char* host = s->cfg.tcp_host;
    if (!is_loopback(host) && !s->cfg.allow_public_bind) {
        fprintf(stderr, "sandbox-api: %s is not a loopback address. The API speaks plain HTTP; put TLS in front of it "
                        "(a reverse proxy) and bind loopback, or pass --allow-public-bind if you have.\n", host);
        return -1;
    }
    if (auth_count_tokens(s->auth) == 0) {
        fprintf(stderr, "sandbox-api: a TCP listener needs at least one token in --tokens (TCP callers have no uid to identify them)\n");
        return -1;
    }
    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in* a4 = (struct sockaddr_in*)&ss;
    struct sockaddr_in6* a6 = (struct sockaddr_in6*)&ss;
    const char* h = strcmp(host, "localhost") ? host : "127.0.0.1";
    if (inet_pton(AF_INET, h, &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port = htons((uint16_t)s->cfg.tcp_port);
        sl = sizeof(*a4);
    } else if (inet_pton(AF_INET6, h, &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons((uint16_t)s->cfg.tcp_port);
        sl = sizeof(*a6);
    } else {
        fprintf(stderr, "sandbox-api: %s is not an IP address\n", host);
        return -1;
    }
    int fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr*)&ss, sl) < 0 || listen(fd, 128) < 0) {
        fprintf(stderr, "sandbox-api: %s:%d: %s\n", host, s->cfg.tcp_port, strerror(errno));
        close(fd);
        return -1;
    }
    sl = sizeof(ss);
    getsockname(fd, (struct sockaddr*)&ss, &sl);
    s->tcp_port = ntohs(ss.ss_family == AF_INET ? a4->sin_port : a6->sin6_port);
    s->tcp_fd = fd;
    return 0;
}

api_server_t* api_server_start(const api_config_t* cfg) {
    struct api_server* s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->cfg = *cfg;
    if (!s->cfg.default_memory_mib) s->cfg.default_memory_mib = 256;
    if (!s->cfg.default_vcpus) s->cfg.default_vcpus = 1;
    if (!s->cfg.max_running) s->cfg.max_running = 64;
    if (!s->cfg.max_sessions_total) s->cfg.max_sessions_total = 256;
    if (!s->cfg.max_sessions_default) s->cfg.max_sessions_default = 16;
    if (!s->cfg.idle_vm_seconds) s->cfg.idle_vm_seconds = 300;
    if (!s->cfg.max_connections) s->cfg.max_connections = 128;
    if (!s->cfg.keepalive_seconds) s->cfg.keepalive_seconds = 10;
    s->eng = cfg->engine ? cfg->engine : &api_engine_libsandbox;
    snprintf(s->default_template, sizeof(s->default_template), "%s", cfg->default_template ? cfg->default_template : "python-agent");
    s->unix_fd = s->tcp_fd = -1;
    s->wake[0] = s->wake[1] = -1;
    pthread_mutex_init(&s->mu, NULL);
    pthread_cond_init(&s->conns_cv, NULL);
    s->conn_fds = calloc(s->cfg.max_connections, sizeof(int));

    char err[256] = "";
    s->auth = auth_load(cfg->tokens_path, err, sizeof(err));
    if (!s->auth) { fprintf(stderr, "sandbox-api: %s\n", err); goto fail; }
    if (!cfg->unix_path && !cfg->tcp_host) { fprintf(stderr, "sandbox-api: give a Unix socket path, a TCP address, or both\n"); goto fail; }
    if (pipe2(s->wake, O_CLOEXEC) < 0 || !s->conn_fds) goto fail;
    if (cfg->tcp_host && listen_tcp(s) < 0) goto fail;
    if (cfg->unix_path && listen_unix(s) < 0) goto fail;

    for (int i = 0; i < 2; i++) {
        int fd = i == 0 ? s->unix_fd : s->tcp_fd;
        if (fd < 0) continue;
        accept_arg_t* aa = malloc(sizeof(*aa));
        aa->srv = s;
        aa->which = i;
        if (pthread_create(&s->t_accept[i], NULL, accept_thread, aa) != 0) { free(aa); goto fail; }
        s->accept_started[i] = 1;
    }
    if (pthread_create(&s->t_reaper, NULL, reaper_thread, s) != 0) goto fail;
    s->reaper_started = 1;
    LOGF(LOG_INFO, "http_api", "listening", "\"unix\":\"%s\",\"tcp_port\":%d,\"tokens\":%zu",
         cfg->unix_path ? cfg->unix_path : "", s->tcp_port, auth_count_tokens(s->auth));
    return s;
fail:
    api_server_stop(s);
    return NULL;
}

int api_server_tcp_port(const api_server_t* s) { return s->tcp_port; }
unsigned api_server_running(const api_server_t* s) {
    pthread_mutex_lock((pthread_mutex_t*)&s->mu);
    unsigned n = s->n_running;
    pthread_mutex_unlock((pthread_mutex_t*)&s->mu);
    return n;
}

unsigned api_server_sessions(const api_server_t* s) {
    pthread_mutex_lock((pthread_mutex_t*)&s->mu);
    unsigned n = s->n_sessions;
    pthread_mutex_unlock((pthread_mutex_t*)&s->mu);
    return n;
}

void api_server_stop(api_server_t* s) {
    if (!s) return;
    __atomic_store_n(&s->stopping, 1, __ATOMIC_RELEASE);
    if (s->wake[1] >= 0) { char c = 1; if (write(s->wake[1], &c, 1) < 0) { /* the loops also poll stopping */ } }
    for (int i = 0; i < 2; i++)
        if (s->accept_started[i]) pthread_join(s->t_accept[i], NULL);
    if (s->reaper_started) pthread_join(s->t_reaper, NULL);
    if (s->unix_fd >= 0) { close(s->unix_fd); if (s->cfg.unix_path) unlink(s->cfg.unix_path); }
    if (s->tcp_fd >= 0) close(s->tcp_fd);
    // Wake every connection thread out of its read, then wait for them to go.
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += 15;
    pthread_mutex_lock(&s->mu);
    for (unsigned i = 0; i < s->n_conns; i++) shutdown(s->conn_fds[i], SHUT_RDWR);
    while (s->n_conns && pthread_cond_timedwait(&s->conns_cv, &s->mu, &dl) == 0) {}
    pthread_mutex_unlock(&s->mu);
    sess_shutdown_all(s);
    if (s->wake[0] >= 0) { close(s->wake[0]); close(s->wake[1]); }
    for (int i = 0; i < API_MAX_IDEM; i++) free(s->idem[i].body);
    auth_free(s->auth);
    free(s->conn_fds);
    pthread_mutex_destroy(&s->mu);
    pthread_cond_destroy(&s->conns_cv);
    free(s);
}
