// SPDX-License-Identifier: GPL-2.0-only
// #27: the control-plane HTTP API, end to end over real sockets, against an
// in-memory fake engine (so it needs no root, no KVM and no daemon). What it
// proves is everything *above* the engine: auth, isolation, determinism,
// idempotency, framing, streaming, limits, lifecycle and error mapping. That the
// real engine honours the same calls is tests/e2e/http_api.sh's job.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "http_api.h"
#include "json.h"
#include "sha256.h"

static int g_fail;
#define CHECK(c, m) do { if (c) printf("[test] %-70s PASS\n", m); else { printf("[test] %-70s FAIL\n", m); g_fail++; } } while (0)

// ---- the fake engine --------------------------------------------------------

typedef struct file { char path[256]; uint8_t* d; size_t n; int dir; struct file* next; } file_t;
typedef struct vol { char key[96]; file_t* files; time_t expires; struct vol* next; } vol_t;
struct sandbox_handle_t { vol_t* vol; };

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static vol_t* g_vols;
static int g_creates, g_destroys, g_live, g_execs;
static char g_last_template[64], g_last_env0[96], g_last_egress0[96];
static uint64_t g_last_mem;
static int g_last_deny;

static vol_t* vol_get(const char* key, int make) {
    for (vol_t* v = g_vols; v; v = v->next) if (!strcmp(v->key, key)) return v;
    if (!make) return NULL;
    vol_t* v = calloc(1, sizeof(*v));
    snprintf(v->key, sizeof(v->key), "%s", key);
    v->next = g_vols;
    g_vols = v;
    return v;
}

static file_t* file_get(vol_t* v, const char* p) {
    for (file_t* f = v->files; f; f = f->next) if (!strcmp(f->path, p)) return f;
    return NULL;
}

static int path_ok(const char* p) {
    return !strncmp(p, "/workspace", 10) && (p[10] == '\0' || p[10] == '/') && !strstr(p, "..");
}

static sandbox_error_t f_create(const sandbox_spec_t* s, sandbox_handle_t** out) {
    usleep(5000);
    if (!strcmp(s->template_name, "bogus")) return SANDBOX_ERR_INVALID_SPEC;
    if (!strcmp(s->template_name, "full")) return SANDBOX_ERR_POOL_EXHAUSTED;
    pthread_mutex_lock(&g_mu);
    g_creates++; g_live++;
    snprintf(g_last_template, sizeof(g_last_template), "%s", s->template_name);
    g_last_mem = s->memory_mib;
    g_last_env0[0] = g_last_egress0[0] = '\0';
    if (s->env_vars && s->env_vars[0]) snprintf(g_last_env0, sizeof(g_last_env0), "%s", s->env_vars[0]);
    if (s->egress_allow && s->egress_allow[0]) snprintf(g_last_egress0, sizeof(g_last_egress0), "%s", s->egress_allow[0]);
    g_last_deny = s->egress_deny_all;
    vol_t* v = vol_get(s->session_key, 1);
    v->expires = time(NULL) + (s->ttl_seconds ? s->ttl_seconds : 604800);
    sandbox_handle_t* h = calloc(1, sizeof(*h));
    h->vol = v;
    pthread_mutex_unlock(&g_mu);
    *out = h;
    return SANDBOX_OK;
}

static sandbox_error_t f_destroy(sandbox_handle_t* h) {
    pthread_mutex_lock(&g_mu);
    g_destroys++; g_live--;
    pthread_mutex_unlock(&g_mu);
    free(h);
    return SANDBOX_OK;
}

static sandbox_error_t f_renew(const char* key, uint32_t extra, uint64_t* exp) {
    pthread_mutex_lock(&g_mu);
    vol_t* v = vol_get(key, 0);
    if (!v) { pthread_mutex_unlock(&g_mu); return SANDBOX_ERR_SESSION_UNKNOWN; }
    time_t now = time(NULL), e = now + (extra ? extra : 604800);
    if (e > now + 30 * 86400) e = now + 30 * 86400;
    if (e < v->expires) e = v->expires;  // never shortened
    v->expires = e;
    *exp = (uint64_t)e;
    pthread_mutex_unlock(&g_mu);
    return SANDBOX_OK;
}

static void put_out(sandbox_exec_result_t* r, const void* d, size_t n) {
    r->out = malloc(n ? n : 1);
    memcpy(r->out, d, n);
    r->out_len = n;
    r->out_total = n;
}

static sandbox_error_t f_exec(sandbox_handle_t* h, const sandbox_exec_spec_t* sp, sandbox_exec_result_t* r) {
    (void)h;
    pthread_mutex_lock(&g_mu);
    g_execs++;
    pthread_mutex_unlock(&g_mu);
    memset(r, 0, sizeof(*r));
    char cmd[512] = "";
    for (const char* const* a = sp->argv; *a; a++) { if (*cmd) strcat(cmd, " "); strncat(cmd, *a, sizeof(cmd) - strlen(cmd) - 1); }
    if (!strncmp(cmd, "echo ", 5)) { char b[512]; int n = snprintf(b, sizeof(b), "%s\n", cmd + 5); put_out(r, b, (size_t)n); }
    else if (!strncmp(cmd, "exit ", 5)) r->exit_code = atoi(cmd + 5);
    else if (!strncmp(cmd, "sleep ", 6)) usleep((useconds_t)atoi(cmd + 6) * 1000);
    else if (!strcmp(cmd, "bytes")) put_out(r, "ok\xff\xfe\n", 5);
    else if (!strcmp(cmd, "cat")) put_out(r, sp->stdin_data ? (const char*)sp->stdin_data : "", sp->stdin_len);
    else if (!strncmp(cmd, "env ", 4)) {
        char b[256] = "unset\n";
        size_t nl = strlen(cmd + 4);
        for (const char* const* e = sp->env; e && *e; e++)
            if (!strncmp(*e, cmd + 4, nl) && (*e)[nl] == '=') snprintf(b, sizeof(b), "%s\n", *e + nl + 1);
        put_out(r, b, strlen(b));
    } else if (!strcmp(cmd, "cwd")) { char b[128]; int n = snprintf(b, sizeof(b), "%s\n", sp->cwd ? sp->cwd : "/workspace"); put_out(r, b, (size_t)n); }
    else if (!strcmp(cmd, "shell?")) put_out(r, sp->shell ? "shell\n" : "argv\n", sp->shell ? 6 : 5);
    else if (!strncmp(cmd, "big ", 4)) { size_t n = (size_t)atol(cmd + 4); char* b = malloc(32768); memset(b, 'x', 32768); put_out(r, b, n < 32768 ? n : 32768); r->out_total = n; free(b); r->output_truncated = n > 4 * 1048576; }
    else if (!strcmp(cmd, "timeout")) { r->timed_out = true; r->exit_code = -1; }
    else if (!strncmp(cmd, "fail ", 5)) return (sandbox_error_t)(-atoi(cmd + 5));
    else if (!strcmp(cmd, "multi")) { put_out(r, "line1\nline2\n", 12); r->err = malloc(5); memcpy(r->err, "oops\n", 5); r->err_len = r->err_total = 5; }
    usleep(1000);
    return SANDBOX_OK;
}

static void f_exec_free(sandbox_exec_result_t* r) { free(r->out); free(r->err); r->out = r->err = NULL; }

static sandbox_error_t f_read(sandbox_handle_t* h, const char* p, uint8_t** d, size_t* n) {
    if (!path_ok(p)) return SANDBOX_ERR_PATH_DENIED;
    pthread_mutex_lock(&g_mu);
    file_t* f = file_get(h->vol, p);
    if (!f || f->dir) { pthread_mutex_unlock(&g_mu); return SANDBOX_ERR_NOT_FOUND; }
    *d = malloc(f->n ? f->n : 1);
    memcpy(*d, f->d, f->n);
    *n = f->n;
    pthread_mutex_unlock(&g_mu);
    return SANDBOX_OK;
}

static sandbox_error_t f_write(sandbox_handle_t* h, const char* p, const uint8_t* d, size_t n, uint32_t mode, uint32_t flags) {
    (void)mode;
    if (!path_ok(p)) return SANDBOX_ERR_PATH_DENIED;
    if (n > SANDBOX_MAX_FILE) return SANDBOX_ERR_TOO_LARGE;
    pthread_mutex_lock(&g_mu);
    file_t* f = file_get(h->vol, p);
    if (f && (flags & SANDBOX_WRITE_EXCL)) { pthread_mutex_unlock(&g_mu); return SANDBOX_ERR_EXISTS; }
    if (!f) {
        f = calloc(1, sizeof(*f));
        snprintf(f->path, sizeof(f->path), "%s", p);
        f->next = h->vol->files;
        h->vol->files = f;
    }
    if (flags & SANDBOX_WRITE_APPEND) {
        f->d = realloc(f->d, f->n + n + 1);
        memcpy(f->d + f->n, d, n);
        f->n += n;
    } else {
        free(f->d);
        f->d = malloc(n + 1);
        memcpy(f->d, d, n);
        f->n = n;
    }
    pthread_mutex_unlock(&g_mu);
    return SANDBOX_OK;
}

static const char* dirname_of(const char* p, char* buf, size_t cap) {
    snprintf(buf, cap, "%s", p);
    char* s = strrchr(buf, '/');
    if (s && s != buf) *s = '\0';
    return buf;
}

static sandbox_error_t f_list(sandbox_handle_t* h, const char* p, sandbox_dirent_t** out, size_t* n, bool* trunc) {
    if (!path_ok(p)) return SANDBOX_ERR_PATH_DENIED;
    pthread_mutex_lock(&g_mu);
    size_t cnt = 0;
    sandbox_dirent_t* e = calloc(64, sizeof(*e));
    for (file_t* f = h->vol->files; f && cnt < 64; f = f->next) {
        char d[256];
        dirname_of(f->path, d, sizeof(d));
        if (strcmp(d, p) != 0) continue;
        snprintf(e[cnt].name, sizeof(e[cnt].name), "%s", strrchr(f->path, '/') + 1);
        e[cnt].type = f->dir ? 2 : 1;
        e[cnt].size = f->n;
        cnt++;
    }
    pthread_mutex_unlock(&g_mu);
    *out = e; *n = cnt; *trunc = false;
    return SANDBOX_OK;
}

static sandbox_error_t f_stat(sandbox_handle_t* h, const char* p, sandbox_fstat_t* st) {
    if (!path_ok(p)) return SANDBOX_ERR_PATH_DENIED;
    memset(st, 0, sizeof(*st));
    if (!strcmp(p, "/workspace")) { st->type = 2; st->mode = 0755; return SANDBOX_OK; }
    pthread_mutex_lock(&g_mu);
    file_t* f = file_get(h->vol, p);
    if (f) { st->type = f->dir ? 2 : 1; st->size = f->n; st->mode = 0644; st->mtime = 1700000000; }
    pthread_mutex_unlock(&g_mu);
    return f ? SANDBOX_OK : SANDBOX_ERR_NOT_FOUND;
}

static sandbox_error_t f_mkdir(sandbox_handle_t* h, const char* p, uint32_t mode, bool parents) {
    (void)mode; (void)parents;
    if (!path_ok(p)) return SANDBOX_ERR_PATH_DENIED;
    pthread_mutex_lock(&g_mu);
    if (file_get(h->vol, p)) { pthread_mutex_unlock(&g_mu); return SANDBOX_ERR_EXISTS; }
    file_t* f = calloc(1, sizeof(*f));
    snprintf(f->path, sizeof(f->path), "%s", p);
    f->dir = 1;
    f->next = h->vol->files;
    h->vol->files = f;
    pthread_mutex_unlock(&g_mu);
    return SANDBOX_OK;
}

static sandbox_error_t f_remove(sandbox_handle_t* h, const char* p, bool rec) {
    if (!path_ok(p) || !strcmp(p, "/workspace")) return SANDBOX_ERR_PATH_DENIED;
    pthread_mutex_lock(&g_mu);
    file_t* tgt = file_get(h->vol, p);
    if (!tgt) { pthread_mutex_unlock(&g_mu); return SANDBOX_ERR_NOT_FOUND; }
    size_t pl = strlen(p);
    int children = 0;
    for (file_t* f = h->vol->files; f; f = f->next) if (!strncmp(f->path, p, pl) && f->path[pl] == '/') children = 1;
    if (children && !rec) { pthread_mutex_unlock(&g_mu); return SANDBOX_ERR_EXISTS; }
    file_t** pp = &h->vol->files;
    while (*pp) {
        file_t* f = *pp;
        if (!strcmp(f->path, p) || (!strncmp(f->path, p, pl) && f->path[pl] == '/')) { *pp = f->next; free(f->d); free(f); }
        else pp = &f->next;
    }
    pthread_mutex_unlock(&g_mu);
    return SANDBOX_OK;
}

static const api_engine_ops_t FAKE = {
    .create = f_create, .destroy = f_destroy, .renew = f_renew, .exec = f_exec, .exec_free = f_exec_free,
    .read_file = f_read, .write_file = f_write, .list_dir = f_list, .stat = f_stat, .mkdir = f_mkdir, .remove = f_remove,
};

// ---- a small HTTP client ----------------------------------------------------

typedef struct { int status; char* body; size_t len; char hdrs[8192]; } resp_t;

static int tcp_connect(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&a, sizeof(a)) < 0) { close(fd); return -1; }
    struct timeval tv = { .tv_sec = 20 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

static int unix_connect(const char* path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr*)&a, sizeof(a)) < 0) { close(fd); return -1; }
    struct timeval tv = { .tv_sec = 20 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

static const char* hdr(const resp_t* r, const char* name) {
    static __thread char val[512];  // the concurrency test reads headers from many threads
    size_t nl = strlen(name);
    for (const char* p = r->hdrs; *p;) {
        const char* e = strstr(p, "\r\n");
        if (!e) break;
        if ((size_t)(e - p) > nl && !strncasecmp(p, name, nl) && p[nl] == ':') {
            const char* v = p + nl + 1;
            while (*v == ' ') v++;
            size_t l = (size_t)(e - v);
            if (l >= sizeof(val)) l = sizeof(val) - 1;
            memcpy(val, v, l);
            val[l] = '\0';
            return val;
        }
        p = e + 2;
    }
    return NULL;
}

// Reads one response off fd. Without a Content-Length it reads to EOF (SSE).
static int read_resp(int fd, resp_t* r) {
    memset(r, 0, sizeof(*r));
    size_t hl = 0;
    char c;
    while (hl < sizeof(r->hdrs) - 1) {
        if (recv(fd, &c, 1, 0) != 1) return -1;
        r->hdrs[hl++] = c;
        if (hl >= 4 && !memcmp(r->hdrs + hl - 4, "\r\n\r\n", 4)) break;
    }
    r->hdrs[hl] = '\0';
    if (sscanf(r->hdrs, "HTTP/1.1 %d", &r->status) != 1) return -1;
    const char* cl = hdr(r, "Content-Length");
    size_t want = cl ? (size_t)strtoul(cl, NULL, 10) : (size_t)-1, cap = 4096, n = 0;
    r->body = malloc(cap);
    while (n < want) {
        if (n + 1 >= cap) { cap *= 2; r->body = realloc(r->body, cap); }
        ssize_t k = recv(fd, r->body + n, cap - n - 1 < want - n ? cap - n - 1 : want - n, 0);
        if (k <= 0) break;
        n += (size_t)k;
    }
    r->body[n] = '\0';
    r->len = n;
    return 0;
}

static int send_req(int fd, const char* method, const char* path, const char* token, const char* extra,
                    const void* body, size_t blen, int close_conn) {
    char h[2048];
    int n = snprintf(h, sizeof(h), "%s %s HTTP/1.1\r\nHost: t\r\n", method, path);
    if (token) n += snprintf(h + n, sizeof(h) - (size_t)n, "Authorization: Bearer %s\r\n", token);
    if (extra) n += snprintf(h + n, sizeof(h) - (size_t)n, "%s", extra);
    if (body || blen) n += snprintf(h + n, sizeof(h) - (size_t)n, "Content-Length: %zu\r\n", blen);
    n += snprintf(h + n, sizeof(h) - (size_t)n, "%s\r\n", close_conn ? "Connection: close\r\n" : "");
    if (send(fd, h, (size_t)n, MSG_NOSIGNAL) != n) return -1;
    if (blen && send(fd, body, blen, MSG_NOSIGNAL) != (ssize_t)blen) return -1;
    return 0;
}

static int g_port;
static char g_sock[256];

static resp_t R(const char* method, const char* path, const char* token, const char* body, const char* extra) {
    resp_t r;
    memset(&r, 0, sizeof(r));
    int fd = tcp_connect(g_port);
    if (fd < 0) { r.status = -1; r.body = strdup(""); return r; }
    const char* ct = body ? "Content-Type: application/json\r\n" : "";
    char hx[1024];
    snprintf(hx, sizeof(hx), "%s%s", ct, extra ? extra : "");
    send_req(fd, method, path, token, hx, body, body ? strlen(body) : 0, 1);
    if (read_resp(fd, &r) < 0) { r.status = -1; if (!r.body) r.body = strdup(""); }
    close(fd);
    return r;
}

static void rfree(resp_t* r) { free(r->body); r->body = NULL; }

// Dotted path into a response's JSON ("error.code"). Returns a malloc'd copy or NULL.
static char* jpath(const resp_t* r, const char* path) {
    jv_t* v = json_parse(r->body, r->len, NULL, 0);
    if (!v) return NULL;
    const jv_t* cur = v;
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char* t = strtok(buf, "."); t && cur; t = strtok(NULL, ".")) cur = json_get(cur, t);
    char* out = NULL;
    if (cur && cur->type == J_STR) out = strdup(cur->s);
    else if (cur && cur->type == J_NUM) { char n[32]; snprintf(n, sizeof(n), "%lld", (long long)cur->num); out = strdup(n); }
    else if (cur && cur->type == J_BOOL) out = strdup(cur->b ? "true" : "false");
    json_free(v);
    return out;
}

static int jeq(const resp_t* r, const char* path, const char* want) {
    char* g = jpath(r, path);
    int ok = g && !strcmp(g, want);
    free(g);
    return ok;
}

static const char TA[] = "token-alice-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char TB[] = "token-bob-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static char* create(const char* tok, const char* body) {
    resp_t r = R("POST", "/v1/sessions", tok, body, NULL);
    char* id = jpath(&r, "id");
    rfree(&r);
    return id;
}

static char P[256];
static const char* sp(const char* id, const char* tail) { snprintf(P, sizeof(P), "/v1/sessions/%s%s", id, tail); return P; }

typedef struct { const char* id; int ok; } conc_t;
static void* conc_exec(void* a) {
    conc_t* c = a;
    char path[128];
    snprintf(path, sizeof(path), "/v1/sessions/%s/exec", c->id);
    resp_t r = R("POST", path, TA, "{\"command\":\"echo hi\"}", NULL);
    c->ok = r.status == 200 && jeq(&r, "stdout", "hi\n");
    rfree(&r);
    return NULL;
}

static void write_tokens(const char* path, mode_t mode, const char* text) {
    FILE* f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
    chmod(path, mode);
}

static void hash_tok(const char* tok, char out[65]) { uint8_t d[32]; sha256(tok, strlen(tok), d); sha256_hex(d, out); }

int main(void) {
    char dir[] = "/tmp/test_httpapi_XXXXXX";
    if (!mkdtemp(dir)) return 1;
    char tokens[300], ha[65], hb[65];
    snprintf(tokens, sizeof(tokens), "%s/tokens.conf", dir);
    snprintf(g_sock, sizeof(g_sock), "%s/api.sock", dir);
    hash_tok(TA, ha);
    hash_tok(TB, hb);
    char text[1024];
    snprintf(text, sizeof(text),
             "# principals\n[alice]\ntoken_sha256 = %s\nmax_sessions = 8\n\n[bob]\ntoken_sha256 = %s\nmax_sessions = 2\ntemplates = python-agent\n\n[uid:%u]\nmax_sessions = 3\n",
             ha, hb, (unsigned)getuid());
    write_tokens(tokens, 0600, text);

    api_config_t cfg = { .unix_path = g_sock, .tcp_host = "127.0.0.1", .tokens_path = tokens, .default_template = "python-agent",
                         .idle_vm_seconds = 3600, .keepalive_seconds = 1, .engine = &FAKE };
    api_server_t* srv = api_server_start(&cfg);
    if (!srv) { fprintf(stderr, "server did not start\n"); return 1; }
    g_port = api_server_tcp_port(srv);

    // ---- auth ----
    resp_t r = R("GET", "/v1/health", NULL, NULL, NULL);
    CHECK(r.status == 200 && jeq(&r, "status", "ok"), "health needs no credentials");
    CHECK(hdr(&r, "X-Request-Id") != NULL, "every response carries a request id");
    rfree(&r);
    r = R("GET", "/v1/sessions", NULL, NULL, NULL);
    CHECK(r.status == 401 && jeq(&r, "error.code", "unauthorized") && hdr(&r, "WWW-Authenticate") != NULL, "no token: 401 with a challenge");
    rfree(&r);
    r = R("GET", "/v1/sessions", "not-a-token", NULL, NULL);
    CHECK(r.status == 401, "a wrong token: 401");
    rfree(&r);
    r = R("GET", "/v1/health", NULL, NULL, "X-Request-Id: my-trace-1\r\n");
    CHECK(hdr(&r, "X-Request-Id") && !strcmp(hdr(&r, "X-Request-Id"), "my-trace-1"), "a caller's request id is echoed");
    rfree(&r);
    r = R("GET", "/v1/health", NULL, NULL, "X-Request-Id: bad id with spaces\r\n");
    CHECK(hdr(&r, "X-Request-Id") && strncmp(hdr(&r, "X-Request-Id"), "bad", 3) != 0, "a malformed request id is replaced");
    rfree(&r);

    // ---- create / get / list ----
    r = R("POST", "/v1/sessions", TA, "{\"key\":\"conv-1\"}", NULL);
    CHECK(r.status == 201 && jeq(&r, "state", "ready") && jeq(&r, "workspace", "/workspace") && jeq(&r, "template", "python-agent"),
          "create: 201, ready, default template");
    char* id1 = jpath(&r, "id");
    char* exp1 = jpath(&r, "expires_at");
    CHECK(id1 && !strncmp(id1, "ses_", 4) && exp1 && atoll(exp1) > time(NULL) + 600000, "the id is ses_..., expires_at is the engine's deadline");
    CHECK(g_creates == 1 && g_last_mem == 256 && !strcmp(g_last_template, "python-agent"), "the engine got the defaults");
    rfree(&r);
    r = R("GET", sp(id1, ""), TA, NULL, NULL);
    CHECK(r.status == 200 && jeq(&r, "key", "conv-1"), "get returns the session");
    rfree(&r);
    r = R("GET", "/v1/sessions", TA, NULL, NULL);
    CHECK(r.status == 200 && strstr(r.body, id1) != NULL, "list shows it");
    rfree(&r);

    // ---- determinism ----
    r = R("POST", "/v1/sessions", TA, "{\"key\":\"conv-1\"}", NULL);
    char* again = jpath(&r, "id");
    CHECK(r.status == 200 && again && !strcmp(again, id1) && g_creates == 1, "the same key attaches: 200, same id, no new VM");
    rfree(&r); free(again);
    r = R("POST", "/v1/sessions", TB, "{\"key\":\"conv-1\"}", NULL);
    char* bobs = jpath(&r, "id");
    CHECK(r.status == 201 && bobs && strcmp(bobs, id1) != 0, "another principal's same key is a different session");
    rfree(&r);
    r = R("POST", "/v1/sessions", TA, "{\"key\":\"conv-1\",\"memory_mib\":512}", NULL);
    CHECK(r.status == 409 && jeq(&r, "error.code", "session_exists"), "the same key with different resources: 409");
    rfree(&r);
    char* anon1 = create(TA, "{}");
    char* anon2 = create(TA, "{}");
    CHECK(anon1 && anon2 && strcmp(anon1, anon2) != 0, "without a key every session is new");

    // ---- validation ----
    r = R("POST", "/v1/sessions", TA, "{\"ttl\":5}", NULL);
    CHECK(r.status == 400 && jeq(&r, "error.code", "unknown_field"), "a misspelt field is refused, not ignored");
    rfree(&r);
    r = R("POST", "/v1/sessions", TA, "{\"key\":\"has space\"}", NULL);
    CHECK(r.status == 400 && jeq(&r, "error.code", "invalid_field"), "a key with illegal characters is refused");
    rfree(&r);
    r = R("POST", "/v1/sessions", TA, "{\"memory_mib\":\"lots\"}", NULL);
    CHECK(r.status == 400, "a wrong-typed field is refused");
    rfree(&r);
    r = R("POST", "/v1/sessions", TA, "{\"egress_deny_all\":true,\"egress_allow\":[\"a.com\"]}", NULL);
    CHECK(r.status == 400, "deny-all with an allow-list is refused");
    rfree(&r);
    r = R("POST", "/v1/sessions", TA, "{not json", NULL);
    CHECK(r.status == 400 && jeq(&r, "error.code", "invalid_json"), "malformed JSON: 400");
    rfree(&r);
    r = R("POST", "/v1/sessions", TA, "[1]", NULL);
    CHECK(r.status == 400, "a non-object body: 400");
    rfree(&r);
    unsigned before = api_server_sessions(srv);
    r = R("POST", "/v1/sessions", TA, "{\"template\":\"bogus\"}", NULL);
    CHECK(r.status == 400 && jeq(&r, "error.code", "invalid_spec") && api_server_sessions(srv) == before, "an engine refusal maps to 400 and leaves no session behind");
    rfree(&r);
    r = R("POST", "/v1/sessions", TA, "{\"template\":\"full\"}", NULL);
    CHECK(r.status == 503 && jeq(&r, "error.code", "capacity") && hdr(&r, "Retry-After") != NULL, "pool exhausted: 503 with Retry-After");
    rfree(&r);
    r = R("POST", "/v1/sessions", TB, "{\"template\":\"other\"}", NULL);
    CHECK(r.status == 403 && jeq(&r, "error.code", "template_not_allowed"), "a template outside the principal's list: 403");
    rfree(&r);
    r = R("POST", "/v1/sessions", TA, "{\"key\":\"p\",\"egress_allow\":[\"pypi.org\"],\"env\":{\"FOO\":\"bar\"},\"memory_mib\":128}", NULL);
    CHECK(r.status == 201 && !strcmp(g_last_egress0, "pypi.org") && !strcmp(g_last_env0, "FOO=bar") && g_last_mem == 128, "egress, env and memory reach the engine");
    rfree(&r);
    r = R("POST", "/v1/sessions", TA, "{\"key\":\"d\",\"egress_deny_all\":true}", NULL);
    CHECK(r.status == 201 && g_last_deny == 1 && jeq(&r, "egress.deny_all", "true"), "deny-all reaches the engine");
    rfree(&r);
    r = R("POST", "/v1/sessions", TA, "{\"key\":\"e\",\"env\":{\"1BAD\":\"x\"}}", NULL);
    CHECK(r.status == 400, "an env name that is not an identifier is refused");
    rfree(&r);
    r = R("POST", "/v1/sessions", TB, "{\"key\":\"second\"}", NULL);
    CHECK(r.status == 201, "bob's second session");
    rfree(&r);
    r = R("POST", "/v1/sessions", TB, "{\"key\":\"third\"}", NULL);
    CHECK(r.status == 429 && jeq(&r, "error.code", "too_many_sessions"), "past the principal's session limit: 429");
    rfree(&r);

    // ---- isolation ----
    const char* probes[][2] = { {"GET", ""}, {"DELETE", ""}, {"POST", "/exec"}, {"GET", "/files?path=/workspace/x"},
                                {"PUT", "/files?path=/workspace/x"}, {"GET", "/ls?path=/workspace"}, {"GET", "/stat?path=/workspace"},
                                {"POST", "/renew"}, {"POST", "/mkdir"} };
    int iso = 1;
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        resp_t x = R(probes[i][0], sp(id1, probes[i][1]), TB, "{}", NULL);
        resp_t y = R(probes[i][0], sp("ses_000000000000000000000000", probes[i][1]), TB, "{}", NULL);
        if (x.status != 404 || !jeq(&x, "error.code", "session_not_found") || !jeq(&y, "error.code", "session_not_found")) iso = 0;
        if (x.status != y.status) iso = 0;  // indistinguishable from a session that does not exist
        rfree(&x); rfree(&y);
    }
    CHECK(iso, "another principal's session answers 404 on every route, as if absent");
    r = R("GET", "/v1/sessions", TB, NULL, NULL);
    CHECK(strstr(r.body, id1) == NULL, "another principal's list never shows it");
    rfree(&r);
    r = R("GET", sp(id1, ""), TA, NULL, NULL);
    CHECK(r.status == 200, "...and the attack changed nothing for the owner");
    rfree(&r);

    // ---- exec ----
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"echo hello world\"}", NULL);
    CHECK(r.status == 200 && jeq(&r, "stdout", "hello world\n") && jeq(&r, "exit_code", "0") && jeq(&r, "stdout_bytes", "12"), "exec a shell command");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"argv\":[\"echo\",\"a\",\"b\"]}", NULL);
    CHECK(r.status == 200 && jeq(&r, "stdout", "a b\n"), "exec an argv");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"shell?\"}", NULL);
    CHECK(jeq(&r, "stdout", "shell\n"), "command runs as a shell script");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"argv\":[\"shell?\"]}", NULL);
    CHECK(jeq(&r, "stdout", "argv\n"), "argv does not");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"exit 7\"}", NULL);
    CHECK(r.status == 200 && jeq(&r, "exit_code", "7"), "a non-zero exit is a 200 with the code");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"env FOO\",\"env\":{\"FOO\":\"from-request\"}}", NULL);
    CHECK(jeq(&r, "stdout", "from-request\n"), "per-command env");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"cat\",\"stdin\":\"fed\"}", NULL);
    CHECK(jeq(&r, "stdout", "fed"), "stdin");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"cat\",\"stdin_base64\":\"AAEC\"}", NULL);
    CHECK(r.status == 200 && jeq(&r, "stdout_bytes", "3"), "stdin_base64");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"cwd\",\"cwd\":\"/workspace/sub\"}", NULL);
    CHECK(jeq(&r, "stdout", "/workspace/sub\n"), "cwd");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"timeout\"}", NULL);
    CHECK(jeq(&r, "timed_out", "true"), "a timed-out command says so");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"bytes\"}", NULL);
    CHECK(r.status == 200 && strstr(r.body, "\xef\xbf\xbd") != NULL, "invalid UTF-8 output is replaced, and the response is still valid JSON");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"bytes\",\"output_encoding\":\"base64\"}", NULL);
    CHECK(jeq(&r, "stdout", "b2v//go=") && jeq(&r, "encoding", "base64"), "base64 output keeps the exact bytes");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"big 100000\"}", NULL);
    CHECK(jeq(&r, "stdout_bytes", "100000") && jeq(&r, "stdout_returned", "32768"), "output beyond the engine's head is reported by its totals");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{}", NULL);
    CHECK(r.status == 400, "exec with neither command nor argv: 400");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"x\",\"argv\":[\"y\"]}", NULL);
    CHECK(r.status == 400, "exec with both: 400");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"x\",\"timeout_ms\":99999999}", NULL);
    CHECK(r.status == 400, "an absurd timeout is refused");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"fail 9\"}", NULL);
    CHECK(r.status == 503 && jeq(&r, "error.code", "guest_unavailable"), "guest unavailable -> 503");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"fail 15\"}", NULL);
    CHECK(r.status == 504 && jeq(&r, "error.code", "timeout"), "engine timeout -> 504");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"fail 13\"}", NULL);
    CHECK(r.status == 413, "too large -> 413");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"fail 5\"}", NULL);
    CHECK(r.status == 500 && jeq(&r, "error.code", "internal"), "an engine internal error -> 500");
    rfree(&r);

    // ---- idempotency ----
    int e0 = g_execs;
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"echo once\"}", "Idempotency-Key: run-1\r\n");
    CHECK(r.status == 200 && hdr(&r, "Idempotent-Replay") == NULL, "first request with a key runs");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"echo once\"}", "Idempotency-Key: run-1\r\n");
    CHECK(r.status == 200 && jeq(&r, "stdout", "once\n") && hdr(&r, "Idempotent-Replay") != NULL && g_execs == e0 + 1,
          "a retry replays the first answer without running again");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"echo different\"}", "Idempotency-Key: run-1\r\n");
    CHECK(r.status == 422 && jeq(&r, "error.code", "idempotency_key_reused"), "the key with a different request: 422");
    rfree(&r);
    int e1 = g_execs;
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"fail 9\"}", "Idempotency-Key: flaky\r\n");
    rfree(&r);
    r = R("POST", sp(id1, "/exec"), TA, "{\"command\":\"fail 9\"}", "Idempotency-Key: flaky\r\n");
    CHECK(g_execs == e1 + 2, "a failed attempt is not remembered: the retry really retries");
    rfree(&r);

    // ---- streaming ----
    {
        int fd = tcp_connect(g_port);
        const char* body = "{\"command\":\"multi\",\"stream\":true}";
        send_req(fd, "POST", sp(id1, "/exec"), TA, "Content-Type: application/json\r\n", body, strlen(body), 1);
        resp_t s;
        read_resp(fd, &s);
        close(fd);
        const char *a = strstr(s.body, "event: started"), *b = strstr(s.body, "event: stdout"),
                   *c = strstr(s.body, "event: stderr"), *d = strstr(s.body, "event: exit");
        CHECK(s.status == 200 && hdr(&s, "Content-Type") && strstr(hdr(&s, "Content-Type"), "text/event-stream"), "stream: 200 text/event-stream");
        CHECK(a && b && c && d && a < b && b < c && c < d, "stream: started, stdout, stderr, exit, in that order");
        CHECK(b && strstr(b, "line1\\nline2\\n") && strstr(s.body, "\"exit_code\":0"), "stream: the output and the exit code arrive");
        rfree(&s);
        fd = tcp_connect(g_port);
        body = "{\"command\":\"sleep 2500\"}";
        send_req(fd, "POST", sp(id1, "/exec"), TA, "Content-Type: application/json\r\nAccept: text/event-stream\r\n", body, strlen(body), 1);
        read_resp(fd, &s);
        close(fd);
        CHECK(strstr(s.body, ": keepalive") != NULL && strstr(s.body, "event: exit") != NULL, "stream: keepalives while a command runs (Accept header selects SSE)");
        rfree(&s);
    }

    // ---- files ----
    const char bin[] = { 'a', 0, 'b', (char)0xff, '\n' };
    {
        int fd = tcp_connect(g_port);
        send_req(fd, "PUT", sp(id1, "/files?path=/workspace/data.bin"), TA, NULL, bin, sizeof(bin), 1);
        read_resp(fd, &r);
        close(fd);
        CHECK(r.status == 200 && jeq(&r, "bytes", "5"), "write a file (binary body)");
        rfree(&r);
        fd = tcp_connect(g_port);
        send_req(fd, "GET", sp(id1, "/files?path=/workspace/data.bin"), TA, NULL, NULL, 0, 1);
        read_resp(fd, &r);
        close(fd);
        CHECK(r.status == 200 && r.len == sizeof(bin) && !memcmp(r.body, bin, sizeof(bin)), "read it back byte for byte, NUL and 0xff included");
        CHECK(hdr(&r, "Content-Type") && !strcmp(hdr(&r, "Content-Type"), "application/octet-stream"), "...served as octet-stream, never as HTML");
        rfree(&r);
        fd = tcp_connect(g_port);
        send_req(fd, "PUT", sp(id1, "/files?path=/workspace/data.bin&append=1"), TA, NULL, "XY", 2, 1);
        read_resp(fd, &r);
        close(fd);
        rfree(&r);
        r = R("GET", sp(id1, "/stat?path=/workspace/data.bin"), TA, NULL, NULL);
        CHECK(jeq(&r, "size", "7") && jeq(&r, "type", "file"), "append grows it; stat reports size and type");
        rfree(&r);
        fd = tcp_connect(g_port);
        send_req(fd, "PUT", sp(id1, "/files?path=/workspace/data.bin&exclusive=1"), TA, NULL, "z", 1, 1);
        read_resp(fd, &r);
        close(fd);
        CHECK(r.status == 409 && jeq(&r, "error.code", "exists"), "exclusive on an existing file: 409");
        rfree(&r);
        fd = tcp_connect(g_port);
        send_req(fd, "PUT", sp(id1, "/files?path=%2Fworkspace%2Fwith%20space.txt"), TA, NULL, "sp", 2, 1);
        read_resp(fd, &r);
        close(fd);
        CHECK(r.status == 200 && jeq(&r, "path", "/workspace/with space.txt"), "percent-encoded paths are decoded");
        rfree(&r);
    }
    r = R("GET", sp(id1, "/files?path=/workspace/missing"), TA, NULL, NULL);
    CHECK(r.status == 404 && jeq(&r, "error.code", "not_found"), "a missing file: 404");
    rfree(&r);
    r = R("GET", sp(id1, "/files?path=/etc/passwd"), TA, NULL, NULL);
    CHECK(r.status == 400 && jeq(&r, "error.code", "path_denied"), "a path outside /workspace: 400 path_denied");
    rfree(&r);
    r = R("GET", sp(id1, "/files?path=/workspace/../etc/passwd"), TA, NULL, NULL);
    CHECK(r.status == 400, "a path with .. is refused");
    rfree(&r);
    r = R("GET", sp(id1, "/files"), TA, NULL, NULL);
    CHECK(r.status == 400, "a missing path parameter: 400");
    rfree(&r);
    r = R("GET", sp(id1, "/files?path=/workspace/a%00b"), TA, NULL, NULL);
    CHECK(r.status == 400, "an encoded NUL in a path is refused");
    rfree(&r);
    r = R("POST", sp(id1, "/mkdir"), TA, "{\"path\":\"/workspace/d\",\"parents\":true}", NULL);
    CHECK(r.status == 204, "mkdir");
    rfree(&r);
    {
        int fd = tcp_connect(g_port);
        send_req(fd, "PUT", sp(id1, "/files?path=/workspace/d/f.txt"), TA, NULL, "in-d", 4, 1);
        read_resp(fd, &r);
        close(fd);
        rfree(&r);
    }
    r = R("GET", sp(id1, "/ls?path=/workspace/d"), TA, NULL, NULL);
    CHECK(r.status == 200 && strstr(r.body, "\"name\":\"f.txt\"") && strstr(r.body, "\"truncated\":false"), "list a directory");
    rfree(&r);
    r = R("DELETE", sp(id1, "/files?path=/workspace/d"), TA, NULL, NULL);
    CHECK(r.status == 409, "removing a non-empty directory without recursive: 409");
    rfree(&r);
    r = R("DELETE", sp(id1, "/files?path=/workspace/d&recursive=1"), TA, NULL, NULL);
    CHECK(r.status == 204, "...and with recursive: 204");
    rfree(&r);
    {
        char* big = malloc(SANDBOX_MAX_FILE + 10);
        memset(big, 'b', SANDBOX_MAX_FILE + 10);
        int fd = tcp_connect(g_port);
        send_req(fd, "PUT", sp(id1, "/files?path=/workspace/big"), TA, NULL, big, SANDBOX_MAX_FILE + 10, 1);
        read_resp(fd, &r);
        close(fd);
        CHECK(r.status == 413, "a file over the engine's limit: 413");
        rfree(&r);
        free(big);
    }

    // ---- framing and limits ----
    {
        char* huge = malloc(1024 * 1024 + 100);
        memset(huge, ' ', 1024 * 1024 + 99);
        huge[1024 * 1024 + 99] = '\0';
        int fd = tcp_connect(g_port);
        send_req(fd, "POST", "/v1/sessions", TA, "Content-Type: application/json\r\n", huge, strlen(huge), 1);
        read_resp(fd, &r);
        close(fd);
        CHECK(r.status == 413, "a JSON body over 1 MiB: 413");
        rfree(&r);
        free(huge);
        fd = tcp_connect(g_port);
        const char* chunked = "POST /v1/sessions HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer token-alice-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
                              "Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        send(fd, chunked, strlen(chunked), 0);
        read_resp(fd, &r);
        close(fd);
        CHECK(r.status == 501 && jeq(&r, "error.code", "chunked_unsupported"), "a chunked request is refused plainly");
        rfree(&r);
        fd = tcp_connect(g_port);
        const char* twocl = "POST /v1/sessions HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer token-alice-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
                            "Content-Length: 2\r\nContent-Length: 40\r\n\r\n{}";
        send(fd, twocl, strlen(twocl), 0);
        read_resp(fd, &r);
        close(fd);
        CHECK(r.status == 400, "conflicting Content-Length headers: 400");
        rfree(&r);
        // Keep-alive: two requests on one connection.
        fd = tcp_connect(g_port);
        send_req(fd, "GET", "/v1/health", NULL, NULL, NULL, 0, 0);
        resp_t r1, r2;
        read_resp(fd, &r1);
        send_req(fd, "GET", "/v1/sessions", TA, NULL, NULL, 0, 0);
        read_resp(fd, &r2);
        close(fd);
        CHECK(r1.status == 200 && r2.status == 200, "two requests share a keep-alive connection");
        rfree(&r1); rfree(&r2);
        // A body larger than its Content-Length promises, sent after the headers, is not read as a new request.
        fd = tcp_connect(g_port);
        const char* smug = "POST /v1/sessions/x/renew HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer token-alice-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
                           "Content-Length: 0\r\n\r\nGET /v1/health HTTP/1.1\r\nHost: t\r\n\r\n";
        send(fd, smug, strlen(smug), 0);
        read_resp(fd, &r1);
        read_resp(fd, &r2);  // the pipelined request is still a request: answered in order
        close(fd);
        CHECK(r1.status == 404 && r2.status == 200, "pipelined requests are answered in order");
        rfree(&r1); rfree(&r2);
    }
    r = R("DELETE", "/v1/sessions", TA, NULL, NULL);
    CHECK(r.status == 405 && hdr(&r, "Allow") != NULL, "a wrong method: 405 with Allow");
    rfree(&r);
    r = R("GET", "/v2/nothing", TA, NULL, NULL);
    CHECK(r.status == 404, "an unknown route: 404");
    rfree(&r);

    // ---- renew ----
    r = R("POST", sp(id1, "/renew"), TA, "{\"ttl_seconds\":2000000}", NULL);
    char* exp2 = jpath(&r, "expires_at");
    CHECK(r.status == 200 && exp2 && atoll(exp2) > atoll(exp1), "renew extends the deadline");
    rfree(&r);
    r = R("POST", sp(id1, "/renew"), TA, "{\"ttl_seconds\":-1}", NULL);
    CHECK(r.status == 400, "a negative ttl is refused");
    rfree(&r);

    // ---- concurrency ----
    {
        pthread_t t[12];
        conc_t c[12];
        for (int i = 0; i < 12; i++) { c[i].id = id1; c[i].ok = 0; pthread_create(&t[i], NULL, conc_exec, &c[i]); }
        int ok = 1;
        for (int i = 0; i < 12; i++) { pthread_join(t[i], NULL); ok &= c[i].ok; }
        CHECK(ok, "twelve concurrent commands in one session all succeed");
    }

    // ---- unix socket: the peer uid is the principal ----
    {
        int fd = unix_connect(g_sock);
        const char* body = "{\"key\":\"local\"}";
        send_req(fd, "POST", "/v1/sessions", NULL, "Content-Type: application/json\r\n", body, strlen(body), 1);
        read_resp(fd, &r);
        close(fd);
        char* uid_sess = jpath(&r, "id");
        CHECK(r.status == 201 && uid_sess, "unix socket: no token needed, the peer uid is the identity");
        rfree(&r);
        resp_t x = R("GET", sp(uid_sess, ""), TA, NULL, NULL);
        CHECK(x.status == 404, "a token principal cannot see a uid principal's session");
        rfree(&x);
        fd = unix_connect(g_sock);
        send_req(fd, "GET", sp(id1, ""), NULL, NULL, NULL, 0, 1);
        read_resp(fd, &x);
        close(fd);
        CHECK(x.status == 404, "...nor the other way round");
        rfree(&x);
        free(uid_sess);
    }

    // ---- delete, and the workspace outliving the session ----
    int d0 = g_destroys;
    r = R("DELETE", sp(id1, ""), TA, NULL, NULL);
    CHECK(r.status == 204 && g_destroys == d0 + 1, "delete: 204, and the VM is destroyed");
    rfree(&r);
    r = R("GET", sp(id1, ""), TA, NULL, NULL);
    CHECK(r.status == 404, "a deleted session is gone");
    rfree(&r);
    r = R("POST", "/v1/sessions", TA, "{\"key\":\"conv-1\"}", NULL);
    char* id1b = jpath(&r, "id");
    CHECK(r.status == 201 && id1b && !strcmp(id1b, id1), "re-creating with the same key gives the same id");
    rfree(&r);
    {
        int fd = tcp_connect(g_port);
        send_req(fd, "GET", sp(id1b, "/files?path=/workspace/data.bin"), TA, NULL, NULL, 0, 1);
        read_resp(fd, &r);
        close(fd);
        CHECK(r.status == 200 && r.len == 7, "...and the files the first incarnation wrote are still there");
        rfree(&r);
    }

    // ---- shutdown reclaims everything ----
    api_server_stop(srv);
    CHECK(g_live == 0, "stopping the server destroys every sandbox it held");
    CHECK(access(g_sock, F_OK) != 0, "...and removes its socket");

    // ---- lifecycle: idle reclaim, eviction, expiry ----
    cfg.idle_vm_seconds = 1;
    cfg.max_running = 2;
    cfg.unix_path = NULL;
    srv = api_server_start(&cfg);
    g_port = api_server_tcp_port(srv);
    char* s1 = create(TA, "{\"key\":\"life-1\"}");
    {
        int fd = tcp_connect(g_port);
        send_req(fd, "PUT", sp(s1, "/files?path=/workspace/keep.txt"), TA, NULL, "persist", 7, 1);
        read_resp(fd, &r);
        close(fd);
        rfree(&r);
    }
    CHECK(api_server_running(srv) == 1, "lifecycle: one VM held");
    sleep(3);
    CHECK(api_server_running(srv) == 0, "an idle VM is reclaimed");
    r = R("GET", sp(s1, ""), TA, NULL, NULL);
    CHECK(r.status == 200 && jeq(&r, "state", "idle"), "...and the session is still there, idle");
    rfree(&r);
    int c0 = g_creates;
    {
        int fd = tcp_connect(g_port);
        send_req(fd, "GET", sp(s1, "/files?path=/workspace/keep.txt"), TA, NULL, NULL, 0, 1);
        read_resp(fd, &r);
        close(fd);
        CHECK(r.status == 200 && r.len == 7 && !memcmp(r.body, "persist", 7) && g_creates == c0 + 1,
              "the next request reprovisions a VM and finds the workspace intact");
        rfree(&r);
    }
    char* s2 = create(TA, "{\"key\":\"life-2\"}");
    char* s3 = create(TA, "{\"key\":\"life-3\"}");
    CHECK(s2 && s3 && api_server_running(srv) <= 2, "past max_running the longest-idle VM is evicted, not refused");
    r = R("POST", sp(s1, "/exec"), TA, "{\"command\":\"echo still-works\"}", NULL);
    CHECK(r.status == 200 && jeq(&r, "stdout", "still-works\n") && api_server_running(srv) <= 2, "an evicted session transparently comes back");
    rfree(&r);
    char* s4 = create(TA, "{\"key\":\"life-short\",\"ttl_seconds\":1}");
    CHECK(s4 != NULL, "create with a 1 s ttl");
    sleep(4);
    r = R("GET", sp(s4, ""), TA, NULL, NULL);
    CHECK(r.status == 404, "a session past its deadline is removed");
    rfree(&r);
    api_server_stop(srv);
    CHECK(g_live == 0, "lifecycle: nothing left running");

    // ---- refusals at start-up ----
    api_config_t bad = cfg;
    bad.unix_path = NULL;
    bad.tcp_host = "0.0.0.0";
    CHECK(api_server_start(&bad) == NULL, "a non-loopback TCP bind is refused without --allow-public-bind");
    bad.tcp_host = "127.0.0.1";
    bad.tokens_path = NULL;
    CHECK(api_server_start(&bad) == NULL, "TCP without any token is refused");
    char t2[300];
    snprintf(t2, sizeof(t2), "%s/loose.conf", dir);
    write_tokens(t2, 0666, text);
    bad.tokens_path = t2;
    CHECK(api_server_start(&bad) == NULL, "a tokens file others can write is refused");
    write_tokens(t2, 0600, "[x]\ntoken_sha256 = nothex\n");
    CHECK(api_server_start(&bad) == NULL, "a malformed token hash is refused");
    char dup[512];
    snprintf(dup, sizeof(dup), "[a]\ntoken_sha256 = %s\n[b]\ntoken_sha256 = %s\n", ha, ha);
    write_tokens(t2, 0600, dup);
    CHECK(api_server_start(&bad) == NULL, "two principals sharing a token is refused");
    write_tokens(t2, 0600, "[x]\nbogus = 1\n");
    CHECK(api_server_start(&bad) == NULL, "an unknown key in the tokens file is refused");
    api_config_t none = { .engine = &FAKE };
    CHECK(api_server_start(&none) == NULL, "no listener at all is refused");

    char cmd[400];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    (void)!system(cmd);
    free(id1); free(exp1); free(exp2); free(bobs); free(anon1); free(anon2); free(id1b); free(s1); free(s2); free(s3); free(s4);
    printf("%s\n", g_fail ? "FAILED" : "ALL PASSED");
    return g_fail ? 1 : 0;
}
