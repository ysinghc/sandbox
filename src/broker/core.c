// Broker core (§5.8): session-token validation with the engine daemon,
// allow-listing, credential injection, and upstream proxying over libcurl.
// Everything here is testable in-process; src/broker/main.c only wires argv/env.

#include "broker.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>

// ---------------------------------------------------------------------------
// Small fixed-size IO + env helpers
// ---------------------------------------------------------------------------

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

static const char* env_or(const char* key, const char* def) {
    const char* v = getenv(key);
    return (v && *v) ? v : def;
}

const char* broker_listen_addr(void) {
    return env_or("SANDBOX_BROKER_LISTEN", "0.0.0.0:8080");
}
const char* broker_credentials_path(void) {
    return env_or("SANDBOX_BROKER_CREDENTIALS", "/etc/sandbox-engine/credentials.conf");
}
const char* broker_control_path(void) {
    return env_or("SANDBOX_BROKER_CONTROL", "/var/run/sandbox-engine/broker-control.sock");
}
static const char* upstream_scheme(void) {
    return env_or("SANDBOX_BROKER_UPSTREAM_SCHEME", "https");
}
static int tls_verify_enabled(void) {
    const char* v = getenv("SANDBOX_BROKER_TLS_VERIFY");
    return !(v && strcmp(v, "0") == 0);
}

// Copy host with any ":port" removed and ASCII case folded.
static void host_key(const char* host, char* out, size_t n) {
    size_t i = 0;
    if (!host) {
        out[0] = '\0';
        return;
    }
    for (const char* p = host; *p && i + 1 < n; p++) {
        if (*p == ':') break;
        out[i++] = (char)tolower((unsigned char)*p);
    }
    out[i] = '\0';
}

// ---------------------------------------------------------------------------
// Token validation
// ---------------------------------------------------------------------------

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int broker_token_from_hex(const char* hex, uint8_t out[32]) {
    if (!hex || strlen(hex) != BROKER_TOKEN_HEX_LEN) return -1;
    for (int i = 0; i < 32; i++) {
        int hi = hexval((unsigned char)hex[2 * i]);
        int lo = hexval((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int broker_engine_connect(const char* path) {
    if (!path || !*path) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
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
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

void session_info_free(session_info_t* s) {
    if (!s || !s->allowed_services) return;
    for (char** p = s->allowed_services; *p; p++) free(*p);
    free(s->allowed_services);
    s->allowed_services = NULL;
    s->sandbox_id = 0;
}

int broker_validate_token(int engine_fd, const char* token_hex, session_info_t* out) {
    if (engine_fd < 0 || !out) return BROKER_VALIDATE_ERROR;
    memset(out, 0, sizeof(*out));

    uint8_t token[32];
    if (broker_token_from_hex(token_hex, token) < 0) return BROKER_VALIDATE_INVALID;

    uint8_t req[BROKER_VALIDATE_REQ_LEN];
    req[0] = BROKER_MSG_VALIDATE_TOKEN;
    memcpy(req + 1, token, sizeof(token));
    if (write_full(engine_fd, req, sizeof(req)) < 0) return BROKER_VALIDATE_ERROR;

    uint8_t status;
    if (read_full(engine_fd, &status, 1) < 0) return BROKER_VALIDATE_ERROR;
    if (status != 0) return BROKER_VALIDATE_INVALID;

    uint8_t id[4];
    if (read_full(engine_fd, id, 4) < 0) return BROKER_VALIDATE_ERROR;
    out->sandbox_id = ((uint32_t)id[0] << 24) | ((uint32_t)id[1] << 16) |
                      ((uint32_t)id[2] << 8) | (uint32_t)id[3];

    uint8_t nb[2];
    if (read_full(engine_fd, nb, 2) < 0) return BROKER_VALIDATE_ERROR;
    uint16_t n = (uint16_t)((nb[0] << 8) | nb[1]);
    out->allowed_services = calloc((size_t)n + 1, sizeof(char*));
    if (!out->allowed_services) return BROKER_VALIDATE_ERROR;
    for (uint16_t i = 0; i < n; i++) {
        uint8_t len;
        if (read_full(engine_fd, &len, 1) < 0) goto fail;
        char* svc = malloc((size_t)len + 1);
        if (!svc) goto fail;
        if (len && read_full(engine_fd, svc, len) < 0) {
            free(svc);
            goto fail;
        }
        svc[len] = '\0';
        out->allowed_services[i] = svc;
    }
    return BROKER_VALIDATE_OK;

fail:
    session_info_free(out);
    return BROKER_VALIDATE_ERROR;
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

bool broker_host_allowed(char* const* allowed_services, const char* host) {
    if (!host || !allowed_services) return false;
    char key[256];
    host_key(host, key, sizeof(key));
    if (key[0] == '\0') return false;
    for (char* const* p = allowed_services; *p; p++) {
        char ent[256];
        host_key(*p, ent, sizeof(ent));
        if (strcmp(ent, "*") == 0 || strcmp(ent, key) == 0) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Upstream forwarding (libcurl)
// ---------------------------------------------------------------------------

struct fwd_ctx {
    int client_fd;
    int body_fd;
    uint64_t body_remaining;
    long status;
};

static int send_all(int fd, const char* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, buf + off, n - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static size_t fwd_write_cb(char* ptr, size_t size, size_t nmemb, void* ud) {
    struct fwd_ctx* c = ud;
    size_t n = size * nmemb;
    if (send_all(c->client_fd, ptr, n) < 0) return 0;  // abort transfer
    return n;
}

static size_t fwd_header_cb(char* buffer, size_t size, size_t nitems, void* ud) {
    struct fwd_ctx* c = ud;
    size_t n = size * nitems;
    if (n >= 5 && strncmp(buffer, "HTTP/", 5) == 0) {
        int code = 0;
        c->status = (sscanf(buffer, "HTTP/%*d.%*d %d", &code) == 1) ? code : 0;
    }
    if (send_all(c->client_fd, buffer, n) < 0) return 0;
    return n;
}

static size_t fwd_read_cb(char* buffer, size_t size, size_t nmemb, void* ud) {
    struct fwd_ctx* c = ud;
    size_t want = size * nmemb;
    if ((uint64_t)want > c->body_remaining) want = (size_t)c->body_remaining;
    if (want == 0) return 0;
    ssize_t r = read(c->body_fd, buffer, want);
    if (r <= 0) return CURL_READFUNC_ABORT;
    c->body_remaining -= (uint64_t)r;
    return (size_t)r;
}

static uint64_t request_content_length(const http_request_t* req) {
    const char* cl = http_get_header(req, "Content-Length");
    if (!cl) return 0;
    char* end = NULL;
    unsigned long long v = strtoull(cl, &end, 10);
    if (end == cl) return 0;
    return (uint64_t)v;
}

int broker_forward_upstream(const http_request_t* req, int client_fd, int body_fd) {
    if (!req || client_fd < 0) return -1;
    const char* host = http_get_header(req, "Host");
    if (!host || !*host) return -1;

    char url[4096];
    int un = snprintf(url, sizeof(url), "%s://%s%s", upstream_scheme(), host,
                      req->target);
    if (un <= 0 || (size_t)un >= sizeof(url)) return -1;

    CURL* h = curl_easy_init();
    if (!h) return -1;

    struct curl_slist* hdrs = NULL;
    for (size_t i = 0; i < req->nheaders; i++) {
        // libcurl regenerates Content-Length from INFILESIZE; passing ours too
        // would duplicate the header. Expect is suppressed below.
        if (strcasecmp(req->headers[i].name, "Content-Length") == 0) continue;
        if (strcasecmp(req->headers[i].name, "Expect") == 0) continue;
        char line[HTTP_MAX_NAME + HTTP_MAX_VALUE + 4];
        snprintf(line, sizeof(line), "%s: %s", req->headers[i].name,
                 req->headers[i].value);
        struct curl_slist* nh = curl_slist_append(hdrs, line);
        if (nh) hdrs = nh;
    }
    hdrs = curl_slist_append(hdrs, "Expect:");  // suppress 100-continue

    uint64_t blen = request_content_length(req);
    struct fwd_ctx ctx = {
        .client_fd = client_fd,
        .body_fd = body_fd,
        .body_remaining = blen,
        .status = 0,
    };

    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, req->method);
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, fwd_header_cb);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, &ctx);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, fwd_write_cb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &ctx);
    // Relay the upstream framing verbatim (no re-encode): the client sees the
    // same Transfer-Encoding/Content-Encoding and length semantics.
    curl_easy_setopt(h, CURLOPT_HTTP_TRANSFER_DECODING, 0L);
    curl_easy_setopt(h, CURLOPT_HTTP_CONTENT_DECODING, 0L);
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, 120L);
    if (tls_verify_enabled()) {
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    if (blen > 0) {
        curl_easy_setopt(h, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(h, CURLOPT_READFUNCTION, fwd_read_cb);
        curl_easy_setopt(h, CURLOPT_READDATA, &ctx);
        curl_easy_setopt(h, CURLOPT_INFILESIZE_LARGE, (curl_off_t)blen);
    }

    CURLcode rc = curl_easy_perform(h);
    long status = ctx.status;
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(h);
    if (rc != CURLE_OK) return -1;
    return (int)status;
}

// ---------------------------------------------------------------------------
// Request pipeline
// ---------------------------------------------------------------------------

static void log_request(uint32_t sandbox_id, const char* host, int status, long ms) {
    char safe[256];
    size_t j = 0;
    for (const char* p = host ? host : ""; *p && j + 1 < sizeof(safe); p++) {
        unsigned char c = (unsigned char)*p;
        safe[j++] = (c == '"' || c == '\\' || c < 0x20) ? '_' : (char)c;
    }
    safe[j] = '\0';
    fprintf(stderr,
            "{\"component\":\"broker\",\"event\":\"proxy\",\"sandbox_id\":%u,"
            "\"host\":\"%s\",\"status\":%d,\"latency_ms\":%ld}\n",
            sandbox_id, safe, status, ms);
}

static long elapsed_ms(const struct timespec* a, const struct timespec* b) {
    return (b->tv_sec - a->tv_sec) * 1000L + (b->tv_nsec - a->tv_nsec) / 1000000L;
}

int broker_handle_request(int client_fd, const credential_store_t* creds, int engine_fd) {
    if (client_fd < 0) return 500;
    http_request_t* req = calloc(1, sizeof(*req));
    if (!req) {
        send_http_error(client_fd, 500, "Out of memory");
        return 500;
    }

    if (http_parse_headers(client_fd, req) < 0) {
        send_http_error(client_fd, 400, "Malformed request");
        free(req);
        return 400;
    }

    // 1. Session token.
    const char* token = http_get_header(req, "X-Sandbox-Token");
    if (!token || !*token) {
        send_http_error(client_fd, 401, "Missing token");
        free(req);
        return 401;
    }

    // 2. Validate with the engine daemon.
    session_info_t session;
    int vr = broker_validate_token(engine_fd, token, &session);
    if (vr == BROKER_VALIDATE_INVALID) {
        send_http_error(client_fd, 401, "Invalid or expired token");
        free(req);
        return 401;
    }
    if (vr == BROKER_VALIDATE_ERROR) {
        send_http_error(client_fd, 502, "Token validation unavailable");
        free(req);
        return 502;
    }

    // 3. Target host + allowlist.
    const char* host = http_get_header(req, "Host");
    if (!host || !*host) {
        session_info_free(&session);
        send_http_error(client_fd, 400, "Missing Host header");
        free(req);
        return 400;
    }
    if (!broker_host_allowed(session.allowed_services, host)) {
        session_info_free(&session);
        send_http_error(client_fd, 403, "Service not allowed");
        free(req);
        return 403;
    }

    // 4. Real credential for this upstream.
    const char* real_cred = credential_store_lookup(creds, host);
    if (!real_cred) {
        session_info_free(&session);
        send_http_error(client_fd, 403, "Service not configured");
        free(req);
        return 403;
    }

    // 5. Strip the session token; inject the real credential.
    http_remove_header(req, "X-Sandbox-Token");
    http_set_header(req, "Authorization", real_cred);

    // 6. Chunked request bodies are not supported (bounded streaming only).
    if (http_get_header(req, "Transfer-Encoding")) {
        session_info_free(&session);
        send_http_error(client_fd, 502, "Chunked request bodies unsupported");
        free(req);
        return 502;
    }

    // 7. Forward upstream, streaming the response back to the guest.
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int status = broker_forward_upstream(req, client_fd, client_fd);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = elapsed_ms(&t0, &t1);

    if (status < 0) {
        // Best-effort: only meaningful if no upstream bytes were relayed yet.
        send_http_error(client_fd, 502, "Upstream unreachable");
        status = 502;
    }
    log_request(session.sandbox_id, host, status, ms);
    session_info_free(&session);
    free(req);
    return status;
}

// ---------------------------------------------------------------------------
// Production run loop
// ---------------------------------------------------------------------------

static int parse_listen(const char* spec, char* host, size_t hn, int* port) {
    const char* colon = strrchr(spec, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - spec);
    if (hl + 1 > hn) return -1;
    memcpy(host, spec, hl);
    host[hl] = '\0';
    *port = atoi(colon + 1);
    return (*port > 0 && *port <= 65535) ? 0 : -1;
}

int broker_run(void) {
    signal(SIGPIPE, SIG_IGN);

    credential_store_t* creds = credentials_load(broker_credentials_path());
    if (!creds) {
        fprintf(stderr, "[broker] cannot load credentials %s: %s\n",
                broker_credentials_path(), strerror(errno));
        return -1;
    }
    int engine_fd = broker_engine_connect(broker_control_path());
    if (engine_fd < 0) {
        fprintf(stderr, "[broker] cannot reach engine at %s: %s\n",
                broker_control_path(), strerror(errno));
        credentials_free(creds);
        return -1;
    }

    char host[256];
    int port = 0;
    if (parse_listen(broker_listen_addr(), host, sizeof(host), &port) < 0) {
        fprintf(stderr, "[broker] bad listen address %s\n", broker_listen_addr());
        close(engine_fd);
        credentials_free(creds);
        return -1;
    }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        close(engine_fd);
        credentials_free(creds);
        return -1;
    }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) sa.sin_addr.s_addr = INADDR_ANY;
    if (bind(lfd, (struct sockaddr*)&sa, sizeof(sa)) < 0 || listen(lfd, 128) < 0) {
        fprintf(stderr, "[broker] bind %s: %s\n", broker_listen_addr(), strerror(errno));
        close(lfd);
        close(engine_fd);
        credentials_free(creds);
        return -1;
    }
    fprintf(stderr, "[broker] listening on %s, credentials %s, engine %s\n",
            broker_listen_addr(), broker_credentials_path(), broker_control_path());

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        // Bound a stalled guest: header/body reads and response writes time out
        // rather than pinning the single-threaded accept loop forever.
        struct timeval tv = {.tv_sec = 30, .tv_usec = 0};
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        broker_handle_request(cfd, creds, engine_fd);
        close(cfd);
    }
    close(lfd);
    close(engine_fd);
    credentials_free(creds);
    return 0;
}
