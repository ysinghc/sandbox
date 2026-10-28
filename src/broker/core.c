// SPDX-License-Identifier: GPL-2.0-only
// Broker core (§5.8): session-token validation with the engine daemon,
// allow-listing, credential injection, and upstream proxying over libcurl.
// Everything here is testable in-process; src/broker/main.c only wires argv/env.

#define _GNU_SOURCE

#include "broker.h"
#include "egress_policy.h"
#include "log.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
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

// The broker port has exactly one source of truth, and it is not this file.
// src/network_manager.c programs each VM's egress rules with a single
// "ip daddr <host> tcp dport <port> accept" -- everything else to the host is
// dropped -- so if the listener and the rules disagree, every guest is cut off
// from the network with no diagnostic. broker_port() (include/broker.h) is that
// one value; SANDBOX_BROKER_LISTEN may still move the listener to another
// interface, as long as its port agrees. (8080 is a busy port on real hosts;
// self-hosters hit the collision immediately.)
const char* broker_listen_addr(void) {
    const char* v = getenv("SANDBOX_BROKER_LISTEN");
    if (v && *v) return v;
    static char buf[64];
    snprintf(buf, sizeof(buf), "0.0.0.0:%d", broker_port());
    return buf;
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
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
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
    return egress_match(allowed_services, host, NULL);
}

// ---------------------------------------------------------------------------
// Upstream forwarding (libcurl)
// ---------------------------------------------------------------------------

// How the request body reaches the upstream. Neither mode buffers it: libcurl
// pulls from the guest socket through fwd_read_cb, a buffer at a time.
enum { BODY_NONE = 0, BODY_LENGTH, BODY_CHUNKED };

struct fwd_ctx {
    int client_fd;
    int body_fd;
    int body_mode;
    uint64_t body_remaining;  // BODY_LENGTH: bytes still owed by the guest
    uint64_t body_total;      // bytes handed to the upstream so far
    uint64_t body_max;
    // BODY_CHUNKED decoder state: bytes left in the current chunk, whether the
    // CRLF that ends the previous chunk is still to be consumed, and EOF.
    uint64_t ch_left;
    bool ch_need_crlf;
    bool ch_done;
    // Why the body failed, if it did: BROKER_FWD_BAD_BODY or BROKER_FWD_TOO_LARGE.
    int body_err;
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

static int recv_crlf_line(int fd, char* line, size_t cap);

static int recv_exact(int fd, void* buf, size_t n) {
    char* p = buf;
    while (n) {
        ssize_t r = recv(fd, p, n, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

// Decode the guest's chunked body on demand: at most `want` bytes of payload per
// call, so memory is bounded by libcurl's buffer however large the upload is.
// Returns bytes produced, 0 at the end of the body, or CURL_READFUNC_ABORT after
// recording why in c->body_err.
static size_t chunked_read(struct fwd_ctx* c, char* buf, size_t want) {
    for (;;) {
        if (c->ch_done) return 0;
        if (c->ch_left == 0) {
            if (c->ch_need_crlf) {
                char crlf[2];
                if (recv_exact(c->body_fd, crlf, 2) < 0 || crlf[0] != '\r' || crlf[1] != '\n')
                    goto bad;
                c->ch_need_crlf = false;
            }
            char line[256];
            if (recv_crlf_line(c->body_fd, line, sizeof(line)) < 0) goto bad;
            char* semi = strchr(line, ';');  // drop any chunk extension
            if (semi) *semi = '\0';
            char* end = NULL;
            errno = 0;
            unsigned long long sz = strtoull(line, &end, 16);
            if (end == line || errno != 0 || line[0] == '-' || line[0] == '+') goto bad;
            if (sz == 0) {
                // Final chunk. Trailers are dropped; read to the blank line.
                for (;;) {
                    if (recv_crlf_line(c->body_fd, line, sizeof(line)) < 0) goto bad;
                    if (line[0] == '\r') break;
                }
                c->ch_done = true;
                return 0;
            }
            if (sz > c->body_max || c->body_total + sz > c->body_max) {
                c->body_err = BROKER_FWD_TOO_LARGE;
                return CURL_READFUNC_ABORT;
            }
            c->ch_left = sz;
        }
        size_t n = want;
        if ((uint64_t)n > c->ch_left) n = (size_t)c->ch_left;
        ssize_t r;
        do {
            r = recv(c->body_fd, buf, n, 0);
        } while (r < 0 && errno == EINTR);
        if (r <= 0) goto bad;
        c->ch_left -= (uint64_t)r;
        c->body_total += (uint64_t)r;
        if (c->ch_left == 0) c->ch_need_crlf = true;
        return (size_t)r;
    }
bad:
    c->body_err = BROKER_FWD_BAD_BODY;
    return CURL_READFUNC_ABORT;
}

static size_t fwd_read_cb(char* buffer, size_t size, size_t nmemb, void* ud) {
    struct fwd_ctx* c = ud;
    size_t want = size * nmemb;
    if (c->body_mode == BODY_CHUNKED) return chunked_read(c, buffer, want);
    if ((uint64_t)want > c->body_remaining) want = (size_t)c->body_remaining;
    if (want == 0) return 0;
    ssize_t r;
    do {
        r = read(c->body_fd, buffer, want);
    } while (r < 0 && errno == EINTR);
    if (r <= 0) {  // the guest promised more bytes than it sent
        c->body_err = BROKER_FWD_BAD_BODY;
        return CURL_READFUNC_ABORT;
    }
    c->body_remaining -= (uint64_t)r;
    c->body_total += (uint64_t)r;
    return (size_t)r;
}

uint64_t broker_max_body(void) {
    const char* v = getenv("SANDBOX_BROKER_MAX_BODY");
    if (v && *v) {
        char* end = NULL;
        unsigned long long n = strtoull(v, &end, 10);
        if (end != v && *end == '\0' && n > 0) return (uint64_t)n;
    }
    return BROKER_DEFAULT_MAX_BODY;
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
        // The guest's framing is replaced by ours: for a chunked upload libcurl
        // re-chunks what the read callback produces.
        if (strcasecmp(req->headers[i].name, "Transfer-Encoding") == 0) continue;
        char line[HTTP_MAX_NAME + HTTP_MAX_VALUE + 4];
        snprintf(line, sizeof(line), "%s: %s", req->headers[i].name,
                 req->headers[i].value);
        struct curl_slist* nh = curl_slist_append(hdrs, line);
        if (nh) hdrs = nh;
    }
    hdrs = curl_slist_append(hdrs, "Expect:");  // suppress 100-continue

    // Framing: chunked wins over Content-Length (RFC 9112 6.1), so a request that
    // sends both is treated as chunked and its Content-Length is ignored.
    const char* te = http_get_header(req, "Transfer-Encoding");
    int mode = BODY_NONE;
    uint64_t blen = 0;
    if (te && strcasestr(te, "chunked")) {
        mode = BODY_CHUNKED;
        hdrs = curl_slist_append(hdrs, "Transfer-Encoding: chunked");
    } else if (te && *te) {
        // Any other transfer coding cannot be relayed faithfully.
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(h);
        return BROKER_FWD_BAD_BODY;
    } else if (http_get_header(req, "Content-Length")) {
        blen = request_content_length(req);
        if (blen > 0) mode = BODY_LENGTH;
    }
    uint64_t max_body = broker_max_body();
    if (mode == BODY_LENGTH && blen > max_body) {
        // Refuse before relaying a byte: the declared size is the whole story.
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(h);
        return BROKER_FWD_TOO_LARGE;
    }
    struct fwd_ctx ctx = {
        .client_fd = client_fd,
        .body_fd = body_fd,
        .body_mode = mode,
        .body_remaining = blen,
        .body_max = max_body,
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
    if (mode != BODY_NONE) {
        curl_easy_setopt(h, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(h, CURLOPT_READFUNCTION, fwd_read_cb);
        curl_easy_setopt(h, CURLOPT_READDATA, &ctx);
        // A known length is sent as Content-Length; an unknown one makes libcurl
        // chunk-encode, which is what the explicit header above asks for.
        if (mode == BODY_LENGTH) curl_easy_setopt(h, CURLOPT_INFILESIZE_LARGE, (curl_off_t)blen);
    }
    // CURLOPT_UPLOAD would turn the verb into PUT; the guest's own method stays.

    CURLcode rc = curl_easy_perform(h);
    long status = ctx.status;
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(h);
    // A body that failed mid-stream is the guest's problem and has a precise
    // answer; anything else that went wrong is the upstream's.
    if (ctx.body_err) return ctx.body_err;
    if (rc != CURLE_OK) return -1;
    return (int)status;
}

static int recv_crlf_line(int fd, char* line, size_t cap) {
    size_t li = 0;
    for (;;) {
        char ch;
        ssize_t r = recv(fd, &ch, 1, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        if (li + 1 >= cap) return -1;
        line[li++] = ch;
        if (li >= 2 && line[li - 2] == '\r' && line[li - 1] == '\n') break;
    }
    line[li] = '\0';
    return (int)li;
}

// ---------------------------------------------------------------------------
// Request pipeline
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// §10.13 broker metrics
// ---------------------------------------------------------------------------

static atomic_long g_req_2xx = 0, g_req_4xx = 0, g_req_5xx = 0;
// #26: what the egress policy decided, independent of how the upstream answered.
static atomic_long g_egress_allowed = 0, g_egress_denied = 0, g_egress_unconfigured = 0;
static atomic_ulong g_up_lat_count = 0, g_up_lat_sum_ms = 0;
#define BROKER_LAT_BUCKETS 11
static const double g_lat_bounds[BROKER_LAT_BUCKETS] = {
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10};
static atomic_long g_up_lat_buckets[BROKER_LAT_BUCKETS];

static void broker_metrics_observe(int status, long ms) {
    if (status >= 500) atomic_fetch_add(&g_req_5xx, 1);
    else if (status >= 400) atomic_fetch_add(&g_req_4xx, 1);
    else if (status > 0) atomic_fetch_add(&g_req_2xx, 1);
    atomic_fetch_add(&g_up_lat_count, 1);
    atomic_fetch_add(&g_up_lat_sum_ms, (unsigned long)ms);
    double sec = (double)ms / 1000.0;
    for (int i = 0; i < BROKER_LAT_BUCKETS; i++) {
        if (sec <= g_lat_bounds[i]) {
            atomic_fetch_add(&g_up_lat_buckets[i], 1);
            break;
        }
    }
}

int broker_metrics_render(char* buf, int cap) {
    if (!buf || cap <= 0) return 0;
    int off = 0;
#define EMIT(...)                                                      \
    do {                                                               \
        int w = snprintf(buf + off, (size_t)(cap - off), __VA_ARGS__); \
        if (w < 0) return off;                                         \
        off += w;                                                      \
        if (off >= cap) return cap;                                    \
    } while (0)
    EMIT("# TYPE broker_requests_total counter\n");
    EMIT("broker_requests_total{status=\"2xx\"} %ld\n", atomic_load(&g_req_2xx));
    EMIT("broker_requests_total{status=\"4xx\"} %ld\n", atomic_load(&g_req_4xx));
    EMIT("broker_requests_total{status=\"5xx\"} %ld\n", atomic_load(&g_req_5xx));
    EMIT("# TYPE broker_egress_decisions_total counter\n");
    EMIT("broker_egress_decisions_total{decision=\"allowed\"} %ld\n",
         atomic_load(&g_egress_allowed));
    EMIT("broker_egress_decisions_total{decision=\"denied_policy\"} %ld\n",
         atomic_load(&g_egress_denied));
    EMIT("broker_egress_decisions_total{decision=\"denied_unconfigured\"} %ld\n",
         atomic_load(&g_egress_unconfigured));
    EMIT("# TYPE broker_upstream_latency_seconds histogram\n");
    for (int i = 0; i < BROKER_LAT_BUCKETS; i++) {
        EMIT("broker_upstream_latency_seconds_bucket{le=\"%g\"} %ld\n",
             g_lat_bounds[i], atomic_load(&g_up_lat_buckets[i]));
    }
    EMIT("broker_upstream_latency_seconds_bucket{le=\"+Inf\"} %ld\n",
         atomic_load(&g_up_lat_count));
    EMIT("broker_upstream_latency_seconds_sum %g\n",
         (double)atomic_load(&g_up_lat_sum_ms) / 1000.0);
    EMIT("broker_upstream_latency_seconds_count %ld\n",
         atomic_load(&g_up_lat_count));
#undef EMIT
    return off;
}

int broker_metrics_serve(int listen_fd) {
    if (listen_fd < 0) return -1;
    char body[8192];
    for (;;) {
        int cfd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        int n = broker_metrics_render(body, sizeof(body));
        char hdr[160];
        int hn = snprintf(hdr, sizeof(hdr),
                          "HTTP/1.0 200 OK\r\nContent-Type: text/plain; "
                          "version=0.0.4\r\nContent-Length: %d\r\n\r\n",
                          n);
        ssize_t w = send(cfd, hdr, (size_t)hn, MSG_NOSIGNAL);
        (void)w;
        if (n > 0) {
            w = send(cfd, body, (size_t)n, MSG_NOSIGNAL);
            (void)w;
        }
        close(cfd);
    }
}

static void log_request(uint32_t sandbox_id, const char* host, int status, long ms,
                        const char* decision) {
    char safe[256];
    size_t j = 0;
    for (const char* p = host ? host : ""; *p && j + 1 < sizeof(safe); p++) {
        unsigned char c = (unsigned char)*p;
        safe[j++] = (c == '"' || c == '\\' || c < 0x20) ? '_' : (char)c;
    }
    safe[j] = '\0';
    int level = (status >= 500) ? LOG_ERROR
                               : (status >= 400 ? LOG_WARN : LOG_INFO);
    LOGF(level, "broker", "proxy",
         "\"sandbox_id\":%u,\"host\":\"%s\",\"decision\":\"%s\",\"status\":%d,"
         "\"latency_ms\":%ld",
         sandbox_id, safe, decision, status, ms);
}

static long elapsed_ms(const struct timespec* a, const struct timespec* b) {
    return (b->tv_sec - a->tv_sec) * 1000L + (b->tv_nsec - a->tv_nsec) / 1000000L;
}

static int broker_handle_request_inner(int client_fd, const credential_store_t* creds, int engine_fd) {
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
    bool via_named = false;
    if (!egress_match(session.allowed_services, host, &via_named)) {
        // Audited like any request: what a sandbox tried to reach and was
        // refused is the part of the log that matters most.
        atomic_fetch_add(&g_egress_denied, 1);
        log_request(session.sandbox_id, host, 403, 0, "denied_policy");
        session_info_free(&session);
        send_http_error(client_fd, 403, "Service not allowed");
        free(req);
        return 403;
    }

    // 4. Real credential for this upstream.
    // A destination the developer named in the session's policy may be relayed
    // without one (a package index has no secret to inject). The daemon-wide "*"
    // never earns that: reaching an arbitrary host unauthenticated was not
    // something anyone asked for.
    const char* real_cred = credential_store_lookup(creds, host);
    if (!real_cred && !via_named) {
        atomic_fetch_add(&g_egress_unconfigured, 1);
        log_request(session.sandbox_id, host, 403, 0, "denied_unconfigured");
        session_info_free(&session);
        send_http_error(client_fd, 403, "Service not configured");
        free(req);
        return 403;
    }
    atomic_fetch_add(&g_egress_allowed, 1);

    // 5. Strip the session token; inject the real credential when there is one.
    http_remove_header(req, "X-Sandbox-Token");
    if (real_cred) http_set_header(req, "Authorization", real_cred);

    // 6. Forward upstream. The request body (Content-Length or chunked) streams
    // from the guest socket straight through; nothing is buffered.
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int status = broker_forward_upstream(req, client_fd, client_fd);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = elapsed_ms(&t0, &t1);

    if (status == BROKER_FWD_TOO_LARGE) {
        send_http_error(client_fd, 413, "Request body too large");
        status = 413;
    } else if (status == BROKER_FWD_BAD_BODY) {
        send_http_error(client_fd, 400, "Malformed request body");
        status = 400;
    } else     if (status < 0) {
        // Best-effort: only meaningful if no upstream bytes were relayed yet.
        send_http_error(client_fd, 502, "Upstream unreachable");
        status = 502;
    }
    log_request(session.sandbox_id, host, status, ms, real_cred ? "allowed_credentialed" : "allowed_anonymous");
    session_info_free(&session);
    free(req);
    return status;
}

// Public entry point: wrap the pipeline so every request is counted (including
// token/allowlist rejections) and total handler latency is recorded.
int broker_handle_request(int client_fd, const credential_store_t* creds, int engine_fd) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int status = broker_handle_request_inner(client_fd, creds, engine_fd);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    broker_metrics_observe(status, elapsed_ms(&t0, &t1));
    return status;
}

// ---------------------------------------------------------------------------
// Production run loop
// ---------------------------------------------------------------------------

static int parse_listen(const char* spec, char* host, size_t hn, int* port) {    const char* colon = strrchr(spec, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - spec);
    if (hl + 1 > hn) return -1;
    memcpy(host, spec, hl);
    host[hl] = '\0';
    *port = atoi(colon + 1);
    return (*port > 0 && *port <= 65535) ? 0 : -1;
}

// §5.8 step 4: drop privileges after binding. Only meaningful when started as
// root; the uid/gid come from SANDBOX_BROKER_UID/SANDBOX_BROKER_GID (default
// nobody:65534) because there is no config-file field for them.
static int drop_broker_privileges(void) {
    if (geteuid() != 0) return 0;
    const char* us = getenv("SANDBOX_BROKER_UID");
    const char* gs = getenv("SANDBOX_BROKER_GID");
    gid_t gid = gs ? (gid_t)strtol(gs, NULL, 10) : 65534;
    uid_t uid = us ? (uid_t)strtol(us, NULL, 10) : 65534;
    if (setgroups(1, &gid) != 0) {
        fprintf(stderr, "[broker] setgroups: %s\n", strerror(errno));
        return -1;
    }
    if (setgid(gid) != 0 || setuid(uid) != 0) {
        fprintf(stderr, "[broker] privilege drop to %d:%d failed: %s\n",
                (int)uid, (int)gid, strerror(errno));
        return -1;
    }
    if (getuid() != uid || geteuid() != uid) {
        fprintf(stderr, "[broker] privilege drop not effective\n");
        return -1;
    }
    return 0;
}

static void* broker_metrics_thread(void* arg) {
    broker_metrics_serve((int)(intptr_t)arg);
    return NULL;
}

// §10.13: optional broker /metrics listener (SANDBOX_BROKER_METRICS_PORT).
static void start_broker_metrics(void) {
    const char* mp = getenv("SANDBOX_BROKER_METRICS_PORT");
    if (!mp || !*mp) return;
    int port = atoi(mp);
    if (port <= 0 || port > 65535) return;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0 || listen(fd, 16) < 0) {
        fprintf(stderr, "[broker] metrics bind :%d failed: %s\n", port,
                strerror(errno));
        close(fd);
        return;
    }
    pthread_t t;
    if (pthread_create(&t, NULL, broker_metrics_thread,
                       (void*)(intptr_t)fd) == 0) {
        pthread_detach(t);
        LOGF(LOG_INFO, "broker", "metrics", "\"port\":%d", port);
    } else {
        close(fd);
    }
}

int broker_run(void) {
    signal(SIGPIPE, SIG_IGN);

    // A group/world-readable secrets file is a credential leak; refuse it
    // before parsing. The check prints its own diagnostic (issue #3).
    if (credentials_check_permissions(broker_credentials_path()) != 0) return -1;

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

    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
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

    start_broker_metrics();  // §10.13 (before the privilege drop, if any)

    if (drop_broker_privileges() != 0) {
        close(lfd);
        close(engine_fd);
        credentials_free(creds);
        return -1;
    }

    for (;;) {
        int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
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
