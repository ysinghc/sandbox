// SPDX-License-Identifier: GPL-2.0-only
// Phase 7 verification: credential broker request pipeline.
//
// Covers credential-file parsing, HTTP header parsing/munging, session-token
// decoding, host allow-listing, and an end-to-end proxy: a mock engine
// validates the session token, a mock upstream receives the proxied request
// (real credential injected, session token stripped, body streamed), and its
// response is relayed back to the "guest". Also asserts the reject paths.
//
// No root, no fixed ports (ephemeral), no real upstream: the upstream scheme
// is overridden to http and both peers are in-process threads.

#define _DEFAULT_SOURCE

#include "broker.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define TOKEN_HEX \
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static const uint8_t TOKEN_BYTES[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};

static int g_fail = 0;
static char g_dir[256];
static char g_creds[512];

#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (!(cond)) {                                            \
            fprintf(stderr, "  FAIL: %s\n", (msg));               \
            g_fail++;                                             \
        }                                                         \
    } while (0)

static void report(const char* name, int before) {
    printf("[test] %-14s %s\n", name, (g_fail == before) ? "PASS" : "FAIL");
    fflush(stdout);
}

// --- tiny IO helpers -------------------------------------------------------
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

static void write_file(const char* path, const char* body) {
    FILE* f = fopen(path, "w");
    if (!f) {
        perror("fopen");
        exit(2);
    }
    fputs(body, f);
    fclose(f);
}

// --- mock engine (broker-control over a Unix socket) -----------------------
typedef struct {
    int listen_fd;
    int client_fd_fd;         // broker->engine connection (test side)
    const uint8_t* expected;  // 32 bytes; NULL => reject every token
    int n_allowed;
    const char* allowed[4];
    int served;
} mock_engine_t;

static int engine_listen(const char* path) {
    unlink(path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(fd, 4) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void* engine_thread(void* arg) {
    mock_engine_t* m = arg;
    int fd = accept(m->listen_fd, NULL, NULL);
    if (fd < 0) return NULL;
    for (;;) {
        uint8_t req[BROKER_VALIDATE_REQ_LEN];
        if (read_full(fd, req, sizeof(req)) < 0) break;
        int ok = m->expected && memcmp(req + 1, m->expected, 32) == 0;
        uint8_t status = ok ? 0 : 1;
        if (write_full(fd, &status, 1) < 0 || !ok) {
            m->served++;
            continue;
        }
        uint8_t id[4] = {0, 0, 0, 42};
        uint8_t nb[2] = {0, (uint8_t)m->n_allowed};
        write_full(fd, id, 4);
        write_full(fd, nb, 2);
        for (int i = 0; i < m->n_allowed; i++) {
            uint8_t len = (uint8_t)strlen(m->allowed[i]);
            write_full(fd, &len, 1);
            write_full(fd, m->allowed[i], len);
        }
        m->served++;
    }
    close(fd);
    return NULL;
}

// --- mock upstream (plain HTTP, loopback, ephemeral port) ------------------
typedef struct {
    int listen_fd;
    char request[16384];
    size_t req_len;
    char response[512];
} mock_upstream_t;

static int upstream_listen(uint16_t* port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    socklen_t sl = sizeof(sa);
    if (getsockname(fd, (struct sockaddr*)&sa, &sl) < 0 || listen(fd, 4) < 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(sa.sin_port);
    return fd;
}

static void read_http_request(int fd, char* out, size_t cap, size_t* out_len) {
    size_t len = 0;
    *out_len = 0;
    for (;;) {
        if (len + 1 >= cap) break;
        ssize_t r = recv(fd, out + len, cap - 1 - len, 0);
        if (r <= 0) break;
        len += (size_t)r;
        out[len] = '\0';
        char* hend = strstr(out, "\r\n\r\n");
        if (!hend) continue;
        size_t hlen = (size_t)(hend + 4 - out);
        long cl = 0;
        char* clp = strstr(out, "Content-Length:");
        if (clp) cl = strtol(clp + 15, NULL, 10);
        while (len < hlen + (size_t)cl && len + 1 < cap) {
            ssize_t r2 = recv(fd, out + len, cap - 1 - len, 0);
            if (r2 <= 0) break;
            len += (size_t)r2;
            out[len] = '\0';
        }
        break;
    }
    *out_len = len;
}

static void* upstream_thread(void* arg) {
    mock_upstream_t* m = arg;
    int fd = accept(m->listen_fd, NULL, NULL);
    if (fd < 0) return NULL;
    read_http_request(fd, m->request, sizeof(m->request), &m->req_len);
    write_full(fd, m->response, strlen(m->response));
    close(fd);
    return NULL;
}

// Read a guest-side response until sentinel (or 2s poll timeout).
static int read_response(int fd, char* out, size_t cap, const char* sentinel) {
    size_t len = 0;
    out[0] = '\0';
    for (;;) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 2000) <= 0) break;
        ssize_t r = recv(fd, out + len, cap - 1 - len, 0);
        if (r <= 0) break;
        len += (size_t)r;
        out[len] = '\0';
        if (sentinel && strstr(out, sentinel)) break;
    }
    return (int)len;
}

// --- unit tests ------------------------------------------------------------

static void test_credentials(void) {
    int b = g_fail;
    char p[512];
    snprintf(p, sizeof(p), "%s/creds.conf", g_dir);
    write_file(p,
               "# comment\n"
               "\n"
               "[api.openai.com]\n"
               "credential = Bearer sk-secret\n"
               "\n"
               "; semicolon comment\n"
               "[127.0.0.1]\n"
               "credential = Bearer local-secret\n");
    credential_store_t* s = credentials_load(p);
    CHECK(s != NULL, "load valid file");
    if (s) {
        CHECK(credential_store_lookup(s, "api.openai.com") &&
                  strcmp(credential_store_lookup(s, "api.openai.com"),
                         "Bearer sk-secret") == 0,
              "exact host lookup");
        CHECK(credential_store_lookup(s, "API.OPENAI.COM:443") &&
                  strcmp(credential_store_lookup(s, "API.OPENAI.COM:443"),
                         "Bearer sk-secret") == 0,
              "case-insensitive + port stripped");
        CHECK(credential_store_lookup(s, "127.0.0.1:8080") &&
                  strcmp(credential_store_lookup(s, "127.0.0.1:8080"),
                         "Bearer local-secret") == 0,
              "host:port lookup");
        CHECK(credential_store_lookup(s, "example.com") == NULL,
              "unknown host -> NULL");
        credentials_free(s);
    }
    CHECK(credentials_load("/nonexistent/xyz.conf") == NULL,
          "missing file -> NULL");

    // #3: permissions / ownership gate on the secrets file.
    CHECK(chmod(p, 0600) == 0, "chmod 0600");
    CHECK(credentials_check_permissions(p) == 0, "0600 file accepted");
    CHECK(chmod(p, 0644) == 0, "chmod 0644");
    CHECK(credentials_check_permissions(p) != 0, "world-readable file refused");
    CHECK(credentials_check_permissions("/nonexistent/xyz.conf") == 0,
          "absent file is not an error");
    setenv("SANDBOX_ALLOW_INSECURE_CREDENTIALS", "1", 1);
    CHECK(credentials_check_permissions(p) == 0,
          "dev override downgrades refusal to a warning");
    unsetenv("SANDBOX_ALLOW_INSECURE_CREDENTIALS");
    report("credentials", b);
}

static void test_http(void) {
    int b = g_fail;
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    const char* raw =
        "POST /v1/echo?x=1 HTTP/1.1\r\n"
        "Host: api.openai.com\r\n"
        "X-Sandbox-Token: " TOKEN_HEX "\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";
    write_full(sv[1], raw, strlen(raw));
    http_request_t* req = calloc(1, sizeof(*req));
    CHECK(http_parse_headers(sv[0], req) == 0, "parse");
    CHECK(strcmp(req->method, "POST") == 0, "method");
    CHECK(strcmp(req->target, "/v1/echo?x=1") == 0, "target");
    CHECK(strcmp(req->version, "HTTP/1.1") == 0, "version");
    CHECK(req->nheaders == 3, "header count");
    CHECK(http_get_header(req, "host") != NULL, "get header (ci)");
    CHECK(http_get_header(req, "X-SANDBOX-TOKEN") != NULL, "get token (ci)");
    CHECK(http_set_header(req, "Authorization", "Bearer z") == 0, "set new");
    CHECK(strcmp(http_get_header(req, "authorization"), "Bearer z") == 0,
          "set + get");
    CHECK(http_set_header(req, "Authorization", "Bearer y") == 0, "set replace");
    CHECK(strcmp(http_get_header(req, "Authorization"), "Bearer y") == 0,
          "replaced value");
    CHECK(req->nheaders == 4, "count after add");
    CHECK(http_remove_header(req, "x-sandbox-token") == 0, "remove (ci)");
    CHECK(http_get_header(req, "X-Sandbox-Token") == NULL, "removed");
    CHECK(req->nheaders == 3, "count after remove");
    // Body untouched: exactly 5 bytes remain readable from the socket.
    char body[8] = {0};
    CHECK(read_full(sv[0], body, 5) == 0 && memcmp(body, "hello", 5) == 0,
          "body left in socket");
    free(req);
    close(sv[0]);
    close(sv[1]);
    report("http", b);
}

static void test_token(void) {
    int b = g_fail;
    uint8_t t[32];
    CHECK(broker_token_from_hex(TOKEN_HEX, t) == 0, "decode 64 hex");
    CHECK(memcmp(t, TOKEN_BYTES, 32) == 0, "decoded bytes match");
    CHECK(broker_token_from_hex("abc", t) == -1, "short rejected");
    CHECK(broker_token_from_hex(
              "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
              t) == -1,
          "non-hex rejected");
    report("token", b);
}

static void test_allowlist(void) {
    int b = g_fail;
    const char* list[] = {"api.openai.com", NULL};
    const char* wild[] = {"*", NULL};
    CHECK(broker_host_allowed((char* const*)list, "api.openai.com"), "exact");
    CHECK(broker_host_allowed((char* const*)list, "API.OpenAI.com:443"),
          "ci + port");
    CHECK(!broker_host_allowed((char* const*)list, "evil.com"), "denied");
    CHECK(broker_host_allowed((char* const*)wild, "anything.at.all"), "wildcard");
    CHECK(!broker_host_allowed(NULL, "api.openai.com"), "empty list denies");
    report("allowlist", b);
}

// Spin up engine + upstream, proxy one request, return the guest status.
static int proxy_once(mock_engine_t* eng, mock_upstream_t* up,
                      const char* guest_req, char* resp, size_t cap,
                      const char* sentinel) {
    CHECK(up->listen_fd >= 0, "upstream listen");
    pthread_t uth;
    pthread_create(&uth, NULL, upstream_thread, up);

    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    write_full(sv[1], guest_req, strlen(guest_req));

    credential_store_t* creds = credentials_load(g_creds);
    CHECK(creds != NULL, "load proxy creds");

    int st = broker_handle_request(sv[0], creds, eng->client_fd_fd);
    read_response(sv[1], resp, cap, sentinel);

    credentials_free(creds);
    close(sv[0]);
    close(sv[1]);
    pthread_join(uth, NULL);
    return st;
}

static void test_proxy(void) {
    int b = g_fail;
    char epath[512];
    snprintf(epath, sizeof(epath), "%s/engine.sock", g_dir);
    mock_engine_t eng;
    memset(&eng, 0, sizeof(eng));
    eng.expected = TOKEN_BYTES;
    eng.n_allowed = 1;
    eng.allowed[0] = "127.0.0.1";
    eng.listen_fd = engine_listen(epath);
    CHECK(eng.listen_fd >= 0, "engine listen");
    pthread_t eth;
    pthread_create(&eth, NULL, engine_thread, &eng);
    eng.client_fd_fd = broker_engine_connect(epath);
    CHECK(eng.client_fd_fd >= 0, "engine connect");

    mock_upstream_t up;
    memset(&up, 0, sizeof(up));
    snprintf(up.response, sizeof(up.response),
             "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"
             "hello");
    uint16_t port = 0;
    up.listen_fd = upstream_listen(&port);

    char greq[1024], resp[4096];
    snprintf(greq, sizeof(greq),
             "POST /v1/echo HTTP/1.1\r\n"
             "Host: 127.0.0.1:%u\r\n"
             "X-Sandbox-Token: " TOKEN_HEX "\r\n"
             "Content-Length: 5\r\n"
             "\r\n"
             "hello",
             port);
    int st = proxy_once(&eng, &up, greq, resp, sizeof(resp), "hello");
    CHECK(st == 200, "upstream status 200");
    CHECK(strstr(resp, "200 OK") && strstr(resp, "hello"), "response relayed");

    // Close the engine connection so its thread sees EOF, then join.
    close(eng.client_fd_fd);
    pthread_join(eth, NULL);
    close(eng.listen_fd);
    unlink(epath);

    CHECK(up.req_len > 0, "upstream received a request");
    CHECK(strstr(up.request, "POST /v1/echo HTTP/1.1") != NULL, "method/target");
    CHECK(strstr(up.request, "Authorization: Bearer test-secret") != NULL,
          "credential injected");
    CHECK(strstr(up.request, "X-Sandbox-Token") == NULL, "token stripped");
    CHECK(strstr(up.request, "hello") != NULL, "request body streamed");
    CHECK(eng.served == 1, "engine validated once");
    report("proxy", b);
}

// §10.14: chunked request bodies are decoded, re-framed with Content-Length,
// and forwarded to the upstream.
static void test_chunked(void) {
    int b = g_fail;
    char epath[512];
    snprintf(epath, sizeof(epath), "%s/engine-chunk.sock", g_dir);
    mock_engine_t eng;
    memset(&eng, 0, sizeof(eng));
    eng.expected = TOKEN_BYTES;
    eng.n_allowed = 1;
    eng.allowed[0] = "127.0.0.1";
    eng.listen_fd = engine_listen(epath);
    CHECK(eng.listen_fd >= 0, "engine listen");
    pthread_t eth;
    pthread_create(&eth, NULL, engine_thread, &eng);
    eng.client_fd_fd = broker_engine_connect(epath);
    CHECK(eng.client_fd_fd >= 0, "engine connect");

    mock_upstream_t up;
    memset(&up, 0, sizeof(up));
    snprintf(up.response, sizeof(up.response),
             "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"
             "hello");
    uint16_t port = 0;
    up.listen_fd = upstream_listen(&port);

    char greq[1024], resp[4096];
    snprintf(greq, sizeof(greq),
             "POST /v1/echo HTTP/1.1\r\n"
             "Host: 127.0.0.1:%u\r\n"
             "X-Sandbox-Token: " TOKEN_HEX "\r\n"
             "Transfer-Encoding: chunked\r\n"
             "\r\n"
             "5\r\nhello\r\n"
             "6\r\n world\r\n"
             "0\r\n\r\n",
             port);
    int st = proxy_once(&eng, &up, greq, resp, sizeof(resp), "hello");
    CHECK(st == 200, "chunked upstream status 200");
    CHECK(strstr(resp, "200 OK") && strstr(resp, "hello"), "chunked response relayed");

    close(eng.client_fd_fd);
    pthread_join(eth, NULL);
    close(eng.listen_fd);
    unlink(epath);

    // The reassembled body must arrive with a Content-Length (no chunked TE).
    CHECK(strstr(up.request, "hello world") != NULL, "chunked body decoded");
    CHECK(strstr(up.request, "Transfer-Encoding") == NULL, "TE header removed");
    CHECK(strstr(up.request, "Content-Length: 11") != NULL, "re-framed length");
    report("chunked", b);
}

static void test_denied(void) {
    int b = g_fail;
    char epath[512];
    snprintf(epath, sizeof(epath), "%s/engine2.sock", g_dir);
    mock_engine_t eng;
    memset(&eng, 0, sizeof(eng));
    eng.expected = TOKEN_BYTES;
    eng.n_allowed = 1;
    eng.allowed[0] = "other.example";
    eng.listen_fd = engine_listen(epath);
    pthread_t eth;
    pthread_create(&eth, NULL, engine_thread, &eng);
    eng.client_fd_fd = broker_engine_connect(epath);

    // No upstream: the request must be rejected before any forward.
    mock_upstream_t up;
    memset(&up, 0, sizeof(up));
    up.listen_fd = -1;

    char greq[1024], resp[2048];
    snprintf(greq, sizeof(greq),
             "GET / HTTP/1.1\r\nHost: 127.0.0.1:9\r\n"
             "X-Sandbox-Token: " TOKEN_HEX "\r\n\r\n");
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    write_full(sv[1], greq, strlen(greq));
    credential_store_t* creds = credentials_load(g_creds);
    int st = broker_handle_request(sv[0], creds, eng.client_fd_fd);
    read_response(sv[1], resp, sizeof(resp), "403");
    credentials_free(creds);
    CHECK(st == 403, "denied status 403");
    CHECK(strstr(resp, "403") != NULL, "403 relayed");

    close(sv[0]);
    close(sv[1]);
    close(eng.client_fd_fd);
    close(eng.listen_fd);
    unlink(epath);
    pthread_join(eth, NULL);
    report("denied", b);
}

static void test_bad_token(void) {
    int b = g_fail;
    char epath[512];
    snprintf(epath, sizeof(epath), "%s/engine3.sock", g_dir);
    mock_engine_t eng;
    memset(&eng, 0, sizeof(eng));
    eng.expected = NULL;  // reject everything
    eng.listen_fd = engine_listen(epath);
    pthread_t eth;
    pthread_create(&eth, NULL, engine_thread, &eng);
    eng.client_fd_fd = broker_engine_connect(epath);

    mock_upstream_t up;
    memset(&up, 0, sizeof(up));
    up.listen_fd = -1;

    char greq[1024], resp[2048];
    snprintf(greq, sizeof(greq),
             "GET / HTTP/1.1\r\nHost: 127.0.0.1:9\r\n"
             "X-Sandbox-Token: " TOKEN_HEX "\r\n\r\n");
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    write_full(sv[1], greq, strlen(greq));
    credential_store_t* creds = credentials_load(g_creds);
    int st = broker_handle_request(sv[0], creds, eng.client_fd_fd);
    read_response(sv[1], resp, sizeof(resp), "401");
    credentials_free(creds);
    CHECK(st == 401, "invalid token -> 401");
    CHECK(strstr(resp, "401") != NULL, "401 relayed");

    close(sv[0]);
    close(sv[1]);
    close(eng.client_fd_fd);
    close(eng.listen_fd);
    unlink(epath);
    pthread_join(eth, NULL);
    report("bad_token", b);
}

static void test_missing_token(void) {
    int b = g_fail;
    char greq[1024], resp[2048];
    snprintf(greq, sizeof(greq), "GET / HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n");
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    write_full(sv[1], greq, strlen(greq));
    credential_store_t* creds = credentials_load(g_creds);
    int st = broker_handle_request(sv[0], creds, -1);  // engine never reached
    read_response(sv[1], resp, sizeof(resp), "401");
    credentials_free(creds);
    CHECK(st == 401, "missing token -> 401");
    CHECK(strstr(resp, "Missing token") != NULL, "missing-token message");
    close(sv[0]);
    close(sv[1]);
    report("missing_token", b);
}

static void test_bad_request(void) {
    int b = g_fail;
    char resp[512];
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    const char* bad = "garbage\r\n\r\n";
    write_full(sv[1], bad, strlen(bad));
    int st = broker_handle_request(sv[0], NULL, -1);
    read_response(sv[1], resp, sizeof(resp), "400");
    CHECK(st == 400, "malformed -> 400");
    close(sv[0]);
    close(sv[1]);
    report("bad_request", b);
}

int main(void) {
    setenv("SANDBOX_BROKER_UPSTREAM_SCHEME", "http", 1);

    char tmpl[] = "/tmp/sbtest-broker-XXXXXX";
    char* d = mkdtemp(tmpl);
    if (!d) {
        perror("mkdtemp");
        return 2;
    }
    snprintf(g_dir, sizeof(g_dir), "%s", d);
    snprintf(g_creds, sizeof(g_creds), "%s/proxy.conf", g_dir);
    write_file(g_creds, "[127.0.0.1]\ncredential = Bearer test-secret\n");

    test_credentials();
    test_http();
    test_token();
    test_allowlist();
    test_proxy();
    test_chunked();
    test_denied();
    test_bad_token();
    test_missing_token();
    test_bad_request();

    // §10.13: broker metrics reflect the requests driven above.
    {
        char mb[8192];
        int n = broker_metrics_render(mb, sizeof(mb));
        if (n <= 0 || !strstr(mb, "broker_requests_total{status=\"2xx\"}") ||
            !strstr(mb, "broker_upstream_latency_seconds_count")) {
            fprintf(stderr, "FAIL: broker metrics render\n%s\n", mb);
            g_fail = 1;
        }
    }

    char rm[512];
    snprintf(rm, sizeof(rm), "rm -rf %s", g_dir);
    if (system(rm) != 0) { /* best effort */ }

    printf("%s\n", g_fail ? "[test] broker: FAIL" : "[test] broker: ALL PASS");
    return g_fail ? 1 : 0;
}
