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
#include "sha256.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
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
        if (strcasestr(out, "Transfer-Encoding: chunked")) {
            // No length to wait for: read to the terminating zero chunk.
            while (!strstr(out + hlen, "\r\n0\r\n\r\n") && len + 1 < cap) {
                ssize_t r2 = recv(fd, out + len, cap - 1 - len, 0);
                if (r2 <= 0) break;
                len += (size_t)r2;
                out[len] = '\0';
            }
            break;
        }
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

// Chunked request bodies stream through: the broker decodes the guest's chunks
// and the upstream receives the same payload, chunk-framed by libcurl.
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

    // The upstream sees chunked framing (never a Content-Length: the total is
    // unknown) and the decoded payload is exactly what the guest sent.
    CHECK(strstr(up.request, "Transfer-Encoding: chunked") != NULL, "upstream gets chunked");
    CHECK(strstr(up.request, "Content-Length") == NULL, "no Content-Length on chunked");
    const char* body = strstr(up.request, "\r\n\r\n");
    char dec[256];
    size_t dn = 0;
    if (body) {
        body += 4;
        while (*body) {
            char* e = NULL;
            unsigned long n = strtoul(body, &e, 16);
            if (e == body || n == 0 || strncmp(e, "\r\n", 2) != 0) break;
            body = e + 2;
            if (dn + n >= sizeof(dec) || strlen(body) < n) break;
            memcpy(dec + dn, body, n);
            dn += n;
            body += n + 2;
        }
    }
    dec[dn] = '\0';
    CHECK(strcmp(dec, "hello world") == 0, "chunked payload intact");
    report("chunked", b);
}

// ---------------------------------------------------------------------------
// Streaming fidelity: a body far larger than any buffer, hashed on both sides.
// The guest side generates it on the fly and the upstream hashes what it
// receives, so neither end holds the body and a bounded broker is the only
// place it could pile up.

typedef struct {
    int listen_fd;
    int chunked_in;           // upstream saw Transfer-Encoding: chunked
    int has_cl;               // upstream saw Content-Length
    uint64_t got;             // body bytes received
    uint8_t digest[32];
    int complete;             // reached the end of the body framing
} stream_up_t;

static int su_getc(int fd, char* buf, size_t* pos, size_t* len) {
    if (*pos == *len) {
        ssize_t r;
        do {
            r = recv(fd, buf, 65536, 0);
        } while (r < 0 && errno == EINTR);
        if (r <= 0) return -1;
        *pos = 0;
        *len = (size_t)r;
    }
    return (unsigned char)buf[(*pos)++];
}

static void* stream_up_thread(void* arg) {
    stream_up_t* u = arg;
    int fd = accept(u->listen_fd, NULL, NULL);
    if (fd < 0) return NULL;
    static char buf[65536];
    size_t pos = 0, len = 0;
    char hdr[8192];
    size_t hl = 0;
    int c;
    while (hl + 1 < sizeof(hdr) && (c = su_getc(fd, buf, &pos, &len)) >= 0) {
        hdr[hl++] = (char)c;
        hdr[hl] = '\0';
        if (hl >= 4 && memcmp(hdr + hl - 4, "\r\n\r\n", 4) == 0) break;
    }
    u->chunked_in = strcasestr(hdr, "Transfer-Encoding: chunked") != NULL;
    const char* clp = strcasestr(hdr, "Content-Length:");
    u->has_cl = clp != NULL;
    uint64_t cl = clp ? strtoull(clp + 15, NULL, 10) : 0;

    sha256_ctx sc;
    sha256_init(&sc);
    uint64_t chunk_left = 0;
    int ok = 1;
    if (u->chunked_in) {
        for (;;) {
            char line[64];
            size_t ln = 0;
            while (ln + 1 < sizeof(line) && (c = su_getc(fd, buf, &pos, &len)) >= 0 && c != '\n')
                line[ln++] = (char)c;
            line[ln] = '\0';
            if (c < 0) { ok = 0; break; }
            chunk_left = strtoull(line, NULL, 16);
            if (chunk_left == 0) {
                // trailing CRLF after the zero chunk
                su_getc(fd, buf, &pos, &len);
                su_getc(fd, buf, &pos, &len);
                break;
            }
            while (chunk_left) {
                if (pos == len) {
                    int c2 = su_getc(fd, buf, &pos, &len);
                    if (c2 < 0) { ok = 0; break; }
                    pos--;  // un-read: su_getc consumed one byte
                }
                size_t avail = len - pos;
                if (avail == 0) continue;
                size_t take = avail < chunk_left ? avail : (size_t)chunk_left;
                sha256_update(&sc, buf + pos, take);
                pos += take;
                chunk_left -= take;
                u->got += take;
            }
            if (!ok) break;
            su_getc(fd, buf, &pos, &len);  // CR
            su_getc(fd, buf, &pos, &len);  // LF
        }
        u->complete = ok;
    } else {
        while (u->got < cl) {
            if (pos == len) {
                int c2 = su_getc(fd, buf, &pos, &len);
                if (c2 < 0) break;
                pos--;
            }
            size_t avail = len - pos;
            if (avail == 0) continue;
            size_t take = avail;
            if ((uint64_t)take > cl - u->got) take = (size_t)(cl - u->got);
            sha256_update(&sc, buf + pos, take);
            pos += take;
            u->got += take;
        }
        u->complete = u->got == cl;
    }
    sha256_final(&sc, u->digest);
    static const char ok_resp[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    write_full(fd, ok_resp, sizeof(ok_resp) - 1);
    close(fd);
    return NULL;
}

typedef struct {
    int fd;
    uint64_t total;
    int chunked;
    int bad_chunk;            // corrupt the framing after the first chunk
    int port;
    uint8_t digest[32];
    uint64_t sent;
} guest_w_t;

static void* guest_writer(void* arg) {
    guest_w_t* g = arg;
    char hdr[512];
    int n = snprintf(hdr, sizeof(hdr),
                     "POST /v1/upload HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                     "X-Sandbox-Token: " TOKEN_HEX "\r\n",
                     g->port);
    if (g->chunked)
        n += snprintf(hdr + n, sizeof(hdr) - (size_t)n, "Transfer-Encoding: chunked\r\n\r\n");
    else
        n += snprintf(hdr + n, sizeof(hdr) - (size_t)n, "Content-Length: %llu\r\n\r\n",
                      (unsigned long long)g->total);
    if (write_full(g->fd, hdr, (size_t)n) < 0) return NULL;

    sha256_ctx sc;
    sha256_init(&sc);
    static uint8_t blk[48 * 1024 + 7];
    uint64_t x = 0x9e3779b97f4a7c15ull, left = g->total;
    unsigned step = 0;
    while (left) {
        // Vary the block size so chunk and read boundaries never line up.
        size_t want = 1 + (size_t)((step++ * 7919u) % (sizeof(blk) - 1));
        if (want > left) want = (size_t)left;
        for (size_t i = 0; i < want; i++) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            blk[i] = (uint8_t)x;
        }
        sha256_update(&sc, blk, want);
        if (g->chunked) {
            char cl[32];
            int cn = snprintf(cl, sizeof(cl), "%zx\r\n", want);
            if (write_full(g->fd, cl, (size_t)cn) < 0) goto out;
        }
        if (write_full(g->fd, blk, want) < 0) goto out;
        if (g->chunked) {
            if (g->bad_chunk && step == 2) {
                write_full(g->fd, "XX", 2);  // not a CRLF
                goto out;
            }
            if (write_full(g->fd, "\r\n", 2) < 0) goto out;
        }
        g->sent += want;
        left -= want;
    }
    if (g->chunked) write_full(g->fd, "0\r\n\r\n", 5);
out:
    sha256_final(&sc, g->digest);
    return NULL;
}

static long vm_hwm_kb(void) {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[128];
    long v = -1;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "VmHWM: %ld kB", &v) == 1) break;
    fclose(f);
    return v;
}

// Drive one upload through the broker. Returns the guest-visible status line
// in `resp` and the broker's own return code.
static int stream_once(const char* tag, uint64_t total, int chunked, int bad_chunk,
                       stream_up_t* up, guest_w_t* gw, char* resp, size_t cap) {
    char epath[512];
    snprintf(epath, sizeof(epath), "%s/engine-%s.sock", g_dir, tag);
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

    uint16_t port = 0;
    memset(up, 0, sizeof(*up));
    up->listen_fd = upstream_listen(&port);
    CHECK(up->listen_fd >= 0, "upstream listen");
    pthread_t uth;
    pthread_create(&uth, NULL, stream_up_thread, up);

    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    memset(gw, 0, sizeof(*gw));
    gw->fd = sv[1];
    gw->total = total;
    gw->chunked = chunked;
    gw->bad_chunk = bad_chunk;
    gw->port = port;
    pthread_t wth;
    pthread_create(&wth, NULL, guest_writer, gw);

    credential_store_t* creds = credentials_load(g_creds);
    CHECK(creds != NULL, "load creds");
    int st = broker_handle_request(sv[0], creds, eng.client_fd_fd);
    read_response(sv[1], resp, cap, "\r\n\r\n");

    // Closing both ends unblocks whichever thread is still mid-transfer.
    close(sv[0]);
    close(sv[1]);
    shutdown(up->listen_fd, SHUT_RDWR);  // wakes accept() if nothing ever connected
    pthread_join(wth, NULL);
    pthread_join(uth, NULL);
    close(up->listen_fd);
    credentials_free(creds);
    close(eng.client_fd_fd);
    pthread_join(eth, NULL);
    close(eng.listen_fd);
    unlink(epath);
    return st;
}

static void check_stream(const char* what, int chunked) {
    int b = g_fail;
    const uint64_t total = 64ull * 1024 * 1024 + 12345;  // not a multiple of anything
    stream_up_t up;
    guest_w_t gw;
    char resp[1024];
    long before = vm_hwm_kb();
    int st = stream_once(chunked ? "big-chunked" : "big-cl", total, chunked, 0, &up, &gw,
                         resp, sizeof(resp));
    long after = vm_hwm_kb();
    CHECK(st == 200, "large upload returns upstream 200");
    CHECK(strstr(resp, "200 OK") != NULL, "response relayed to guest");
    CHECK(up.complete, "upstream saw the whole body");
    CHECK(up.got == total, "byte count identical");
    CHECK(gw.sent == total, "guest sent everything");
    CHECK(memcmp(up.digest, gw.digest, 32) == 0, "SHA-256 identical end to end");
    CHECK(up.chunked_in == chunked, "framing towards upstream follows the guest's");
    CHECK(chunked ? !up.has_cl : up.has_cl, "Content-Length only when the guest gave one");
    // 64 MiB went through; memory may grow by socket/curl buffers, never by the body.
    CHECK(before > 0 && after > 0 && after - before < 16 * 1024, "peak RSS stays bounded");
    if (g_fail != b)
        fprintf(stderr, "  (%s: status %d, got %llu/%llu, hwm %ld -> %ld kB)\n", what, st,
                (unsigned long long)up.got, (unsigned long long)total, before, after);
    report(what, b);
}

static void test_stream_large(void) {
    check_stream("stream_content_length", 0);
    check_stream("stream_chunked", 1);
}

// Oversize bodies fail predictably and are never silently truncated.
static void test_body_limits(void) {
    int b = g_fail;
    setenv("SANDBOX_BROKER_MAX_BODY", "1048576", 1);  // 1 MiB
    CHECK(broker_max_body() == 1048576, "limit read from the environment");

    stream_up_t up;
    guest_w_t gw;
    char resp[1024];

    // Declared Content-Length over the limit: refused before anything is sent.
    int st = stream_once("cl-big", 4 * 1024 * 1024, 0, 0, &up, &gw, resp, sizeof(resp));
    CHECK(st == 413, "oversize Content-Length -> 413");
    CHECK(strstr(resp, "413") != NULL, "guest sees 413");
    CHECK(up.got == 0, "nothing reached the upstream");

    // Chunked stream that crosses the limit: cut off, 413, upstream never completes.
    st = stream_once("chunk-big", 4 * 1024 * 1024, 1, 0, &up, &gw, resp, sizeof(resp));
    CHECK(st == 413, "oversize chunked stream -> 413");
    CHECK(strstr(resp, "413") != NULL, "guest sees 413 for chunked");
    CHECK(!up.complete || up.got < 4u * 1024 * 1024, "upstream did not get the whole body");

    // Exactly at the limit is fine (Content-Length framing).
    st = stream_once("cl-edge", 1048576, 0, 0, &up, &gw, resp, sizeof(resp));
    CHECK(st == 200, "body exactly at the limit passes");
    CHECK(up.got == 1048576 && memcmp(up.digest, gw.digest, 32) == 0, "edge body intact");

    // Malformed chunk framing -> 400.
    st = stream_once("chunk-bad", 512 * 1024, 1, 1, &up, &gw, resp, sizeof(resp));
    CHECK(st == 400, "malformed chunking -> 400");
    CHECK(strstr(resp, "400") != NULL, "guest sees 400");

    unsetenv("SANDBOX_BROKER_MAX_BODY");
    CHECK(broker_max_body() == BROKER_DEFAULT_MAX_BODY, "default limit restored");
    report("body_limits", b);
}

// ---------------------------------------------------------------------------
// #26 egress policy at the broker: what the token's list allows, what a named
// destination may do without a credential, and that refusals are accounted.

// One request through a fresh engine mock that hands out `allowed` as the
// session's policy. With `upstream` non-NULL the upstream is live and gets the
// connection; otherwise the request must be refused before any forward.
static int policy_raw(const char* tag, const char* const* allowed, int n_allowed,
                      const char* greq, mock_upstream_t* upstream, char* resp, size_t cap) {
    char epath[512];
    snprintf(epath, sizeof(epath), "%s/engine-%s.sock", g_dir, tag);
    mock_engine_t eng;
    memset(&eng, 0, sizeof(eng));
    eng.expected = TOKEN_BYTES;
    eng.n_allowed = n_allowed;
    for (int i = 0; i < n_allowed && i < 4; i++) eng.allowed[i] = allowed[i];
    eng.listen_fd = engine_listen(epath);
    CHECK(eng.listen_fd >= 0, "engine listen");
    pthread_t eth;
    pthread_create(&eth, NULL, engine_thread, &eng);
    eng.client_fd_fd = broker_engine_connect(epath);
    CHECK(eng.client_fd_fd >= 0, "engine connect");

    int st;
    if (upstream) {
        st = proxy_once(&eng, upstream, greq, resp, cap, "hello");
    } else {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        write_full(sv[1], greq, strlen(greq));
        credential_store_t* creds = credentials_load(g_creds);
        st = broker_handle_request(sv[0], creds, eng.client_fd_fd);
        read_response(sv[1], resp, cap, "\r\n\r\n");
        credentials_free(creds);
        close(sv[0]);
        close(sv[1]);
    }
    close(eng.client_fd_fd);
    pthread_join(eth, NULL);
    close(eng.listen_fd);
    unlink(epath);
    return st;
}

static int policy_case(const char* tag, const char* const* allowed, int n_allowed,
                       const char* host_hdr, mock_upstream_t* upstream, char* resp,
                       size_t cap) {
    char greq[1024];
    snprintf(greq, sizeof(greq),
             "GET /simple/ HTTP/1.1\r\nHost: %s\r\n"
             "X-Sandbox-Token: " TOKEN_HEX "\r\n\r\n",
             host_hdr);
    return policy_raw(tag, allowed, n_allowed, greq, upstream, resp, cap);
}

static void test_egress_policy(void) {
    int b = g_fail;
    char resp[2048], host[64];
    uint16_t port = 0;
    mock_upstream_t up;

    // A destination the developer named, with no credential on file: relayed,
    // and nothing is injected (a package index has no secret).
    memset(&up, 0, sizeof(up));
    snprintf(up.response, sizeof(up.response),
             "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
    up.listen_fd = upstream_listen(&port);
    snprintf(host, sizeof(host), "localhost:%u", port);
    const char* named[] = {"localhost"};
    int st = policy_case("named", named, 1, host, &up, resp, sizeof(resp));
    CHECK(st == 200, "named host without a credential is relayed");
    CHECK(strstr(resp, "hello") != NULL, "its response reaches the guest");
    CHECK(strstr(up.request, "GET /simple/ HTTP/1.1") != NULL, "request forwarded");
    CHECK(strstr(up.request, "Authorization") == NULL, "no credential is made up");
    CHECK(strstr(up.request, "X-Sandbox-Token") == NULL, "session token never leaves");
    close(up.listen_fd);

    // A named host that does have a credential still gets it.
    memset(&up, 0, sizeof(up));
    snprintf(up.response, sizeof(up.response),
             "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
    up.listen_fd = upstream_listen(&port);
    snprintf(host, sizeof(host), "127.0.0.1:%u", port);
    const char* cred_named[] = {"127.0.0.1"};
    st = policy_case("cred", cred_named, 1, host, &up, resp, sizeof(resp));
    CHECK(st == 200 && strstr(up.request, "Authorization: Bearer test-secret") != NULL,
          "a configured credential is still injected");
    close(up.listen_fd);

    // A malformed entry in the list allows nothing (and does not poison the rest).
    snprintf(host, sizeof(host), "localhost:%u", 9);
    const char* wild[] = {"*.nope.test", "localhost:0000"};
    st = policy_case("bad-entry", wild, 2, host, NULL, resp, sizeof(resp));
    CHECK(st == 403, "malformed entries allow nothing");

    // Default deny: not on the list.
    const char* other[] = {"pypi.org"};
    st = policy_case("deny", other, 1, "evil.example", NULL, resp, sizeof(resp));
    CHECK(st == 403 && strstr(resp, "Service not allowed") != NULL, "unlisted host -> 403");

    // Empty policy (deny-all): nothing is reachable, not even a credentialed host.
    st = policy_case("none", NULL, 0, "127.0.0.1:9", NULL, resp, sizeof(resp));
    CHECK(st == 403 && strstr(resp, "Service not allowed") != NULL, "empty policy -> 403");

    // Port is part of the policy.
    const char* ported[] = {"localhost:1"};
    st = policy_case("port", ported, 1, "localhost:2", NULL, resp, sizeof(resp));
    CHECK(st == 403, "wrong port -> 403");
    // No port in the request means 443, so a :80 entry does not match it.
    const char* p80[] = {"localhost:80"};
    st = policy_case("p80", p80, 1, "localhost", NULL, resp, sizeof(resp));
    CHECK(st == 403, "implicit 443 does not match a :80 entry");

    // The daemon-wide "*" is a ceiling, not a statement of intent: with no
    // credential on file the request is refused, as before #26.
    const char* star[] = {"*"};
    st = policy_case("star", star, 1, "localhost:9", NULL, resp, sizeof(resp));
    CHECK(st == 403 && strstr(resp, "Service not configured") != NULL,
          "star without a credential is not relayed");

    // Every decision is counted.
    char mb[8192];
    int n = broker_metrics_render(mb, sizeof(mb));
    CHECK(n > 0 && strstr(mb, "broker_egress_decisions_total{decision=\"allowed\"}") &&
              strstr(mb, "broker_egress_decisions_total{decision=\"denied_policy\"}") &&
              strstr(mb, "broker_egress_decisions_total{decision=\"denied_unconfigured\"}"),
          "egress decisions are exported");
    CHECK(strstr(mb, "{decision=\"allowed\"} 0\n") == NULL, "allowed counter moved");
    CHECK(strstr(mb, "{decision=\"denied_policy\"} 0\n") == NULL, "denied counter moved");
    CHECK(strstr(mb, "{decision=\"denied_unconfigured\"} 0\n") == NULL,
          "unconfigured counter moved");
    report("egress_policy", b);
}

// ---------------------------------------------------------------------------
// #26 forward-proxy mode: what pip/npm/apt/curl send when given a proxy URL.

// base64 of "sandbox:" TOKEN_HEX, precomputed by the test at runtime.
static void proxy_auth_value(char* out, size_t cap) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char raw[128];
    int n = snprintf(raw, sizeof(raw), "sandbox:%s", TOKEN_HEX);
    size_t o = (size_t)snprintf(out, cap, "Basic ");
    for (int i = 0; i < n; i += 3) {
        unsigned v = (unsigned char)raw[i] << 16;
        if (i + 1 < n) v |= (unsigned char)raw[i + 1] << 8;
        if (i + 2 < n) v |= (unsigned char)raw[i + 2];
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = i + 1 < n ? tbl[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? tbl[v & 63] : '=';
    }
    out[o] = '\0';
}

static void test_proxy_helpers(void) {
    int b = g_fail;
    char auth[256], tok[BROKER_TOKEN_HEX_LEN + 1];
    proxy_auth_value(auth, sizeof(auth));
    CHECK(broker_token_from_proxy_auth(auth, tok) == 0 && strcmp(tok, TOKEN_HEX) == 0,
          "token comes out of Proxy-Authorization");
    CHECK(broker_token_from_proxy_auth("Bearer abc", tok) != 0, "only Basic");
    CHECK(broker_token_from_proxy_auth("Basic !!!!", tok) != 0, "bad base64");
    CHECK(broker_token_from_proxy_auth("Basic c2FuZGJveA==", tok) != 0, "no colon");
    CHECK(broker_token_from_proxy_auth("Basic c2FuZGJveDpzaG9ydA==", tok) != 0,
          "a password that is not 64 chars is not a token");
    CHECK(broker_token_from_proxy_auth(NULL, tok) != 0, "null");

    char a[64], p[256];
    CHECK(http_split_absolute("http://pypi.org/simple/x?y=1", a, sizeof(a), p, sizeof(p)) == 0 &&
              strcmp(a, "pypi.org") == 0 && strcmp(p, "/simple/x?y=1") == 0,
          "absolute-form split");
    CHECK(http_split_absolute("http://pypi.org:8080", a, sizeof(a), p, sizeof(p)) == 0 &&
              strcmp(a, "pypi.org:8080") == 0 && strcmp(p, "/") == 0,
          "no path -> /");
    CHECK(http_split_absolute("http://pypi.org?q=1", a, sizeof(a), p, sizeof(p)) == 0 &&
              strcmp(p, "/?q=1") == 0,
          "query without a path");
    CHECK(http_split_absolute("HTTPS://PyPI.org/a", a, sizeof(a), p, sizeof(p)) == 0, "scheme case");
    CHECK(http_split_absolute("/simple/", a, sizeof(a), p, sizeof(p)) != 0, "origin-form is not absolute");
    CHECK(http_split_absolute("http://allowed.example@evil.example/", a, sizeof(a), p, sizeof(p)) != 0,
          "userinfo is refused");
    CHECK(http_split_absolute("http:///path", a, sizeof(a), p, sizeof(p)) != 0, "empty authority");
    CHECK(http_split_absolute("http://a b/", a, sizeof(a), p, sizeof(p)) != 0, "space in host");
    CHECK(http_split_absolute("http://x/p#frag", a, sizeof(a), p, sizeof(p)) != 0, "fragment");
    CHECK(http_split_absolute("http://[::1]/", a, sizeof(a), p, sizeof(p)) != 0, "ipv6 literal");

    struct sockaddr_in s4;
    memset(&s4, 0, sizeof(s4));
    s4.sin_family = AF_INET;
    const char* priv[] = {"127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
                          "169.254.169.254", "169.254.0.2", "100.64.0.1", "0.0.0.0",
                          "224.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.0.1"};
    for (size_t i = 0; i < sizeof(priv) / sizeof(*priv); i++) {
        inet_pton(AF_INET, priv[i], &s4.sin_addr);
        char m[64];
        snprintf(m, sizeof(m), "not public: %s", priv[i]);
        CHECK(!broker_addr_public((struct sockaddr*)&s4), m);
    }
    const char* pub[] = {"8.8.8.8", "151.101.0.223", "172.32.0.1", "172.15.255.255", "100.63.0.1",
                         "100.128.0.1", "198.20.0.1", "1.1.1.1"};
    for (size_t i = 0; i < sizeof(pub) / sizeof(*pub); i++) {
        inet_pton(AF_INET, pub[i], &s4.sin_addr);
        char m[64];
        snprintf(m, sizeof(m), "public: %s", pub[i]);
        CHECK(broker_addr_public((struct sockaddr*)&s4), m);
    }
    struct sockaddr_in6 s6;
    memset(&s6, 0, sizeof(s6));
    s6.sin6_family = AF_INET6;
    const char* priv6[] = {"::", "::1", "fe80::1", "fc00::1", "fd12::1", "ff02::1",
                           "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254"};
    for (size_t i = 0; i < sizeof(priv6) / sizeof(*priv6); i++) {
        inet_pton(AF_INET6, priv6[i], &s6.sin6_addr);
        char m[64];
        snprintf(m, sizeof(m), "not public: %s", priv6[i]);
        CHECK(!broker_addr_public((struct sockaddr*)&s6), m);
    }
    inet_pton(AF_INET6, "2606:4700::1111", &s6.sin6_addr);
    CHECK(broker_addr_public((struct sockaddr*)&s6), "public v6");
    inet_pton(AF_INET6, "::ffff:8.8.8.8", &s6.sin6_addr);
    CHECK(broker_addr_public((struct sockaddr*)&s6), "v4-mapped public");
    struct sockaddr_un su;
    su.sun_family = AF_UNIX;
    CHECK(!broker_addr_public((struct sockaddr*)&su), "other families are refused");
    report("proxy_helpers", b);
}

typedef struct {
    int listen_fd;
    uint64_t got;
} echo_t;

static void* echo_thread(void* arg) {
    echo_t* e = arg;
    int fd = accept(e->listen_fd, NULL, NULL);
    if (fd < 0) return NULL;
    char buf[4096];
    for (;;) {
        ssize_t r = recv(fd, buf, sizeof(buf), 0);
        if (r <= 0) break;
        e->got += (uint64_t)r;
        if (write_full(fd, buf, (size_t)r) < 0) break;
    }
    close(fd);
    return NULL;
}

typedef struct {
    int fd, engine;
    int rc;
} broker_run_t;

static void* broker_once_thread(void* arg) {
    broker_run_t* b = arg;
    credential_store_t* creds = credentials_load(g_creds);
    b->rc = broker_handle_request(b->fd, creds, b->engine);
    credentials_free(creds);
    return NULL;
}

// One CONNECT through the broker against a live echo upstream. Returns the
// broker's status; *tunnel_ok says the echo worked end to end.
static int connect_case(const char* tag, const char* const* allowed, int n_allowed,
                        const char* authority_fmt, int* tunnel_ok, char* resp, size_t cap,
                        uint64_t* echoed) {
    char epath[512];
    snprintf(epath, sizeof(epath), "%s/engine-%s.sock", g_dir, tag);
    mock_engine_t eng;
    memset(&eng, 0, sizeof(eng));
    eng.expected = TOKEN_BYTES;
    eng.n_allowed = n_allowed;
    for (int i = 0; i < n_allowed && i < 4; i++) eng.allowed[i] = allowed[i];
    eng.listen_fd = engine_listen(epath);
    pthread_t eth;
    pthread_create(&eth, NULL, engine_thread, &eng);
    eng.client_fd_fd = broker_engine_connect(epath);

    echo_t echo = {0};
    uint16_t port = 0;
    echo.listen_fd = upstream_listen(&port);
    pthread_t uth;
    pthread_create(&uth, NULL, echo_thread, &echo);

    char authority[128];
    snprintf(authority, sizeof(authority), authority_fmt, port);
    char auth[256], greq[1024];
    proxy_auth_value(auth, sizeof(auth));
    snprintf(greq, sizeof(greq),
             "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", authority,
             authority, auth);

    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    broker_run_t br = {.fd = sv[0], .engine = eng.client_fd_fd, .rc = 0};
    pthread_t bth;
    pthread_create(&bth, NULL, broker_once_thread, &br);

    write_full(sv[1], greq, strlen(greq));
    read_response(sv[1], resp, cap, "\r\n\r\n");
    *tunnel_ok = 0;
    *echoed = 0;
    if (strstr(resp, "200 Connection Established")) {
        // 300 KiB each way, so the pump has to loop, not just relay one read.
        enum { N = 300 * 1024 };
        static char out[N], in[N];
        for (int i = 0; i < N; i++) out[i] = (char)(i * 31 + 7);
        // Writer in this thread would deadlock against the echo's full buffers, so
        // interleave: write a block, read the same block back.
        int ok = 1;
        for (int off = 0; off < N && ok; off += 8192) {
            int n = N - off < 8192 ? N - off : 8192;
            if (write_full(sv[1], out + off, (size_t)n) < 0) ok = 0;
            else if (read_full(sv[1], in + off, (size_t)n) < 0) ok = 0;
        }
        *tunnel_ok = ok && memcmp(in, out, N) == 0;
        *echoed = N;
    }
    shutdown(sv[1], SHUT_WR);  // half-close: the broker must pass it on and finish
    pthread_join(bth, NULL);
    close(sv[0]);
    close(sv[1]);
    shutdown(echo.listen_fd, SHUT_RDWR);
    pthread_join(uth, NULL);
    close(echo.listen_fd);
    close(eng.client_fd_fd);
    pthread_join(eth, NULL);
    close(eng.listen_fd);
    unlink(epath);
    return br.rc;
}

static void test_proxy_mode(void) {
    int b = g_fail;
    char resp[4096], auth[256], greq[2048], host[64];
    uint16_t port = 0;
    mock_upstream_t up;
    proxy_auth_value(auth, sizeof(auth));

    // Absolute-form GET: the upstream is the URI's authority (the Host header is
    // ignored), the request line becomes origin-form, and our headers are gone.
    memset(&up, 0, sizeof(up));
    snprintf(up.response, sizeof(up.response),
             "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
    up.listen_fd = upstream_listen(&port);
    snprintf(host, sizeof(host), "localhost:%u", port);
    snprintf(greq, sizeof(greq),
             "GET http://%s/simple/pip/?x=1 HTTP/1.1\r\nHost: evil.example\r\n"
             "Proxy-Authorization: %s\r\nProxy-Connection: keep-alive\r\n\r\n",
             host, auth);
    const char* named[] = {"localhost"};
    int st = policy_raw("abs", named, 1, greq, &up, resp, sizeof(resp));
    CHECK(st == 200 && strstr(resp, "hello") != NULL, "absolute-form is relayed");
    CHECK(strstr(up.request, "GET /simple/pip/?x=1 HTTP/1.1") != NULL, "request line is origin-form");
    CHECK(strstr(up.request, "Host: localhost") != NULL && strstr(up.request, "evil.example") == NULL,
          "the URI decides the host, not the Host header");
    CHECK(strstr(up.request, "Proxy-Authorization") == NULL && strstr(up.request, "Proxy-Connection") == NULL,
          "proxy headers are not forwarded");
    CHECK(strstr(up.request, "Authorization") == NULL, "nothing is injected for a named host");
    close(up.listen_fd);

    // The Host header cannot be used to dodge the policy when the URI says otherwise.
    snprintf(greq, sizeof(greq),
             "GET http://evil.example/ HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: %s\r\n\r\n",
             auth);
    st = policy_raw("abs-evil", named, 1, greq, NULL, resp, sizeof(resp));
    CHECK(st == 403 && strstr(resp, "Service not allowed"), "URI authority is what the policy sees");

    // Userinfo trick.
    snprintf(greq, sizeof(greq),
             "GET http://localhost@evil.example/ HTTP/1.1\r\nHost: x\r\nProxy-Authorization: %s\r\n\r\n",
             auth);
    st = policy_raw("abs-userinfo", named, 1, greq, NULL, resp, sizeof(resp));
    CHECK(st == 400, "userinfo in the target is refused");

    // Credentials: proxy clients are told to authenticate (407), not given 401.
    st = policy_raw("abs-noauth", named, 1,
                    "GET http://localhost/ HTTP/1.1\r\nHost: localhost\r\n\r\n", NULL, resp, sizeof(resp));
    CHECK(st == 407 && strstr(resp, "Proxy-Authenticate: Basic") != NULL, "missing proxy credentials -> 407");
    st = policy_raw("abs-badauth", named, 1,
                    "GET http://localhost/ HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: Basic AAAA\r\n\r\n",
                    NULL, resp, sizeof(resp));
    CHECK(st == 407, "unusable proxy credentials -> 407");
    st = policy_raw("conn-noauth", named, 1, "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n",
                    NULL, resp, sizeof(resp));
    CHECK(st == 407 && strstr(resp, "407") != NULL, "CONNECT without credentials -> 407");
    // The token is still checked against the engine.
    snprintf(greq, sizeof(greq),
             "GET http://localhost/ HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: Basic "
             "c2FuZGJveDowMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw\r\n\r\n");
    st = policy_raw("abs-wrongtok", named, 1, greq, NULL, resp, sizeof(resp));
    CHECK(st == 407, "a wrong token in Proxy-Authorization is refused");

    // CONNECT: a real tunnel to a live echo server.
    int ok = 0;
    uint64_t echoed = 0;
    const char* named_h[] = {"localhost"};
    st = connect_case("conn", named_h, 1, "localhost:%u", &ok, resp, sizeof(resp), &echoed);
    CHECK(st == 200, "CONNECT to a named host succeeds");
    CHECK(ok && echoed == 300 * 1024, "300 KiB round-trips through the tunnel intact");

    const char* star[] = {"*"};
    st = connect_case("conn-star", star, 1, "localhost:%u", &ok, resp, sizeof(resp), &echoed);
    CHECK(st == 403 && !ok, "CONNECT is not allowed on the strength of '*'");
    const char* other[] = {"pypi.org"};
    st = connect_case("conn-other", other, 1, "localhost:%u", &ok, resp, sizeof(resp), &echoed);
    CHECK(st == 403 && !ok, "CONNECT to an unlisted host is refused");
    const char* wrongport[] = {"localhost:1"};
    st = connect_case("conn-port", wrongport, 1, "localhost:%u", &ok, resp, sizeof(resp), &echoed);
    CHECK(st == 403 && !ok, "CONNECT to a port the policy does not name is refused");
    st = connect_case("conn-bad", named_h, 1, "localhost", &ok, resp, sizeof(resp), &echoed);
    CHECK(st == 400 && !ok, "CONNECT without a port is a bad request");

    // The broker will not dial the host's own network, whatever the policy says.
    unsetenv("SANDBOX_BROKER_ALLOW_PRIVATE_UPSTREAM");
    memset(&up, 0, sizeof(up));
    snprintf(up.response, sizeof(up.response),
             "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
    up.listen_fd = upstream_listen(&port);
    snprintf(host, sizeof(host), "localhost:%u", port);
    snprintf(greq, sizeof(greq),
             "GET http://%s/ HTTP/1.1\r\nHost: x\r\nProxy-Authorization: %s\r\n\r\n", host, auth);
    pthread_t uth;
    pthread_create(&uth, NULL, upstream_thread, &up);
    st = policy_raw("ssrf", named, 1, greq, NULL, resp, sizeof(resp));
    CHECK(st == 403 && strstr(resp, "Upstream address not permitted"),
          "a named host resolving to loopback is refused (relay)");
    shutdown(up.listen_fd, SHUT_RDWR);
    pthread_join(uth, NULL);
    close(up.listen_fd);
    st = connect_case("ssrf-conn", named_h, 1, "localhost:%u", &ok, resp, sizeof(resp), &echoed);
    CHECK(st == 403 && !ok, "...and for CONNECT");
    setenv("SANDBOX_BROKER_ALLOW_PRIVATE_UPSTREAM", "1", 1);
    CHECK(broker_private_upstream_allowed(), "the operator can opt in");

    char mb[8192];
    int n = broker_metrics_render(mb, sizeof(mb));
    CHECK(n > 0 && strstr(mb, "decision=\"denied_address\"") &&
              strstr(mb, "broker_relayed_bytes_total{direction=\"to_guest\"}"),
          "address denials and relayed bytes are exported");
    CHECK(strstr(mb, "{decision=\"denied_address\"} 0\n") == NULL, "denied_address counted");
    CHECK(strstr(mb, "{direction=\"to_guest\"} 0\n") == NULL, "bytes counted");
    report("proxy_mode", b);
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
    signal(SIGPIPE, SIG_IGN);
    setenv("SANDBOX_BROKER_UPSTREAM_SCHEME", "http", 1);
    // The mock upstreams are on loopback, which the broker refuses by default.
    setenv("SANDBOX_BROKER_ALLOW_PRIVATE_UPSTREAM", "1", 1);

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
    test_stream_large();
    test_body_limits();
    test_egress_policy();
    test_proxy_helpers();
    test_proxy_mode();
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
