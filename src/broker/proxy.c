// SPDX-License-Identifier: GPL-2.0-only
// Forward-proxy support for the broker (#26): the pieces that let ordinary tools
// (pip, npm, apt, curl via http_proxy/https_proxy) reach an allow-listed host
// through it -- Basic proxy credentials carrying the session token, a dialer
// that refuses to be steered at the host's own network, and the byte pump behind
// CONNECT tunnels.

#define _GNU_SOURCE

#include "broker.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Decode standard base64 (padding optional). Returns length, or -1.
static int b64_decode(const char* in, unsigned char* out, size_t cap) {
    size_t n = 0;
    unsigned acc = 0;
    int bits = 0;
    for (; *in && *in != '='; in++) {
        int v = b64_val((unsigned char)*in);
        if (v < 0) return -1;
        acc = (acc << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= cap) return -1;
            out[n++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    return (int)n;
}

int broker_token_from_proxy_auth(const char* value, char out[BROKER_TOKEN_HEX_LEN + 1]) {
    if (!value) return -1;
    while (*value == ' ') value++;
    if (strncasecmp(value, "Basic", 5) != 0 || (value[5] != ' ' && value[5] != '\t')) return -1;
    value += 5;
    while (*value == ' ' || *value == '\t') value++;
    unsigned char dec[256];
    int n = b64_decode(value, dec, sizeof(dec) - 1);
    if (n <= 0) return -1;
    dec[n] = '\0';
    // "user:password": the user is whatever the client wants to call itself; the
    // session token is the password (a URL like http://sandbox:TOKEN@broker:8080).
    char* colon = strchr((char*)dec, ':');
    if (!colon) return -1;
    size_t tl = strlen(colon + 1);
    if (tl != BROKER_TOKEN_HEX_LEN) return -1;
    memcpy(out, colon + 1, tl + 1);
    return 0;
}

// ---------------------------------------------------------------------------
// Where the broker is willing to connect
// ---------------------------------------------------------------------------

bool broker_private_upstream_allowed(void) {
    const char* v = getenv("SANDBOX_BROKER_ALLOW_PRIVATE_UPSTREAM");
    return v && strcmp(v, "1") == 0;
}

static bool v4_public(uint32_t a /* host order */) {
    uint8_t b0 = (uint8_t)(a >> 24), b1 = (uint8_t)(a >> 16), b2 = (uint8_t)(a >> 8);
    if (b0 == 0 || b0 == 10 || b0 == 127) return false;
    if (b0 == 100 && (b1 & 0xc0) == 64) return false;        // 100.64/10 CGNAT
    if (b0 == 169 && b1 == 254) return false;                // link-local: the VM subnets live here
    if (b0 == 172 && (b1 & 0xf0) == 16) return false;
    if (b0 == 192 && b1 == 0 && b2 == 0) return false;       // 192.0.0.0/24
    if (b0 == 192 && b1 == 168) return false;
    if (b0 == 198 && (b1 & 0xfe) == 18) return false;        // 198.18/15 benchmarking
    if (b0 >= 224) return false;                             // multicast + reserved
    return true;
}

bool broker_addr_public(const struct sockaddr* sa) {
    if (!sa) return false;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in* s = (const struct sockaddr_in*)sa;
        return v4_public(ntohl(s->sin_addr.s_addr));
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6* s = (const struct sockaddr_in6*)sa;
        const uint8_t* a = s->sin6_addr.s6_addr;
        static const uint8_t zero[16] = {0};
        if (memcmp(a, zero, 16) == 0) return false;                         // ::
        uint8_t loop[16] = {0};
        loop[15] = 1;
        if (memcmp(a, loop, 16) == 0) return false;                         // ::1
        bool mapped = true;                                                  // ::ffff:a.b.c.d
        for (int i = 0; i < 10; i++) if (a[i]) mapped = false;
        if (mapped && a[10] == 0xff && a[11] == 0xff)
            return v4_public(((uint32_t)a[12] << 24) | ((uint32_t)a[13] << 16) |
                             ((uint32_t)a[14] << 8) | a[15]);
        if ((a[0] & 0xfe) == 0xfc) return false;                            // fc00::/7
        if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return false;            // fe80::/10
        if (a[0] == 0xff) return false;                                     // multicast
        return true;
    }
    return false;
}

// Connect with a deadline. *denied is set when every address the name resolved
// to was off-limits (as opposed to merely unreachable).
int broker_dial(const char* host, unsigned port, int timeout_ms, bool* denied) {
    if (denied) *denied = false;
    char ps[8];
    snprintf(ps, sizeof(ps), "%u", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ps, &hints, &res) != 0 || !res) return -1;

    bool any_allowed = false, any_denied = false;
    bool allow_private = broker_private_upstream_allowed();
    int fd = -1;
    for (struct addrinfo* ai = res; ai && fd < 0; ai = ai->ai_next) {
        if (!allow_private && !broker_addr_public(ai->ai_addr)) {
            any_denied = true;
            continue;
        }
        any_allowed = true;
        int s = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0) continue;
        int rc = connect(s, ai->ai_addr, ai->ai_addrlen);
        if (rc < 0 && errno == EINPROGRESS) {
            struct pollfd p = {.fd = s, .events = POLLOUT};
            int pr;
            do {
                pr = poll(&p, 1, timeout_ms);
            } while (pr < 0 && errno == EINTR);
            int err = 0;
            socklen_t el = sizeof(err);
            if (pr == 1 && getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) rc = 0;
        }
        if (rc == 0) {
            fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK);
            fd = s;
        } else {
            close(s);
        }
    }
    freeaddrinfo(res);
    if (fd < 0 && denied) *denied = any_denied && !any_allowed;
    return fd;
}

// ---------------------------------------------------------------------------
// CONNECT tunnel pump
// ---------------------------------------------------------------------------

static int write_all(int fd, const char* b, size_t n) {
    while (n) {
        ssize_t w = send(fd, b, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        b += w;
        n -= (size_t)w;
    }
    return 0;
}

void broker_tunnel(int a, int b, int idle_ms, uint64_t* a_to_b, uint64_t* b_to_a) {
    uint64_t up = 0, down = 0;
    char buf[16384];
    bool a_open = true, b_open = true;  // still reading from that side
    while (a_open || b_open) {
        struct pollfd p[2];
        int n = 0, ia = -1, ib = -1;
        if (a_open) { ia = n; p[n++] = (struct pollfd){.fd = a, .events = POLLIN}; }
        if (b_open) { ib = n; p[n++] = (struct pollfd){.fd = b, .events = POLLIN}; }
        int pr;
        do {
            pr = poll(p, (nfds_t)n, idle_ms);
        } while (pr < 0 && errno == EINTR);
        if (pr <= 0) break;  // idle past the limit, or error: drop the tunnel
        for (int k = 0; k < 2; k++) {
            int idx = k == 0 ? ia : ib;
            if (idx < 0 || !(p[idx].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            int src = k == 0 ? a : b, dst = k == 0 ? b : a;
            ssize_t r;
            do {
                r = recv(src, buf, sizeof(buf), 0);
            } while (r < 0 && errno == EINTR);
            if (r <= 0) {
                // This direction is finished; pass the half-close on and keep
                // draining the other one (a server may still be replying).
                shutdown(dst, SHUT_WR);
                if (k == 0) a_open = false; else b_open = false;
                continue;
            }
            if (write_all(dst, buf, (size_t)r) < 0) {
                a_open = b_open = false;
                break;
            }
            if (k == 0) up += (uint64_t)r; else down += (uint64_t)r;
        }
    }
    if (a_to_b) *a_to_b = up;
    if (b_to_a) *b_to_a = down;
}
