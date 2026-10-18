// SPDX-License-Identifier: GPL-2.0-only
// §10.13 verification: /health, /ready (pool-gated), /metrics (incl. process
// self-stats) and 404 handling. No root; binds an ephemeral loopback port.

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "telemetry.h"

static int g_listen = -1;

static void* serve(void* arg) {
    (void)arg;
    telemetry_serve(g_listen);
    return NULL;
}

// One request/response round trip; returns the HTTP status code or -1.
static int http_get(int port, const char* path, char* body, size_t bn) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    char req[256];
    int rn = snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\n\r\n", path);
    if (send(fd, req, (size_t)rn, 0) < 0) { close(fd); return -1; }

    char buf[16384];
    ssize_t total = 0, r;
    while ((r = recv(fd, buf + total, sizeof(buf) - 1 - (size_t)total, 0)) > 0) {
        total += r;
        if ((size_t)total >= sizeof(buf) - 1) break;
    }
    close(fd);
    buf[total] = '\0';

    int code = -1;
    sscanf(buf, "HTTP/1.%*d %d", &code);
    char* sep = strstr(buf, "\r\n\r\n");
    if (body && bn) {
        body[0] = '\0';
        if (sep) snprintf(body, bn, "%s", sep + 4);
    }
    return code;
}

int main(void) {
    g_listen = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;  // ephemeral
    if (bind(g_listen, (struct sockaddr*)&sa, sizeof(sa)) < 0 ||
        listen(g_listen, 16) < 0) {
        perror("bind/listen");
        return 1;
    }
    socklen_t sl = sizeof(sa);
    getsockname(g_listen, (struct sockaddr*)&sa, &sl);
    int port = ntohs(sa.sin_port);

    pthread_t t;
    if (pthread_create(&t, NULL, serve, NULL) != 0) { perror("pthread"); return 1; }

    char body[16384];

    if (http_get(port, "/health", body, sizeof(body)) != 200) {
        fprintf(stderr, "FAIL: /health not 200\n");
        return 1;
    }

    // No warm VMs yet -> not ready.
    telemetry_pool_state(0, 0, 0);
    if (http_get(port, "/ready", body, sizeof(body)) != 503) {
        fprintf(stderr, "FAIL: /ready should be 503 with empty pool\n");
        return 1;
    }
    telemetry_pool_state(3, 0, 0);
    if (http_get(port, "/ready", body, sizeof(body)) != 200) {
        fprintf(stderr, "FAIL: /ready should be 200 with warm VMs\n");
        return 1;
    }

    if (http_get(port, "/metrics", body, sizeof(body)) != 200) {
        fprintf(stderr, "FAIL: /metrics not 200\n");
        return 1;
    }
    if (!strstr(body, "sandbox_pool_warm_count 3")) {
        fprintf(stderr, "FAIL: /metrics missing warm count\n%s\n", body);
        return 1;
    }
    if (!strstr(body, "sandbox_process_open_fds") ||
        !strstr(body, "sandbox_process_resident_memory_bytes")) {
        fprintf(stderr, "FAIL: /metrics missing process stats\n");
        return 1;
    }

    if (http_get(port, "/nope", body, sizeof(body)) != 404) {
        fprintf(stderr, "FAIL: unknown path should be 404\n");
        return 1;
    }

    printf("ALL METRICS TESTS PASSED\n");
    close(g_listen);
    return 0;
}
