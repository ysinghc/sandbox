// Observability (§11.1): Prometheus-format counters. All counters are atomic
// so the pool/gateway/uffd paths can bump them without a lock.

#include "telemetry.h"

#include <dirent.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static atomic_long g_pool_warm = 0;
static atomic_long g_pool_restoring = 0;
static atomic_long g_pool_overflow = 0;
static atomic_long g_pool_exhaustions = 0;
static atomic_long g_provision_count = 0;
static atomic_ulong g_provision_sum_ms = 0;
static atomic_long g_provision_buckets[5];  // <50,<100,<250,<500,<1000 ms
static atomic_long g_uffd_faults = 0;
static atomic_long g_vmm_crashes = 0;

void telemetry_pool_state(int warm, int restoring, int overflow) {
    atomic_store(&g_pool_warm, warm);
    atomic_store(&g_pool_restoring, restoring);
    atomic_store(&g_pool_overflow, overflow);
}

// §10.13: process self-stats from /proc/self (fd count, virtual + resident mem).
static long proc_open_fds(void) {
    DIR* d = opendir("/proc/self/fd");
    if (!d) return -1;
    long n = 0;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (e->d_name[0] != '.') n++;
    }
    closedir(d);
    return n;
}

static void proc_memory(unsigned long* virt_kb, unsigned long* rss_kb) {
    *virt_kb = 0;
    *rss_kb = 0;
    FILE* f = fopen("/proc/self/statm", "r");
    if (!f) return;
    unsigned long size = 0, resident = 0;
    if (fscanf(f, "%lu %lu", &size, &resident) == 2) {
        long ps = sysconf(_SC_PAGESIZE);
        unsigned long kb = (ps > 0) ? (unsigned long)ps / 1024 : 4;  // pages->KiB
        *virt_kb = size * kb;
        *rss_kb = resident * kb;
    }
    fclose(f);
}

void telemetry_provision_latency(uint64_t latency_ms) {
    atomic_fetch_add(&g_provision_count, 1);
    atomic_fetch_add(&g_provision_sum_ms, (unsigned long)latency_ms);
    static const uint64_t bounds[5] = {50, 100, 250, 500, 1000};
    for (int i = 0; i < 5; i++) {
        if (latency_ms < bounds[i]) {
            atomic_fetch_add(&g_provision_buckets[i], 1);
            break;
        }
    }
}

void telemetry_uffd_fault(void) { atomic_fetch_add(&g_uffd_faults, 1); }
void telemetry_vmm_crash(void) { atomic_fetch_add(&g_vmm_crashes, 1); }
void telemetry_pool_exhausted(void) { atomic_fetch_add(&g_pool_exhaustions, 1); }

int telemetry_render(char* buf, int cap) {
    if (!buf || cap <= 0) return 0;
    int off = 0;
    static const uint64_t bounds[5] = {50, 100, 250, 500, 1000};
#define EMIT(...)                                                       \
    do {                                                                \
        int w = snprintf(buf + off, (size_t)(cap - off), __VA_ARGS__);  \
        if (w < 0) return off;                                          \
        off += w;                                                       \
        if (off >= cap) return cap;                                     \
    } while (0)

    EMIT("# HELP sandbox_pool_warm_count Current warm VMs in pool\n");
    EMIT("# TYPE sandbox_pool_warm_count gauge\n");
    EMIT("sandbox_pool_warm_count %ld\n", atomic_load(&g_pool_warm));
    EMIT("# TYPE sandbox_pool_restoring_count gauge\n");
    EMIT("sandbox_pool_restoring_count %ld\n", atomic_load(&g_pool_restoring));
    EMIT("# TYPE sandbox_pool_overflow_depth gauge\n");
    EMIT("sandbox_pool_overflow_depth %ld\n", atomic_load(&g_pool_overflow));
    EMIT("# TYPE sandbox_pool_exhaustion_total counter\n");
    EMIT("sandbox_pool_exhaustion_total %ld\n", atomic_load(&g_pool_exhaustions));
    EMIT("# TYPE sandbox_provision_latency_ms histogram\n");
    for (int i = 0; i < 5; i++) {
        EMIT("sandbox_provision_latency_ms_bucket{le=\"%llu\"} %ld\n",
             (unsigned long long)bounds[i],
             atomic_load(&g_provision_buckets[i]));
    }
    EMIT("sandbox_provision_latency_ms_bucket{le=\"+Inf\"} %ld\n",
         atomic_load(&g_provision_count));
    EMIT("sandbox_provision_latency_ms_sum %lu\n",
         (unsigned long)atomic_load(&g_provision_sum_ms));
    EMIT("sandbox_provision_latency_ms_count %ld\n",
         atomic_load(&g_provision_count));
    EMIT("# TYPE sandbox_uffd_faults_total counter\n");
    EMIT("sandbox_uffd_faults_total %ld\n", atomic_load(&g_uffd_faults));
    EMIT("# TYPE sandbox_vmm_crashes_total counter\n");
    EMIT("sandbox_vmm_crashes_total %ld\n", atomic_load(&g_vmm_crashes));
    // §10.13: process self-stats so operators can spot fd/memory leaks.
    unsigned long virt_kb = 0, rss_kb = 0;
    proc_memory(&virt_kb, &rss_kb);
    EMIT("# TYPE sandbox_process_open_fds gauge\n");
    EMIT("sandbox_process_open_fds %ld\n", proc_open_fds());
    EMIT("# TYPE sandbox_process_virtual_memory_bytes gauge\n");
    EMIT("sandbox_process_virtual_memory_bytes %lu\n", virt_kb * 1024);
    EMIT("# TYPE sandbox_process_resident_memory_bytes gauge\n");
    EMIT("sandbox_process_resident_memory_bytes %lu\n", rss_kb * 1024);
#undef EMIT
    return off;
}

// §10.13: HTTP endpoint for orchestrator probes + Prometheus scraping.
//   GET /health  -> 200 always (liveness)
//   GET /ready   -> 200 when the pool has >= 1 warm VM, else 503
//   GET /metrics -> Prometheus text
//   anything else -> 404
static void serve_http(int cfd) {
    char req[1024];
    ssize_t r = recv(cfd, req, sizeof(req) - 1, 0);
    if (r <= 0) return;
    req[r] = '\0';

    // First request line: "GET /path HTTP/1.x".
    char method[8] = {0}, path[256] = {0};
    sscanf(req, "%7s %255s", method, path);

    const char* status = "200 OK";
    const char* ctype = "text/plain; version=0.0.4";
    char body[16384];
    int n = 0;

    if (strcmp(path, "/health") == 0 || strcmp(path, "/healthz") == 0) {
        ctype = "text/plain";
        n = snprintf(body, sizeof(body), "ok\n");
    } else if (strcmp(path, "/ready") == 0 || strcmp(path, "/readyz") == 0) {
        ctype = "text/plain";
        if (atomic_load(&g_pool_warm) > 0) {
            n = snprintf(body, sizeof(body), "ready\n");
        } else {
            status = "503 Service Unavailable";
            n = snprintf(body, sizeof(body), "not ready\n");
        }
    } else if (strcmp(path, "/metrics") == 0 || strcmp(path, "/") == 0) {
        n = telemetry_render(body, sizeof(body));
    } else {
        status = "404 Not Found";
        ctype = "text/plain";
        n = snprintf(body, sizeof(body), "not found\n");
    }

    char hdr[192];
    int hn = snprintf(hdr, sizeof(hdr),
                      "HTTP/1.0 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
                      "Connection: close\r\n\r\n",
                      status, ctype, n);
    ssize_t w = send(cfd, hdr, (size_t)hn, MSG_NOSIGNAL);
    (void)w;
    if (n > 0) {
        w = send(cfd, body, (size_t)n, MSG_NOSIGNAL);
        (void)w;
    }
}

int telemetry_serve(int listen_fd) {
    if (listen_fd < 0) return -1;
    for (;;) {
        int cfd = accept(listen_fd, NULL, NULL);
        if (cfd < 0) return -1;
        serve_http(cfd);
        close(cfd);
    }
}
