// Observability (§11.1): Prometheus-format counters. All counters are atomic
// so the pool/gateway/uffd paths can bump them without a lock.

#include "telemetry.h"

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
#undef EMIT
    return off;
}

int telemetry_serve(int listen_fd) {
    if (listen_fd < 0) return -1;
    char body[8192];
    for (;;) {
        int cfd = accept(listen_fd, NULL, NULL);
        if (cfd < 0) return -1;
        int n = telemetry_render(body, sizeof(body));
        char hdr[128];
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
