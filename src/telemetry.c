#include "telemetry.h"

void telemetry_pool_state(int warm, int restoring, int overflow) {
    (void)warm; (void)restoring; (void)overflow;
}

void telemetry_provision_latency(uint64_t latency_ms) {
    (void)latency_ms;
}

void telemetry_uffd_fault(void) {
}

void telemetry_vmm_crash(void) {
}

int telemetry_serve(int listen_fd) {
    (void)listen_fd;
    return 0;
}
