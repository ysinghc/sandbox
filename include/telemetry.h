#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <stdint.h>

void telemetry_pool_state(int warm, int restoring, int overflow);
void telemetry_provision_latency(uint64_t latency_ms);
void telemetry_uffd_fault(void);
void telemetry_vmm_crash(void);
int telemetry_serve(int listen_fd);

#endif // TELEMETRY_H
