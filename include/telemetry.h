// SPDX-License-Identifier: GPL-2.0-only
#ifndef TELEMETRY_H
#define TELEMETRY_H

// Observability (§11). Metrics are in-process counters rendered in Prometheus
// text format; structured logs are emitted as JSON on stderr by the component
// that owns the event (journald captures them).

#include <stdint.h>

void telemetry_pool_state(int warm, int restoring, int overflow);
void telemetry_provision_latency(uint64_t latency_ms);
void telemetry_uffd_fault(void);
void telemetry_vmm_crash(void);
void telemetry_pool_exhausted(void);

// Render the current metrics as Prometheus text into buf (NUL-terminated).
// Returns the number of bytes written.
int telemetry_render(char* buf, int cap);

// Accept connections on listen_fd and answer each with the metrics text, then
// close. Blocks until the listener errors. Intended to run in its own thread.
int telemetry_serve(int listen_fd);

#endif // TELEMETRY_H
