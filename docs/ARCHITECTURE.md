# Architecture

This document is a working map of the running system. The authoritative design —
including the ground-truth deviations recorded in §15 — is
[`SYSTEM DESIGN.md`](../SYSTEM%20DESIGN.md).

## Data flow

```
client ──protobuf/AF_UNIX──> sandboxd ──restore──> Firecracker (jailed, cgroup)
   │                             │                        │
   │                             │ token validation       │ vsock
   │                             └──── broker-control <── sandbox-broker <── guest
   │                                                            │
   │                                                        https upstream
   └── session_token (from CreateResponse) ────────────────────┘
```

A client opens a session, sends `Create`, receives a `sandbox_id` and a
`session_token`. The guest uses the token (via `X-Sandbox-Token`) to reach
allow-listed upstreams through the broker. If the client disconnects, the daemon
reclaims every sandbox in that session.

## Components

| Component | Source | Responsibility |
| --- | --- | --- |
| IPC server | `src/ipc_server.c` | Client-facing socket; async `Create` worker pool, per-session FIFO dispatch, per-session/uid rate limits, session lifecycle. |
| Pool manager | `src/pool_manager.c` | Keeps `target_size` warm VMs; bounded queue; hands VMs to `Create`. |
| VMM manager | `src/vmm_manager.c` | Restores a VM from a template, injects env, waits for guest readiness, places the VMM in its cgroup, tracks pidfd/handles. |
| Jailer | `src/jailer.c` | Creates the jail, chroots, drops uid/gid, applies seccomp, raises the ambient UFFD capability. |
| seccomp | `src/seccomp.c` | Builds/loads the Firecracker syscall allow-list. |
| UFFD handler | `src/uffd_handler.c`, `src/prefault_worker.c` | Serves memory page faults from the snapshot on restore. |
| Snapshot manager | `src/snapshot_manager.c`, `src/sha256.c` | Template manifest, atomic publish, integrity verification (`sandbox-cli verify`, `--validate-config`). |
| Network manager | `src/network_manager.c` | Per-VM tap and nftables rules (via libnftables, or `nft`). |
| cgroups | `src/cgroup.c` | cgroup v2 hierarchy, memory/cpu limits, OOM grouping. |
| Broker | `src/broker/{core,http,credentials}.c` | Token validation, allow-listing, credential injection, HTTPS proxying. |
| Telemetry | `src/telemetry.c` | `/health`, `/ready`, `/metrics`. |
| Logging | `src/log.c` | Structured JSON logs to stderr (captured by journald). |
| Client libs | `src/lifecycle.c`, `src/cpp/sandbox.cpp` | C and C++ client APIs. |
| Daemon | `src/daemon/main.c`, `src/daemon/config.c` | Startup, config resolution, wiring. |

## Trust boundaries

1. **Client ↔ daemon.** UNIX socket guarded by `SO_PEERCRED` against
   `allowed_uids`. The daemon is the trust root.
2. **Daemon ↔ Firecracker.** Each VMM runs chrooted, as `jailer_uid`, under
   seccomp, in its own cgroup, with `no_new_privs` and an intentionally narrow
   capability set.
3. **Guest ↔ host.** The guest never holds upstream credentials. It can only
   reach services that (a) are in the session's allow-list and (b) have a
   credential on the host, and only through the broker.
4. **Host ↔ upstream.** The broker is the only component that possesses
   credentials; it verifies upstream TLS by default.

## Create lifecycle (§10.8)

`Create` is asynchronous and bounded:

1. The IPC loop accepts a request and enqueues it (per-session FIFO).
2. A worker from the `create_workers` pool provisions a VM, injects environment
   variables, and mints the session token.
3. The size of the in-flight set is capped per session
   (`max_creates_per_session`) and per peer uid (`max_creates_per_uid`);
   overflow is rejected with `POOL_EXHAUSTED`.
4. The loop thread owns lifecycle, session bookkeeping, pidfd tracking, and the
   response, preserving response order per session.

Restore readiness is detected from the guest agent's post-restore markers
(`SANDBOX-TICK` / `SANDBOX-VSOCK-`), with a tunable fallback settle
(`vsock_settle_ms`); env delivery is confirmed by `SANDBOX-ENV-END` (§15).

## Snapshot integrity (§10.10)

Each template directory holds the memory snapshot, rootfs, and a manifest built
from a self-contained SHA-256 implementation (no external crypto library). The
manifest carries a `header_size` guard so old/foreign manifests are rejected
rather than misread. `sandbox-cli verify` and `sandboxd --validate-config`
perform the same check.

## Observability (§10.12, §10.13)

- **Logs**: structured JSON on stderr — `ts`, `level`, `component`, `event`.
  Threshold via `log_level`.
- **Metrics**: `/health` and `/ready` probes plus `/metrics` (Prometheus text)
  with `process_*` stats and broker counters.

## Out of scope (V1) and deferred (V2)

Recorded in §13 of the design and tracked as issues: pool auto-scaling,
content-addressed snapshot storage, snapshot delta encoding, GPU passthrough,
multi-tenant isolation, a distributed engine (V1); privilege separation, vsock
payload authentication, per-tenant quotas, and IPC request-ids (V2).
