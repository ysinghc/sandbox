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
| Jailer | `src/jailer.c` | Creates the jail, chroots, drops uid/gid, applies seccomp, raises the ambient UFFD capability. Owns jail teardown and the crash sweep (moved from vmm in #9). |
| Privileged helper | `src/privileged/main.c`, `src/privileged/service.c` | `sandbox-privileged` (#9): the root half of the daemon. Serves taps, nftables, jail setup, cgroups, and VMM spawn/poll/reap over the `include/privsep.h` protocol; the daemon side is `src/privsep_client.c`. |
| seccomp | `src/seccomp.c` | Builds/loads the Firecracker syscall allow-list. |
| UFFD handler | `src/uffd_handler.c`, `src/prefault_worker.c` | Serves memory page faults from the snapshot on restore. |
| Snapshot manager | `src/snapshot_manager.c`, `src/sha256.c` | Template manifest, atomic publish, integrity verification (`sandbox-cli verify`, `--validate-config`). |
| Network manager | `src/network_manager.c` | Per-VM tap and nftables rules (via libnftables, or `nft`). |
| cgroups | `src/cgroup.c` | cgroup v2 hierarchy, memory/cpu limits, OOM grouping. |
| Broker | `src/broker/{core,http,credentials}.c` | Token validation, allow-listing, credential injection, HTTPS proxying. |
| HTTP API | `src/http_api/{server,sessions,auth,json,main}.c` | `sandbox-api`: unprivileged HTTP front end (#27). Sessions = persistent workspace + lazily provisioned VM; a libsandbox client of the daemon. |
| MCP gateway | `src/mcp_gateway/*.go` | `mcp-gateway`: remote MCP server + OAuth 2.1 AS (#28). Streamable HTTP tools 1:1 onto the #27 API; stdlib-only Go. |
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
5. **Daemon ↔ helper (#9).** A `SOCK_SEQPACKET` socket the helper binds
   `0700` to the daemon uid, gated again by `SO_PEERCRED`: exactly one peer
   uid may connect, and every request is re-validated (vm-id charset, path
   roots, daemon-ownership of writable binds, jailed ids ≠ daemon ids).

## Privilege separation (#9)

`sandboxd` runs as the `sandboxd` user with no capabilities; every operation
that needs privilege -- tap + nftables (`NET_UP`/`NET_DOWN`), jail setup +
`spawn_jailed` + teardown (`SPAWN`/`TEARDOWN`), cgroup leaves (inside
`SPAWN`), VMM status/reaping (`POLL`), the crash sweep (`SWEEP`) -- is served
by the root helper `sandbox-privileged` over the protocol in
`include/privsep.h` (8-byte header, strict bodies: NUL strings + little-endian
integers, no trailing bytes). The wire cannot express a tap name, argv, the
Firecracker path, or cgroup paths: the helper derives them all, so a
compromised daemon can only aim privileged operations at its own files.

Consequences of the split:

- The helper is the VMM's parent, so only it can reap; the daemon's crash
  detection (pidfd + epoll) still fires, and `TEARDOWN` reaps. A dead helper
  connection fails the daemon fast (exit 75) for a supervised restart.
- Jails are `0770 jailed-uid:sandboxd` and serial logs `0640`, so the daemon
  keeps the traverse/read access it had as root; the world stays out. Writable
  binds (session volumes, ephemeral clones) are chowned back to the daemon on
  `TEARDOWN`, which is what lets the next attach pass the ownership check.
- The two units share a lifecycle (mutual `BindsTo=`): a daemon restart
  reuses `vm-*` ids from `vm-1`, so the helper must forget its child table at
  the same moment. Restarting either restarts both.
- A root daemon without `privileged_socket` configured keeps the legacy
  in-process path (development, CLI template capture); template capture stays
  root-only via `sandbox-cli`.
- The snapshot store is operator-written and daemon-read (world-readable
  files); session workspaces and ephemeral clones live in the daemon-owned
  workspace store; unprivileged `userfaultfd(2)` needs
  `vm.unprivileged_userfaultfd=1` (shipped as a sysctl fragment).

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

## Live exec streaming and volume delete (#34)

A streaming exec (`GuestRequest.stream`) answers with one `GuestResponse` chunk
frame per output chunk plus the usual terminal reply. The guest worker posts
chunks through the existing result queue, so the IPC loop thread still owns
every send and the per-session slot frees only on the terminal frame.
libsandbox delivers chunks on the caller's thread with a bounded (2 MiB)
queue: a slow consumer kills its own stream instead of stalling the shared
connection. `sandbox-api` forwards chunks as SSE `stdout`/`stderr` events
(UTF-8 sequences split across chunks are held back and emitted whole).

Session volumes are deleted by key (`SessionDelete`), refused with
`SESSION_BUSY` while a sandbox of the session runs. The lease check and the
removal are atomic with respect to new creates (creates lease before touching
the image), so a racing create either pins the old volume or starts a fresh
one. `DELETE /v1/sessions/{id}` reclaims the VM, deletes the volume, and only
then forgets the record, so a failed delete leaves the session usable.

## Snapshot integrity (§10.10)

Each template directory holds the memory snapshot, rootfs, and a manifest built
from a self-contained SHA-256 implementation (no external crypto library). The
manifest carries a `header_size` guard so old/foreign manifests are rejected
rather than misread. `sandbox-cli verify` and `sandboxd --validate-config`
perform the same check.

Published templates are content-addressed and immutable: `.store/<digest>/` holds the
files and the template name is a symlink to it, repointed atomically on publish and
rollback (`src/template_store.c`; see [TEMPLATES.md](TEMPLATES.md)).

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
