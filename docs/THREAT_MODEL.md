# Threat Model

<!-- SPDX-License-Identifier: GPL-2.0-only -->

> Scope: the **self-hosted** engine (M0–M3). Multi-tenant/hosted concerns are
> noted where they change the analysis and are owned by #17/#9/#11.
> Every claim below was checked against the tree; file references are to the
> implementation, not the design intent.

## 1. What we are protecting

| Asset | Why it matters |
|---|---|
| **Upstream credentials** (`credentials.conf`, held only by the broker) | Real API keys. A leak is the worst-case outcome. |
| **Host filesystem & kernel** | The jailer exists so a compromised Firecracker cannot touch the host. |
| **Other tenants' sessions** (hosted, later) | Workspaces and snapshots are per-session. |
| **Session tokens** (64-hex, per create) | Bearer credential for the broker; authorises upstream egress. |
| **Snapshot store** | Trusted input: a tampered template is arbitrary code execution in the guest. |
| **Session workspace** | The only writable surface (D3); persists user data for the TTL. |

## 2. Trust boundaries

```
  assistant / caller            the guest (UNTRUSTED)             host
  ─────────────────             ──────────────────────            ────────────────────
  libsandbox / HTTP      ──▶    Firecracker ──▶ guest kernel      sandboxd (root)
  (Unix socket, SO_PEERCRED)    + agent (root in-guest)           ├─ jailer: chroot,
                                vsock :5001  ◀── host ──▶           ├─ setuid 65534,
                                                                    ├─ seccomp,
                                                                    └─ cgroup v2
                        broker (own uid)  ──▶  upstream (TLS)
```

Three boundaries matter:

1. **Guest ↔ host (`/dev/kvm`)** — the strong boundary. Firecracker in a
   `chroot` jail, uid 65534, seccomp-filtered, one cgroup, no `/proc` mounted.
2. **Guest ↔ internet** — nftables drops all egress except the host broker
   (`169.254.0.0/16` /30 per VM, no NAT). Egress is a *policy*, not a filter.
3. **Caller ↔ engine daemon** — a Unix socket with `SO_PEERCRED` uid
   allow-listing (`allowed_uids`).

## 3. Actors and what they can do

| Actor | Capability | Assumed hostile? |
|---|---|---|
| **Guest code** (assistant-generated) | root *inside* the VM; can run anything, exhaust its own memory/CPU, talk to vsock and (policy-limited) the network | **yes** |
| **Local unprivileged user** | can reach the engine socket only if in `allowed_uids`; can read any world-readable file | **yes** |
| **Caller / assistant** | supplies the command and its arguments that become guest code | **partly** (prompt injection) |
| **Operator** | edits config, templates, `credentials.conf` | no |
| **Snapshot author / supply chain** | produces the image the guest boots | no, but must be verifiable |

## 4. Threats

### 4.1 Guest → host escape

| # | Threat | Mitigation (verified) | Status |
|---|---|---|---|
| T1 | Path traversal out of the jail | `chroot()` + `chdir("/")` (`src/jailer.c:266-267`); kernel resolves `..` inside the new root | tested (`jailer_probe` exit 12, #2) |
| T2 | Escape via an inherited fd | jailer keeps no host fd beyond the serial fd, opened pre-chroot and dup2'd | `jailer_probe` exit 10 covers the sentinel path |
| T3 | `/proc/self/root` escape | `/proc` is **not** mounted in the jail (only `/dev/kvm`, `/dev/net/tun`, `/dev/userfaultfd`, `vmlinux`, `rootfs.ext4`, `vmstate`, `memory.snap`) | by construction (§12.2) |
| T4 | Arbitrary syscalls from a compromised Firecracker | seccomp allow-list; the Release default action is `SCMP_ACT_KILL_PROCESS` (`src/seccomp.c:27`) | tested unprivileged in CI (`tests/test_seccomp.c`, #1) |
| T5 | `CAP_SYS_PTRACE` misuse | the jailer keeps it **only** to create UFFD objects (`unprivileged_userfaultfd=0`), and `ptrace()` itself is *not* in the allow-list | **watch**: if the filter is ever loosened, this cap becomes an escape primitive |

### 4.2 Guest → network / credentials

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T6 | Guest reaches the internet directly | nft drops all egress except the host broker; no NAT (`src/network_manager.c`) | `tests/test_network.c` (root) |
| T7 | Guest reads an upstream credential | credentials live only in the broker; the guest sees just its session token | by design |
| T8 | Local user reads `credentials.conf` | broker now refuses a group/world-readable or foreign-owned file (#3) | `tests/test_broker.c` |
| T9 | Upstream TLS interception / MITM | `CURLOPT_SSL_VERIFYPEER=1`, `VERIFYHOST=2` by default (`src/broker/core.c:343-345`); off only via `SANDBOX_BROKER_TLS_VERIFY=0` | default-safe |
| T10 | A guest forges host→guest control traffic on vsock :5001 | the agent accepts only a peer whose vsock CID is `VMADDR_CID_HOST`; anything else is closed and logged (`include/vsock_peer.h`, `scripts/sandbox-agent.c`). A guest cannot forge CID 2: `connect()` to it is routed out to the host, never back to the guest's listener | fixed (#10): host test with a real loopback peer + in-guest `cid=2` assertion |
| T11 | Token guessing | 32 bytes from `getrandom()`, `/dev/urandom` only as fallback (`src/ipc_server.c:290`) | adequate |
| T12 | Stolen token replayed by another guest | the token is per-session and validated against the engine; no binding to the peer VM. The vsock control channel is now peer-CID authenticated (T10), but the broker token itself still has no VM binding | partially mitigated; VM binding stays open for #17 |

### 4.3 Caller → engine

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T13 | Unprivileged user drives the daemon | `SO_PEERCRED` + `allowed_uids`; per-uid create quotas | implemented |
| T14 | Shell injection through a template/jail path | all four `system()` shell-outs removed; `sandbox_rm_rf`/`sandbox_copy_file` are in-process (`src/fs_util.c`) | fixed (`d2eff09`) |
| T15 | Resource exhaustion / DoS | cgroup v2 memory/CPU/OOM-group; pool queue depth; per-uid create caps | implemented, not yet load-tested |
| T16 | Prompt-injected command does something destructive **inside** the VM | out of scope for isolation: the VM *is* the blast radius. Containment is the workspace-only writable surface (D3/D4) | by design |

### 4.4 Supply chain & integrity

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T17 | Tampered snapshot restores arbitrary guest code | `memory.snap`, `vmstate` **and `rootfs.ext4`** are SHA-256-bound in the manifest and verified on restore (`src/snapshot_manager.c`); the rootfs was the gap — a swapped image changes the guest without touching either hashed file (#22) | implemented |
| T18 | Counterfeit release binary | releases ship `.sha256` per archive; `scripts/install.sh` verifies before writing | fixed (`install.sh`) |
| T19 | Unsigned releases | **none** — no signing yet | **open (#19)** |
| T20 | World-readable workspace/snapshot dirs | state lives under `/var/lib/sandbox-engine`; snapshot store permissions are not asserted at startup | **open** |

## 5. Residual risk, ranked

1. **#9 — the daemon is one big root TCB (T4/T5/T15).** Every mitigation above
   runs inside `sandboxd` (root). Splitting the privileged operations into a
   small helper is what makes the seccomp/capability surface auditable, and
   lets the jail move to `pivot_root`.
2. **T12 — the broker token is not bound to a VM.** The vsock control channel is
   peer-CID authenticated now, but a token stolen inside one sandbox still
   authorises broker requests from any guest that can present it. Real under
   multi-tenancy (#17); cheap to bind by including the VM identity in the token
   claims when #24 lands.
3. **T5 — ambient `CAP_SYS_PTRACE`.** Justified and currently inert (seccomp
   blocks `ptrace`), but it is a single filter edit away from being dangerous;
   assert the two invariants together if either changes.
4. **T19/T20 — unsigned releases, unasserted store permissions.** Cheap to
   close, and they are the two places where "trusted input" is assumed rather
   than checked.

## 6. Explicit non-goals

- **Guest-internal containment.** Once code runs in the VM, it owns the VM.
  Isolation is the boundary, not a sandbox within the sandbox (#24 must still
  confine file paths to `/workspace`, but that is hygiene, not a boundary).
- **Confidentiality from the operator.** The operator owns the host and the
  credentials; this is not a defence against them.
- **Network-level anonymity.** Egress policy bounds *destination*, not
  content; anything the caller sends to an allowed host leaves the host.

## 7. Maintaining this document

This is a code-derived model, not an aspiration. When you change the jailer,
the seccomp policy, the vsock protocol, the network rules or the credential
path, update the matching row — and prefer a test over prose. `§12.2` of
[`SYSTEM DESIGN.md`](../SYSTEM%20DESIGN.md) tracks the same items as an audit
checklist.
