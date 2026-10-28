# Implementation Plan — Sandbox Engine → Web-Assistant Agent Sandbox

<!-- SPDX-License-Identifier: GPL-2.0-only -->

> **The *how*.** The *why* lives in the roadmap Discussion on GitHub. This
> document is the corrected, ground-truthed version of the original plan: every
> file path, symbol and API field below was checked against the tree at
> commit `e5a5cc7` and corrected where the original was wrong (§0).

**Ground truth as of 2026-10-18** — `HEAD = e5a5cc7`.

> **Platform focus (2026-10-20): x86_64 first, aarch64 deferred.**
> The definition of done for this stretch is concrete: *a Debian guest boots, has a
> persistent `/workspace`, and a web assistant can run commands and read/write files
> in it through the control plane.* Until that is true on x86_64, ARM parity work is
> off the critical path.
>
> Why this order is not arbitrary: the aarch64 post-restore timer bug turned out not
> to be a guest-kernel problem — Linux 6.1.155 (Firecracker's own CI kernel) shows the
> same behaviour, with the vCPU running, `CLOCK_MONOTONIC` advancing and VMGenID
> delivered, while `sleep()` never returns. It is a Firecracker defect
> ([firecracker#6313](https://github.com/firecracker-microvm/firecracker/issues/6313)).
> It only affects restored aarch64 guests; on x86_64 timers work, so none of the
> features below are blocked by it. The ARM runner stays online and its leg keeps
> running as an early-warning signal, but ARM-only defects are recorded and deferred
> (see #30) rather than fixed in this stretch.

---

## 0. Ground-truth corrections

The original plan contained four details that were wrong. Three of them would
have caused real breakage or wasted work; they are corrected throughout, and
listed here so the corrections are not lost.

### C1 — #22: the clock field is `clock_realtime`, and it can *fail the load* (WAS WRONG)

The plan proposed adding to the `/snapshot/load` body in `src/vmm_manager.c`:

```json
"clock_override": {"wall_clock_time_ns": 1234567890}
```

That field does not exist. Verified against the Firecracker source
(`src/vmm/src/vmm_config/snapshot.rs`), the swagger, the snapshot docs and PR
[#5809](https://github.com/firecracker-microvm/firecracker/pull/5809):

- The field is **`"clock_realtime": true`** — a boolean, not an object.
- `LoadSnapshotConfig` is `#[serde(deny_unknown_fields)]`, so an unknown
  `clock_override` key makes `/snapshot/load` return **400**: every restore
  breaks. It is not silently ignored.
- It is **x86_64 only**. On aarch64 — a first-class target (D2) — it is
  unsupported, so the clock must be fixed guest-side there.
- It requires host Linux ≥ 5.16 **and** a snapshot captured with a TSC-based
  clock. Otherwise the load fails with
  `clock_realtime requested but not present in the snapshot state`.

**Corrected approach:** set `"clock_realtime": true` on the x86_64 leg only,
treat a failed load as a fallback trigger, and do the aarch64 clock fix in the
guest (see #22 below).

### C2 — #2: the jailer uses `chroot`, not `pivot_root` (WAS WRONG)

The plan says "verify `pivot_root` is used, not plain chroot". `src/jailer.c`
calls `chroot(jail_root)` then `chdir("/")` (steps 9–10 of the jailer). There is
no `pivot_root`. The chroot-escape test therefore tests a chroot jail, and
file-descriptor-based escapes (`openat` on an inherited fd) are the realistic
risk, not `..` traversal.

### C3 — #1: there is no `tests/test_seccomp` (WAS WRONG)

The plan calls it "already exists as a binary". It does not: `tests/CMakeLists.txt`
has no such target. The only thing linking `src/seccomp.c` is `tests/jailer_probe.c`.
Also, "add the aarch64 block" is already done — `src/seccomp.c` builds the common
allow-list from Firecracker's **aarch64** filter and adds exactly four x86_64-only
syscalls (`dup2`, `arch_prctl`, `open`, `stat`) under `#if defined(__x86_64__)`.

### C4 — #10: reuse the existing `session_token`; there is no bootstrap problem (WAS INVENTED)

The plan invents a `session_key` from `urandom(32)` and then wrestles with a
"bootstrap problem". The engine **already** mints a per-create 64-hex
`session_token` (returned in `CreateResponse`, validated by the broker — see
`docs/API.md`). Reuse it as the vsock authentication key; the bootstrap question
disappears.

### C5 — the SPDX one-liner breaks shebangs *and* file modes (WAS WRONG)

`sed -i '1s|^|# SPDX…|' scripts/*.sh` has two traps, and both were hit for real
while applying this plan:

- It puts the tag **above** `#!/usr/bin/env bash`, which disables the shebang.
  Insert on **line 2** for any file that starts with `#!`.
- A rewrite that replaces the inode (e.g. `mv tmp file`) gives the file the
  umask's mode and **silently drops the executable bit**. The first sweep lost
  `+x` on `scripts/benchmark.sh` and `tests/net_cleanup.sh`, and clobbered an
  unrelated uncommitted mode change on `scripts/build-custom-rootfs.sh`. Always
  re-apply modes after a bulk rewrite; `git diff --cached --summary | grep mode`
  catches a regression before it is committed.

(Implemented correctly in `scripts/check-spdx.sh` + the sweep.)

### C6 — #1: the seccomp trace was already taken (WAS IMPLIED TO BE OUTSTANDING)

The plan's step 1 is "generate a real trace". The allow-list comments in
`src/seccomp.c` already cite a real x86_64 strace as their source. The genuine
gap was only the **regression test**, which did not exist (`tests/test_seccomp.c`
now does).

### C7 — #2: the escape test already existed (WAS IMPLIED TO BE MISSING)

`tests/jailer_probe.c` already exits 10 when an outside sentinel is openable
inside the chroot, and `tests/test_jailer.c` drives it through a real
`spawn_jailed()` inside a user namespace. No new `tests/e2e/chroot_escape.sh`
was needed — only the `..`/`getcwd` assertion the plan named, which is now in
the probe (exit 12). Note what actually closes the `/proc/self/root` escape:
**`/proc` is not mounted in the jail**, not the chroot alone.

### C8 — #22: `vmstate_sha256` already exists; the real gap was the rootfs (WAS WRONG TWICE)

`snap_manifest_t` (`include/snapshot_manager.h`) already carried both
`memory_sha256` and `vmstate_sha256`, so "add vmstate" was already done. The
plan then guessed the remaining gap was **kernel image identity** — also wrong:
a restore never loads the kernel (`/snapshot/load` needs only vmstate, memory
and the disk image the VM booted from). The actual unbound file was
**`rootfs.ext4`**: the guest resumes with that image's page cache and inode
state, so swapping it changes the sandbox while every hashed file still
matches. That is what #22 binds now.

### C9 — #19: the published asset layout is not what the plan assumes (WAS WRONG)

The plan says "add checksums" — they already ship. And `v0.12.0`, the only
release so far, publishes **only** `sandbox-engine-<ver>-linux-<arch>.tar.gz`
(+ `.sha256`): the `-bin.tar.gz` and standalone `-linux-<arch>` binaries are
new in the rewritten workflow and appear only from the *next* release. Any
installer must therefore target the staged tree. `scripts/install.sh` does.

### C10 — §12.2 items already satisfied (WERE OPEN IN THE DOC, NOT IN THE CODE)

Broker TLS verification is **on by default** (`CURLOPT_SSL_VERIFYPEER=1`,
`VERIFYHOST=2`; off only via `SANDBOX_BROKER_TLS_VERIFY=0`), and the session
token already comes from `getrandom()` (`/dev/urandom` is a fallback). Both
were ticked off with evidence rather than "fixed".

### C11 — the privileged suite was green while executing nothing (WAS BELIEVED VERIFIED)

`privileged-e2e.yml` reported success from its first run, but `tmpl_setup`
exited in **0.01 s** and `pool`/`vmm`/`ipc` skipped behind it (only `network`
did real work). The e2e scripts were unaffected because `benchmark.sh` builds
its own template.

Root cause: the tests were invoked as `sudo -E`, and sudo resets the
environment, so the roots ctest supplies through its `ENVIRONMENT` property
(`SANDBOX_SNAPSHOT_ROOT`, `SANDBOX_JAIL_ROOT`) never reached `make_template`. A
test missing its roots SKIPs with exit 0 — deliberately, so an unprivileged
`ctest` stays honest — so the whole chain looked green.

Fix: no `sudo` inside the test commands; the *suite* runs as root (the labs job
does, and `docs/TESTING.md` documents it), so ctest's environment arrives
intact. `privileged-e2e-run.yml` now runs the set with `-V` and **fails the job
if any of those tests report Skipped/Not Run** — a skipped privileged test is a
green no-op and must not pass.

Lesson applied elsewhere: never let "passed" stand for "ran". Assert execution,
not just exit status.

### C12 — #10: a per-session token cannot authenticate host→guest (C4 WAS WRONG)

C4's "reuse `session_token`" does not work in the direction that matters. The
token would have to reach the guest *over the channel being authenticated*, and
a snapshot template is built once and restored per session, so nothing
per-session can be baked into the guest. Guest→host needs no token either: each
VM has its own vsock UDS, so provenance is already per-VM.

What actually authenticates the host is the **peer CID**. Only the hypervisor's
proxy presents `VMADDR_CID_HOST` (2), and a guest process cannot forge it:
`connect()` to CID 2 from inside the guest is routed out to the host, never back
into the guest's own listener.

Second correction: the pinned guest kernel is **6.18.54** (#33), so it knows
`VMADDR_CID_LOCAL` (Linux 5.6+), but Firecracker's own CI kernel config sets
`# CONFIG_VSOCKETS_LOOPBACK is not set`. An in-guest self-test that connects to
its own listener therefore still has no local transport to complete on — the
first attempt (on 4.14, where the address did not exist at all) wedged the
agent's serve loop. The negative direction cannot be produced inside this guest,
so it is verified on the host (`tests/test_vsock_peer.c` against a real loopback
peer, cid 1) and the guest asserts the positive direction
(`SANDBOX-VSOCK-HOST cid=2` in serial).

### Sharper alternatives adopted

- **#19** — checksums already ship for both architectures (`.sha256` since
  `d98d31f`). The remainder is signatures and `scripts/install.sh`.
- **#27** — "reuse `src/broker/`'s HTTP plumbing" overstates it: the broker is an
  **outbound forward proxy** (guest → upstream), not an inbound REST router. Only
  its HTTP parse/serialise helpers are reusable; routing is new code.
- **#23** — a design already exists and is committed as
  `docs/WORKSPACE_DISK.md` (D7). Do not re-design it.

---

## Confirmed design decisions

| # | Decision | Detail |
|---|---|---|
| D1 | Self-host now, hosted later | multi-tenant (#17), quotas (#11), privilege split (#9) → M4 |
| D2 | ARM is first-class | #6 + #19 in M1; CI needs an aarch64 runner |
| D3 | Pre-baked images + writable `/workspace` only | root stays immutable read-only |
| D4 | Persistence unit = per session / conversation | session-scoped workspace + TTL |
| D5 | TTL renewal | **absolute** TTL from creation (default 7 d); `sandbox_renew(handle, extra_seconds)` extends up to a platform max (default 30 d); never automatic |
| D6 | MCP gateway language | **Go**, new process `src/mcp_gateway/`; a thin OAuth/SSE adapter over the control-plane API (#27). The C engine is unchanged |
| D7 | Workspace disk format | pre-formatted sparse ext4 stamped at template-build; session-create reflink-copies it. No runtime `mkfs`. See `docs/WORKSPACE_DISK.md` |

---

## Status

| Item | State |
|---|---|
| Perf fixes (`snapshot_manager.c`, `vmm_manager.c`) | ✅ `e5a5cc7` |
| `jail_cleanup` shell-injection fix (#5) | ✅ `d2eff09` — **plus three more call sites the plan missed** |
| SPDX headers + `scripts/check-spdx.sh` + CI gate (#8) | ✅ `085d594` — 66 files |
| `tests/e2e/smoke.sh` + `tests/e2e/latency.sh`, gated `privileged-e2e.yml` (#20) | ✅ **executed on a real runner**: warm 0.18 ms, provisioned 45.33 ms |
| Threat model + §12.2 close-out (#21, #5) | ✅ `13b36ce`/later |
| `credentials.conf` permissions gate (#3) | ✅ + `test_broker` coverage |
| Seccomp allow-list regression test (#1) | ✅ `tests/test_seccomp.c` — runs unprivileged in CI |
| Chroot `..`-escape assertion (#2) | ✅ `jailer_probe` exit 12 |
| `scripts/install.sh` + release docs (#19) | ✅ verified offline against a staged tree |
| vsock peer authentication (#10) | ✅ guest+host code; classifier unit-tested on the host, host CID asserted in-guest |
| #22 determinism (clock + rootfs pinning) | ✅ verified on the kvm runner: guest skew 0 s vs host with a 16 s-old template |
| M1 ARM timer (#6) | ✅ investigated on real hardware — **not fixed**, documented (§15.7); fix path #30 (modern guest kernel) |
| M1 aarch64 privileged leg | ✅ live on the Pi 5 (`sandbox-arm64-pi5`), both legs green on `62ae6e5` |
| #23 session workspaces + TTL | ✅ **0.14.0** — privileged e2e proves in-guest persistence across destroy/re-create |
| #24 guest RPC | ✅ guest, host client, IPC, libsandbox, C++, CLI; privileged CI green on busybox and Debian |
| #7 broker streaming | ✅ chunked and Content-Length bodies stream with bounded memory; `SANDBOX_BROKER_MAX_BODY` (256 MiB) → 413; 64 MiB SHA-256 fidelity + RSS bound tested |
| M2 #25–#28 | ⏳ not started |

### What the `jail_cleanup` fix actually became

The plan described one call site, `jail_cleanup()` in `src/vmm_manager.c`. There
were **three** `system()` shell-outs reachable with a caller-influenced path:

| Call site | Was | Now |
|---|---|---|
| `vmm_manager.c` `jail_cleanup()` | `system("rm -rf <jail_root>")` | `sandbox_rm_rf()` |
| `snapshot_manager.c` `rm_rf()` | `system("rm -rf <path>")` | `sandbox_rm_rf()` |
| `snapshot_manager.c` `copy_into()` | `system("cp <src> <dst>")` | `sandbox_copy_file()` |
| `vmm_manager.c` serial-log stash | `system("cp … \|\| true")` | `sandbox_copy_file()` |

New: `include/sandbox_fs.h` + `src/fs_util.c` — `sandbox_rm_rf()` (`nftw` with
`FTW_DEPTH | FTW_PHYS`, so symlinks are unlinked, never followed) and
`sandbox_copy_file()` (in-process read/write, source mode preserved).

Still shelling out: `src/network_manager.c` `system()` — the **libnftables-less
fallback** only, built from internal interface names. Tracked as a follow-up.

---

## M0 — Safety net & hygiene

### #20 — Privileged e2e in CI (x86_64 + aarch64)

**Root cause of the gap:** the hosted CI runs `ctest` unprivileged, so every
sudo/KVM-dependent case is skipped and regressions in the restore path, jailer or
nftables ship silently.

**Delivered:**
- `tests/e2e/smoke.sh` — one warm + one cold restore via
  `scripts/benchmark.sh --pool 1 --count 2`; asserts the restore path logged
  `[vmm_restore] time total=`. It owns **no** harness of its own: benchmark.sh is
  the single source of truth for workspace/template/daemon setup.
- `tests/e2e/latency.sh` — runs the benchmark once and asserts **warm < 5 ms** and
  **cold < 250 ms** (flags override). *Replaces the planned `bench_warm.sh` +
  `bench_provisioned.sh`, which would each have re-run the full harness.*
- `.github/workflows/privileged-e2e.yml` — per-arch jobs (a `matrix` is not a
  valid context in `jobs.<job_id>.if`, so the two legs are separate jobs over a
  reusable body), gated by `if: vars.PRIVILEGED_RUNNERS == 'true'` (x86_64) and
  `vars.PRIVILEGED_ARM` (aarch64). Fork PRs are refused outright: the runner
  executes code as root.
- `.github/workflows/privileged-e2e-run.yml` builds the guest image from the
  checkout, runs the root/KVM tests with `-V`, and **fails if any of them
  skipped** (C11).
- `docs/TESTING.md` §"Privileged runners" — the host prerequisites (KVM, tun,
  nftables, Firecracker, guest assets, dev-capable workdir) and the registration
  sequence.

**Verified on the operator's host** (`sandbox-x86-01`, root service): warm
**0.18 ms**, provisioned **45.33 ms** (budget 5 ms / 250 ms); `tmpl_setup`
really boots (2.01 s); `pool`, `network`, `network_cleanup`, `vmm`, `ipc`,
`cgroup` execute rather than skip.

**aarch64 (2026-10-20):** _sandbox-arm64-pi5_ is registered (Pi 5, Ubuntu 24.04,
non-root runner with passwordless sudo, KVM, cgroup v2) and both legs are green
on `62ae6e5`: 10/10 unprivileged and 7/7 privileged tests, the #23 session
persistence and renewal checks included, on the guest image that run built
(warm **2.07 ms**, provisioned **132.33 ms**; the budget check now has ~2.5×
less headroom than on x86, which is the number that matters).

Two environment bugs had to be fixed to get there, both of which made the leg
"pass" or die misleadingly: `sudo ctest` on a non-root runner reset the
environment and dropped `SANDBOX_ROOTFS`, so the suite ran a guest image older
than the code (fixed by baking the asset paths into the test definition, plus a
job assertion that the fixture loaded the image the job built); and the sudo'd
rootfs build left the runner's `guest/` root-owned, which made every later
checkout fail before its first step (fixed by chowning the output and its dir).

**This exposed #6, which is real and now documented (§15.7):** on aarch64 the
guest's timer interrupt is never delivered after a restore — a guest snapshotted
mid-`sleep` never wakes, reproduced with no engine involved. The agent's
busy-poll heartbeat is therefore load-bearing, and any workload that blocks on a
timeout in a restored ARM sandbox hangs. #30 (modern guest kernel) is the fix
path and is now the top M1 item.

### #8 — SPDX headers + CI gate

Delivered: `SPDX-License-Identifier: GPL-2.0-only` on all 66 source files
(`src/`, `include/`, `tests/`, `scripts/`), `scripts/check-spdx.sh`, and an
`spdx` job in `ci.yml` that runs on every push/PR. Shebangs preserved (C5).

---

## M1 — Isolation boundary + ARM correctness

### #21 — Threat model
Write `docs/THREAT_MODEL.md` from the code, not the design intent. Input to
#17/#9/#11. Cover the chroot reality (C2), the vsock surface, the snapshot store,
and pickled/untrusted guest input (prompt injection).

### #1 — Seccomp allow-list from a real trace
- Generate a real trace (`strace -f -e trace=all` around one create; user runs).
- Diff against `src/seccomp.c`; remove extras, add missing.
- The x86_64 delta is already isolated at `src/seccomp.c:155`; on aarch64 the
  common set *is* the policy.
- **Regression test:** create `tests/test_seccomp.c` (does **not** exist today,
  C3) that installs the filter in a forked child, invokes each allowed syscall and
  asserts none are killed, plus a forbidden syscall asserts `SIGSYS`.

### #2 — Chroot-escape regression test
`src/jailer.c` uses `chroot()` + `chdir("/")` (**not** `pivot_root`, C2). Test
`tests/e2e/chroot_escape.sh` (root): assert a `..` traversal stays at `/`, and
assert the fd-based escape also fails once #9 reduces the inherited fd set.
Document that `pivot_root` is the stronger primitive and evaluate it in #9.

### #3 — Reject unsafe `credentials.conf` mode/ownership
The load path is `src/broker/credentials.c` (`credentials_load`) reached from
`src/broker/core.c:748` — **not** `src/broker.h`. Add a `stat()` check before
parsing: refuse if `st_mode & 0o077` or `st_uid != getuid()`. Unit-test in
`tests/test_broker.c` (exists). Document in `docs/CONFIGURATION.md`.

### #10 — Authenticate vsock payloads
**Delivered (C12).** The channel is authenticated by **peer CID**, not a token:
`include/vsock_peer.h` + `src/vsock_peer.c` hold the classifier
(`vsock_peer_is_host()`), and the agent
(`scripts/sandbox-agent.c`, `ENV_PORT 5001`) accepts only a peer whose CID is
`VMADDR_CID_HOST`; anything else is closed and logged as
`SANDBOX-VSOCK-REJECT cid=<n>`. The classifier is freestanding so the same file
is linked into a host test and into the static guest agent (built by
`scripts/build-custom-rootfs.sh`).

Verification is split because the guest cannot test it from the inside:
- host: `tests/test_vsock_peer.c` — decision table plus a real AF_VSOCK
  loopback peer (kernel reports cid 1) that must be refused; unprivileged, so it
  runs in hosted CI;
- guest: the agent logs `SANDBOX-VSOCK-HOST cid=2` on the first accepted
  connection, asserted by `tests/test_ipc.c`, which proves the CID it reads is
  real and is the host's.

Rejected from the plan: the `session_token` HMAC (C4) — the token cannot reach
the guest over the channel it would authenticate, across a snapshot boundary.

### #6 — aarch64 arch-timer after restore
`scripts/sandbox-agent.c:11-20` documents the workaround: the arch timer does not
re-arm, so the agent busy-polls with a zero-timeout `poll()` instead of sleeping.
User code still hangs. Root-cause path: instrument on the ARM runner (`sleep 1`
must return within 2 s), inspect Firecracker's aarch64 vCPU restore, and either
reset the timer offset via `KVM_ARM_VCPU_TIMER_CTRL` post-load or inject a
guest-side calibration. `docs/TESTING.md` already lists this as a known host
limitation.

### #19 — Multi-arch release artifacts
Checksums already ship (C5-adjacent, see §0). Remaining: optional signing and a
`scripts/install.sh` that picks the arch-specific asset, plus `docs/BUILDING.md`
`ARCH=aarch64` instructions.

---

## M2 — Agent-capable product core

Dependency order:

```
#22 determinism/time
      ↓
#23 session workspace + TTL
      ↓
#24 guest RPC (exec + fs)
      ↓
#25 template pipeline      #26 egress policy
      ↓                          ↓
            #27 control-plane API
                      ↓
              #28 remote MCP server (Go, D6)
```

### #22 — Determinism & time correctness — **delivered**
- **Stale clock:** `vmm_build_load_request()` (`src/vmm_manager.c`) sets
  `"clock_realtime": true` on x86_64 only, with `SANDBOX_FC_CLOCK_REALTIME=0` as
  the escape hatch for a host kernel < 5.16 (where the field makes the load fail
  — C1). No TSC pre-check was added: Firecracker validates the field itself, and
  a rejected load fails loudly rather than silently keeping a stale clock.
  aarch64: not sent at all (unknown field); the guest-side time sync is still
  open, and `tests/test_ipc.c` says so rather than pretending.
- **Duplicate entropy:** *closed by the kernel pin (#33).* On the old 4.14.174
  image there was no VMGenID (5.18+), so a restored guest kept the template's
  CRNG state. The pinned 6.18.54 has `CONFIG_VMGENID=y`: a restore delivers the
  VMGenID notification, the kernel reseeds, and the console shows
  `random: crng reseeded due to virtual machine fork` (verified on x86_64,
  Firecracker v1.17.0, 2026-10-21). Files captured in the template still repeat,
  so §15.16 and `docs/API.md` still require per-session secrets to be generated
  after resume and forbid secrets in templates.
- **Pinned images:** the gap was **not** kernel identity (C8 was wrong: a
  restore never loads the kernel). It was `rootfs.ext4`, which was not bound at
  all while the guest resumed with that image's page cache and inode state. It
  is now `rootfs_sha256`/`rootfs_size` in `snap_manifest_t`, computed at build
  time and verified once per template on restore; `sandbox-cli verify` re-hashes.
- **Docs:** §15.16 and `docs/API.md` state what determinism does and does not
  guarantee; `docs/UPGRADE.md` records that 0.12.0 templates must be rebuilt.

### #23 — Session workspace volumes + TTL — ✅ delivered in 0.14.0

Follow `docs/WORKSPACE_DISK.md` (D7) — do not re-design. Extend `sandbox_spec_t`
(`include/libsandbox.h`) with `session_id`, `workspace_mb`, `ttl_seconds`. Add a
TTL reaper and `sandbox_renew`. New config keys (`workspace_root`,
`workspace_default_ttl_seconds`, `workspace_max_ttl_seconds`,
`workspace_default_size_mb`) — none exist in `config/engine.conf` yet.

**As delivered (deviations from the paragraph above, all deliberate):**

| Planned | Delivered | Why |
|---|---|---|
| `session_id` | `session_key` | The key is caller-chosen and the registry directory is `sha256(key)`, so it doubles as the isolation boundary and cannot traverse paths. |
| `workspace_mb` per sandbox | `workspace_size_mb` per **template** | D7: the image is pre-formatted and cloned, so its size is a property of the template, not of a request. One size per template also keeps the clone path simple. |
| `sandbox_renew(handle, …)` | `sandbox_session_renew(key, …)` | The volume outlives every VM; a handle-based renew could not keep a quiet conversation alive with nothing running. |
| config keys in `engine.conf` | `SANDBOX_WORKSPACE_ROOT`, `SANDBOX_WORKSPACE_MAX_TTL`, `SANDBOX_REAP_INTERVAL_SECONDS`, `SANDBOX_FLUSH_MS` | Matches how every other runtime knob in this engine is configured; `config/engine.conf` is the systemd unit's environment, not a second parser. |

Also not in the original paragraph, but required by the tests:

- The guest mounts `/workspace` **after** each restore, never before the capture
  (`docs/WORKSPACE_DISK.md` §0.2). Capturing a mount served every restore an ext4
  whose in-RAM state belonged to a different file.
- The engine **flushes** the guest (`sync()`) before destroying a session VM
  (§0.3). Without it, a workload's write could still be in the guest's page cache
  when the VMM was SIGKILLed, so a re-created session did not see its own file.
- Session creates **bypass the warm pool** and take an exclusive lease: a pool VM
  is restored before a request exists, and Firecracker cannot swap a block device
  after restore.

### #24 — Guest RPC: exec + file operations over vsock
**Built as designed-then-corrected.** The plan said newline-delimited JSON; the
implementation is a length-prefixed binary frame protocol (`include/guest_rpc.h`)
because the agent is a static C binary with no JSON or protobuf library, and exec
streams raw bytes that JSON would have to escape. Port **5002** (5001 stays the
env port), one request per connection, concurrency = more connections.

Status:

| Piece | State |
|---|---|
| Wire format, byte codec, path policy (`include/guest_rpc.h`, `src/guest_rpc_wire.c`) | ✅ |
| Guest server: exec (streaming, timeout, output cap, process-group kill, cancel on disconnect) and read/write/list/stat/mkdir/remove (`src/guest_rpc_server.c`, linked into the agent) | ✅ |
| Host client (`src/guest_rpc_client.c`, in `libsandbox`) | ✅ |
| Unprivileged test: the real server against the real client over socketpairs — 82 checks, clean under ASan/UBSan (`tests/test_guest_rpc.c`) | ✅ |
| Booted-guest check after a snapshot restore (`tests/test_ipc.c`, privileged) | ⏳ written; awaiting the first CI run |
| Exposure through the daemon IPC (`GuestRequest`/`GuestResponse`), `libsandbox` C API, C++ wrapper, `sandbox-cli run --exec` | ✅ |
| Full-stack unprivileged test: libsandbox → daemon → worker pool → hybrid-vsock-style UDS → the real guest server, 40 checks, clean under ASan/UBSan (`tests/test_ipc_guest.c`) | ✅ |
| Same path on a restored guest, plus "a command writes in sandbox 1, sandbox 2 of the same session reads it" (`tests/test_ipc.c`) | ⏳ written; awaiting the first CI run |

**Auth is the #10 rule, and that is a decision, not an omission.** The issue asked
for a per-VM key with replay protection. #10 established that a token cannot be
delivered to the guest over the channel it would authenticate (the template is
built once and restored per session), so the gate is the vsock peer CID: a guest
process cannot present CID 2. Replay is not a separate threat here: there are no
signed messages to replay — each request is a fresh connection, and the only way
to open one is the per-VM UDS in a 0700 jail. Malformed or hostile frames from a
peer that passed the gate are tested (bad reserved byte, 2 GiB length, wrong
frame type, unknown version/op, truncated header, half-sent requests, NUL in a
path); none is acted on and the server keeps serving.

Path policy: absolute, no `.`/`..` components, under `/workspace`; the parent is
`realpath`'d and must stay inside (a symlink planted in the workspace cannot lead
out); the final component is never followed for write/stat/remove. A request may
opt out per call with `GRPC_F_ALLOW_OUTSIDE` — that is the host's choice, not the
guest's. `/` and the workspace root are never removable.

Known limits (v1): a file is one guest frame, so ≤ 4 MiB (`GRPC_MAX_FILE`). The
IPC leg is a 64 KiB frame, so `libsandbox` chunks files at 48 KiB and exec
returns the head of each stream (32 KiB / 16 KiB) with the true byte counts.
Guest ops need a non-zero `request_id` and run on a pool of 8 workers, 16 in
flight per session, 256 daemon-wide. stdin is ≤ 64 KiB then EOF.
The agent is PID 1 and reaps every orphan; background daemons started by `exec`
survive the call (only the timeout/cancel path kills the group).

### #25 — Template pipeline
`scripts/build-template.sh`, `publish-template.sh`, `gc-templates.sh`;
`template.json` metadata; `snapshot_publish()`/GC in `src/snapshot_manager.c`;
`sandbox-cli template {list,build,gc}`.

### #26 — Per-session egress policy
Extend `sandbox_egress_policy_t` into `sandbox_spec_t`. `src/network_manager.c`
already builds per-VM nft rules; add allowlist accepts. M2 allows IP:port/CIDR
only (DNS resolution is the caller's job); the broker path stays always-on.

### #27 — Control-plane HTTP API
New `src/http_api/`. Only the broker's HTTP parse helpers are reusable (C5
alternative). Endpoints under `/v1/sessions`. Auth: Unix-socket owner check
locally; bearer token when bound to TCP for #28.

### #28 — Remote MCP server (Go, D6)
New `src/mcp_gateway/` (Go): Streamable HTTP + OAuth 2.1 (PKCE, refresh, RFC 7591
DCR) + SSE. Tools map 1:1 onto #27. Verified: Claude/ChatGPT/Gemini web all
connect via remote MCP over HTTPS with OAuth + DCR.

---

## M3 — Self-host beta hardening

- **#4** hierarchical config (`engine.conf` + `conf.d/*.conf`), via
  `include/engine_config.h` / `libsandbox_config.a`.
- **#12** concurrent-create correlation: `src/pool_manager.c` has a single
  `replenishment_thread` (confirmed). Add `pool_replenish_concurrency`
  (default 2); `network_subnet_addrs()` is already a pure FNV-1a /30 allocator, so
  the only shared resource is nftables state.
- Observability: per-session metrics + `GET /v1/metrics`.

## M4 — Hosted multi-tenant GA
**#17** multi-tenant isolation · **#9** privilege separation (`sandbox-privileged`
helper; also enables `pivot_root`) · **#11** per-tenant quotas incl. storage bytes.

## M5 — Scale & cost
**#7** broker streaming · **#13** pool autoscaling · **#14** CAS store ·
**#15** delta snapshots.

## M6 — Breadth
**#18** distributed engine · **#16** GPU passthrough (no upstream support).

---

## Immediate next steps

```
Done     perf fixes; e2e smoke + latency harness; 4 shell-outs removed; SPDX sweep + CI gate
Done     #21 threat model + §12.2 close-out; #1 seccomp regression test; #2 chroot ".." assertion
Done     #3 credentials.conf permissions gate; #19 scripts/install.sh + prebuilt-release docs
Done     #20 privileged e2e now *runs*: warm 0.18 ms / provisioned 45.33 ms on sandbox-x86-01,
         with a gate that fails the job if a privileged test skips (C11)
Done     #10 vsock peer authentication (C12), verified host-side + in-guest
Done     #22 determinism: clock_realtime on load (guest skew 0 s vs host with a
         16 s-old template) + rootfs digest in the manifest + docs
Done     #23 session workspace volume + TTL — follow docs/WORKSPACE_DISK.md (D7)
Done     #6  aarch64 arch timer — reproduced on the Pi, documented in §15.7, not fixed;
         product consequence recorded; the fix path is #30 (modern guest kernel)
Done     #31 crash-left jails: startup sweep, liveness via /proc/<pid>/root, privileged
         ctest jail_sweep green on x86_64 *and* aarch64
Done     #12 request correlation: request_id echoed, per-session create serialization
         removed for id-carrying requests, libsandbox reader thread, ctest ipc_codec
Next     #32 Debian guest image + /workspace — the visible milestone; everything below
         is easier to judge once the guest is a real userland
         → #24 guest RPC (exec/files) → #7 broker streaming → #26 egress policy
         → #25 template pipeline → #27 control-plane API → #28 MCP gateway
         → #4 config layer → #17, #9, #11, #13, #14, #15, #18, #16
Done     #33 pin a current guest kernel (6.18.54, digest-checked): CI fetches it per
         run instead of using the runner's 4.14; VMGenID reseed verified on restore
Deferred #30 ARM milestone: guest-local vsock (CONFIG_VSOCKETS_LOOPBACK is off in
         Firecracker's CI kernel) and re-running the timer reproduction on the 6.18
         pin. The timer half is upstream (firecracker#6313).

The order is set by *rework*, not by phase: the wire protocol (#12 → #24 → #27), the
privileged runtime (#31 → #9 → #11), the broker body path (#7 → #26), and the guest
image (#32 → #33 → #24 → #25 → #14 → #15) each form a chain where doing the later item first
means rewriting it. The Project's Sequence field and Discussion #29 carry the same
order.
```

> **Note on the order.** The privileged host came online on Day 3, and it changed what "done"
> means: the labs job now executes the root/KVM tests and fails if they skip, so an item can be
> *observed* rather than merely written. Items are only marked done here after a green run that
> shows them executing (C11 is the counter-example that made this rule).
