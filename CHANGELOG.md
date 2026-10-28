# Changelog

All notable changes to Sandbox Engine are documented here. This project follows
a phase-based development log; the per-phase implementation record (including
design deviations) lives in [`docs/IMPLEMENTATION_LOG.md`](docs/IMPLEMENTATION_LOG.md)
and §15 of [`SYSTEM DESIGN.md`](SYSTEM%20DESIGN.md).

## [Unreleased]

### Template pipeline (#25)

- **Spec-driven builds.** `scripts/build-template.sh templates/<name>` goes from a
  checked-in `template.conf` (suite, packages, optional pinned archive snapshot,
  optional provision script, VM shape) to a published template. `--check` validates
  a spec without root.
- **Content-addressed, immutable store.** Templates live at `.store/<digest>/`; the
  name the daemon opens is a symlink repointed atomically. Digests cover memory,
  vmstate, rootfs, workspace base and kernel. Identical content is stored once.
- **`sandbox-cli template build|publish|list|verify|rollback|unpublish|gc`.** GC keeps
  what a name points at plus its previous version, honours a grace period, reports every
  decision, and does nothing without `--apply`.
- **Reproducible guest image.** Fixed filesystem identity and timestamps; CI builds the
  image twice and compares bytes. The captured snapshot itself is not bit-reproducible.
- `manifest.version` is now derived from the content digest instead of counted, so a
  rollback is noticed by the daemon. The template VM's id is now derived from a hash of
  the name: a name of more than seven characters used to overflow the 15-character tap
  device name and build a template with no NIC, and `.`/`_` made an id Firecracker refuses.
- `docs/TEMPLATES.md`: the three ways to get a library (already in the image, into
  `/workspace`, extend the template).

## [0.14.0] — 2026-10-20

Session workspaces (#23): a sandbox's `/workspace` can now outlive the VM that
wrote it, under a strict, creator-controlled TTL. This is the first release in
which "the assistant remembers things between calls" is a property of the engine
rather than of the model's context window.

### Added

- **Session volumes** (#23): `sandbox_spec_t.session_key` gives a sandbox a
  persistent `/workspace`; `ttl_seconds` sets its lifetime. Volumes are a
  pre-formatted sparse ext4 image built with the template and cloned per session
  (reflink where the filesystem supports it, sparse extent copy otherwise), keyed
  by `sha256(session_key)` in `SANDBOX_WORKSPACE_ROOT`, created in a staging
  directory and `rename()`d into place. A session is exclusive-use: a lease
  prevents two VMs writing one image, and a `session_key` create bypasses the warm
  pool because Firecracker cannot swap a block device after restore.
- **TTL policy (D5)**: `expires_at = created_at + clamp(ttl, 60 s, platform max)`,
  default 7 days, maximum 30 days (`SANDBOX_WORKSPACE_MAX_TTL`). Absolute from
  creation, never extended automatically. A reaper thread expires sessions on a
  timer (`SANDBOX_REAP_INTERVAL_SECONDS`, default 60 s) and also collects
  abandoned staging directories.
- **Renewal**: `sandbox_session_renew(key, extra_seconds, &expires_at)` and
  `sandbox-cli renew --session-key KEY [--extra SECONDS]`, plus
  `sandbox::renew_session()` in the C++ SDK. Keyed by session, not by sandbox, so
  a quiet conversation can be kept alive with nothing running. `extra_seconds` is
  added to *now*, clamped to the platform maximum, never shortened; a past
  deadline returns `SANDBOX_ERR_SESSION_EXPIRED` (the volume is already gone), an
  unknown key `SANDBOX_ERR_SESSION_UNKNOWN`, and a session already at the maximum
  `SANDBOX_ERR_SESSION_LIMIT`.
- **Durable teardown**: the engine asks the guest to `sync()` before it SIGKILLs
  the VMM (reserved `SANDBOX_CONTROL=flush` on the vsock control channel,
  acknowledged with `SANDBOX-FLUSH-OK`, bounded by `SANDBOX_FLUSH_MS`). Without
  it, a page written by the workload was still in the guest's page cache when the
  VM died, and the next sandbox of the same session simply did not see the file.
- **In-guest persistence evidence**: the guest agent appends a checksum of each
  injection to `/workspace/.sandbox-probe` and reports `mounted=`, `lines=`,
  `first=` and `last=` on the serial console, so the privileged e2e test proves
  persistence from inside the guest instead of reading back a file the host wrote.
- **Workspace metrics** and `docs/WORKSPACE_DISK.md` (including the deviations
  from the original D7 design and why they were made).

### Fixed

- **ext4 corruption after restore** (`f1a2ba7`): the guest mounted `/workspace`
  before the template snapshot was captured, so every restore resumed a *mounted*
  ext4 whose backing file had been replaced — the guest then reported
  `EXT4-fs error (device vdb): checksumming directory block 0`. The volume is now
  mounted by the agent on first use *after* each restore, which also makes
  "a clone is byte-identical to its base" true by construction and lets ext4
  replay the journal of a sandbox killed mid-write.
- **Leaked jail bind mount** (`976299b`): `jail_cleanup()` never unmounted
  `/workspace.ext4`, so removing the jail hit `EBUSY`, the jail survived, and
  later creates failed at `[jailer] step 6 failed: errno=2`. Unmount added, and
  bind failures now name the source, the destination and whether the source
  exists.
- **Latency probe segfault**: the generated probe in `scripts/benchmark.sh` built
  its `sandbox_spec_t` on the stack without initialising it; the new pointer field
  turned that into a wild dereference. Zero-initialised, and the contract is now
  stated in `docs/API.md`.
- **Network test flake**: the broker port was hard-coded to 8080 (a genuinely busy
  port) and the drop verdict failed if *any* frame arrived, including a
  retransmission from the previous connection. The port is now chosen per run and
  the verdict is keyed to the connection under test.
- **Test isolation**: the privileged suite now clears its test root before a run.
  Re-runs on the same runner were inheriting the previous run's session volumes
  (durable by design), which surfaced as a "new volume starts empty" failure.

### Changed

- **`SANDBOX_BROKER_PORT`** (default `8080`) is the single source of truth for the
  port guests may reach on the host: the egress rules and the broker listener both
  derive from it, so moving the broker off a busy port is now one variable instead
  of two values that silently disagree.
- **`sandbox_spec_t` grew two fields.** Callers must zero-initialise it
  (`sandbox_spec_t spec = {0};`); an uninitialised `session_key` is a crash, not a
  default. All in-tree callers already did.

### Verified

- Privileged e2e (self-hosted, KVM): all 7 suites pass, including the session
  persistence test (create → write in guest → destroy → re-create → the file is
  still there, with the *pre-destroy* line first) and `tests/e2e/smoke.sh`.
- Restore latency on the reference host: **38.49 ms** cold (provisioned),
  **55.76 ms** average over five provisioned restores, budget 250 ms.

## [0.13.0] — 2026-10-20

Security and verification release: the privileged suite now *runs* in CI instead
of skipping, the vsock control channel is authenticated, and the release pipeline
builds both architectures natively from one tag.

### Added

- **Privileged e2e in CI** (#20): `privileged-e2e.yml` dispatches per-arch jobs
  to self-hosted runners over a shared reusable body; `tests/e2e/smoke.sh` and
  `tests/e2e/latency.sh` assert the restore path end to end with budgets of
  **5 ms warm / 250 ms provisioned**. Fork PRs are refused (the runner executes
  code as root). Observed on the reference host: 0.18 ms warm, 45 ms provisioned.
- **vsock peer authentication** (#10): the guest agent accepts a control
  connection only when the peer's vsock CID is `VMADDR_CID_HOST`, and logs
  `SANDBOX-VSOCK-REJECT cid=<n>` otherwise. The classifier (`src/vsock_peer.c`)
  is freestanding and shared by the agent and a host test.
- **Release pipeline for both architectures** (`d98d31f`): `v*` tags build
  natively on `ubuntu-24.04` and `ubuntu-24.04-arm` from the same revision and
  publish, per arch: the staged install tree, a bare-binary archive, the
  individual binaries and libraries, and SHA-256 checksums.
- **`scripts/install.sh`** (#19): detects the architecture, downloads the right
  asset, verifies its checksum, and installs it; `--dry-run` prints the plan.
- **Regression tests**: seccomp allow-list (`tests/test_seccomp.c`, #1),
  chroot `..`/`getcwd` escape (`jailer_probe` exit 12, #2), and
  `credentials.conf` mode/ownership refusal (`tests/test_broker.c`, #3).
- **`docs/THREAT_MODEL.md`** (#21): T1–T20 derived from the code, each with its
  mitigation, location, and status; residual risk ranked.
- **SPDX enforcement** (#8): `GPL-2.0-only` identifiers on every source file,
  checked by `scripts/check-spdx.sh` in CI.
- **Deterministic restore** (#22): `/snapshot/load` now carries
  `clock_realtime` (x86_64), so a restored guest starts at host time instead of
  the template's capture time; the template manifest also binds `rootfs.ext4`
  by SHA-256, so the disk image cannot drift away from the captured memory
  state. Both are asserted (`vmm` for the request, `ipc` for the guest clock,
  `snapshot` for the image digest).
- **Project site** with downloads and a contribution guide.

### Changed

- **Restore latency**: the snapshot manifest digest is verified once and cached
  (`e5a5cc7`), poll intervals were tightened, and the restore path logs per-step
  timings (`[vmm_restore] time total=`).
- **Seccomp**: added `poll()` and the remaining x86_64-only syscalls the aarch64
  policy never exercised, found by running Firecracker under the filter.
- **Benchmarking**: one real-VM harness (`scripts/benchmark.sh`) replaced the
  previous suite; it works on `nodev` filesystems.

### Fixed

- **Security**: removed `system()` shell-outs on caller-influenced paths
  (jail cleanup and friends), closing a command-injection class of bug.
- **CI was green while testing nothing**: the privileged tests were invoked via
  `sudo -E`, which drops the environment, so the fixture roots never arrived and
  `tmpl_setup` plus every test depending on it skipped with exit 0. The suite now
  runs as root and the job **fails if any privileged test skips**.
- **Security**: the jailer's seccomp default action was selected with
  `#ifdef NDEBUG`, so a Debug build (or any target compiled with `-UNDEBUG`)
  silently installed the *permissive* filter — forbidden syscalls returned
  `EPERM` instead of killing the process. The default is now always
  `SCMP_ACT_KILL_PROCESS`; tests that need to observe the denial opt in with
  `SANDBOX_SECCOMP_ACTION=errno`.
- **Tests were not asserting in Release builds**: CMake defines `NDEBUG`, which
  compiles `assert()` out, so 34 assertions in `test_snapshot` never ran. Test
  binaries now build with `-UNDEBUG`; the rootfs-digest checks above are covered
  as a direct result.
- Benchmark: the template name handed to the daemon now matches the one built,
  and the daemon log is dumped when the warm pool fails to fill.

### Docs

- `docs/IMPLEMENTATION_PLAN.md` is ground-truthed against the code, with the
  deviations (C1–C12) recorded rather than quietly dropped, including the two
  that mattered here: a per-session token cannot authenticate host→guest across
  a snapshot (C12), and "passed" must not be allowed to mean "ran" (C11).

## [0.12.0] — 2026-10-17

First packaged release. Everything below is part of the initial public version.

### Added

- **Engine core**: environment setters in the pool; `sandbox_inspect` surface
  (`uptime_ms`, `memory_rss_mib`, `page_faults`).
- **Credential broker**: token validation with the engine, upstream
  allow-listing, credential injection, HTTPS proxying, broker metrics
  (`src/broker/`).
- **Daemon & lifecycle**: client IPC with protobuf framing, warm-pool
  integration, pidfd crash detection, engine-side broker-control socket.
- **Packaging**: `cmake --install` layout, systemd unit, runtime/state/config
  directories.
- **Security hardening**: `no_new_privs`, tightened systemd capability bounding
  set, peer-uid allow-list (`SO_PEERCRED`).
- **Config**: dedicated parser (`src/daemon/config.c`) with a documented file,
  `SANDBOX_*` environment overrides, and `--validate-config`.
- **Reliability**: asynchronous `Create` worker pool with per-session FIFO
  dispatch and per-session/uid caps; guest-readiness detection and env-delivery
  confirmation; per-VM cgroup v2 limits; snapshot integrity via a self-contained
  SHA-256 and a manifest `header_size` guard; `sandbox-cli verify`.
- **Observability**: structured JSON logging; `/health`, `/ready`, `/metrics`.
- **Tooling**: sanitizer build option, libFuzzer harnesses (`fuzz/`), CI
  workflow.
- **Docs**: README, build/config/API/deployment/testing/troubleshooting guides,
  runbook, upgrade and backup guides.
- **License**: GNU General Public License v2 (`GPL-2.0-only`).

### Fixed

- **C API linkage**: `libsandbox.h` now wraps declarations in `extern "C"`, so
  the C++ wrapper resolves the unmangled symbols. Previously the wrapper
  referenced C++-mangled names that the C library does not export.
- **CI**: cmake flag continuations in the workflow no longer get mangled (which
  had silently disabled the fuzzers and sanitizers); the static `jailer_probe`
  is built unsanitized in sanitizer builds; the `jailer` sequence SKIPs when
  unprivileged user namespaces are restricted.

### Known limitations

Tracked as issues and in the design's §12.2/§13. Highlights: seccomp filter not
yet audited against a real Firecracker syscall trace; no hierarchical config
layer; `credentials.conf` mode not enforced at load; privilege separation, vsock
payload authentication, per-tenant quotas, and IPC request-ids deferred to V2.

[0.13.0]: https://github.com/ysinghc/sandbox/releases/tag/v0.13.0
[0.12.0]: https://github.com/ysinghc/sandbox/releases/tag/v0.12.0
