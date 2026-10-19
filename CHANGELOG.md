# Changelog

All notable changes to Sandbox Engine are documented here. This project follows
a phase-based development log; the per-phase implementation record (including
design deviations) lives in [`docs/IMPLEMENTATION_LOG.md`](docs/IMPLEMENTATION_LOG.md)
and §15 of [`SYSTEM DESIGN.md`](SYSTEM%20DESIGN.md).

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
