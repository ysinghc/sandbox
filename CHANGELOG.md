# Changelog

All notable changes to Sandbox Engine are documented here. This project follows
a phase-based development log; the per-phase implementation record (including
design deviations) lives in [`docs/IMPLEMENTATION_LOG.md`](docs/IMPLEMENTATION_LOG.md)
and §15 of [`SYSTEM DESIGN.md`](SYSTEM%20DESIGN.md).

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

[0.12.0]: https://github.com/ysinghc/sandbox/releases/tag/v0.12.0
