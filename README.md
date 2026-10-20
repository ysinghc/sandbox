# Sandbox Engine

**Fast, isolated microVM sandboxes for untrusted code — pooled, snapped, and
ready in milliseconds.**

Sandbox Engine is a daemon plus client libraries that hand out short-lived
Firecracker microVMs on demand. Instead of booting a VM per request, it keeps a
pool of pre-booted VMs restored from memory snapshots, so a caller can go from
"create" to "running guest" in a fraction of a second. Each VM is jailed
(chroot + seccomp + uid drop), capped with its own cgroup, and optionally given
the network it needs through a credential broker that injects secrets on the
host so guests never hold them.

It is built for a single trusted operator running untrusted workloads on one
host (a lab box, a CI runner, an appliance). It is **not** a multi-tenant
isolation boundary.

---

## Table of contents

- [Why](#why)
- [Architecture at a glance](#architecture-at-a-glance)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Using the API](#using-the-api)
- [Command-line tools](#command-line-tools)
- [Configuration](#configuration)
- [Documentation map](#documentation-map)
- [Project status](#project-status)
- [License](#license)

---

## Why

Provisioning a VM per request is slow: boot, agent handshake, and first-request
latency dominate. Sandbox Engine front-loads that work:

- **Snapshot & restore** — templates are captured once (booted Firecracker +
  guest memory snapshot) and restored into fresh VMs.
- **Warm pool** — a bounded pool of restored VMs is kept ready, so `Create`
  usually takes a page-fault-backed resume, not a boot.
- **Userfaultfd demand paging** — memory is restored lazily; only the pages the
  guest actually touches are loaded.
- **Jailing** — every Firecracker process runs chrooted, as an unprivileged uid,
  under a seccomp allowlist, with `no_new_privs`.
- **Per-VM cgroups** — memory/CPU limits are enforced per VM, so one runaway
  guest cannot take down the host or the daemon.
- **Credential broker** — guests talk to an allow-listed upstream through a host
  broker that validates a per-session token and injects real credentials;
  secrets never cross into the guest.

## Architecture at a glance

```
            +-------------------------------------------------------------+
 client     |  sandbox-cli          C lib (libsandbox)   C++ (libsandbox++) |
            +-----------------------------+-------------------------------+
                                          | protobuf over AF_UNIX
                                          v
            +-------------------------------------------------------------+
 daemon     |  sandboxd                                                    |
            |   - IPC server (async Create worker pool, per-session FIFO)  |
            |   - pool manager (warm VMs, bounded depth)                   |
            |   - vmm manager   (restore, env inject, cgroup placement)    |
            |   - jailer        (chroot + seccomp + uid drop)              |
            |   - uffd handler  (demand paging from the snapshot)          |
            |   - vsock + telemetry (/health /ready /metrics)             |
            +------+--------------------------+---------------------------+
                   | restore/jail             | validate tokens
                   v                          v
            +----------------+        +-----------------------------+
 VMs        | Firecracker xN |        | sandbox-broker              |
            |  jailed, cgroup|  https |  allow-list + cred inject   |
            |  no_new_privs  |<------>|  upstream (e.g. api.openai) |
            +----------------+        +-----------------------------+
```

Trust boundaries and the full component/behavior model live in
[`SYSTEM DESIGN.md`](SYSTEM%20DESIGN.md) and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Requirements

- **Linux, x86_64 or aarch64** with **KVM** (`/dev/kvm`) and
  **userfaultfd** (`/dev/userfaultfd` or `vm.unprivileged_userfaultfd=1`).
  Verified on Ubuntu 24.04 (aarch64, Raspberry Pi 5).
- **Root** for the daemon (it creates taps, device nodes, cgroups, and jails).
- Build dependencies:
  - a C11/C++17 toolchain (`gcc`/`clang`), `cmake >= 3.20`
  - `libprotobuf-dev`, `protobuf-compiler`, `libprotoc-dev`
  - `libseccomp-dev`
  - `libcurl4-openssl-dev`
  - `libnftables-dev` (optional; falls back to the `nft` binary if absent)
  - `libsystemd-dev` (optional; enables sd_notify watchdog support)
- Runtime assets:
  - a `firecracker` binary (`FIRECRACKER_BIN`, default `/usr/local/bin/firecracker`)
  - a guest kernel and rootfs, or the prebuilt assets used by the test rig
    (`/opt/sandbox-assets/vmlinux`, `/opt/sandbox-assets/rootfs.ext4`)

See [`docs/BUILDING.md`](docs/BUILDING.md) for exact commands and
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for host preparation.

## Quick start

```sh
# 1. Build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# 2. Install (defaults to /usr/local, /var/lib/sandbox-engine, /etc/sandbox-engine)
sudo cmake --install build

# 3. Stamp a template once (needs root + /dev/kvm + assets), then verify it
sudo -E env SANDBOX_SNAPSHOT_ROOT=/var/lib/sandbox-engine/snapshots \
  build/tests/make_template
sudo sandbox-cli verify --template e2e

# 4. Start the daemon and the broker
sudo systemctl enable --now sandboxd
sudo sandbox-broker &

# 5. Create a sandbox (the CLI holds the session open until Ctrl-C)
sudo sandbox-cli run --template e2e --memory 512 --vcpus 1
# {"event":"created","sandbox_id":1,"running":true,"memory_rss_mib":57}
```

A one-shot script that builds, installs, and runs the whole test suite on a
prepared host is [`scripts/build-and-test.sh`](scripts/build-and-test.sh).

## Using the API

**C** — link `-lsandbox` and include `<libsandbox.h>`:

```c
#include <libsandbox.h>

sandbox_init("/var/run/sandbox-engine/engine.sock");

const char* env[] = {"GREETING=hi", NULL};
sandbox_spec_t spec = {
    .memory_mib = 512, .vcpu_count = 1,
    .template_name = "python-agent",
    .env_vars = env, .pool_wait_ms = 500,
};

sandbox_handle_t* h = NULL;
if (sandbox_create(&spec, &h) == SANDBOX_OK) {
    sandbox_status_t st;
    sandbox_inspect(h, &st);
    /* ... use the sandbox ... */
    sandbox_destroy(h);
}
sandbox_cleanup();
```

**C++** — link `-lsandbox++` and include `<libsandbox.hpp>`:

```cpp
#include <libsandbox.hpp>

sandbox::Engine engine;                       // default engine socket
auto sb = engine.create(
    sandbox::Spec(512, "python-agent").vcpus(1).env("GREETING", "hi"));
sb->pause();
sb->resume();
uint32_t id = sb->id();
```

Full API, wire protocol, and broker behavior: [`docs/API.md`](docs/API.md).

## Command-line tools

| Tool | Purpose |
| --- | --- |
| `sandboxd` | The daemon. `--config FILE`, `--socket PATH`, `--validate-config`, `--version`. |
| `sandbox-cli` | `run --template NAME [--socket PATH] [--memory MiB] [--vcpus N] [--wait MS]`; `verify --template NAME`. |
| `sandbox-broker` | Credential-injecting HTTPS proxy for guests (separate process/uid). |

## Configuration

`sandboxd` reads a flat `key = value` file (`[section]` headers are cosmetic).
Precedence is **CLI flags > environment (`SANDBOX_*`) > config file > defaults**.
The packaged file is [`config/engine.conf`](config/engine.conf); the daemon's
default path is `/var/lib/sandbox-engine/config/engine.conf` (override with
`--config`).

Every key, its environment-variable equivalent, default, and meaning is
documented in [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

## Documentation map

| Document | Contents |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Components, data flow, trust boundaries. |
| [`docs/BUILDING.md`](docs/BUILDING.md) | Dependencies, build options, sanitizers, fuzzers. |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | All config keys and environment variables. |
| [`docs/API.md`](docs/API.md) | C/C++ API, CLI, wire protocol, broker HTTP. |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Host prep, install layout, systemd, hardening. |
| [`docs/TESTING.md`](docs/TESTING.md) | Test suite, what runs where, CI layout. |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Day-2 operations, health checks, metrics. |
| [`docs/UPGRADE.md`](docs/UPGRADE.md) | Version upgrades and on-disk format changes. |
| [`docs/BACKUP.md`](docs/BACKUP.md) | What to back up and how to restore. |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Common failures and fixes. |
| [`SYSTEM DESIGN.md`](SYSTEM%20DESIGN.md) | Authoritative design and ground-truth deviations (§15). |
| [`docs/IMPLEMENTATION_LOG.md`](docs/IMPLEMENTATION_LOG.md) | Phase-by-phase implementation record. |
| [`CHANGELOG.md`](CHANGELOG.md) | Release notes. |

## Project status

Current release: **0.14.0**. The engine, jailer, uffd path, snapshot manager,
broker, pool, cgroups, snapshot integrity, structured logging, metrics, and CLI
are implemented and covered by the test suite (see `docs/TESTING.md`). The
privileged tests (jailer, seccomp, real VM restore, vsock IPC, cgroup, nftables)
now run in CI on a self-hosted KVM host rather than being skipped, and the job
fails if any of them skips. Items still open — hierarchical config, aarch64
arch-timer restore, workspace/TTL, and the V2 hardening backlog (privilege
separation, per-tenant quotas) — are tracked in
[`docs/IMPLEMENTATION_LOG.md`](docs/IMPLEMENTATION_LOG.md), the issue tracker,
and §12.2/§13 of the design. Deviations from the original design are recorded in
§15 of [`SYSTEM DESIGN.md`](SYSTEM%20DESIGN.md).

## License

This project is licensed under the **GNU General Public License, version 2**
(SPDX: `GPL-2.0-only`). See [`LICENSE`](LICENSE) for the full text.

Copyright (C) 2026 the Sandbox Engine contributors.
