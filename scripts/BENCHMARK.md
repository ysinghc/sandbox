# Benchmarking Sandbox Engine

`scripts/bench.sh` measures the engine on a real KVM host: it stamps a real
production template, starts a private `sandboxd`, and drives **live Firecracker
microVMs** through their full lifecycle. Results are printed as a report with an
SLA pass/fail summary and can be saved as JSON.

This is not a unit test. Every measurement comes from an actual
snapshot-restore → run → destroy cycle.

## Requirements

- Run as **root** (the jailer needs chroot + setuid, and the daemon socket is
  root-only).
- A KVM host with `/dev/kvm`, `/dev/net/tun`, and cgroup v2.
- Firecracker + kernel/rootfs assets already installed (see `docs/BUILDING.md`).
- A built tree with `sandboxd`, `sandbox-cli`, `bench_client`, and
  `tests/make_template`:

  ```sh
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
  cmake --build build -j
  ```

The script uses `${REPO}/build` by default; override with `BENCH_BUILD_DIR`.

## Quick start

```sh
# Fast smoke test (5 iterations, 2 sessions, 128 MiB guests)
sudo scripts/bench.sh --quick

# Realistic default run (20 iterations, 4 concurrent sessions, 256 MiB guests)
sudo scripts/bench.sh

# Heavier run with a saved report
sudo scripts/bench.sh --iterations 50 --concurrency 8 --output bench.json
```

## What it does

1. **Preflight** — verifies root, KVM, TUN, userfaultfd, firecracker, assets,
   and binaries.
2. **Isolation** — stops the system `sandboxd` for the duration (so it cannot
   busy-spin CPU and skew latency), then starts a private instance in
   `/tmp/sandbox-bench-<timestamp>` with its own socket, snapshot root, jail
   root, and metrics port. The system service is restarted on exit.
3. **Template** — builds the real `e2e` template with `tests/make_template`
   (cold boot → snapshot) and verifies its integrity, timing the whole step.
4. **Warm pool** — waits until the daemon reports `/ready` (≥1 warm VM) and
   records the pool fill time.
5. **Sequential bench** — one session, N create/destroy cycles plus pause/resume,
   reporting min/avg/p50/p90/p99/max.
6. **Concurrent bench** — C sessions (C forked worker processes, one session
   each), reporting per-op latency and aggregate throughput.
7. **Engine stats** — scrapes `/metrics` before/after for server-side restore
   latency, userfaultfd faults served, and VMM crashes.
8. **Report + SLA** — human summary and pass/fail against targets.
9. **Cleanup** — kills the daemon and any stray firecracker, detaches mounts,
   removes the workspace (kept on failure or with `--keep`), restarts the
   system service.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--iterations N` | 20 | measured create/destroy cycles per worker |
| `--warmup N` | 3 | unmeasured warm-up cycles per worker |
| `--concurrency N` | 4 | concurrent sessions (forked worker processes) |
| `--pause-cycles N` | 20 | pause/resume cycles timed on the first sandbox |
| `--memory MiB` | 256 | guest memory |
| `--vcpus N` | 1 | guest vCPUs |
| `--template NAME` | e2e | snapshot template |
| `--pool-size N` | concurrency+2 (min 5) | daemon warm-pool target |
| `--output FILE` | — | write a merged JSON report |
| `--workdir DIR` | /tmp/... | workspace (reuse it to skip the template build) |
| `--keep` | off | keep the workspace after the run |
| `--no-systemctl` | off | do not touch the system `sandboxd` service |
| `--quick` | off | fast smoke run |
| `-h, --help` | | help |

## Interpreting the output

- **Sequential create p50** is the steady-state cost of handing a client a warm
  VM (snapshot restore + UFFD faults on first touch). Lower is better.
- **Concurrent throughput** is creates/second across all sessions, bounded by
  pool size and `create_workers`. `failed` counts creates that timed out waiting
  for a warm VM — raise `--pool-size` or `--concurrency` headroom if nonzero.
- **Server-side provision latency** comes from the engine's own histogram, so it
  isolates the engine's restore cost from client/IPC overhead.
- **uffd faults served** shows how much lazy paging the guests actually triggered.

Default SLA targets (edit `report()` to change): create p50 < 100 ms, create p99
< 200 ms, concurrent throughput > 5 creates/s, concurrent create p99 < 500 ms.

## Troubleshooting

- **"must run as root"** — rerun with `sudo`.
- **Template build fails** — check the firecracker/kernel/rootfs paths and
  `/opt/sandbox-assets`; see the tail shown on failure.
- **Creates fail (`failed` > 0)** — the warm pool was too small for the
  concurrency; increase `--pool-size`.
- **Daemon log** — kept at `<workdir>/results/daemon.log`; the workspace is
  retained automatically when a run reports issues.
