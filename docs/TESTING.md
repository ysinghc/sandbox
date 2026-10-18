# Testing

## Running the suite

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Most end-to-end tests need **root, `/dev/kvm`, Firecracker, and guest assets**,
so run `ctest` as root on a prepared host. `sudo -E` preserves the environment
(the tests re-exec themselves under `sudo` where needed).

The template fixture (`tmpl_setup`) builds the `e2e` template once per build
directory under `/tmp/sbtest-<builddir>/`. Tests that need it declare
`FIXTURES_REQUIRED tmplfix`.

## What each test covers

| Test | Root? | Needs KVM/assets? | Covers |
| --- | --- | --- | --- |
| `pool` | yes (fixture) | yes | Warm pool concurrency/invariants; real restores. Run under TSan via `build-tsan`. |
| `jailer` | no* | no | seccomp enforcement (always); full chroot+uid-drop sequence (*SKIPs where unprivileged user namespaces are restricted, e.g. Ubuntu 24.04 AppArmor). |
| `network` / `network_cleanup` | yes | no | Per-VM tap + nftables rules; leaks are cleaned by fixture teardown. |
| `snapshot` | no | no | Manifest build/read, `header_size` guard, SHA-256 integrity. |
| `tmpl_setup` | yes | yes | Builds the `e2e` template (fixture setup). |
| `vmm` | yes | yes | Restore, env inject, readiness/confirm, cgroup placement. |
| `uffd` | no | no | Lazy-restore page-fault handling (SKIPs if userfaultfd denied). |
| `broker` | no | no | Request pipeline against an in-process mock engine + upstream. |
| `ipc` | yes | yes | Daemon IPC, async `Create`, client API, broker-control. |
| `config` | no | no | Config parser against the packaged `engine.conf`. |
| `cgroup` | yes | no | cgroup v2 hierarchy + limits (SKIPs if not writable). |
| `metrics` | no | no | `/health`, `/ready`, `/metrics`. |
| `cpp_wrap` | no | no | C++ wrapper linkage against the C API. |

## CI

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs four jobs on
hosted runners (no KVM/assets/root), excluding the privileged set via
`CI_TEST_EXCLUDE="pool|network|tmpl_setup|vmm|ipc|cgroup"`:

1. **spdx** — `scripts/check-spdx.sh`: every source file carries a licence tag.
2. **build-and-test** — Release build + the unprivileged tests.
3. **asan-ubsan** — Debug build with `-DSANDBOX_SANITIZE=address,undefined`.
4. **fuzz-smoke** — clang + libFuzzer build of `fuzz_http`/`fuzz_config`/
   `fuzz_proto` plus a short smoke run over the corpora.

The privileged/end-to-end coverage lives in
[`.github/workflows/privileged-e2e.yml`](../.github/workflows/privileged-e2e.yml)
and needs self-hosted runners (see below).

## Privileged runners

`tests/e2e/` drives the real restore path and is **not runnable on hosted
runners**. [`privileged-e2e.yml`](../.github/workflows/privileged-e2e.yml) is
inert until a repository variable turns it on:

```sh
gh variable set PRIVILEGED_RUNNERS --body true
```

Until then every job is skipped rather than queued, so pull requests are never
blocked. Register two self-hosted runners and label them `sandbox-x86` (x86_64)
and `sandbox-arm64` (aarch64). Each host needs:

- `/dev/kvm` and `/dev/net/tun`, and `nftables` on the host;
- Firecracker at `${FIRECRACKER_BIN:-/usr/local/bin/firecracker}`;
- guest assets at `${SANDBOX_KERNEL:-/opt/sandbox-assets/vmlinux}` and
  `${SANDBOX_ROOTFS:-/opt/sandbox-assets/rootfs.ext4}`;
- a build toolchain plus `libprotobuf-dev`, `libseccomp-dev`,
  `libcurl4-openssl-dev`, `libnftables-dev`, `libsystemd-dev`;
- a dev-capable (not `nodev`) working filesystem under `/var/tmp` or `$HOME` —
  `scripts/benchmark.sh` selects one automatically.

Run the same checks by hand with:

```sh
sudo tests/e2e/smoke.sh          # one warm + one cold restore; checks the timing log
sudo tests/e2e/latency.sh        # warm <5 ms, cold <250 ms (override with flags)
```

## Sanitizers and fuzzers

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DSANDBOX_SANITIZE=address,undefined
cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure

cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DSANDBOX_TSAN=ON
cmake --build build-tsan -j --target test_pool

cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug \
      -DSANDBOX_BUILD_FUZZERS=ON -DSANDBOX_SANITIZE=address,undefined
cmake --build build-fuzz -j --target fuzz_http fuzz_config fuzz_proto
```

## Cleaning between runs

If a run is interrupted, clear leaked state before retrying:

```sh
sudo pkill -9 -x firecracker
sudo umount -l /tmp/sbtest-* 2>/dev/null
sudo rm -rf /tmp/sbtest-* build/Testing
sudo rmdir /sys/fs/cgroup/sandboxd/active/* 2>/dev/null
```

## Known host limitations

- On hosts where the aarch64 arch timer does not re-arm across snapshot
  restore, a guest `sleep` blocks in WFI; the test heartbeat busy-spins instead.
- On Ubuntu 24.04, `kernel.apparmor_restrict_unprivileged_userns=1` makes the
  unprivileged `jailer` sequence unable to `chroot`; it SKIPs and the root path
  provides coverage.
