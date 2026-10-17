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

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs three jobs on
hosted runners (no KVM/assets/root), excluding the privileged set via
`CI_TEST_EXCLUDE="pool|network|tmpl_setup|vmm|ipc|cgroup"`:

1. **build-and-test** — Release build + the unprivileged tests.
2. **asan-ubsan** — Debug build with `-DSANDBOX_SANITIZE=address,undefined`.
3. **fuzz-smoke** — clang + libFuzzer build of `fuzz_http`/`fuzz_config`/
   `fuzz_proto` plus a short smoke run over the corpora.

The privileged/end-to-end coverage runs on a prepared lab host (see
[`BUILDING.md`](BUILDING.md)).

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
