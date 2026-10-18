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
gh variable set PRIVILEGED_RUNNERS --body true   # master switch
gh variable set PRIVILEGED_ARM     --body true   # ONLY once an ARM runner exists
```

Until then every job is skipped rather than queued, so pull requests are never
blocked. The aarch64 leg is gated separately on purpose: with no runner serving
`sandbox-arm64`, that job does not fail — it queues for ~24 h and is then
cancelled, which is indistinguishable from a broken workflow.

The two legs share [`privileged-e2e-run.yml`](../.github/workflows/privileged-e2e-run.yml)
and are separate jobs rather than matrix rows, because `matrix` is **not** an
available context in `jobs.<job_id>.if` (only `github`, `needs`, `vars`,
`inputs`) — referencing it there invalidates the entire workflow file.

> **Security.** A self-hosted runner executes workflow code as **root** on the
> operator's machine. `privileged-e2e.yml` therefore refuses pull requests from
> forks (`github.event.pull_request.head.repo.full_name == github.repository`)
> and only ever runs the owner's own branches. Do not remove that guard: a
> privileged runner plus an untrusted PR is a root compromise.

### Registering a runner

The harness needs **root** (`chroot`, `setuid`, cgroup writes, `mknod` of
`/dev/kvm`), and `sudo` normally prompts for a password — so run the runner
service **as root**. Do not run it as an unprivileged user unless that user has
passwordless `sudo`.

```sh
# 1. Fetch the runner and unpack it. Check the version on
#    https://github.com/actions/runner/releases (v2.338.0 at time of writing);
#    use actions-runner-linux-arm64-... on aarch64.
sudo mkdir -p /opt/actions-runner && cd /opt/actions-runner
curl -fsSL --retry 3 -o runner.tar.gz \
  https://github.com/actions/runner/releases/download/v2.338.0/actions-runner-linux-x64-2.338.0.tar.gz
sudo tar xzf runner.tar.gz -C /opt/actions-runner

# 2. Registration token (valid ~1 hour), then configure. `--labels` is
#    ADDITIVE: the runner also keeps self-hosted, linux and x64.
TOKEN=$(gh api -X POST repos/ysinghc/sandbox/actions/runners/registration-token --jq .token)
sudo /opt/actions-runner/config.sh \
  --url https://github.com/ysinghc/sandbox --token "$TOKEN" \
  --name "$(hostname)-x86" --labels sandbox-x86 --unattended

# 3. Install and start it as a root systemd service (survives reboots).
cd /opt/actions-runner && sudo ./svc.sh install root && sudo ./svc.sh start

# 4. Verify it is online with the right labels.
gh api repos/ysinghc/sandbox/actions/runners \
  --jq '.runners[] | "\(.name) \(.status) [\(.labels|map(.name)|join(","))]"'

# 5. Flip the switch and trigger the workflow.
gh variable set PRIVILEGED_RUNNERS --body true
gh workflow run "Privileged e2e" --ref master
gh run watch
```

Before wiring up CI, prove the host can do it at all — this is the fastest way
to surface a missing asset or a `nodev` workspace:

```sh
sudo tests/e2e/smoke.sh
sudo tests/e2e/latency.sh
```

Each host needs:

- `/dev/kvm` and `/dev/net/tun`, and `nftables` on the host;
- Firecracker at `${FIRECRACKER_BIN:-/usr/local/bin/firecracker}`;
- guest assets at `${SANDBOX_KERNEL:-/opt/sandbox-assets/vmlinux}` and
  `${SANDBOX_ROOTFS:-/opt/sandbox-assets/rootfs.ext4}`;
- a build toolchain plus `libprotobuf-dev`, `libseccomp-dev`,
  `libcurl4-openssl-dev`, `libnftables-dev`, `libsystemd-dev`;
- a dev-capable (not `nodev`) working filesystem under `/var/tmp` or `$HOME` —
  `scripts/benchmark.sh` selects one automatically;
- that same kind of filesystem for the CMake test root: the VM tests (`pool`,
  `vmm`, `ipc`) build their jail under `${SANDBOX_TEST_TMPDIR:-/tmp}`, so
  configure with `-DSANDBOX_TEST_TMPDIR=/var/tmp` where `/tmp` is `nodev`.
  `privileged-e2e.yml` already does this.

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
