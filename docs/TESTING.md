# Testing

## Running the suite

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Most end-to-end tests need **root, `/dev/kvm`, Firecracker, and guest assets**,
so run the whole suite **as root** on a prepared host — not via `sudo`, and not
via `sudo -E`:

```sh
sudo ctest --test-dir build -V   # or: run ctest as root directly
```

`sudo` resets the environment, and ctest supplies each test's roots through its
`ENVIRONMENT` property, so `sudo -E` still loses them. A test that cannot find
its roots SKIPs with exit 0 (deliberately, so an unprivileged run stays honest),
which is exactly how the privileged CI spent several runs "passing" while
executing nothing. The privileged workflow therefore runs the set with `-V` and
fails if any test reports Skipped/Not Run. Two rules follow:

- **Never let "passed" mean "ran".** Assert execution (duration, a marker in the
  output, a non-skip assertion), not just exit status.
- **A test that only calls `assert()` is not testing in Release.** CMake's
  Release flags define `NDEBUG`, which compiles `assert()` out. `tests/` adds
  `-UNDEBUG` to every test binary for this reason; without it, 34 assertions in
  `test_snapshot` were no-ops and its "PASS" proved nothing.

The template fixture (`tmpl_setup`) builds the `e2e` template once per build
directory under `/tmp/sbtest-<builddir>/`. Tests that need it declare
`FIXTURES_REQUIRED tmplfix`.

## What each test covers

| Test | Root? | Needs KVM/assets? | Covers |
| --- | --- | --- | --- |
| `pool` | yes (fixture) | yes | Warm pool concurrency/invariants; real restores. Run under TSan via `build-tsan`. |
| `jailer` | no* | no | seccomp enforcement (always); full chroot+uid-drop sequence (*SKIPs where unprivileged user namespaces are restricted, e.g. Ubuntu 24.04 AppArmor). |
| `network` / `network_cleanup` | yes | no | Per-VM tap + nftables rules; leaks are cleaned by fixture teardown. |
| `snapshot` | no | no | Manifest build/read, `header_size` guard, SHA-256 integrity of `memory.snap`, `vmstate` **and `rootfs.ext4`**. |
| `tmpl_setup` | yes | yes | Builds the `e2e` template (fixture setup). |
| `vmm` | yes | yes | Restore, env inject, readiness/confirm, cgroup placement; the `/snapshot/load` body (clock/tap/vsock) is asserted even without root. |
| `uffd` | no | no | Lazy-restore page-fault handling (SKIPs if userfaultfd denied). |
| `broker` | no | no | Request pipeline against an in-process mock engine + upstream. #26: proxy mode (absolute-form, 407, CONNECT through a live echo with 300 KiB round trips and half-close), the public-address guard (relay and CONNECT, v4/v6/mapped), a named host is relayed without a credential, `*` is not, wrong port / unlisted / empty policy → 403, decisions exported as metrics. #7: 64 MiB bodies (Content-Length and chunked) hashed end to end with a peak-RSS bound, 413 for oversize (declared and chunked), exact-limit pass, 400 for bad chunk framing. |
| `egress` | no | no | #26 policy module: entry grammar (valid/invalid), host/port/wildcard matching incl. suffix and prefix confusion, the daemon ceiling rule, `egress_resolve` (inherit, deny-all, narrow, refuse). Pure logic. |
| `ipc` | yes | yes | Daemon IPC, async `Create`, client API, broker-control; #24 exec/file ops against a *restored* guest, and a session workspace that carries a command's file from one sandbox to the next. #26: token carries the session's policy; a restored Debian guest is configured with its /30 and proxy env, reaches an allow-listed mock upstream through the real broker (relay and CONNECT), is refused for unlisted hosts / loopback / a forged token, cannot reach the host on any other port, and (with `SANDBOX_E2E_INTERNET=1`, set in CI) fetches the real pypi.org simple index over TLS. |
| `guest_rpc` | no | no | #24 guest server against the host client over socketpairs: exec (streaming, timeout, output cap, process-group kill, cancel on disconnect), file ops, path-escape and malformed-frame cases, concurrency. 91 checks. |
| `ipc_guest` | no | no | #24 through the whole IPC stack (libsandbox → daemon → worker pool → a hybrid-vsock-style UDS → the real guest server); only the VM is faked. Ownership, per-session cap, chunked 4 MiB transfers, reply-frame budgets, error mapping. 40 checks. |
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

**Platform focus (2026-10-20).** Both legs remain enabled: the aarch64 leg is
cheap and catches portability regressions early, which is exactly what it did
for #6. But it is a *signal*, not a gate on the x86_64 feature path — an
ARM-only failure is recorded and deferred to the ARM milestone (#30) instead of
being fixed here, and the x86_64 leg is the one that must be green for a release.
Do not weaken the aarch64 assertions to make the leg pass; that would turn the
signal into noise.

> **Security.** A self-hosted runner executes workflow code as **root** on the
> operator's machine. `privileged-e2e.yml` therefore refuses pull requests from
> forks (`github.event.pull_request.head.repo.full_name == github.repository`)
> and only ever runs the owner's own branches. Do not remove that guard: a
> privileged runner plus an untrusted PR is a root compromise.

### Registering a runner

The harness needs **root** (`chroot`, `setuid`, cgroup writes, `mknod` of
`/dev/kvm`). There are two supportable shapes:

- run the runner **service as root** (the x86_64 runner does this), or
- run it as an unprivileged user with **passwordless `sudo`** (the aarch64
  runner on a Pi 5 does this). The workflow then prefixes the suite with `sudo`.

The second shape has two traps, both seen in practice and both now handled:

1. **`sudo` resets the environment.** `SANDBOX_ROOTFS` / `SANDBOX_KERNEL` are
   what point the harness at the guest image this job just built. Lost, the
   suite runs against the operator's `/opt/sandbox-assets/rootfs.ext4` — older
   guest, current host — and the failures look like architecture bugs (no clock
   line, no workspace probe, no vsock peer line) while every test still "runs".
   The configure-time values are therefore baked into each test's `ENVIRONMENT`
   property as `<NAME>_DEFAULT`, and the job fails unless the fixture reports the
   image and kernel the job built. They are deliberately *not* baked as
   `<NAME>`: ctest applies `ENVIRONMENT` over the inherited environment, so a
   baked `SANDBOX_ROOTFS` would itself silently defeat
   `sudo env SANDBOX_ROOTFS=... ctest` — which is how the Debian suite selects
   its image. That exact mix-up made a whole Debian run boot the busybox fixture
   and pass 4/4 before the image assertion caught it.
2. **Files written under `sudo` belong to root.** The guest image lands in the
   runner's work tree; the *next* checkout cannot delete it (`EACCES`) and dies
   before its first step, poisoning every later run. `build-custom-rootfs.sh`
   chowns its output back to `SUDO_UID`/`SUDO_GID`.

```sh
# 1. Fetch the runner and unpack it. Check the version on
#    https://github.com/actions/runner/releases (v2.338.0 at time of writing);
#    use actions-runner-linux-arm64-... on aarch64.
sudo mkdir -p /opt/actions-runner && cd /opt/actions-runner
sudo curl -fsSL --retry 3 -o runner.tar.gz \
  https://github.com/actions/runner/releases/download/v2.338.0/actions-runner-linux-x64-2.338.0.tar.gz
sudo tar xzf runner.tar.gz -C /opt/actions-runner
sudo chown -R root:root /opt/actions-runner   # the tarball preserves uid 1001

# 2. Registration token (valid ~1 hour), then configure.
#    config.sh refuses to run as root -- `if [ $(id -u) -eq 0 -a -z
#    "$RUNNER_ALLOW_RUNASROOT" ]` -- so opt in explicitly. This flag is only
#    needed for *configure*; run.sh and runsvc.sh have no such guard.
#    `--labels` is ADDITIVE: the runner also keeps self-hosted, linux and x64.
TOKEN=$(gh api -X POST repos/ysinghc/sandbox/actions/runners/registration-token --jq .token)
sudo env RUNNER_ALLOW_RUNASROOT=1 /opt/actions-runner/config.sh \
  --url https://github.com/ysinghc/sandbox --token "$TOKEN" \
  --name sandbox-x86-01 --labels sandbox-x86 --unattended

# 3. svc.sh did not exist before step 2 -- config.sh generates it from
#    bin/systemd.svc.sh.template. Install and start it as a root service
#    (survives reboots). `install <account>` -> run_as_user; omit it and the
#    service runs as $SUDO_USER instead.
cd /opt/actions-runner && sudo ./svc.sh install root && sudo ./svc.sh start
sudo systemctl status 'actions.runner.*.service' --no-pager   # expect active (running)

# 4. Verify it is online with the right labels.
gh api repos/ysinghc/sandbox/actions/runners \
  --jq '.runners[] | "\(.name) \(.status) [\(.labels|map(.name)|join(","))]"'

# 5. Flip the switch and trigger the workflow.
gh variable set PRIVILEGED_RUNNERS --body true
gh workflow run "Privileged e2e" --ref master
gh run watch
```

For the **aarch64 leg** the same steps with the arm64 tarball, label
`sandbox-arm64`, and a non-root account:

```sh
mkdir -p ~/actions-runner && cd ~/actions-runner
curl -fsSL -o runner.tar.gz \
  https://github.com/actions/runner/releases/download/v2.338.0/actions-runner-linux-arm64-2.338.0.tar.gz
tar xzf runner.tar.gz && rm runner.tar.gz
./config.sh --url https://github.com/ysinghc/sandbox --token "$TOKEN" \
  --name sandbox-arm64-pi5 --labels sandbox-arm64 --unattended --replace
sudo ./svc.sh install "$USER" && sudo ./svc.sh start
gh variable set PRIVILEGED_ARM --body true       # only now: the label exists
```

The Pi 5 needs the host prerequisites above plus `libprotoc-dev`, `unzip`, and
passwordless `sudo` for the runner account; `/var/tmp` must be on a dev-capable
filesystem (`findmnt -T /var/tmp`). Measured there (4 cores, 8 GiB, mmc root):
warm 2.07 ms, provisioned 132.33 ms — both inside budget, but the provisioned
figure is ~2.5× the x86_64 runner's, so treat it as the real budget check.

Before wiring up CI, prove the host can do it at all — this is the fastest way
to surface a missing asset or a `nodev` workspace:

```sh
sudo tests/e2e/smoke.sh
sudo tests/e2e/latency.sh

# The privileged CTest set: run the whole suite as root. Do NOT wrap the tests
# in `sudo` inside CMakeLists.txt -- sudo resets the environment, so the
# workspace roots ctest passes via its ENVIRONMENT property never arrive, every
# fixture-dependent test SKIPs (exit 0), and the run goes green having executed
# nothing. `privileged-e2e-run.yml` also fails the job if any of these skip.
sudo ctest --test-dir build -V -R "^(pool|network|network_cleanup|tmpl_setup|vmm|ipc|cgroup)$"
```

Each host needs:

- `/dev/kvm` and `/dev/net/tun`, and `nftables` on the host;
- Firecracker at `${FIRECRACKER_BIN:-/usr/local/bin/firecracker}`;
- guest assets at `${SANDBOX_KERNEL:-/opt/sandbox-assets/vmlinux}` and
  `${SANDBOX_ROOTFS:-/opt/sandbox-assets/rootfs.ext4}`.
  The kernel is **fetched, pinned and digest-checked**, not rebuilt:
  `scripts/fetch-guest-kernel.sh --arch x86_64 --out guest/vmlinux` (see
  [`BUILDING.md`](BUILDING.md#guest-kernels)). The privileged workflow does this
  for every run and points `SANDBOX_KERNEL` at the result, so CI never tests the
  runner's stale `/opt` kernel. The rootfs is rebuildable from this tree with
  `sudo scripts/build-custom-rootfs.sh` (writes `/opt/sandbox-assets/rootfs.ext4`,
  or `${SANDBOX_ROOTFS_OUT}`). The workflow builds it into the checkout and
  points `SANDBOX_ROOTFS` at the result, so guest-side changes
  (`scripts/sandbox-agent.c`, `/init`) are exercised in CI without clobbering the
  operator's asset. The workflow then builds the **Debian**
  image (`sudo scripts/build-debian-rootfs.sh`) and runs the same privileged suite
  against it a second time: the busybox image catches engine regressions cheaply,
  the Debian image is what a user boots, and a suite that only passes on the
  fixture would be green in exactly the wrong way;
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
  Confirmed not to be a guest-kernel issue (Linux 6.1.155 behaves identically)
  and reported upstream: [firecracker#6313](https://github.com/firecracker-microvm/firecracker/issues/6313).
  x86_64 is unaffected.
- On Ubuntu 24.04, `kernel.apparmor_restrict_unprivileged_userns=1` makes the
  unprivileged `jailer` sequence unable to `chroot`; it SKIPs and the root path
  provides coverage.
