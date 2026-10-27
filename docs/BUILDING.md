# Building

## Dependencies

**Build tools**

```sh
sudo apt-get install -y build-essential cmake pkg-config
```

**Libraries** (Ubuntu/Debian names)

```sh
sudo apt-get install -y \
  libprotobuf-dev protobuf-compiler libprotoc-dev \
  libseccomp-dev libcurl4-openssl-dev libnftables-dev libsystemd-dev
```

`libnftables-dev` and `libsystemd-dev` are optional: without `libnftables` the
network manager falls back to invoking the `nft` binary; without `libsystemd`
`sd_notify`/watchdog support is compiled out.

## Configure and build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

### Build options

| Option | Default | Effect |
| --- | --- | --- |
| `SANDBOX_VERSION` | `0.14.0` | Version string for `--version` and packaging. |
| `CMAKE_BUILD_TYPE` | *(unset)* | `Release` (`-O3 -DNDEBUG`) or `Debug` (`-g -O0 -DDEBUG`). |
| `SANDBOX_TSAN` | `OFF` | Build with ThreadSanitizer (pool concurrency verification). |
| `SANDBOX_SANITIZE` | *(empty)* | Comma-separated sanitizers, e.g. `address,undefined`. |
| `SANDBOX_BUILD_FUZZERS` | `OFF` | Build the libFuzzer harnesses in `fuzz/` (needs clang). |
| `SANDBOX_STATE_DIR` | `/var/lib/sandbox-engine` | Install target for state (jail, snapshots, config). |
| `SANDBOX_ETC_DIR` | `/etc/sandbox-engine` | Install target for host config (`credentials.conf.example`). |
| `SANDBOX_RUN_DIR` | `/var/run/sandbox-engine` | Install target for the runtime socket dir. |

> Because `SANDBOX_VERSION` is a cache variable, an existing build directory must
> be reconfigured (`-DSANDBOX_VERSION=...`) when the version changes.

### Sanitizer builds

```sh
# Address + UndefinedBehavior sanitizers
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DSANDBOX_SANITIZE=address,undefined
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure

# ThreadSanitizer (pool concurrency)
cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DSANDBOX_TSAN=ON
cmake --build build-tsan -j --target test_pool
```

The fully-static `jailer_probe` is built unsanitized in sanitizer builds (a
static binary cannot link the sanitizer runtime).

### Fuzzers

Clang with libFuzzer is required:

```sh
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_BUILD_TYPE=Debug -DSANDBOX_BUILD_FUZZERS=ON \
      -DSANDBOX_SANITIZE=address,undefined
cmake --build build-fuzz -j --target fuzz_http fuzz_config fuzz_proto
./build-fuzz/fuzz/fuzz_http -max_total_time=60 fuzz/corpus/http
```

Each harness has a standalone stdio driver so it can also run under gcc without
libFuzzer.

## Install

```sh
sudo cmake --install build                 # absolute paths by default
cmake --install build --prefix /opt/sandbox-engine   # or a custom prefix
DESTDIR=/tmp/stage cmake --install build   # staging (packaging)
```

See [`DEPLOYMENT.md`](DEPLOYMENT.md) for the resulting layout.

### Installing a prebuilt release

Releases ship per-architecture assets for **x86_64** and **aarch64**.
[`scripts/install.sh`](../scripts/install.sh) selects this machine's
architecture, verifies the SHA-256, and installs the binaries and libraries:

```sh
sudo scripts/install.sh                    # latest, into /usr/local
sudo scripts/install.sh --version v0.12.0  # a specific tag
sudo scripts/install.sh --full             # also extract units/config/state dirs over /
scripts/install.sh --dry-run               # print the plan; download nothing
```

Set `SANDBOX_BASE_URL` to install from a mirror (the assets are also fetchable
by hand). Per architecture (`<arch>` is `x86_64` or `aarch64`):

| asset | contents |
|---|---|
| `sandbox-engine-<ver>-linux-<arch>.tar.gz` | staged install tree (the "zip") |
| `sandbox-engine-<ver>-linux-<arch>-bin.tar.gz` | bare binaries + shared libraries |
| `sandboxd-linux-<arch>`, `sandbox-cli-linux-<arch>`, … | standalone binaries |
| `*.sha256` | checksums for the two archives |

aarch64 assets are built **natively** on `ubuntu-24.04-arm` — there is no
cross-toolchain, and no qemu emulation. `install.sh` also works offline against
`file://` (or a mirror), which is how it is smoke-tested.

## Guest images

The host binaries and the guest image are built separately; the engine never
compiles a guest at runtime. Two images exist, and they share `/init`
(`scripts/guest-init.sh`) and the static agent on purpose:

| Image | Script | Purpose |
| --- | --- | --- |
| busybox (128 MiB) | `scripts/build-custom-rootfs.sh` | Test fixture. Minimal: proves snapshots, vsock, `/workspace` and the agent without a package manager to slow it down. |
| Debian (`bookworm` 12.15, 308 MiB apparent / ~199 MiB on disk) | `scripts/build-debian-rootfs.sh` | What a user actually gets: `dpkg`, `apt`, `bash`, coreutils and `python3`, plus the same agent and `/init`. |

Both require root (`debootstrap` for Debian, a loop mount for busybox) and both
accept `SANDBOX_ROOTFS_OUT` so CI writes into its own work tree:

```sh
sudo SANDBOX_ROOTFS_OUT=$PWD/guest/rootfs-debian.ext4 \
     bash scripts/build-debian-rootfs.sh
```

The Debian script prints the suite, the size and the SHA-256 of the finished
image, and verifies the *image* (not the source directory): `/etc/debian_version`,
an executable `/init`, the agent, and the `/workspace` mountpoint. Cross-arch
builds are refused rather than half-done — the agent is compiled for the guest,
so build on the architecture you intend to boot.

CI build of 45c7828..f5bcee5 (x86_64, bookworm 12.15): 181 MiB of content in a
308 MiB sparse ext4, sha256 `02b8408beb474c9820498110149f1e047648ca442bc3a1630976964ae630f90a`
(debootstrap output is not byte-reproducible across runs; treat the digest as a
record, not a pin).

`/` is mounted read-only in the guest. That is not an oversight: package
installs at runtime would be lost at the next restore and would break
determinism. Bake software into a template (#25) or install into the persistent
`/workspace` (`pip --target`, `npm --prefix`, `GOPATH`).

## Guest kernels

The guest kernel is pinned, downloaded and digest-checked by
[`scripts/fetch-guest-kernel.sh`](../scripts/fetch-guest-kernel.sh). The pin is
the single source of truth; the script refuses a version, snapshot or checksum
that is not compiled into it.

| field | value |
| --- | --- |
| version | `6.18.54` |
| source | `s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261021-1e5fcc27b59f-0/<arch>/vmlinux-6.18.54` |
| x86_64 sha256 | `f697969a2f005d296e8c5e2fcd0f6a4f305eb3a06b085d3930d10f1eab3a0883` |
| aarch64 sha256 | `92f2569ccb456f62c2c7618b9d9ce40020effbd173783633da051d1d9816b9ba` |
| config | published next to the image as `vmlinux-6.18.54.config`; the fetch script stores it as `<out>.config` |

```sh
# Install the operator default:
sudo scripts/fetch-guest-kernel.sh --arch x86_64 --out /opt/sandbox-assets/vmlinux
# Or into a work tree (what CI does):
scripts/fetch-guest-kernel.sh --arch x86_64 --out guest/vmlinux
SANDBOX_KERNEL=$PWD/guest/vmlinux sudo -E ctest --test-dir build -R '^(tmpl_setup|vmm|ipc)$'
```

These are the kernels Firecracker's own CI builds and tests against this release
line, so the guest/host interface is the one upstream exercises. We previously
used the 4.14 quickstart kernel; it is end-of-life, predates modern ext4
metadata and the vsock local transport (Linux 5.6), and is not something to put
inside an isolation boundary. `scripts/fetch-guest-kernel.sh` is also how a
self-built kernel would be introduced later: change the pin and the digests in
one reviewed place.

Verified locally on x86_64 with Firecracker v1.17.0 and the busybox guest:
cold boot to `SANDBOX-READY` in ~1.2 s, `/dev/vdb` mounted at `/workspace`,
`SANDBOX-VSOCK-HOST cid=2`, and `sleep`/`nanosleep`/`poll` timing exact
(`2001/1000/501 ms`). Templates must be rebuilt after a kernel change — the
kernel path is part of the template configuration, not of the snapshot.

Two facts worth knowing before changing the pin:

- The Firecracker CI config sets `# CONFIG_VSOCKETS_LOOPBACK is not set`, so
  `VMADDR_CID_LOCAL` still does not exist in these guests. That keeps the
  guest-local half of #30 open even on 6.18.
- The aarch64 timer-interrupt defect after snapshot restore is a Firecracker
  issue, not a kernel one: it reproduces on 4.14, 6.1 and (per the same
  reproduction) on current kernels. See `SYSTEM DESIGN.md` §15.7 and
  https://github.com/firecracker-microvm/firecracker/issues/6313.

### Clocksource (6.x guests)

A 6.18 x86_64 guest boots on kvm-clock and then switches to `tsc`. After a
snapshot restore the TSC resumes from its snapshot value, so the realtime jump
that `clock_realtime` requests never reaches the guest: CI measured a -18 s skew.
`FC_BOOT_ARGS` therefore carries `clocksource=kvm-clock`; skew is 0 s on both
the busybox and Debian suites.

## Cross / on-target builds

The engine builds natively on both x86_64 and aarch64. On a small host (e.g. a
Raspberry Pi 5) build on-target; there is no cross-toolchain requirement. The
helper [`scripts/sync-to-pi.sh`](../scripts/sync-to-pi.sh) rsyncs a working tree
to a remote builder and [`scripts/build-and-test.sh`](../scripts/build-and-test.sh)
runs the full configure/build/test cycle.

## Troubleshooting build failures

See [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md). Common issues: missing
`libnftables-dev` (falls back, but you lose the library path), a stale
`protobuf` toolchain, or a build directory whose cached `SANDBOX_VERSION` is
older than the source.
