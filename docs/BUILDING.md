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
