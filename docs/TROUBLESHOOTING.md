# Troubleshooting

## Daemon

**`sandboxd --validate-config` exits non-zero.**
It prints a per-item report. A non-zero exit with "template not found" or an
integrity mismatch means the configured template is missing or was built by an
older version. Re-stamp it (see [`DEPLOYMENT.md`](DEPLOYMENT.md)) and retry.
Template manifests changed in 0.12.0, so pre-0.12.0 templates are rejected by
design.

**`sandboxd` refuses to start: `no template configured`.**
Set `template` in the config (or `SANDBOX_TEMPLATE`). The default config path is
`/var/lib/sandbox-engine/config/engine.conf`.

**`sandboxd` refuses to start: `invalid pool_size N`.**
`pool_size` must be between `1` and the compiled maximum. Check
`engine.conf`.

**Client cannot connect.**
Confirm the socket path matches on both sides (`socket_path` /
`SANDBOX_ENGINE_SOCK` vs the client's `sandbox_init` argument), that the daemon
is running, and that the client uid is permitted by `allowed_uids`.

## Sandbox creation

**`sandbox_create` returns `-1` (`POOL_EXHAUSTED`).**
Either the pool was empty and `pool_wait_ms` expired, or a
`max_creates_per_session` / `max_creates_per_uid` cap was hit. Raise
`pool_size`, raise the request's `--wait`, or reduce concurrency.

**`sandbox_create` returns `-2` (`INVALID_SPEC`).**
Unknown template, or memory/vCPU outside the supported range.

**Restore fails / timeout.**
The guest readiness markers were not seen and the fallback settle expired. Check
`vsock_settle_ms`, the serial log for the VM, and that the guest agent is
included in the snapshot.

**uFFD not available.**
`/dev/userfaultfd` missing and `vm.unprivileged_userfaultfd=0`. The daemon runs
as root and uses `CAP_SYS_PTRACE` to deliver an ambient capability to the VMM;
verify the capability is present (`systemctl show sandboxd -p
CapabilityBoundingSet`) and that the kernel exposes userfaultfd.

**Firecracker fails to bind its API/uffd socket.**
Unix sockets cannot be created on some network/9p mounts (`EPERM`). Keep
`jail_root` and `snapshot_root` on local disk (e.g. `/var/lib/...`, `/tmp`), not
a shared mount.

## Broker

**`401 Missing/Invalid token`.**
The guest did not send `X-Sandbox-Token`, or the token expired / the session
closed. A destroyed sandbox's token is no longer valid.

**`403` (host not allowed).**
Add the upstream host to `allowed_services` so it is included in session tokens.

**`502` upstream failure.**
Upstream unreachable or TLS verification failed. Check
`SANDBOX_BROKER_UPSTREAM_SCHEME` and `SANDBOX_BROKER_TLS_VERIFY` (the latter
should be left on in production).

**Credentials not injected.**
Confirm `credentials.conf` exists at `SANDBOX_BROKER_CREDENTIALS`, is readable
by the broker uid, and has a section for the upstream `Host` (case-insensitive,
`:port` ignored).

## Build

**`cannot specify -static with -fsanitize=...`.**
Only when building the static `jailer_probe` under sanitizers; handled
automatically (`-fno-sanitize=all` for that target). If you see it for another
target, you are statically linking a sanitized binary, which is unsupported.

**`libnftables not found`.**
Install `libnftables-dev`, or accept the fallback to the `nft` binary.

**Version looks stale.**
`SANDBOX_VERSION` is a cache variable; reconfigure the existing build directory
with `-DSANDBOX_VERSION=<x>`.

**Fuzz targets missing (`No rule to make target 'fuzz_http'`).**
Configure with `-DSANDBOX_BUILD_FUZZERS=ON` and clang. A stray argument (for
example a mangled `-D` flag in a script) silently disables the option — check the
configure output for "Ignoring extra path from command line".

## Tests

**Privileged tests hang or fail.**
Run as root on a host with `/dev/kvm` and guest assets; clean leaked state
between runs (see [`TESTING.md`](TESTING.md#cleaning-between-runs)).

**`jailer` sequence SKIPs.**
Expected on Ubuntu 24.04 (AppArmor restricts unprivileged user namespaces); the
root path still covers it.

## Runtime state

**Stale cgroup directories.**
After a hard kill, remove leftover `sandboxd/active/*` directories before
restarting:

```sh
sudo rmdir /sys/fs/cgroup/sandboxd/active/* 2>/dev/null
```

**Orphaned Firecracker processes.**

```sh
sudo pkill -9 -x firecracker
```
