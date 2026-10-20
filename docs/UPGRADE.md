# Sandbox Engine — Upgrade Guide

Covers upgrading `sandboxd`, `sandbox-broker`, `sandbox-cli` and the client
library (`libsandbox.so` / `libsandbox++.so`) to a new engine version.

> **Golden rule:** the on-disk snapshot **manifest format is tied to the engine
> version**. Phase 12 added a manifest `header_size` guard and SHA-256 digests,
> so templates built by an older engine are *rejected* by a newer one. **Rebuild
> every template after upgrading** (and keep the previous engine until you have).

## 1. Pre-flight

```sh
sandboxd --version
sandbox-cli verify --template /var/lib/sandbox-engine/snapshots/python-agent
curl -sf http://127.0.0.1:9180/ready    # note current readiness
```

Record the running versions, the pool size, and the template list. Take a
backup (see `BACKUP.md`) — especially the **credentials** and **config**.

## 2. Drain

```sh
sudo systemctl stop sandboxd.service
sudo systemctl stop sandbox-broker.service   # if installed as a unit
# Ensure nothing remains before swapping binaries:
sudo pkill -9 -x firecracker 2>/dev/null || true
```

Clients connected to `engine.sock` get a connection close; the client library
returns `DAEMON_UNREACHABLE`. Stop accepting new work first (remove the service
from your load balancer).

## 3. Install the new version

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSANDBOX_VERSION=<x.y.z>
cmake --build build -j
sudo cmake --install build            # stage with DESTDIR= to test first
sudo systemctl daemon-reload          # if the unit changed
```

The install places binaries in `bin`, the shared libraries beside them
(`$ORIGIN/../lib`), and **overwrites `engine.conf`**. Diff first:

```sh
sudo diff /var/lib/sandbox-engine/config/engine.conf <(cat config/engine.conf)
```

New keys (added by later phases) get their defaults from the code even if the
file omits them, but the packaged file is the reference. Re-validate:

```sh
sandboxd --config /var/lib/sandbox-engine/config/engine.conf --validate-config
```

## 4. Rebuild templates (required)

Because the manifest format is version-bound, templates must be rebuilt with the
new binaries (e.g. via your capture tooling / `make_template`), replacing
`/var/lib/sandbox-engine/snapshots/<name>` atomically. Then:

```sh
sandbox-cli verify --template /var/lib/sandbox-engine/snapshots/python-agent
# -> "ok" / exit 0
```

If you skip this step, restores fail the integrity check and `/ready` never
turns green.

## 5. Start and verify

```sh
sudo systemctl start sandbox-broker.service
sudo systemctl start sandboxd.service
watch -n1 'curl -s :9180/metrics | grep sandbox_pool_warm_count'
curl -sf http://127.0.0.1:9180/ready && echo READY
journalctl -u sandboxd.service -n 20 --no-pager
```

Expect `/health` immediately and `/ready` after `pool_size` restores complete.
Smoke-test one create/destroy through your normal client.

### Client library
If you vendored `libsandbox++`/`libsandbox`, rebuild/link clients against the new
shared library and redeploy the `.so` alongside clients (the install sets
`INSTALL_RPATH=$ORIGIN/../lib`).

## 6. Rollback

Keep the previous binaries and a rebuilt-for-the-old-version template set:

```sh
sudo systemctl stop sandboxd.service
sudo cp /var/lib/sandbox-engine/backup/bin/sandboxd /usr/local/bin/sandboxd   # and broker/cli
# restore the matching templates and engine.conf
sudo systemctl start sandboxd.service
```

Because manifest compatibility is not guaranteed across versions, a rollback
may also require restoring the **previous templates**, not just the binaries.

## 7. Version compatibility notes

| Engine | Manifest | Notes |
|---|---|---|
| ≤ 0.10.x | no header_size / no digests | Rejected by ≥ 0.12.0 |
| 0.12.0 | `header_size` + SHA-256 | Templates must be rebuilt from ≤ 0.10.x |
| 0.13.0 | + `rootfs_sha256` / `rootfs_size` | **Rebuild templates.** A 0.12.0 manifest is refused (`header_size` mismatch); the rootfs is now integrity-checked, so the image and the captured memory state cannot drift apart |
| 0.14.0 | + `workspace_sha256` / `workspace_size` (only for templates built with a workspace) | Templates gain an optional base workspace image. A 0.13.0 template still loads, but it has no workspace: `sandbox_create` with a `session_key` fails with `INVALID_SPEC` ("rebuild the template to use session_key"). Rebuild to use session volumes. `sandbox_spec_t` also grew two fields — **zero-initialise it** (`= {0}`) or the `session_key` pointer is stack garbage |

Environment variables that carry over between versions (all optional):
`SANDBOX_LOG_LEVEL`, `SANDBOX_VSOCK_SETTLE_MS`, `SANDBOX_VSOCK_CONFIRM_MS`,
`SANDBOX_VERIFY_SNAPSHOT`, `SANDBOX_CREATE_WORKERS`,
`SANDBOX_MAX_CREATES_PER_SESSION`, `SANDBOX_MAX_CREATES_PER_UID`,
`SANDBOX_CGROUP_*`, `SANDBOX_BROKER_*`.

New in 0.13.0: `SANDBOX_FC_CLOCK_REALTIME=0` suppresses `clock_realtime` on
`/snapshot/load` (only needed on a host kernel < 5.16, where Firecracker would
otherwise reject the load request).

New in 0.14.0 (#23): `SANDBOX_WORKSPACE_ROOT`, `SANDBOX_WORKSPACE_MAX_TTL`,
`SANDBOX_REAP_INTERVAL_SECONDS` (session store), and `SANDBOX_FLUSH_MS` (how long
a destroy waits for the guest's `sync()` acknowledgement before killing the VMM).
Session volumes are **not** part of the snapshot and are **not** removed by an
upgrade or a rebuild; they live under their own root and expire on their own TTL.
An upgraded engine keeps serving them, but a template rebuilt after the upgrade
produces a new base image, and existing sessions keep the base they were cloned
from — that is intentional: a session is the user's data, not the template's.
