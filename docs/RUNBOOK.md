# Sandbox Engine — Runbook

Operational procedures for a production install. Paths use the CMake defaults
(`SANDBOX_STATE_DIR=/var/lib/sandbox-engine`, `SANDBOX_RUN_DIR=/var/run/sandbox-engine`,
`SANDBOX_ETC_DIR=/etc/sandbox-engine`).

## 1. What runs

| Unit / process | Binary | Listens / talks to |
|---|---|---|
| `sandboxd.service` | `/usr/local/bin/sandboxd` | `engine.sock` (clients), `broker-control.sock` (broker), `:9180` (metrics/health) |
| `sandbox-api.service` | `/usr/local/bin/sandbox-api` | `/run/sandbox-api/api.sock`, `127.0.0.1:8088` (see [API.md](API.md#http-control-plane-api-27)); exits 75 if the daemon is lost and is restarted by systemd. Its tokens file lives at `/etc/sandbox-engine/api-tokens.conf`; mint one with `sandbox-api new-token NAME`. Add the service uid (and any unix-socket callers) to `allowed_uids` |
| `sandbox-broker` | `/usr/local/bin/sandbox-broker` | `0.0.0.0:8080` (guests), `broker-control.sock` (engine) |
| Firecracker | `/usr/local/bin/firecracker` | spawned per VM by sandboxd, jailed + cgroup-limited |

State: `/var/lib/sandbox-engine/{jail,snapshots,config}`. Config:
`/var/lib/sandbox-engine/config/engine.conf`; credentials (broker only, mode
0600): `/etc/sandbox-engine/credentials.conf`.

## 2. Daily checks

```sh
# Liveness / readiness / metrics
curl -sf http://127.0.0.1:9180/health   && echo health-ok
curl -sf http://127.0.0.1:9180/ready    && echo ready-ok   # 503 until pool is warm
curl -s  http://127.0.0.1:9180/metrics | grep -E 'sandbox_(pool_warm_count|pool_exhaustions_total|vmm_crashes_total|process_open_fds)'

systemctl status sandboxd.service
systemctl status sandbox-broker.service    # if installed as a unit

# Recent structured logs (JSON lines on stderr -> journald)
journalctl -u sandboxd.service -n 50 --no-pager
journalctl -u sandboxd.service -p warning -n 50 --no-pager
```

`/ready` returns **503** whenever the warm pool is empty (expected briefly at
startup and right after a template rebuild); `/health` is always **200** while
the process is up.

## 3. Common operations

### Reload configuration
There is no SIGHUP reload (deliberately: the pool and template are process
state). Edit `/var/lib/sandbox-engine/config/engine.conf`, validate, restart:

```sh
sandboxd --config /var/lib/sandbox-engine/config/engine.conf --validate-config
systemctl restart sandboxd.service
```

`--validate-config` also verifies the active template's snapshot integrity
(SHA-256) and exits non-zero on success-**critical** problems.

### Change the warm-pool size
`pool_size` in `engine.conf` (or `--pool-size`). Restart. Watch
`sandbox_pool_warm_count` climb back to the target.

### Log verbosity
`log_level = debug|info|warn|error` in `engine.conf`, `--log-level`, or
`SANDBOX_LOG_LEVEL`. Lines are JSON (`ts`, `level`, `component`, `event`, plus
event fields) captured and rotated by journald.

### Rebuild a template
A template built by an older engine is rejected (the manifest is format-versioned).
Rebuild with the current binaries from its spec; the engine can keep serving the
old template until the new one is published, and the switch is atomic:

```sh
sudo bash scripts/build-template.sh templates/python-agent
sandbox-cli template verify --name python-agent
```

No restart is needed: the daemon notices the new manifest version and drains its
warm pool. Roll back with `sandbox-cli template rollback --name python-agent`.
Reclaiming disk: `sandbox-cli template gc` (report) then `--apply`. See
[TEMPLATES.md](TEMPLATES.md).

## 4. Failure playbook

### `/ready` stays 503 after startup
- Check `/var/log` / journald for `component":"daemon","event":"start` and for
  restore errors from `vmm_*`.
- Verify the template exists and verifies: `sandbox-cli verify --template <name>`.
- Verify guest assets: `/opt/sandbox-assets/{vmlinux,rootfs.ext4}` and
  `/usr/local/bin/firecracker` are present and executable.
- Verify `/dev/kvm` and (for UFFD restore) `/dev/userfaultfd` exist and the
  daemon has `CAP_SYS_PTRACE` (ambient) when `vm.unprivileged_userfaultfd=0`.

### `sandbox_vmm_crashes_total` increasing
Look for `component":"ipc_server","event":"vmm_crash`. A crashed VMM is reaped
and its cgroup removed. Inspect the per-VM jail's `serial.log`; a crash loop
usually means a bad snapshot or a resource limit that is too tight.

### OOM / a VM disappears
Per-VM cgroups set `memory.max = guest size + slack` and `memory.oom.group = 1`,
so an over-limit guest kills only its Firecracker. Raise `cgroup_slack_mib`, or
lower the guest `memory_mib` request. Confirm limits:
`cat /sys/fs/cgroup/sandboxd/active/vm-*/memory.max`.

### `sandbox_pool_exhaustions_total` climbing
Clients are requesting faster than restores complete. Raise `pool_size`, or
reduce per-session concurrency pressure (`max_creates_per_session` /
`max_creates_per_uid`). Exhaustion is returned as an error code, never a hang.

### Large or chunked uploads rejected
Request bodies (`Content-Length` or `Transfer-Encoding: chunked`) stream through
the broker and are not buffered. Anything over `SANDBOX_BROKER_MAX_BODY` bytes
(default 256 MiB) gets `413`; malformed chunk framing or a short body gets
`400`. Raise the limit by setting `SANDBOX_BROKER_MAX_BODY` in the broker's
environment and restarting it.

### Cleaning up after a hard stop / crash

Since #31, restarting the daemon reclaims the jails a previous run could not
clean up: at startup `vmm_jail_sweep()` walks the jail root, detaches each
stale jail's bind mounts (with `MNT_DETACH`) and removes the directory. It keeps
a jail whose directory is younger than `JAIL_SWEEP_MIN_AGE_SECONDS` (5 s, so a
jailer that is mid-setup is not raced) and one that still has a process rooted
in it (a VMM that outlived the daemon is still serving its sandbox; killing it
would be worse than leaking a directory). Each removal is logged as
`[jail_sweep] reclaimed stale jail vm-N` and counted in the `jail_sweep` daemon
log event.

So the normal recovery is only:

```sh
systemctl restart sandboxd.service
journalctl -u sandboxd | grep jail_sweep      # what it reclaimed
```

A VMM left alive by the dead daemon keeps its jail and its sandbox; stop it
explicitly if you want the space back:

```sh
sudo pkill -9 -x firecracker
systemctl restart sandboxd.service            # the next start sweeps the rest
```

Manual cleanup is only needed for damage the daemon cannot see (e.g. a jail root
that was moved or is on a filesystem the daemon cannot access):

```sh
sudo find /var/lib/sandbox-engine/jail -mindepth 1 -maxdepth 1 -exec rm -rf {} +
sudo ip -all netns delete 2>/dev/null   # if per-VM netns were used
```

Cgroup leaves are removed on VM destroy; stale empty ones can be removed with
`sudo rmdir /sys/fs/cgroup/sandboxd/active/* /sys/fs/cgroup/sandboxd/active`.

## 5. Diagnostics bundle
Collect for a bug report:

```sh
{ systemctl status sandboxd.service;
  journalctl -u sandboxd.service -n 500 --no-pager;
  curl -s http://127.0.0.1:9180/metrics;
  sandboxd --version; uname -a;
} > /tmp/sandboxd-diag.txt
```

## 6. Quick reference

| Task | Command |
|---|---|
| Validate config + template | `sandboxd --config <file> --validate-config` |
| Verify a template | `sandbox-cli template verify --name <name\|digest>` |
| Health / readiness | `curl -sf :9180/health` / `curl -sf :9180/ready` |
| Metrics | `curl -s :9180/metrics` |
| Logs (warnings+) | `journalctl -u sandboxd -p warning` |
| Restart | `systemctl restart sandboxd` |
| Kill stray VMMs | `sudo pkill -9 -x firecracker` |
