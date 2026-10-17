# Sandbox Engine — Runbook

Operational procedures for a production install. Paths use the CMake defaults
(`SANDBOX_STATE_DIR=/var/lib/sandbox-engine`, `SANDBOX_RUN_DIR=/var/run/sandbox-engine`,
`SANDBOX_ETC_DIR=/etc/sandbox-engine`).

## 1. What runs

| Unit / process | Binary | Listens / talks to |
|---|---|---|
| `sandboxd.service` | `/usr/local/bin/sandboxd` | `engine.sock` (clients), `broker-control.sock` (broker), `:9180` (metrics/health) |
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
Templates carry a manifest with SHA-256 digests (§10.10); a template built by an
older engine is rejected. Rebuild with the current binaries:

```sh
sudo systemctl stop sandboxd.service
# rebuild the "python-agent" template (make_template or your capture tooling),
# writing into /var/lib/sandbox-engine/snapshots/python-agent
sandbox-cli verify --template /var/lib/sandbox-engine/snapshots/python-agent
sudo systemctl start sandboxd.service
```

## 4. Failure playbook

### `/ready` stays 503 after startup
- Check `/var/log` / journald for `component":"daemon","event":"start` and for
  restore errors from `vmm_*`.
- Verify the template exists and verifies: `sandbox-cli verify --template <path>`.
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

### Chunked uploads rejected
Request bodies with `Transfer-Encoding: chunked` are decoded in memory and
bounded to 8 MiB. Larger or malformed bodies get `400`. Ask clients to send
`Content-Length`, or raise the limit in `src/broker/core.c`
(`CHUNKED_MAX_BODY`).

### Cleaning up after a hard stop / crash
A SIGKILL can leave jailed Firecracker processes, taps and mounts behind:

```sh
sudo pkill -9 -x firecracker
for m in $(mount | grep -oE '/var/lib/sandbox-engine/jail/[^ ]*' | sort -ru); do
  sudo umount -l "$m" 2>/dev/null
done
sudo find /var/lib/sandbox-engine/jail -mindepth 1 -maxdepth 1 -exec rm -rf {} +
sudo ip -all netns delete 2>/dev/null   # if per-VM netns were used
systemctl start sandboxd.service
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
| Verify a template | `sandbox-cli verify --template <dir>` |
| Health / readiness | `curl -sf :9180/health` / `curl -sf :9180/ready` |
| Metrics | `curl -s :9180/metrics` |
| Logs (warnings+) | `journalctl -u sandboxd -p warning` |
| Restart | `systemctl restart sandboxd` |
| Kill stray VMMs | `sudo pkill -9 -x firecracker` |
