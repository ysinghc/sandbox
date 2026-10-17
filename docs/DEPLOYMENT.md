# Deployment

This guide covers turning a built tree into a running host: directories, the
installed layout, systemd, credentials, templates, and hardening.

## 1. Host preparation

- **KVM**: `/dev/kvm` must exist and be usable. Add the operator/service user to
  the `kvm` group if the daemon is not run as root.
- **userfaultfd**: either `/dev/userfaultfd` is present, or
  `vm.unprivileged_userfaultfd=1`. The daemon runs as root, so it holds
  `CAP_SYS_PTRACE` and can use uffd regardless; the capability is delivered as
  an *ambient* capability to the jailed VMM because `no_new_privs` makes execve
  ignore file capabilities.
- **Firecracker**: install it at `/usr/local/bin/firecracker` (or set
  `FIRECRACKER_BIN`).
- **cgroup v2**: mounted at `/sys/fs/cgroup` (unified hierarchy). Per-VM
  cgroups are created under `sandboxd/active/`.
- **Guest assets**: a kernel and rootfs. The test rig uses
  `/opt/sandbox-assets/vmlinux` and `/opt/sandbox-assets/rootfs.ext4`.

## 2. Install

```sh
sudo cmake --install build
```

Default layout (with the default prefix `/usr/local`):

| Path | Contents |
| --- | --- |
| `/usr/local/bin/sandboxd` | Daemon. |
| `/usr/local/bin/sandbox-broker` | Credential broker. |
| `/usr/local/bin/sandbox-cli` | CLI. |
| `/usr/local/lib/libsandbox.so` | C client library. |
| `/usr/local/lib/libsandbox++.so` | C++ client library. |
| `/usr/local/include/libsandbox.h`, `libsandbox.hpp` | Public headers. |
| `/var/lib/sandbox-engine/config/engine.conf` | Packaged config (daemon default path). |
| `/var/lib/sandbox-engine/jail/` | Per-VM jail root. |
| `/var/lib/sandbox-engine/snapshots/` | Template/snapshot store. |
| `/var/run/sandbox-engine/` | Runtime socket directory. |
| `/etc/sandbox-engine/credentials.conf.example` | Credential store template. |
| `/usr/local/lib/systemd/system/sandboxd.service` | systemd unit. |

State/config/runtime directories are configurable at build time via
`SANDBOX_STATE_DIR`, `SANDBOX_ETC_DIR`, and `SANDBOX_RUN_DIR`.

## 3. Credentials

```sh
sudo cp /etc/sandbox-engine/credentials.conf.example /etc/sandbox-engine/credentials.conf
sudo chmod 600 /etc/sandbox-engine/credentials.conf
sudo chown <broker-uid>:<broker-gid> /etc/sandbox-engine/credentials.conf
# edit in real credentials
```

Only upstreams you add here can be reached, and only if their host is in
`allowed_services`. Secrets are injected by the broker on the host and never
enter the guest.

## 4. Stamp a template

Templates are created once per host and restored for every VM. The test helper
`make_template` builds the `e2e` template from the guest assets:

```sh
sudo -E env SANDBOX_SNAPSHOT_ROOT=/var/lib/sandbox-engine/snapshots \
            SANDBOX_JAIL_ROOT=/var/lib/sandbox-engine/jail \
            FIRECRACKER_BIN=/usr/local/bin/firecracker \
  build/tests/make_template
sudo sandbox-cli verify --template e2e
```

> On-disk template manifests changed in 0.12.0. Pre-0.12.0 templates are
> rejected by the integrity check and must be re-stamped.

If your template is named differently, set `template` in the config (or
`SANDBOX_TEMPLATE`) so the daemon restores the right one.

## 5. Configure and start

Edit `/var/lib/sandbox-engine/config/engine.conf` (see
[`CONFIGURATION.md`](CONFIGURATION.md)), then validate and start:

```sh
sudo sandboxd --validate-config        # checks config + template integrity
sudo systemctl daemon-reload
sudo systemctl enable --now sandboxd
sudo sandbox-broker &                  # or a second unit
```

`--validate-config` fails if the configured template does not exist or fails
integrity — that is an integrity failure, not necessarily a config error.

## 6. Hardening notes

The daemon runs as **root by design**: it builds taps, mknod's jail device
nodes, chroots, and drops uid per VM at runtime. The systemd unit compensates:

- `NoNewPrivileges=true`; the daemon also sets `PR_SET_NO_NEW_PRIVS` in-process.
- A tight `CapabilityBoundingSet` (the capabilities the runtime actually uses).
- `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, and
  `ReadWritePaths=/var/lib/sandbox-engine /var/run/sandbox-engine`.

The jailer additionally applies chroot, an unprivileged uid/gid, a seccomp
allow-list, and per-VM cgroup limits to each Firecracker process.

**Deviations & open items** (tracked in §15 of
[`SYSTEM DESIGN.md`](../SYSTEM%20DESIGN.md) and the issue tracker):

- The daemon keeps a set of runtime capabilities rather than dropping to none;
  **privilege separation into helper processes is a V2 item.**
- Shared host paths are read-write for the daemon; per-file `credentials.conf`
  mode enforcement is an open hardening item.
- vsock payload authentication (HMAC) is a V2 item.

## 7. Verify

```sh
curl -s localhost:9180/health
curl -s localhost:9180/ready
curl -s localhost:9180/metrics | head
sudo sandbox-cli run --template e2e
```

See [`RUNBOOK.md`](RUNBOOK.md) for day-2 checks and
[`UPGRADE.md`](UPGRADE.md) / [`BACKUP.md`](BACKUP.md) for maintenance.
