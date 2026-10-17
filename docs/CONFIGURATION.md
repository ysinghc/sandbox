# Configuration

`sandboxd` reads a flat `key = value` file. `[section]` headers are cosmetic —
the parser ignores them and matches keys by name, so **key names must be
unique**. Lines starting with `#` or `;` are comments.

**Precedence (highest first):**

1. Command-line flags (`sandboxd --socket ...`)
2. Environment variables (`SANDBOX_*`)
3. The config file
4. Built-in defaults

**Default config path:** `/var/lib/sandbox-engine/config/engine.conf`
(override with `sandboxd --config FILE`). The packaged file is
[`config/engine.conf`](../config/engine.conf).

Unknown keys are reported on stderr (`unknown config key '...'`) and ignored.
Run `sandboxd --validate-config` to check a configuration and the template
integrity before starting.

## Daemon keys

| Key | Env var | Default | Meaning |
| --- | --- | --- | --- |
| `socket_path` (aliases: `socket`, `engine_socket`) | `SANDBOX_ENGINE_SOCK` | `/var/run/sandbox-engine/engine.sock` | Client-facing Unix socket (protobuf IPC). |
| `broker_control_socket` (alias: `broker_control`) | `SANDBOX_BROKER_CONTROL` | `/var/run/sandbox-engine/broker-control.sock` | Internal socket the broker uses to validate session tokens. |
| `template` (alias: `template_name`) | `SANDBOX_TEMPLATE` | `python-agent` | Snapshot template restored for each VM. Required at startup. |
| `pool_size` (alias: `target_size`) | `SANDBOX_POOL_SIZE` | `5` | Number of warm VMs kept ready. Must be `1..POOL_MAX_SIZE`. |
| `max_queue_depth` | `SANDBOX_MAX_QUEUE_DEPTH` | pool default (`50`) | Max queued `Create` requests before back-pressure/`POOL_EXHAUSTED`. |
| `pool_wait_timeout_ms` | `SANDBOX_POOL_WAIT_MS` | `0` | Server-side default wait for a warm VM when the pool is empty (`0` = use the request's value). |
| `allowed_services` | `SANDBOX_ALLOWED_SERVICES` | *(empty — deny all)* | Comma-separated upstream host allow-list copied into every session token. |
| `allowed_uids` | `SANDBOX_ALLOWED_UIDS` | *(empty)* | Peer-uid allow-list for the engine socket (checked via `SO_PEERCRED`). Empty accepts any uid in the socket's group; `0` = root only. |
| `jailer_uid` | `SANDBOX_JAILER_UID` | `65534` (nobody) | Unprivileged uid Firecracker runs as inside the jail. |
| `jailer_gid` | `SANDBOX_JAILER_GID` | `65534` | Unprivileged gid inside the jail. |
| `jail_root` | `SANDBOX_JAIL_ROOT` | *(state dir)* | Root under which per-VM jail directories are created. |
| `snapshot_root` | `SANDBOX_SNAPSHOT_ROOT` | *(state dir)* | Root of the template/snapshot store. |
| `vsock_settle_ms` | `SANDBOX_VSOCK_SETTLE_MS` | `1000` | Fallback settle time before the first vsock `CONNECT` if the guest readiness marker is not seen (§10.9). |
| `metrics_port` | `SANDBOX_METRICS_PORT` | `9180` | Metrics/health port. |
| `metrics_bind` | `SANDBOX_METRICS_BIND` | `0.0.0.0` | Metrics bind address; **empty disables** the listener. |
| `log_level` | `SANDBOX_LOG_LEVEL` | `info` | Structured log threshold: `debug`, `info`, `warn`, `error`. |

## Create concurrency (§10.8)

| Key | Env var | Default | Meaning |
| --- | --- | --- | --- |
| `create_workers` | `SANDBOX_CREATE_WORKERS` | `4` | Number of worker threads that provision+inject+toke VMs. |
| `max_creates_per_session` | `SANDBOX_MAX_CREATES_PER_SESSION` | `16` | Per-session in-flight `Create` cap. |
| `max_creates_per_uid` | `SANDBOX_MAX_CREATES_PER_UID` | `64` | Per-peer-uid in-flight `Create` cap. |

Requests beyond a cap are rejected with `POOL_EXHAUSTED`. Per-session requests
are dispatched one at a time (FIFO) so responses retain request order.

## cgroup v2 (§10.11)

| Key | Env var | Default | Meaning |
| --- | --- | --- | --- |
| `cgroup_enable` | `SANDBOX_CGROUP_ENABLE` | `1` | Enable per-VM cgroup placement. |
| `cgroup_slack_mib` | `SANDBOX_CGROUP_SLACK_MIB` | `64` | Head-room added to `memory.max` on top of the guest size. |
| `cgroup_cpu_max` | `SANDBOX_CGROUP_CPU_MAX` | `max` | `cpu.max` value. `max` = no CPU cap. Use `"100000 200000"` to cap a VM at 50% of one core. |

Per-VM cgroups live under `<jail_root-parent>/sandboxd/active/<vm-id>`, with
swap disabled and `memory.oom.group` set so the VMM (not the daemon) is the OOM
victim.

## Command-line flags

```
sandboxd [--config FILE] [--socket PATH] [--broker-control PATH]
         [--template NAME] [--pool-size N] [--allowed-services CSV]
         [--allowed-uids CSV] [--metrics-port N] [--metrics-bind ADDR]
         [--jail-root DIR] [--snapshot-root DIR] [--log-level LEVEL]
         [--validate-config] [--version]
```

## Broker environment variables

The broker is configured purely through the environment (its defaults are
production-oriented):

| Variable | Default | Meaning |
| --- | --- | --- |
| `SANDBOX_BROKER_LISTEN` | `0.0.0.0:8080` | Broker listen address. |
| `SANDBOX_BROKER_CREDENTIALS` | `/etc/sandbox-engine/credentials.conf` | Credential store (must be `0600`). |
| `SANDBOX_BROKER_CONTROL` | `/var/run/sandbox-engine/broker-control.sock` | Engine token-validation socket. |
| `SANDBOX_BROKER_UPSTREAM_SCHEME` | `https` | Scheme used to reach upstreams. |
| `SANDBOX_BROKER_TLS_VERIFY` | on | Set to `0` to disable upstream TLS verification (**testing only**). |
| `SANDBOX_BROKER_UID` / `SANDBOX_BROKER_GID` | *(unset)* | Drop to this uid/gid after binding. |
| `SANDBOX_BROKER_METRICS_PORT` | *(unset)* | Optional broker `/metrics` listener. |

## Other environment variables

| Variable | Meaning |
| --- | --- |
| `FIRECRACKER_BIN` | Path to the Firecracker binary (default `/usr/local/bin/firecracker`). |
| `SANDBOX_FC_SECCOMP` | `0` disables the Firecracker-internal seccomp (lab only). |
| `SANDBOX_FC_PCI` | Enable PCI (`pci=on`) for the VMM when set. |
| `SANDBOX_VERIFY_SNAPSHOT` | On restore, verify the memory snapshot against the manifest. |
| `NOTIFY_SOCKET` | Set by systemd; enables `sd_notify` readiness/watchdog. |

## Credential store format

`/etc/sandbox-engine/credentials.conf` is an INI file keyed by upstream host; a
`:port` suffix and letter case are ignored on lookup. See
[`config/credentials.conf.example`](../config/credentials.conf.example).

```ini
[api.openai.com]
credential = Bearer sk-...        # injected verbatim as Authorization

[s3.amazonaws.com]
credential = AWS4-HMAC-SHA256 ... # provider-specific scheme
```

> **Note:** the file must be `0600` and owned by the broker uid. Mode enforcement
> is an open hardening item (see the issue tracker); set it correctly today.
