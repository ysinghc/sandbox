# API Reference

Three ways to drive the engine: the **C library**, the **C++ wrapper**, and the
**`sandbox-cli`** tool. Beneath them all is a small **protobuf-over-Unix-socket**
protocol. Guests reach upstream services through the **credential broker** using
plain HTTP.

- [C library (`libsandbox`)](#c-library-libsandbox)
- [C++ wrapper (`libsandbox++`)](#c-wrapper-libsandbox)
- [CLI](#cli)
- [Wire protocol](#wire-protocol)
- [Credential broker](#credential-broker)

---

## C library (`libsandbox`)

Header: `<libsandbox.h>` — link with `-lsandbox`.

### Types

```c
typedef struct sandbox_handle_t sandbox_handle_t;   // opaque

typedef struct {
    uint64_t    memory_mib;     // guest memory in MiB
    uint32_t    vcpu_count;     // number of vCPUs
    const char* template_name;  // snapshot template to restore
    const char** env_vars;      // NULL-terminated "KEY=VALUE" array (may be NULL)
    uint32_t    pool_wait_ms;   // max wait when the pool is empty (0 = fail fast)
    const char* session_key;    // persistent /workspace volume; NULL = ephemeral
    uint32_t    ttl_seconds;    // volume lifetime; 0 = platform default (7 days)
    const char** egress_allow;  // #26: NULL-terminated hosts this sandbox may reach; NULL = daemon default
    int         egress_deny_all; // #26: 1 = may reach nothing
} sandbox_spec_t;

**Zero-initialise it** (`sandbox_spec_t spec = {0};`) and then set the fields you
need. The struct grows as the engine gains features, and a field the caller did
not set must read as 0/NULL. An uninitialised local is uninitialised stack
garbage — for `session_key` that is a crash, not a wrong default.

A spec is a *request*, not a description of what you get: the daemon clamps
`ttl_seconds` to the platform maximum and rejects a `session_key` that is not
1–127 printable bytes without `"` or `\`.

typedef struct {
    uint32_t sandbox_id;
    bool     is_running;        // false when paused
    uint64_t uptime_ms;         // since last resume
    uint64_t memory_rss_mib;    // resident set size
    uint32_t page_faults;       // cumulative uffd page faults served
} sandbox_status_t;
```

### Error codes (`sandbox_error_t`)

| Code | Value | Meaning |
| --- | --- | --- |
| `SANDBOX_OK` | `0` | Success. |
| `SANDBOX_ERR_POOL_EXHAUSTED` | `-1` | No warm VM and the wait timed out (or a per-session/uid cap was hit). |
| `SANDBOX_ERR_INVALID_SPEC` | `-2` | Unknown template or invalid memory/vCPU value. |
| `SANDBOX_ERR_DAEMON_UNREACHABLE` | `-3` | Could not connect to / talk to the daemon socket. |
| `SANDBOX_ERR_PERMISSION_DENIED` | `-4` | Rejected by the daemon (e.g. peer-uid allow-list). |
| `SANDBOX_ERR_INTERNAL` | `-5` | Unexpected daemon-side failure. |
| `SANDBOX_ERR_SESSION_EXPIRED` | `-6` | The session's TTL has passed; its volume is already gone, so there is nothing to renew. |
| `SANDBOX_ERR_SESSION_LIMIT` | `-7` | The session is already at the platform maximum lifetime (`SANDBOX_WORKSPACE_MAX_TTL`, 30 days by default). |
| `SANDBOX_ERR_SESSION_UNKNOWN` | `-8` | No volume exists for that session key. |
| `SANDBOX_ERR_GUEST_UNAVAILABLE` | `-9` | The guest agent could not be reached or is not ready, or the per-session cap on concurrent guest operations was hit. Retryable. |
| `SANDBOX_ERR_PATH_DENIED` | `-10` | A file path was not absolute, contained `.`/`..`, or resolved outside `/workspace` (including through a symlink). |
| `SANDBOX_ERR_NOT_FOUND` | `-11` | The path does not exist. |
| `SANDBOX_ERR_EXISTS` | `-12` | The path exists and the call asked for exclusivity (`SANDBOX_WRITE_EXCL`, or `mkdir` without `parents`). |
| `SANDBOX_ERR_TOO_LARGE` | `-13` | A file, chunk or stdin is over its limit (4 MiB / 48 KiB / 64 KiB). |
| `SANDBOX_ERR_GUEST_IO` | `-14` | The guest's filesystem failed the operation (full disk, a directory where a file was expected, …). |
| `SANDBOX_ERR_TIMEOUT` | `-15` | The host-side deadline expired before the guest answered. |

### Functions

```c
sandbox_error_t sandbox_init(const char* socket_path);
sandbox_error_t sandbox_create(const sandbox_spec_t* spec, sandbox_handle_t** out_handle);
sandbox_error_t sandbox_pause(sandbox_handle_t* handle);
sandbox_error_t sandbox_resume(sandbox_handle_t* handle);
sandbox_error_t sandbox_destroy(sandbox_handle_t* handle);
sandbox_error_t sandbox_inspect(sandbox_handle_t* handle, sandbox_status_t* out_status);

// Session volumes (#23). Keyed by session key, not by handle: the volume
// outlives every VM, so this works with nothing running.
sandbox_error_t sandbox_session_renew(const char* session_key,
                                      uint32_t extra_seconds,
                                      uint64_t* out_expires_at);
const char* sandbox_error_string(sandbox_error_t code);
void            sandbox_cleanup(void);

// Guest operations (#24): run commands and touch files in a running sandbox.
sandbox_error_t sandbox_exec(sandbox_handle_t*, const sandbox_exec_spec_t*, sandbox_exec_result_t*);
void            sandbox_exec_result_free(sandbox_exec_result_t*);
sandbox_error_t sandbox_read_file(sandbox_handle_t*, const char* path, uint8_t** data, size_t* len);
sandbox_error_t sandbox_write_file(sandbox_handle_t*, const char* path, const uint8_t* data,
                                   size_t len, uint32_t mode, uint32_t flags);
sandbox_error_t sandbox_list_dir(sandbox_handle_t*, const char* path, sandbox_dirent_t** entries,
                                 size_t* count, bool* truncated);
sandbox_error_t sandbox_stat(sandbox_handle_t*, const char* path, sandbox_fstat_t*);
sandbox_error_t sandbox_mkdir(sandbox_handle_t*, const char* path, uint32_t mode, bool parents);
sandbox_error_t sandbox_remove(sandbox_handle_t*, const char* path, bool recursive);
```

- `sandbox_init` opens the session socket. One process may hold several handles
  over the same session.
- `sandbox_create` blocks up to `pool_wait_ms` for a warm VM.
- `sandbox_cleanup` destroys **every** sandbox owned by the session and closes
  the socket. **A disconnected session reclaims its sandboxes**, so a client
  must stay connected for as long as it wants the VM alive.
- All functions are thread-safe, including on one shared connection: since
  #12 every request carries a correlation id and `libsandbox` runs a reader
  thread that matches the reply, so N threads may have N Creates in flight at
  once and the daemon may complete them in any order.
- A handle must not be used from one thread while destroyed in another.
- **Guest operations** (`sandbox_exec`, `sandbox_*_file`, …) run on a daemon
  worker pool, concurrently, and may take as long as the command does. They
  require the session to own the sandbox (`SANDBOX_ERR_PERMISSION_DENIED`
  otherwise) and, on the wire, a non-zero `request_id` (`libsandbox` always sets
  one). At most 16 may be in flight per session; the rest get the retryable
  `SANDBOX_ERR_GUEST_UNAVAILABLE`.
  - `sandbox_exec` returns `SANDBOX_OK` for any command that ran — a non-zero
    exit, a timeout (`timed_out`) and a kill by the output cap
    (`output_truncated`) are results, not errors.
  - A reply is one 64 KiB IPC frame, so exec returns the **head** of each stream
    (32 KiB stdout, 16 KiB stderr) plus `out_total`/`err_total`, the bytes the
    command really wrote. For more, redirect to a file in `/workspace` and read
    it back. Input is bounded too: stdin ≤ 64 KiB.
  - `sandbox_read_file`/`sandbox_write_file` move whole files up to 4 MiB,
    chunked at 48 KiB per message internally. A write that fits one chunk replaces
    the file atomically; a larger one is sent as replace-then-append, so a failure
    partway can leave a partial file.
  - File paths are confined to `/workspace`; exec is not (a command can read
    whatever the guest can). The wire protocol has no "allow outside" switch;
    that exists only on the host↔guest leg for the engine's own use.

### Example

```c
#include <libsandbox.h>

sandbox_init("/var/run/sandbox-engine/engine.sock");
const char* env[] = {"GREETING=hello", NULL};
sandbox_spec_t spec = { .memory_mib = 512, .vcpu_count = 1,
                        .template_name = "python-agent",
                        .env_vars = env, .pool_wait_ms = 500 };
sandbox_handle_t* h = NULL;
if (sandbox_create(&spec, &h) != SANDBOX_OK) { /* handle error */ }
/* ... */
sandbox_destroy(h);
sandbox_cleanup();
```

## C++ wrapper (`libsandbox++`)

Header: `<libsandbox.hpp>` — link with `-lsandbox++`. RAII around the C API;
errors are thrown as `sandbox::SandboxError` (carrying a `sandbox_error_t`).

```cpp
namespace sandbox {
  class Spec {                                  // fluent
    Spec(uint64_t memory_mib, const std::string& template_name);
    Spec& vcpus(uint32_t n);
    Spec& env(const std::string& key, const std::string& value);
    Spec& pool_wait(uint32_t ms);
  };
  class Sandbox {                               // move-only handle
    void pause(); void resume();
    sandbox_status_t inspect() const;
    uint32_t id() const;
  };
  class Engine {
    explicit Engine(const std::string& sock = "/var/run/sandbox-engine/engine.sock");
    std::unique_ptr<Sandbox> create(const Spec& spec);
  };
}
```

```cpp
#include <libsandbox.hpp>

sandbox::Engine engine;
auto sb = engine.create(sandbox::Spec(512, "python-agent").vcpus(2).env("K", "V"));
sb->pause();
```

## CLI

```
sandbox-cli run    --template NAME [--socket PATH] [--memory MiB] [--vcpus N] [--wait MS]
                   [--session-key KEY] [--exec SCRIPT]...
                   [--egress HOST[:PORT]]... [--no-egress]
sandbox-cli verify --template NAME
```

- `run` creates one sandbox, prints a JSON line
  (`{"event":"created","sandbox_id":N,...}`), and **holds the session open**
  until `SIGINT`/`SIGTERM` (so the sandbox is not reclaimed), then destroys it.
  Exit code `1` on failure, `2` on usage error.
- `run --exec SCRIPT` (repeatable, up to 16) instead runs each script with
  `sh -c` in the new sandbox, prints its stdout/stderr and one
  `{"event":"exec",...,"exit_code":N}` line per script, destroys the sandbox and
  exits with the first non-zero exit status (`1` for an API error). A sandbox
  dies with its session, so commands for a given sandbox must come from the
  process that created it; use `--session-key` to carry `/workspace` across runs.
- `run --egress HOST` (repeatable, up to 16) limits the sandbox to those
  destinations; `--no-egress` gives it none. Without either, the daemon-wide
  policy applies. See [Egress policy](#egress-policy-26).
- `verify` runs the snapshot integrity check (`§10.10`) for a template and
  returns `0` if the manifest and files match, `1` otherwise.

### Egress policy (#26)

A sandbox reaches the outside world only through the credential broker, and
what the broker will relay is the **egress policy** copied into that sandbox's
session token when it is created. It cannot be changed afterwards and nothing in
the guest can widen it.

| `egress_allow` / `egress_deny_all` | Effective policy |
|---|---|
| unset / 0 | the daemon-wide `allowed_services` list (the default, as before #26) |
| entries / 0 | exactly those entries |
| unset / 1 | none: the broker refuses every request from this sandbox |
| entries / 1 | error (`SANDBOX_ERR_INVALID_SPEC`): contradictory |

Entries are `host`, `host:port` or `*.suffix[:port]` (case-insensitive;
`*.example.org` matches subdomains, not `example.org` itself). An entry with no
port matches any port; a request with no port counts as `443`. The daemon-wide
list is a **ceiling**: every entry a session asks for must be covered by it, so a
developer can narrow what the operator allows but never widen it. A request that
is not covered, is malformed, or lists more than 64 entries fails the create with
`SANDBOX_ERR_INVALID_SPEC` rather than being silently trimmed.

A destination named in the policy may be relayed **without** a stored credential,
which is what package indexes need. The daemon-wide `*` never earns that: with
no entry in `credentials.conf` such a request is still refused (`403`). Where a
credential *is* on file it is injected as before.

Every decision is logged by the broker as one JSON line carrying `sandbox_id`,
`host`, `decision` (`allowed_credentialed`, `allowed_anonymous`,
`denied_policy`, `denied_unconfigured`), the status and the latency, and counted
in `broker_egress_decisions_total{decision=...}` on the broker's `/metrics`.
Refused requests are logged too: they are the interesting ones.

```c
const char* hosts[] = { "pypi.org", "*.pythonhosted.org", NULL };
sandbox_spec_t spec = { .memory_mib = 256, .vcpu_count = 1,
                        .template_name = "debian", .egress_allow = hosts };
```

```cpp
engine.create(sandbox::Spec(256, "debian").allow_egress("pypi.org")
                                          .allow_egress("*.pythonhosted.org"));
engine.create(sandbox::Spec(256, "debian").no_egress());
```

## HTTP control-plane API (#27)

`sandbox-api` is a separate, **unprivileged** process in front of the daemon. It
turns the engine into something a web assistant (or the MCP gateway, #28) can call
over HTTP: a *session* is a persistent `/workspace` plus a VM that is provisioned on
demand and reclaimed when idle. It speaks libsandbox to the daemon over one IPC
connection; it holds no credentials and runs no code itself.

```
sandbox-api --socket /run/sandbox-api/api.sock --listen 127.0.0.1:8088 \
            --tokens /etc/sandbox-engine/api-tokens.conf
sandbox-api new-token alice      # prints the token once, and the tokens-file entry
```

### Sessions and determinism

`POST /v1/sessions {"key": "..."}` is **create-or-attach**. The session id is
`ses_` + 24 hex of SHA-256(owner, key); the engine workspace key is derived from the
same inputs. So the same principal and key always get the same id and the same
files, across VM reclaim, `DELETE`, and an API restart. A different principal using
the same key gets a different session and a different workspace. Omit `key` and the
API picks a random one.

| State | Meaning |
| --- | --- |
| `ready` | a VM is attached |
| `idle` | the VM was reclaimed after `--idle` seconds; the next call re-provisions one (workspace intact) |
| `closing` | being deleted |

### Endpoints

All bodies are JSON unless stated. Unknown request fields are rejected (400).

| Method and path | Purpose |
| --- | --- |
| `GET /v1/health` | liveness; no credentials |
| `POST /v1/sessions` | create or attach. Fields: `key`, `template`, `memory_mib`, `vcpus`, `ttl_seconds`, `env`, `egress_allow` (≤16 hosts), `egress_deny_all`. `201` new, `200` attached, `409` if an existing session has different resources |
| `GET /v1/sessions` | the caller's sessions |
| `GET /v1/sessions/{id}` | one session |
| `DELETE /v1/sessions/{id}` | release the VM and forget the session (`204`). The workspace remains until its TTL: the engine has no volume delete |
| `POST /v1/sessions/{id}/renew` | `{"ttl_seconds": N}`; returns the new `expires_at` |
| `POST /v1/sessions/{id}/exec` | `command` (shell) **or** `argv`; `cwd`, `env`, `timeout_ms`, `max_output`, `stdin` / `stdin_base64`, `output_encoding`, `stream` |
| `PUT/GET/DELETE /v1/sessions/{id}/files?path=` | raw bytes in and out; `PUT` takes `append=1` / `exclusive=1`; limit `SANDBOX_MAX_FILE` (4 MiB) → `413` |
| `GET /v1/sessions/{id}/stat?path=`, `/ls?path=` | metadata, directory listing |
| `POST /v1/sessions/{id}/mkdir` | `{"path": ..., "parents": bool}` |

`exec` returns `exit_code`, `term_signal`, `timed_out`, `output_truncated`,
`duration_ms`, `stdout`, `stderr`. Invalid UTF-8 is replaced with U+FFFD unless
`output_encoding` is `base64`. Paths must be under `/workspace` (`400 path_denied`).

### Streaming

`"stream": true` answers `text/event-stream` with `started`, `stdout`, `stderr`,
`exit` (and `error`) events plus `: keepalive` comments. **Output is delivered when
the command finishes**: the engine returns a command's output at completion, so this
is a transport for long commands (the connection stays alive), not live tailing. Live
streaming needs a streaming operation in the guest RPC and is not done.

### Authentication and isolation

* **TCP** requires a bearer token. The tokens file (INI, mode ≤ 0640, never
  group/world-writable) stores only `token_sha256`; comparison is constant time over
  every entry. Per-principal `max_sessions` and `templates` allow-list. Without
  tokens a TCP listener is refused at start-up; non-loopback needs `--allow-public-bind`
  (and TLS in front: the API speaks plain HTTP).
* **Unix socket** (mode 0600 by default): the caller is `uid:N` from `SO_PEERCRED`;
  no token.
* A session belongs to its principal. Anyone else gets `404`, identical to a session
  that does not exist.

### Idempotency

`Idempotency-Key` on `exec` replays the first response for 10 minutes instead of
running the command again (128-entry cache; `5xx` responses are not cached). Create
is idempotent by construction.

### Errors

`{"error": {"code": "...", "message": "..."}}`. Engine errors map as: invalid
argument/path → 400, not found → 404, quota/pool exhausted → 429 (with `Retry-After`),
timeout → 504, unavailable → 503, other → 500. `401` bad or missing token, `403`
template not allowed, `413` body/file too large, `501` chunked requests (send
`Content-Length`).

### Limits

JSON body ≤ 1 MiB; `--max-connections` 128; `--max-running` VMs 64 (least-recently-used
idle sessions are evicted to admit a new one); sessions per principal default 16.
One process holds one daemon connection, so total capacity is bounded by the engine's
per-connection caps (128 owned sandboxes, 16 concurrent guest operations). If the
daemon stays unreachable (3 failures in 10 s) the process exits `75` so systemd
restarts it. The session table is in memory: after a restart, re-POST `create` with
the same key to reattach.

## Determinism

"Deterministic" here means **a reproducible environment and start state**, not
bit-exact execution. For a given template (identified by `manifest.bin`, which
binds `memory.snap`, `vmstate` and `rootfs.ext4` by SHA-256), every sandbox
starts from the same state:

- **Wall clock**: the guest starts at current host time, not the template's
  capture time (`clock_realtime` on `/snapshot/load`; x86_64, host kernel
  ≥ 5.16). A template is therefore safe to keep for as long as you like.
- **Installed software and files**: identical, because all three files are
  hash-verified before the guest is resumed; a template cannot be changed
  silently. `sandbox-cli verify --template NAME` re-checks on demand.
- **Host view**: the guest sees the CPU model and kernel it was captured on.

What is **not** guaranteed:

- **Entropy and unique IDs.** Firecracker restores memory, so anything the
  template wrote before capture repeats across sandboxes. The pinned 6.18 guest
  kernel has `CONFIG_VMGENID=y`, so Firecracker's VMGenID notification makes the
  kernel reseed its CRNG on restore (visible in the restored guest's console as
  `crng reseeded due to virtual machine fork`): random bytes generated *after*
  the sandbox starts differ between sandboxes. Bytes captured *in* the template
  do not, including `/etc/machine-id`, SSH host keys, and any secret a build
  wrote. Generate per-session secrets after the sandbox starts, and never bake
  secrets into a template.
- **Timing/interleaving**: scheduler and device timing after resume are not
  reproducible, so lock-free races that a test wins on one run may lose on the
  next. That is a property of the workload, not of the sandbox.

A sandbox is therefore the right place for work that must *start* from a known
state (builds, tests, reproducible agent sessions), and the wrong place to store
long-lived secrets that were captured in a template.

## Wire protocol

Unix socket, length-prefixed protobuf messages (see
[`proto/sandbox.proto`](../proto/sandbox.proto)).

**Client → daemon:** `CreateRequest`, `DestroyRequest`, `PauseRequest`,
`ResumeRequest`, `InspectRequest`.
**Daemon → client:** `CreateResponse` (includes a 64-hex-char `session_token`),
`DestroyResponse`, `PauseResponse`, `ResumeResponse`, `InspectResponse`,
`ErrorResponse` (`error_code` maps to `sandbox_error_t`).

`Create` is served asynchronously by a worker pool; the `session_token` returned
in `CreateResponse` is the only credential a guest uses to reach the broker.

### Request correlation (#12)

Every `ClientMessage` may carry `request_id` (field 100, `uint64`); the daemon
echoes it on the matching `ServerMessage`, including errors.

- **Non-zero**: the client may have several requests in flight on one
  connection. Replies are *not* ordered — match them by `request_id`. This is
  what makes several Creates run concurrently on one session: the daemon
  dispatches all queued id-carrying Creates and replies as each finishes.
- **Zero** (or absent): legacy mode, byte-identical to the pre-0.15 wire. The
  daemon keeps that session's replies in request order and runs one Create at a
  time, because such a client identifies replies only by arrival order. A
  request with id 0 that is queued behind in-flight Creates waits for them, so
  it cannot overtake an earlier request.

A malformed frame that cannot be parsed replies with `request_id = 0`; a client
with outstanding ids must treat that as fatal for the connection, not as one of
its own replies.

## Guest RPC (#24)

Exec and file operations against a running sandbox. This is the *guest-facing*
protocol between the engine and the agent inside the VM; the client-facing
surface (`ClientMessage`, `libsandbox.h`, CLI) is wired separately.

Clients do not speak this directly: the daemon relays it (`GuestRequest` /
`GuestResponse` in `proto/sandbox.proto`, see the C library section above). The
daemon-to-guest limits below are larger than what one IPC reply can carry, and
`libsandbox` closes that gap by chunking.

Transport: vsock port 5002, reached through the VM's Firecracker UDS
(`CONNECT 5002\n`). One request per connection. Frame:
`u32le payload_len | u8 type | u8 0 | payload`; requests are
`u8 version(1) | u8 op | u32 flags | body`. Replies stream `STDOUT`/`STDERR`
frames (exec only) and end with one `RESULT`: `u8 status | i32 errno | body`
(a human message string when `status != 0`).

| Op | Body | Notes |
|---|---|---|
| `exec` | cwd, argv[], env[], timeout_ms, max_output, stdin | `GRPC_F_SHELL`: argv[0] is a script for `/bin/sh -c`. Own process group; killed on timeout, output cap, or host disconnect. Result: exit code, signal, flags (`TIMED_OUT`, `TRUNCATED`). Defaults: cwd `/workspace`, 1 h cap, 4 MiB output. |
| `read_file` | path, offset, max_bytes | ≤ 4 MiB; reports truncation. |
| `write_file` | path, mode, data | ≤ 4 MiB; overwrite is atomic (temp + rename); flags `APPEND`, `EXCL`, `PARENTS`. |
| `list_dir` | path | name, type, size, mtime. |
| `stat` | path | Does not follow a final symlink. |
| `mkdir` | path, mode | `PARENTS` = `mkdir -p`. |
| `remove` | path | `RECURSIVE` for directories; never `/` or the workspace root. |

Statuses: `0` ok, `1` bad request, `2` denied (outside `/workspace`, not
absolute, `..`, symlink escape), `3` not found, `4` I/O, `5` too large, `6` bad
version, `7` busy (16 connections max), `8` exists, `9` workspace not mounted.

A host-side deadline expiring closes the connection; the guest treats that as
cancellation and kills the exec's process group.

## Credential broker

The broker is an HTTP proxy. A guest sends a request with:

- `Host:` set to the allow-listed upstream (e.g. `api.openai.com`);
- `X-Sandbox-Token:` set to the `session_token` from `CreateResponse`;
- a normal origin-form target (`GET /v1/models HTTP/1.1`).

The broker then:

1. validates the token against the engine (returns `401` if invalid/expired);
2. checks `Host` against the token's allow-list (`403` if not allowed);
3. removes `X-Sandbox-Token`, injects `Authorization: <credential>` from
   `credentials.conf`;
4. proxies to `https://<host><target>` and streams the response back.

### What a guest is given

A sandbox with a non-empty policy gets, at Create, in the same single exchange
as its `env_vars`: an address for its NIC (the guest end of a private `/30` on
its own tap, `169.254.x.y`; the host end is where the broker listens), and these
variables, which every `exec` inherits:

| Variable | Value |
|---|---|
| `http_proxy`, `https_proxy` (and upper-case) | `http://sandbox:<token>@<host end>:<broker port>` |
| `no_proxy`, `NO_PROXY` | `127.0.0.1,localhost` |
| `SANDBOX_BROKER` | `<host end>:<broker port>` |
| `SANDBOX_SESSION_TOKEN` | the session token |
| `SANDBOX_NET_ADDR`, `SANDBOX_NET_MASK` | what the guest agent configured |

A variable the spec's `env_vars` already sets is left alone, so a spec can
override any of them. A sandbox whose policy is empty (`no_egress()`, or an empty
daemon list) gets **none** of this: no address, no variables, no route. Its NIC
stays unconfigured, which is the strongest form of deny-all.

The host drops everything the guest sends except TCP to the broker port on the
host end of its own `/30` (`src/network_manager.c`), so the broker is the only
thing reachable, whatever the guest tries.

Since #26 the spec's `env_vars` also reach `exec`'d commands. Until then they
were written to a file inside the guest that nothing read.

### Using it as a proxy

Stock tools reach the broker the way they reach any forward proxy, so no
per-tool glue is needed. Give them the broker's address and the session token as
the proxy password (the user name is ignored):

```
export http_proxy=http://sandbox:<session_token>@<broker host>:8080
export https_proxy=$http_proxy
pip install --target /workspace/lib requests     # CONNECT pypi.org:443, files.pythonhosted.org:443
curl http://pypi.org/simple/                     # absolute-form, upgraded to https by the broker
```

The broker understands three request shapes:

1. **Origin-form with `X-Sandbox-Token`** (as above): `Host:` names the upstream.
2. **Absolute-form** (`GET http://host/path`): the URI's authority names the
   upstream (the `Host:` header is ignored, as a proxy must) and the broker
   always speaks https to it. Userinfo or a fragment in the target → `400`.
3. **`CONNECT host:port`**: an opaque tunnel, which is what `https_proxy`
   clients (pip, npm, apt-over-https) use. The broker cannot see inside TLS and
   so cannot inject a credential; it therefore tunnels **only to destinations the
   session's policy names**, never on the strength of the daemon-wide `*`. An
   entry with no port allows any port; write `host:443` to pin it.

Credentials for 2 and 3 travel as `Proxy-Authorization: Basic base64(user:token)`.
A missing or unusable one gets `407` with `Proxy-Authenticate` (rather than `401`)
so tools prompt for it. The broker strips `Proxy-Authorization`,
`Proxy-Connection` and `X-Sandbox-Token` before forwarding.

The broker only connects to **public** addresses. A name the policy allows that
resolves to loopback, RFC 1918, link-local (`169.254/16`: the VM subnets and the
cloud metadata address), CGNAT or multicast space is refused with `403`
(`decision":"denied_address"`), for relayed requests and tunnels alike; see
`SANDBOX_BROKER_ALLOW_PRIVATE_UPSTREAM` in CONFIGURATION.md. Each connection is
served on its own thread (`SANDBOX_BROKER_MAX_CONNS`), and the bytes moved in each
direction are logged and exported as `broker_relayed_bytes_total`.

Both directions are streamed with bounded memory: a request body is relayed a
buffer at a time and never held whole, so a multi-hundred-MiB upload costs the
same as a small one. A `Content-Length` body is forwarded with that length; a
`Transfer-Encoding: chunked` body is decoded as it arrives and re-chunked
towards the upstream (trailers are dropped, chunk extensions ignored). If a
request carries both, chunked wins. Any other transfer coding is refused.

The body size limit is `SANDBOX_BROKER_MAX_BODY` bytes (default 256 MiB). A
declared `Content-Length` over it is refused before anything is sent upstream;
a chunked body is cut off when it crosses it, so the upstream never sees a
silently truncated request as complete. Successful calls and rejections are
counted in the broker's `/metrics`.

Errors: `400` malformed request or body (bad chunk framing, short body,
unsupported transfer coding, bad target), `401` missing/invalid token, `403` host
not allow-listed or address not permitted, `407` the same for proxy-style
requests, `413` request body over the limit, `502` upstream failure, `503`
broker at its connection limit.
