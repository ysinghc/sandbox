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
sandbox-cli verify --template NAME
```

- `run` creates one sandbox, prints a JSON line
  (`{"event":"created","sandbox_id":N,...}`), and **holds the session open**
  until `SIGINT`/`SIGTERM` (so the sandbox is not reclaimed), then destroys it.
  Exit code `1` on failure, `2` on usage error.
- `verify` runs the snapshot integrity check (`§10.10`) for a template and
  returns `0` if the manifest and files match, `1` otherwise.

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

Request bodies are decoded (bounded at 8 MiB, re-framed with `Content-Length`);
responses are streamed. Successful calls and rejections are counted in the
broker's `/metrics`.

Errors: `400` malformed request, `401` missing/invalid token, `403` host not
allow-listed, `502` upstream failure.
