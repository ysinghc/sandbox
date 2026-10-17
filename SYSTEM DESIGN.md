# Sandbox Engine — Low-Level Design Document

**Project:** Firecracker-based sandboxing engine for AI agent isolation  
**Target:** Production-grade implementation, portfolio piece for Dedalus Labs (YC S25)  
**Language:** C (core engine) + C++ (RAII wrapper)  
**Deployment:** Standalone daemon with Unix socket IPC

---

## 1. System Overview

### 1.1 Purpose

A sandboxing engine that provisions isolated execution environments for AI agents in sub-100ms using Firecracker microVMs with userfaultfd-based snapshot restore. The engine provides hardware-level isolation (KVM) with minimal provisioning latency via a warm VM pool and lazy memory loading.

### 1.2 Key Requirements

| Requirement | Target | Rationale |
|---|---|---|
| Provisioning latency | < 100ms from API call to guest-running | Agent interaction feels synchronous |
| Isolation strength | Hardware VM boundary (KVM) | Prompt injection makes agent code adversarial |
| Guest compatibility | Arbitrary unmodified Linux binaries | Python/Node agents run without recompilation |
| Memory overhead | < 10MB per idle VM | Pool of 10–20 warm VMs is economically viable |
| Credential safety | Zero long-lived credentials in guest | Guest compromise cannot exfiltrate API keys |

### 1.3 Non-Goals (Explicit Scope Limits)

- Multi-backend abstraction (namespaces/gVisor/etc.) — single backend only, Firecracker
- Dynamic pool auto-scaling — static pool size, runtime-configurable
- GUI/TUI control plane — API-only; CLI for ops, no desktop UI in scope
- Windows/macOS host support — Linux-only (KVM dependency)

---

## 2. Architecture Decisions

### 2.1 Isolation Backend: Firecracker + userfaultfd

**Decision:** Firecracker microVM with userfaultfd-based lazy snapshot restore.

**Why Firecracker:**
- KVM hardware boundary — guest kernel compromise is contained to that guest
- Rust VMM — memory-safe, no buffer overflow / use-after-free class
- Production-proven at AWS Lambda scale
- Full Linux guest compatibility (no compilation constraint on agent code)

**Why userfaultfd:**
- Cold boot ~125ms + app init (seconds) is non-viable for < 100ms target
- Eager snapshot restore (read all memory from disk) costs ~7,140ms for 2GB guest
- Lazy restore via userfaultfd: ~83ms to vCPU resume, pages loaded on-demand
- Prefault worker streams remaining pages in background (50–200ms full warm)

**Why not namespaces:**
- Shared kernel — kernel vuln has blast radius across all sandboxes on host
- Prompt injection → treat agent code as adversarial → hardware boundary correct default

### 2.2 Privilege Model: Rootful Daemon, Jailed VMM

**Decision:** Engine daemon runs as root. Each Firecracker VMM process runs unprivileged inside a Jailer (chroot + seccomp + cgroup + capability drop).

**Daemon privilege flow:**
```
Engine daemon (root, PID 1000)
  → creates tap device (requires CAP_NET_ADMIN)
  → writes cgroup hierarchy (requires root)
  → spawns Jailer binary (root → Jailer does privilege drop)
    Jailer (PID 1001, root initially)
      → chroot into /var/lib/sandbox-engine/jail/<vm-id>/
      → write cgroup files, place self in cgroup
      → setuid/setgid to unprivileged uid (e.g., 65534)
      → apply seccomp-bpf filter
      → exec Firecracker binary
        Firecracker VMM (PID 1001, uid 65534, chrooted, seccomp-filtered)
          → opens /dev/kvm inside jail
          → guest runs inside KVM hardware boundary
```

**Security boundary established:**
- Guest workload: isolated by KVM hardware (cannot touch host kernel directly)
- Firecracker VMM: unprivileged + chrooted + seccomp (guest's only reach into host userspace)
- Engine daemon: root but has no guest-controlled input paths (all guest I/O via Firecracker's API socket)

### 2.3 IPC: Unix Socket + Protobuf

**Decision:** `SOCK_SEQPACKET` Unix domain socket at `/var/run/sandbox-engine/engine.sock`, length-prefixed protobuf, persistent per-client-session connections.

**Why SEQPACKET:** Message boundaries preserved by kernel — no framing code, no partial reads.

**Why protobuf:** Formal schema, backward-compatible versioning, strongly-typed client bindings.

**Why persistent connections:** Daemon already needs epoll loop for pidfd watching — connection multiplexing is free. Lower per-call overhead than reconnect-per-request.

### 2.4 Credential Brokering: HTTP Proxy + Session Tokens

**Decision:** Separate broker process, HTTP proxy at link-local `169.254.0.1:8080`, session tokens only in guest.

**Flow:**
```
Guest agent (169.254.0.2)
  → HTTP request to proxy with X-Sandbox-Token: <session-token>
  → plain HTTP on link-local tap interface (never leaves host)
Broker (169.254.0.1:8080)
  → validates token, checks allowlist
  → strips token, injects real credential (API key)
  → makes real HTTPS call to upstream (api.openai.com)
  → streams response back to guest
```

**Why separate process:** Broker holds credentials, engine holds none — if engine has bug, credentials never reachable.

**Why session tokens:** Guest never holds long-lived credentials. Token is 256-bit random value, valid only for sandbox lifetime, worthless outside broker's validation context.

---

## 3. Public API

### 3.1 C API Surface

**Header:** `libsandbox.h`

```c
#ifndef LIBSANDBOX_H
#define LIBSANDBOX_H

#include <stdint.h>
#include <stdbool.h>

// Opaque handle to a running sandbox
typedef struct sandbox_handle_t sandbox_handle_t;

// Configuration for sandbox creation
typedef struct {
    uint64_t memory_mib;        // Guest memory in MiB (e.g., 512)
    uint32_t vcpu_count;        // Number of vCPUs (e.g., 1)
    const char* template_name;  // Snapshot template to restore from (e.g., "python-agent")
    const char** env_vars;      // NULL-terminated array of "KEY=VALUE" strings
    uint32_t pool_wait_ms;      // Max time to wait if pool exhausted, 0 = fail immediately
} sandbox_spec_t;

// Error codes
typedef enum {
    SANDBOX_OK = 0,
    SANDBOX_ERR_POOL_EXHAUSTED  = -1,  // Pool empty and wait timed out
    SANDBOX_ERR_INVALID_SPEC    = -2,  // Bad config (unknown template, invalid memory size)
    SANDBOX_ERR_DAEMON_UNREACHABLE = -3,
    SANDBOX_ERR_PERMISSION_DENIED  = -4,
    SANDBOX_ERR_INTERNAL           = -5,
} sandbox_error_t;

// Initialize client connection to daemon
// Returns 0 on success, error code on failure
sandbox_error_t sandbox_init(const char* socket_path);

// Create a new sandbox from the specified template
// On success, returns SANDBOX_OK and writes handle to *out_handle
// On failure, returns error code
sandbox_error_t sandbox_create(const sandbox_spec_t* spec, sandbox_handle_t** out_handle);

// Pause vCPU execution (guest state frozen, memory preserved)
sandbox_error_t sandbox_pause(sandbox_handle_t* handle);

// Resume vCPU execution
sandbox_error_t sandbox_resume(sandbox_handle_t* handle);

// Destroy sandbox and reclaim resources
// After this call, handle is invalid
sandbox_error_t sandbox_destroy(sandbox_handle_t* handle);

// Query sandbox status
typedef struct {
    uint32_t sandbox_id;
    bool is_running;          // false if paused
    uint64_t uptime_ms;       // Time since vCPU resume
    uint64_t memory_rss_mib;  // Resident set size
    uint32_t page_faults;     // Cumulative uffd page faults served
} sandbox_status_t;

sandbox_error_t sandbox_inspect(sandbox_handle_t* handle, sandbox_status_t* out_status);

// Disconnect from daemon (destroys all sandboxes owned by this session)
void sandbox_cleanup(void);

#endif // LIBSANDBOX_H
```

### 3.2 C++ RAII Wrapper

**Header:** `libsandbox.hpp`

```cpp
#ifndef LIBSANDBOX_HPP
#define LIBSANDBOX_HPP

#include "libsandbox.h"
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

namespace sandbox {

class SandboxError : public std::runtime_error {
public:
    explicit SandboxError(sandbox_error_t code)
        : std::runtime_error(error_string(code)), code_(code) {}
    sandbox_error_t code() const { return code_; }
private:
    static const char* error_string(sandbox_error_t code);
    sandbox_error_t code_;
};

class Spec {
public:
    Spec(uint64_t memory_mib, const std::string& template_name)
        : memory_mib_(memory_mib), vcpu_count_(1), template_name_(template_name), pool_wait_ms_(500) {}
    
    Spec& vcpus(uint32_t count) { vcpu_count_ = count; return *this; }
    Spec& env(const std::string& key, const std::string& value) {
        env_vars_.push_back(key + "=" + value);
        return *this;
    }
    Spec& pool_wait(uint32_t ms) { pool_wait_ms_ = ms; return *this; }
    
    sandbox_spec_t to_c_struct() const;
private:
    uint64_t memory_mib_;
    uint32_t vcpu_count_;
    std::string template_name_;
    std::vector<std::string> env_vars_;
    uint32_t pool_wait_ms_;
};

class Sandbox {
public:
    explicit Sandbox(const Spec& spec);
    ~Sandbox();
    
    // Move-only (no copy — handle is unique)
    Sandbox(Sandbox&& other) noexcept;
    Sandbox& operator=(Sandbox&& other) noexcept;
    Sandbox(const Sandbox&) = delete;
    Sandbox& operator=(const Sandbox&) = delete;
    
    void pause();
    void resume();
    sandbox_status_t inspect() const;
    
    uint32_t id() const;
    
private:
    sandbox_handle_t* handle_;
};

class Engine {
public:
    explicit Engine(const std::string& socket_path = "/var/run/sandbox-engine/engine.sock");
    ~Engine();
    
    std::unique_ptr<Sandbox> create(const Spec& spec);
    
private:
    bool initialized_;
};

} // namespace sandbox

#endif // LIBSANDBOX_HPP
```

---

## 4. Component Design

### 4.1 Component Graph

```
┌─────────────────────────────────────────────────────────────┐
│  Client Process (uses libsandbox.so)                        │
│    ↓  SOCK_SEQPACKET + protobuf                             │
├─────────────────────────────────────────────────────────────┤
│  Sandbox Engine Daemon (sandboxd)                           │
│                                                              │
│  ┌──────────────┐        ┌──────────────┐                  │
│  │ IPC Server   │───────→│ Session Mgr  │                  │
│  │ (epoll loop) │        │ (per-client  │                  │
│  └──────────────┘        │  state)      │                  │
│         ↓                └──────────────┘                   │
│  ┌──────────────────────────────────────────┐              │
│  │         Pool Manager                     │              │
│  │  - warm VM queue                         │              │
│  │  - overflow request queue                │              │
│  │  - replenishment thread                  │              │
│  └──────────────────────────────────────────┘              │
│         ↓                       ↓                           │
│  ┌──────────────┐        ┌──────────────┐                  │
│  │ VMM Manager  │        │ Snapshot Mgr │                  │
│  │ (Firecracker │        │ (template    │                  │
│  │  lifecycle)  │        │  creation)   │                  │
│  └──────────────┘        └──────────────┘                  │
│         ↓                       ↓                           │
│  ┌──────────────┐        ┌──────────────┐                  │
│  │ Jailer       │        │ UFFD Handler │                  │
│  │ (chroot +    │        │ (page fault  │                  │
│  │  seccomp)    │        │  resolution) │                  │
│  └──────────────┘        └──────────────┘                  │
│         ↓                       ↓                           │
│  ┌──────────────┐        ┌──────────────┐                  │
│  │ Network Mgr  │        │ Prefault Wkr │                  │
│  │ (tap devices)│        │ (background  │                  │
│  └──────────────┘        │  streaming)  │                  │
│                          └──────────────┘                  │
└─────────────────────────────────────────────────────────────┘
         ↓                              ↓
┌──────────────────┐         ┌──────────────────┐
│ Firecracker VMM  │         │ Credential Broker│
│ (per VM, uid     │         │ (separate proc,  │
│  65534, jailed)  │         │  holds API keys) │
└──────────────────┘         └──────────────────┘
         ↓                              ↑
┌──────────────────┐                    │
│ Guest VM         │                    │
│ (KVM boundary)   │────────────────────┘
│                  │  HTTP to 169.254.0.1:8080
└──────────────────┘
```

### 4.2 Threading Model

| Thread | Lifecycle | Purpose |
|---|---|---|
| Main (IPC server) | Daemon lifetime | `epoll_wait()` on client connections + pidfd events |
| Replenishment thread | Daemon lifetime | Blocks on condition variable, restores VMs from snapshot when pool drains |
| Per-VM uffd_handler | VM restore → destroy | Blocks on `read(uffd_fd)`, serves page faults synchronously |
| Per-VM prefault_worker | VM restore → destroy | Streams snapshot pages into page cache in background |

---

## 5. Detailed Component Specifications

> The code bodies in this section are the **LLD pseudocode**. Where the shipped
> implementation differs (ordering, signatures, file layout, syscall set, …),
> **§15 (Ground-Truth Deviations) is authoritative**.

### 5.1 Pool Manager

**Responsibility:** Maintain a fixed-size pool of warm VMs, serve provision requests from the pool, queue overflow requests.

**Data structures:**

```c
typedef struct {
    vm_handle_t* warm_queue[POOL_MAX_SIZE];  // Circular buffer
    int warm_head, warm_tail, warm_count;
    
    pending_request_t* overflow_queue[POOL_MAX_QUEUE_DEPTH];
    int overflow_head, overflow_tail, overflow_count;
    
    int target_size;        // Runtime-configurable (from config file)
    int restoring_count;    // VMs currently being restored (not yet warm)
    
    pthread_mutex_t lock;
    pthread_cond_t vm_available;    // Signaled when warm VM enqueued
    pthread_cond_t slot_available;  // Signaled when replenishment can start
    bool shutdown;
} pool_manager_t;
```

**Invariant:**
```c
warm_count + restoring_count <= target_size
```

**Critical paths:**

1. **Provision from warm pool (fast path):**
```c
pthread_mutex_lock(&pool->lock);
if (pool->warm_count > 0) {
    vm = pool->warm_queue[pool->warm_head];
    pool->warm_head = (pool->warm_head + 1) % POOL_MAX_SIZE;
    pool->warm_count--;
    pool->restoring_count++;  // Reserve slot for replenishment
    pthread_cond_signal(&pool->slot_available);
    pthread_mutex_unlock(&pool->lock);
    return vm;  // < 1ms if pool hit
}
```

2. **Provision with overflow queue (slow path):**
```c
if (pool->overflow_count >= POOL_MAX_QUEUE_DEPTH) {
    return SANDBOX_ERR_POOL_EXHAUSTED;  // Immediate rejection
}
pending_request_t req = { .result = NULL, .ready = false };
enqueue_overflow(pool, &req);
struct timespec deadline = now_plus_ms(spec->pool_wait_ms);
while (!req.ready && !pool->shutdown) {
    int rc = pthread_cond_timedwait(&pool->vm_available, &pool->lock, &deadline);
    if (rc == ETIMEDOUT) {
        dequeue_overflow(pool, &req);
        return SANDBOX_ERR_POOL_EXHAUSTED;
    }
}
return req.result;  // Handed off by replenishment thread
```

3. **Replenishment thread:**
```c
void* replenishment_thread(void* arg) {
    pool_manager_t* pool = arg;
    for (;;) {
        pthread_mutex_lock(&pool->lock);
        while (pool->warm_count + pool->restoring_count >= pool->target_size) {
            pthread_cond_wait(&pool->slot_available, &pool->lock);
        }
        pool->restoring_count++;
        pthread_mutex_unlock(&pool->lock);
        
        // Restore VM from snapshot (blocking, ~83ms)
        vm_handle_t* vm = restore_vm_from_snapshot();
        
        pthread_mutex_lock(&pool->lock);
        pool->restoring_count--;
        if (pool->overflow_count > 0) {
            // Hand directly to waiting caller
            pending_request_t* req = peek_overflow(pool);
            req->result = vm;
            req->ready = true;
            dequeue_overflow(pool, req);
            pthread_cond_broadcast(&pool->vm_available);
        } else {
            // Enqueue to warm pool
            pool->warm_queue[pool->warm_tail] = vm;
            pool->warm_tail = (pool->warm_tail + 1) % POOL_MAX_SIZE;
            pool->warm_count++;
        }
        pthread_mutex_unlock(&pool->lock);
    }
}
```

**Configuration (runtime):**
```ini
# /var/lib/sandbox-engine/config/engine.conf
[pool]
target_size = 5
max_queue_depth = 50
pool_wait_timeout_ms = 500
```

---

### 5.2 UFFD Handler

**Responsibility:** Serve guest page faults on-demand from mmap'd snapshot file. One thread per VM.

**Setup sequence (on restore):**

```c
// 1. mmap snapshot into daemon address space
void* snap_base = mmap(NULL, snap_size, PROT_READ, MAP_SHARED, snap_fd, 0);

// 2. Register guest memory region with userfaultfd
int uffd_fd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
struct uffdio_api api = { .api = UFFD_API, .features = 0 };
ioctl(uffd_fd, UFFDIO_API, &api);

struct uffdio_register reg = {
    .range = { .start = (uint64_t)guest_mem_base, .len = guest_mem_size },
    .mode = UFFDIO_REGISTER_MODE_MISSING,
};
ioctl(uffd_fd, UFFDIO_REGISTER, &reg);

// 3. Spawn fault handler thread BEFORE vCPU resume
pthread_create(&vm->uffd_thread, NULL, uffd_thread_fn, vm);

// 4. Resume vCPUs — guest starts executing, faults delegated to uffd_fd
vmm_resume_vcpus(vm);
```

**Fault handler loop:**

```c
void* uffd_thread_fn(void* arg) {
    vm_handle_t* vm = arg;
    struct uffd_msg msg;
    
    for (;;) {
        ssize_t nread = read(vm->uffd_fd, &msg, sizeof(msg));
        if (nread <= 0) break;  // fd closed (VM destroyed) or error
        
        if (msg.event != UFFD_EVENT_PAGEFAULT) continue;
        
        uint64_t fault_addr = msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
        uint64_t offset = fault_addr - (uint64_t)vm->guest_mem_base;
        
        if (snapshot_page_present(vm->manifest, offset)) {
            // Non-zero page: copy from snapshot
            struct uffdio_copy copy = {
                .dst = fault_addr,
                .src = (uint64_t)(vm->snap_base + offset),
                .len = PAGE_SIZE,
                .mode = 0,
            };
            ioctl(vm->uffd_fd, UFFDIO_COPY, &copy);
        } else {
            // Zero page: kernel maps zero page (cheaper than copy)
            struct uffdio_zeropage zero = {
                .range = { .start = fault_addr, .len = PAGE_SIZE },
                .mode = 0,
            };
            ioctl(vm->uffd_fd, UFFDIO_ZEROPAGE, &zero);
        }
    }
    return NULL;
}
```

**Race safety:** The `uffdio_register` call must complete before `vmm_resume_vcpus()`. The kernel holds faulting vCPUs blocked until the handler serves the fault — no window for unhandled guest page access.

**Latency profile:**
- Page in page cache: ~1–10µs (`UFFDIO_COPY` from mmap, no disk I/O)
- Page cold (not in cache): ~50–200µs (mmap fault triggers disk read, then `UFFDIO_COPY`)
- `prefault_worker` races to warm cache within 50–200ms post-resume

---

### 5.3 Prefault Worker

**Responsibility:** Stream snapshot pages into page cache in background after vCPU resume.

**Thread function:**

```c
void* prefault_worker_fn(void* arg) {
    vm_handle_t* vm = arg;
    
    // Advise kernel: sequential read-ahead
    madvise(vm->snap_base, vm->snap_size, MADV_SEQUENTIAL);
    
    // Touch every page to fault it into page cache
    for (size_t off = 0; off < vm->snap_size; off += PAGE_SIZE) {
        if (vm->destroyed) break;  // Early exit if VM destroyed mid-stream
        
        volatile uint8_t touch = *((uint8_t*)vm->snap_base + off);
        (void)touch;  // Suppress unused warning
    }
    return NULL;
}
```

**Coordination with uffd_handler:** No explicit coordination needed. Both threads read from the same mmap region. The `uffd_handler` serves faults synchronously on-demand; `prefault_worker` races to populate the page cache so subsequent faults hit cache instead of disk.

---

### 5.4 Jailer

**Responsibility:** Confine and privilege-drop the Firecracker VMM process before it handles any guest input.

**Execution sequence:**

```c
// Called by vmm_manager when spawning a new Firecracker process
int spawn_firecracker_jailed(const char* vm_id, const jailer_config_t* config) {
    pid_t pid = fork();
    if (pid != 0) return pid;  // Parent returns child PID
    
    // Child becomes the Jailer, then execs Firecracker
    
    // 1. Create jail directory structure
    char jail_root[PATH_MAX];
    snprintf(jail_root, sizeof(jail_root), "/var/lib/sandbox-engine/jail/%s", vm_id);
    mkdir_recursive(jail_root, 0755);
    
    // 2. Bind-mount /dev/kvm, /dev/net/tun into jail
    mount_jail_devices(jail_root);
    
    // 3. chroot into jail
    chroot(jail_root);
    chdir("/");
    
    // 4. Place self in cgroup (memory/CPU limits for VMM process)
    write_cgroup_procs(config->cgroup_path, getpid());
    
    // 5. Drop capabilities (keep only CAP_NET_ADMIN if needed for tap, then drop that too)
    drop_capabilities();
    
    // 6. setuid/setgid to unprivileged uid
    setgid(config->jailer_gid);  // e.g., 65534
    setuid(config->jailer_uid);  // e.g., 65534
    
    // 7. Apply seccomp filter
    apply_seccomp_filter();  // Whitelist from §5.5
    
    // 8. exec Firecracker
    execve("/firecracker", firecracker_args, env);
    _exit(127);  // exec failed
}
```

**Jail directory layout:**

```
/var/lib/sandbox-engine/jail/<vm-id>/
  dev/
    kvm          → bind-mount of /dev/kvm
    net/
      tun        → bind-mount of /dev/net/tun
  firecracker    → copy of Firecracker binary
  api.sock       → Unix socket for Firecracker API (created by Firecracker)
```

> **Superseded in the implementation:** the device nodes are fresh `mknod` +
> `chown` (not bind mounts), and the jail also carries `/vmlinux`,
> `/rootfs.ext4`, `/vmstate`, `/memory.snap`, `/out`, `/uffd.sock`,
> `/serial.log` and (when present) `/dev/userfaultfd`. See §15.3.

---

### 5.5 Jailer Seccomp Policy

**Default action:** Build-time toggle

```c
#ifdef NDEBUG
  #define JAILER_SECCOMP_DEFAULT SCMP_ACT_KILL_PROCESS  // Release
#else
  #define JAILER_SECCOMP_DEFAULT SCMP_ACT_ERRNO(EPERM)  // Debug
#endif
```

**Whitelist (Firecracker VMM process):**

```c
int apply_seccomp_filter(void) {
    scmp_filter_ctx ctx = seccomp_init(JAILER_SECCOMP_DEFAULT);
    
    // KVM interaction
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
                     SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFF00, 0xAE00));  // KVM_* ioctls only
    
    // Memory management
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
    
    // File I/O (snapshot files, API socket)
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    
    // Signaling
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    
    // Epoll/event loop
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd), 0);
    
    // Threading
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
                     SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_VM, CLONE_VM));  // Thread creation only
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    
    // Process lifecycle
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
    
    // Time
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep), 0);
    
    // Load filter
    seccomp_load(ctx);
    seccomp_release(ctx);
    return 0;
}
```

**Critical detail:** `ioctl` is argument-filtered to allow only `KVM_*` commands (`0xAE00` family). Blanket-allowing `ioctl` would undermine the entire filter.

> **Superseded in the implementation:** the shipped filter is broader than this
> sketch — it mirrors Firecracker's own aarch64 policy plus the calls it makes
> before installing its per-thread filters, and its `ioctl` allow-list also
> covers the UFFD class (`0xAA`) and specific tap/block/terminal requests. See
> §15.3.

---

### 5.6 Snapshot Manager

**Responsibility:** Create snapshot templates (boot VM, serialize to disk), manage snapshot versions.

**Snapshot layout:**

```
/var/lib/sandbox-engine/snapshots/<template-name>/
  vmstate              # Firecracker microVM state file (~KB, JSON+binary)
  memory.snap          # Guest memory dump (sparse file, memory_mib × 1MiB)
  manifest.bin         # Page bitmap + metadata
  vmlinux              # bundled kernel copy      (implementation; see §15.5)
  rootfs.ext4          # bundled rootfs copy      (implementation; see §15.5)
```

**Manifest format:**

```c
typedef struct {
    uint32_t magic;          // 0x534E4150 ("SNAP")
    uint32_t version;        // Incremented on every template rebuild
    uint64_t guest_mem_size; // Total guest memory bytes
    uint32_t page_size;      // Always 4096
    uint32_t page_count;     // guest_mem_size / page_size
    uint8_t  page_bitmap[];  // 1 bit per page: 1=present, 0=zero (packed)
} snap_manifest_t;
```

**Template creation flow:**

```c
int create_snapshot_template(const char* template_name, const template_config_t* config) {
    char temp_dir[PATH_MAX];
    snprintf(temp_dir, sizeof(temp_dir), "/var/lib/sandbox-engine/snapshots/.tmp-%s", template_name);
    mkdir(temp_dir, 0755);
    
    // 1. Boot a fresh VM (cold boot, ~125ms)
    vm_handle_t* vm = vmm_cold_boot(config);
    
    // 2. Wait for application init to complete inside guest
    //    (Guest signals readiness via vsock or by writing to a known file)
    wait_for_guest_ready(vm);
    
    // 3. Pause vCPUs
    vmm_pause_vcpus(vm);
    
    // 4. Call Firecracker API: create_snapshot
    char vmstate_path[PATH_MAX], memory_path[PATH_MAX];
    snprintf(vmstate_path, sizeof(vmstate_path), "%s/vmstate", temp_dir);
    snprintf(memory_path, sizeof(memory_path), "%s/memory.snap", temp_dir);
    firecracker_create_snapshot(vm, vmstate_path, memory_path);
    
    // 5. Scan memory.snap, build page bitmap
    snap_manifest_t* manifest = build_manifest(memory_path);
    manifest->version = read_current_version(template_name) + 1;
    
    char manifest_path[PATH_MAX];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.bin", temp_dir);
    write_manifest(manifest_path, manifest);
    
    // 6. Atomic rename to final path
    char final_dir[PATH_MAX];
    snprintf(final_dir, sizeof(final_dir), "/var/lib/sandbox-engine/snapshots/%s", template_name);
    rename(temp_dir, final_dir);  // Atomic on same filesystem
    
    // 7. Destroy template VM
    vmm_destroy(vm);
    
    // 8. Signal pool manager: new version available
    pool_manager_flush_and_rebuild(template_name, manifest->version);
    
    return 0;
}
```

**Version check (on daemon startup / pool init):**

```c
uint32_t loaded_version = read_manifest_version(template_name);
if (loaded_version != pool->expected_version) {
    // Drain warm queue, destroy all warm VMs from old snapshot
    pool_drain(pool);
    pool->expected_version = loaded_version;
    // Replenishment thread will rebuild pool from new snapshot
}
```

---

### 5.7 Network Manager

**Responsibility:** Create tap devices, assign IPs, configure firewall rules to force traffic through broker.

**Per-VM network setup:**

```c
int network_setup(const char* vm_id, vm_network_t* out_net) {
    char tap_name[IFNAMSIZ];
    snprintf(tap_name, sizeof(tap_name), "tap-%s", vm_id);  // e.g., "tap-vm-001"
    
    // 1. Create tap device
    int tap_fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, tap_name, IFNAMSIZ);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    ioctl(tap_fd, TUNSETIFF, &ifr);
    
    // 2. Bring tap interface up
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    ioctl(sock, SIOCSIFFLAGS, &ifr);
    
    // 3. Assign host-side IP (169.254.0.1)
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr("169.254.0.1");
    ioctl(sock, SIOCSIFADDR, &ifr);
    close(sock);
    
    // 4. Configure nftables rule: force all guest traffic to broker
    char nft_cmd[1024];
    snprintf(nft_cmd, sizeof(nft_cmd),
        "nft add rule ip sandbox_policy forward "
        "iifname %s ip daddr 169.254.0.1 tcp dport 8080 accept; "
        "nft add rule ip sandbox_policy forward iifname %s drop",
        tap_name, tap_name);
    system(nft_cmd);  // TODO: use libnftables instead of system() in production
    
    // 5. Return tap_fd and guest IP to vmm_manager (Firecracker will use this fd)
    out_net->tap_fd = tap_fd;
    out_net->guest_ip = inet_addr("169.254.0.2");
    strncpy(out_net->tap_name, tap_name, IFNAMSIZ);
    
    return 0;
}
```

**Cleanup (on VM destroy):**

```c
int network_cleanup(const vm_network_t* net) {
    // 1. Delete nftables rules
    char nft_cmd[1024];
    snprintf(nft_cmd, sizeof(nft_cmd),
        "nft delete rule ip sandbox_policy forward handle <handle>");  // TODO: track rule handles
    system(nft_cmd);
    
    // 2. Close tap fd (kernel removes interface)
    close(net->tap_fd);
    
    return 0;
}
```

**Network policy enforced:**
- Guest can reach `169.254.0.1:8080` (broker) only
- All other outbound traffic is dropped at host firewall
- No direct internet access from guest

---

### 5.8 Credential Broker

**Responsibility:** Validate session tokens, inject real credentials, proxy HTTP requests to upstream services. Separate process from engine daemon.

**Broker process architecture:**

```c
int main(int argc, char** argv) {
    // 1. Load credentials from config file (chmod 600)
    credential_store_t* creds = load_credentials("/etc/sandbox-engine/credentials.conf");
    
    // 2. Connect to engine daemon over Unix socket (for token validation)
    int engine_sock = connect_to_engine("/var/run/sandbox-engine/broker-control.sock");
    
    // 3. Bind HTTP listener to 169.254.0.1:8080
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = inet_addr("169.254.0.1"),
        .sin_port = htons(8080),
    };
    bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(listen_fd, 128);
    
    // 4. Drop privileges (after binding privileged port)
    setgid(broker_gid);
    setuid(broker_uid);
    
    // 5. Accept loop
    for (;;) {
        int client_fd = accept(listen_fd, NULL, NULL);
        handle_request(client_fd, creds, engine_sock);
        close(client_fd);
    }
}
```

**Request handling:**

```c
void handle_request(int client_fd, credential_store_t* creds, int engine_sock) {
    // 1. Parse HTTP request (headers only — no buffering of body)
    http_request_t req = parse_http_headers(client_fd);
    
    // 2. Extract X-Sandbox-Token header
    const char* token = http_get_header(&req, "X-Sandbox-Token");
    if (!token) {
        send_http_error(client_fd, 401, "Missing token");
        return;
    }
    
    // 3. Validate token with engine daemon
    session_info_t session;
    if (validate_token(engine_sock, token, &session) != 0) {
        send_http_error(client_fd, 401, "Invalid or expired token");
        return;
    }
    
    // 4. Check target hostname against allowlist
    const char* host = http_get_header(&req, "Host");
    if (!is_allowed(session.allowed_services, host)) {
        send_http_error(client_fd, 403, "Service not allowed");
        return;
    }
    
    // 5. Strip X-Sandbox-Token from request
    http_remove_header(&req, "X-Sandbox-Token");
    
    // 6. Inject real credential
    const char* real_cred = credential_store_lookup(creds, host);
    http_set_header(&req, "Authorization", real_cred);  // e.g., "Bearer sk-..."
    
    // 7. Rewrite scheme: http:// → https://
    req.scheme = "https";
    
    // 8. Forward request to upstream (blocking, use libcurl or custom HTTPS client)
    http_response_t resp = forward_request_upstream(&req);
    
    // 9. Stream response back to guest
    send_http_response(client_fd, &resp);
    
    // 10. Log (sandbox_id, host, status, latency)
    log_request(session.sandbox_id, host, resp.status, resp.latency_ms);
}
```

**Session token validation (via engine daemon):**

```c
// Broker sends validation request to engine over Unix socket
typedef struct {
    uint8_t type;           // BROKER_MSG_VALIDATE_TOKEN
    char token_hex[65];
} broker_validate_req_t;

typedef struct {
    uint8_t status;         // 0=valid, 1=invalid
    uint32_t sandbox_id;
    char** allowed_services;  // NULL-terminated array
} broker_validate_resp_t;

int validate_token(int engine_sock, const char* token, session_info_t* out_session) {
    broker_validate_req_t req = { .type = BROKER_MSG_VALIDATE_TOKEN };
    strncpy(req.token_hex, token, sizeof(req.token_hex));
    send(engine_sock, &req, sizeof(req), 0);
    
    broker_validate_resp_t resp;
    recv(engine_sock, &resp, sizeof(resp), MSG_WAITALL);
    
    if (resp.status != 0) return -1;
    
    out_session->sandbox_id = resp.sandbox_id;
    out_session->allowed_services = resp.allowed_services;
    return 0;
}
```

---

## 6. Data Formats

### 6.1 Protobuf Schema (IPC)

**File:** `proto/sandbox.proto`

```protobuf
syntax = "proto3";
package sandbox;

// Client → Daemon
message ClientMessage {
  oneof payload {
    CreateRequest  create  = 1;
    DestroyRequest destroy = 2;
    PauseRequest   pause   = 3;
    ResumeRequest  resume  = 4;
    InspectRequest inspect = 5;
  }
}

message CreateRequest {
  uint64 memory_mib = 1;
  uint32 vcpu_count = 2;
  string template_name = 3;
  repeated string env_vars = 4;  // "KEY=VALUE"
  uint32 pool_wait_ms = 5;
}

message DestroyRequest {
  uint32 sandbox_id = 1;
}

message PauseRequest {
  uint32 sandbox_id = 1;
}

message ResumeRequest {
  uint32 sandbox_id = 1;
}

message InspectRequest {
  uint32 sandbox_id = 1;
}

// Daemon → Client
message ServerMessage {
  oneof payload {
    CreateResponse  create  = 1;
    DestroyResponse destroy = 2;
    ErrorResponse   error   = 3;
    InspectResponse inspect = 4;
  }
}

message CreateResponse {
  uint32 sandbox_id = 1;
  string session_token = 2;  // Hex-encoded 256-bit token
}

message DestroyResponse {
  uint32 sandbox_id = 1;
}

message ErrorResponse {
  int32 error_code = 1;       // Maps to sandbox_error_t
  string error_message = 2;
}

message InspectResponse {
  uint32 sandbox_id = 1;
  bool is_running = 2;
  uint64 uptime_ms = 3;
  uint64 memory_rss_mib = 4;
  uint32 page_faults = 5;
}
```

**Wire format:**
```
[ 4 bytes: uint32 message length (big-endian) ]
[ N bytes: serialized protobuf message ]
```

---

## 7. Configuration Files

### 7.1 Engine Configuration

**File:** `/var/lib/sandbox-engine/config/engine.conf`

```ini
[daemon]
socket_path = /var/run/sandbox-engine/engine.sock
jailer_uid = 65534
jailer_gid = 65534

[pool]
target_size = 5
max_queue_depth = 50
pool_wait_timeout_ms = 500

[paths]
jail_root = /var/lib/sandbox-engine/jail
snapshot_root = /var/lib/sandbox-engine/snapshots
```

### 7.2 Broker Credentials

**File:** `/etc/sandbox-engine/credentials.conf` (chmod 600, owned by broker uid)

```ini
[api.openai.com]
credential = Bearer sk-proj-...

[s3.amazonaws.com]
credential = AWS4-HMAC-SHA256 ...
```

---

## 8. Build System

### 8.1 CMakeLists.txt (Top-level)

```cmake
cmake_minimum_required(VERSION 3.20)
project(sandbox-engine C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Build types
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Dependencies
find_package(Protobuf REQUIRED)
find_library(SECCOMP_LIB seccomp REQUIRED)

# Protobuf code generation
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS proto/sandbox.proto)

# Core library
add_library(sandbox SHARED
    src/pool_manager.c
    src/uffd_handler.c
    src/prefault_worker.c
    src/vmm_manager.c
    src/snapshot_manager.c
    src/network_manager.c
    src/jailer.c
    src/seccomp.c
    src/lifecycle.c
    src/telemetry.c
    src/ipc_server.c
    ${PROTO_SRCS}
)
target_link_libraries(sandbox ${SECCOMP_LIB} ${Protobuf_LIBRARIES} pthread)

# C++ wrapper
add_library(sandbox++ SHARED
    src/cpp/sandbox.cpp
)
target_link_libraries(sandbox++ sandbox)

# Daemon
add_executable(sandboxd
    src/daemon/main.c
)
target_link_libraries(sandboxd sandbox)

# Broker
add_executable(sandbox-broker
    src/broker/main.c
    src/broker/http.c
    src/broker/credentials.c
)

# CLI tool
add_executable(sandbox-cli
    src/cli/main.c
)
target_link_libraries(sandbox-cli sandbox++)

# Tests
enable_testing()
add_subdirectory(tests)
```

---

## 9. Testing Strategy

> The tables below are the LLD's intended test matrix. The **shipped** CTest
> suite (8 targets) and its environment are listed in §15.7.

### 9.1 Unit Tests

| Component | Test Coverage |
|---|---|
| Pool manager | Warm queue, overflow queue, replenishment, invariant checks |
| UFFD handler | Page fault dispatch, zero page vs. copy, race conditions |
| Jailer | Seccomp filter correctness (syscall allow/deny), chroot isolation |
| Snapshot manager | Manifest generation, version increment, atomic rename |
| Network manager | Tap creation, IP assignment, firewall rule application |

### 9.2 Integration Tests

| Test Case | Pass Criteria |
|---|---|
| Provision from warm pool | < 100ms end-to-end |
| Provision with pool exhaustion | Overflow queue blocks, timeout fires |
| Snapshot restore | Guest resumes at correct instruction, memory intact |
| Credential brokering | Guest HTTP call succeeds, real API key never in guest |
| VMM crash recovery | Lifecycle manager detects pidfd event, pool replenishes |

### 9.3 Stress Tests

- Concurrent provision (100 requests in 1 second)
- Pool churn (create/destroy loop for 1 hour)
- Large snapshot (2GB guest, verify uffd latency profile)

---

## 10. Deployment

### 10.1 System Requirements

- Linux kernel >= 5.10 (userfaultfd, cgroups v2, KVM)
- `/dev/kvm` accessible
- 4GB+ RAM (for pool of 5 × 512MB guests)
- NVMe storage (snapshot loading performance)

### 10.2 Installation

```bash
# 1. Install dependencies
apt-get install firecracker libseccomp-dev protobuf-compiler

# 2. Build engine
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# 3. Install binaries
sudo install -m 755 build/sandboxd /usr/local/bin/
sudo install -m 755 build/sandbox-broker /usr/local/bin/
sudo install -m 755 build/libsandbox.so /usr/local/lib/

# 4. Create directories
sudo mkdir -p /var/lib/sandbox-engine/{jail,snapshots,config}
sudo mkdir -p /var/run/sandbox-engine

# 5. Install config
sudo install -m 644 config/engine.conf /var/lib/sandbox-engine/config/
sudo install -m 600 config/credentials.conf /etc/sandbox-engine/

# 6. Create systemd service
sudo install -m 644 systemd/sandboxd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sandboxd
```

### 10.3 Systemd Service

**File:** `systemd/sandboxd.service`

```ini
[Unit]
Description=Sandbox Engine Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sandboxd
Restart=on-failure
RestartSec=5s

# Security hardening
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_CHROOT
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_CHROOT
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sandbox-engine /var/run/sandbox-engine

[Install]
WantedBy=multi-user.target
```

---

## 11. Observability

### 11.1 Metrics (Prometheus format)

Served by the daemon on `metrics_bind:metrics_port` (default `0.0.0.0:9180`;
set `metrics_bind = ` empty to disable). Three endpoints:

| Path | Behaviour |
|---|---|
| `/health` | `200` while the process is up (liveness) |
| `/ready` | `200` when the warm pool is non-empty, else `503` (readiness) |
| `/metrics` | Prometheus text |

```
sandbox_pool_warm_count         # Current warm VMs in pool
sandbox_pool_restoring_count    # VMs currently being restored
sandbox_pool_overflow_depth     # Pending requests in overflow queue
sandbox_pool_exhaustion_total   # Cumulative pool exhaustions
sandbox_provision_latency_ms    # Histogram: sandbox_create() latency
sandbox_uffd_faults_total       # Cumulative page faults served
sandbox_vmm_crashes_total       # VMM processes killed by seccomp or crashed
sandbox_process_open_fds        # Daemon self-stat (fd leak detection)
sandbox_process_virtual_memory_bytes
sandbox_process_resident_memory_bytes
```

The broker exposes its own counters on an optional listener
(`SANDBOX_BROKER_METRICS_PORT`):

```
broker_requests_total{status="2xx|4xx|5xx"}
broker_upstream_latency_seconds  # histogram
```

### 11.2 Structured Logging

One JSON object per line on stderr; journald captures and rotates it
(`StandardError=journal`). Field names are standardised across the daemon, IPC
server and broker:

```json
{"ts":"2026-10-17T10:15:32.123Z","level":"INFO","component":"broker",
 "event":"proxy","sandbox_id":42,"host":"api.openai.com","status":200,
 "latency_ms":87}
```

`level` is filtered by `log_level` (`debug|info|warn|error`, from `engine.conf`,
`--log-level`, or `SANDBOX_LOG_LEVEL`). Emission goes through `src/log.c`
(`LOGF(level, component, event, "<extra fields>")`).

---

## 12. Security Considerations

### 12.1 Threat Model

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Guest kernel escape | KVM hardware boundary | Zero-day in KVM itself |
| VMM compromise | Jailer (chroot + seccomp + unprivileged uid) | Bug in Jailer setup code |
| Credential exfiltration | Session tokens only, broker validates | Token leaked within sandbox lifetime |
| Host DoS via resource exhaustion | Per-VM cgroups (memory/CPU/OOM-group, §10.11) + pool size limit | Engine daemon itself has no resource limit |
| Snapshot poisoning | Atomic rename, SHA-256 of memory.snap/vmstate in manifest (§10.10), verified on restore | TOCTOU if snapshot dir writable by attacker |

### 12.2 Audit Checklist (Pre-Production)

- [ ] Seccomp filter tested against Firecracker syscall trace
- [ ] Jailer chroot verified (no escape via /proc/self/root)
- [ ] Credential config file permissions (chmod 600, root-owned)
- [x] Engine daemon runs with `PR_SET_NO_NEW_PRIVS` after setup — Phase 10.4,
      see §15.12; CAP_SYS_PTRACE delivered as an ambient cap (§15.3)
- [ ] Network policy tested (guest cannot reach internet directly)
- [x] nftables rules applied without a shell (libnftables) — Phase 10.5, §15.12
- [x] Engine socket authenticates peers (SO_PEERCRED allowlist) — Phase 10.1, §15.9
- [x] Snapshot integrity verified (SHA-256 in manifest, checked on restore) —
      Phase 12.10, §15.14
- [x] Per-VM resource enforcement (cgroup v2 memory/CPU/OOM-group) — Phase
      12.11, §15.14
- [x] Structured logs with levels, captured/rotated by journald — Phase 12.12,
      §15.15
- [x] Liveness/readiness probes + process self-metrics — Phase 13.13, §15.15
- [x] CI builds + ASan/UBSan + fuzz smoke — Phase 13.14, §15.15
- [ ] Broker TLS cert validation enabled (HTTPS to upstream)
- [ ] Session token entropy (getrandom, not /dev/urandom)

---

## 13. Future Enhancements (Out of Scope for V1)

- Dynamic pool auto-scaling (PID controller based on request rate)
- Content-addressed snapshot store (dedup shared pages across templates)
- Snapshot delta encoding (store only changed pages vs. base)
- GPU passthrough for local model inference (requires Cloud Hypervisor)
- Multi-tenant isolation (per-client pool quotas, accounting)
- Distributed engine (pool spread across multiple hosts, central scheduler)

---

## 14. References

- Firecracker design paper: [NSDI 2020](https://www.usenix.org/conference/nsdi20/presentation/agache)
- userfaultfd man page: `man 2 userfaultfd`
- libseccomp docs: https://github.com/seccomp/libseccomp
- KVM API: https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt
- Protobuf C++: https://protobuf.dev/reference/cpp/

---

**Document Version:** 1.1
**Last Updated:** 2026-10-17
**Status:** Implementation-ready + ground-truth deviations (see §15)

---

## 15. Ground-Truth Deviations (implementation wins over §§4–8)

Deviations below are implemented, tested, and previously recorded only in
`docs/IMPLEMENTATION_LOG.md` or code comments. This section makes them
authoritative.

### 15.1 Pool Manager (§5.1)
- Fast path does NOT do `restoring_count++`. Kept verbatim it double-counts
  with the replenishment thread and pins `warm + restoring == target` so the
  pool never refills. Only the replenishment thread owns `restoring_count`.
  (`src/pool_manager.c:2`)
- `pool_manager_t` gains `pthread_t replenish_thread` (joined on destroy).
- `target_size` clamped to `POOL_MAX_SIZE` (64); `init` rejects `target <= 0`;
  `pool_wait_ms == 0` / NULL spec fails immediately; shutdown wakes waiters
  with `INTERNAL`; NULL restore hands off NULL or retries after 10ms backoff.
- `POOL_MAX_SIZE = 64`, `POOL_MAX_QUEUE_DEPTH = 128` in code vs `max_queue_depth = 50`
  in `config/engine.conf`.

### 15.2 Network Manager (§5.7)
- LLD fixed `169.254.0.1` (host) / `.0.2` (guest) is NOT implemented. Code uses
  per-VM `/30` subnets from `169.254.0.0/16` (16384 slots, FNV-1a hash of
  `vm_id`; subnet `i` = host `.4i+1`, guest `.4i+2`) via `network_subnet_addrs()`.
  Broker endpoint is therefore per-VM (its `/30` host IP), not a single `.1:8080`.
- `SIOCSIFNETMASK /30` (`255.255.255.252`) is set after `SIOCSIFADDR`; bare
  `SIOCSIFADDR` leaves a `/32` with no connected route and guest replies escape
  via the default interface.
- Rules are installed on BOTH `forward` and `input` chains (per-tap
  allow `ip daddr <host-ip> tcp dport 8080` + drop). LLD `forward`-only rules
  leave host-local ports reachable (measured SYN `.2`→`.1:9999` got RST,ACK =
  guest port-scan); `input` rules close this.
- Daemon auto-creates `table ip sandbox_policy` + `forward`/`input` chains
  (`type filter hook …; policy accept`); LLD assumes they exist.
  `network_manager_init()` (daemon startup) ensures chains; `network_setup()`
  re-ensures. Cleanup resolves rule handles via `nft -a list` per chain, so
  `vm_network_t` is unchanged (LLD TODO on handle tracking resolved this way).
- The tap is created **persistent** and the setup fd is **released**
  (`vm_network_t.tap_fd = -1`); Firecracker opens the device by name itself.
  Holding the fd (the LLD/old behaviour) makes Firecracker's own `TUNSETIFF`
  fail `EBUSY (Resource busy, os error 16)` — one non-multiqueue fd is the
  only attachment allowed. `network_tap_open()` attaches a fresh fd for tests
  (frame injection); `network_cleanup()` deletes the device **by name** (attach
  → `TUNSETPERSIST 0` → close). `TUNSETPERSIST` takes its argument **by value**
  — passing `&zero` *sets* (never clears) the flag, silently leaking every tap
  until fixed (proved via `/sys/class/net/<tap>/tun_flags = 0x1802`).
- `tap_fd == -1` is the "no fd held" sentinel; the VMM never holds one.

### 15.3 Jailer / Seccomp (§§5.4–5.5)
- Order is cgroup → chroot → caps → setuid/setgid → seccomp → exec. LLD
  pseudocode places cgroup after chroot, which cannot work (`/sys/fs/cgroup`
  unreachable post-chroot).
- There is **no separate jailer binary** (§2.2's "spawns Jailer binary" is
  conceptual). `spawn_jailed()` is an in-daemon `fork()`; the forked child does
  the jail setup and then directly `execve`s `/firecracker`. Cgroup placement is
  `write_cgroup_procs(cgroup_path, getpid())` into a caller-provided
  `cgroup.procs`; since Phase 12 (§15.14) `vmm_restore` creates the per-VM leaf
  and passes its path, so each Firecracker runs inside
  `<root>/sandboxd/active/<vm-id>/`.
- `drop_capabilities()` retains `CAP_SETUID`/`CAP_SETGID` (required by the
  later setuid/setgid per LLD order) plus `CAP_SYS_PTRACE` (Firecracker UFFD
  creation gate where `unprivileged_userfaultfd=0`; `ptrace()` itself stays
  seccomp-blocked). Bounding-set drops run BEFORE the `capset` clear.
- **CAP_SYS_PTRACE delivery is now an *ambient* capability, not a file cap**
  (Phase 10.4). `PR_SET_KEEPCAPS` is set before `setuid`, then after the uid
  transition `raise_ambient_sys_ptrace()` re-adds `CAP_SYS_PTRACE` to the
  permitted/effective/inheritable sets and raises it in the ambient set, so it
  survives `execve` into Firecracker. This replaces the previous
  `security.capability` xattr because `PR_SET_NO_NEW_PRIVS` silently drops file
  caps at exec (the daemon now runs with no_new_privs — §15.12); ambient caps
  are carried across exec under no_new_privs. It also removes the daemon's need
  for `CAP_SETFCAP` and any dependence on a writable/capable jail fs.
- The per-VM jail directory is created `0700` (owner = jailed uid) so the vsock
  injection UDS underneath it is reachable only by root and the VMM (§15.12).
- `serial.log` is opened `0600` (was `0644`) — it can carry guest console output.
- Devices are fresh `mknod` + `chown` nodes (`/dev/kvm`, `/dev/net/tun`,
  optionally `/dev/userfaultfd`), NOT LLD bind-mounts (bind preserves
  root-only modes). `mount_jail_devices()` remains only for tests.
- `spawn_jailed()` signature is extended vs LLD: `(jail_root, config, bin,
  argv, mount_devices, apply_seccomp, files{jail-bind kernel/rootfs/vmstate/
  memory.snap/out_dir}, serial_log)` with child exit codes 1–16
  (1=mkdir … 14=seccomp, 15=execve, 16=ambient-cap). Serial log is opened pre-chroot, `dup2`'d
  post-setuid. Firecracker is launched with `--no-seccomp` (own libseccomp
  filter applied by us) toggled by `SANDBOX_FC_SECCOMP`.
- Jail contents additionally include `/vmlinux`, `/rootfs.ext4`, `/vmstate`,
  `/memory.snap`, `/out`, `/uffd.sock`, `/serial.log`.
- **Seccomp whitelist is NOT verbatim §5.5.** It is Firecracker v1.17's own
  aarch64 policy (`resources/seccomp/aarch64-unknown-linux-musl.json`, the union
  of its vmm/api/vcpu thread filters) **plus** the calls FC makes *before* it
  would install its own per-thread filters — because FC runs `--no-seccomp` and
  the jailer installs our filter first, ours is the only filter, so it also
  covers that pre-filter window. Added beyond §5.5: `socket`/`bind`/`listen`/
  `accept4` (UDS API server), `connect`/`sendmsg`/`recvmsg` (UFFD handshake),
  `ppoll`, `uname`, `prctl`, `clone` (CLONE_VM only), `execve`, `dup3` (what
  `dup2()` lowers to on aarch64 — there is no `dup2` syscall), `dup`,
  `epoll_create1`, `prlimit64`, `readv`/`writev`, `timerfd_*`, `tkill`,
  `getpid`, `set_robust_list`, `set_tid_address`.
- The `ioctl` filter is no longer KVM-only. It allows the KVM class
  (`arg1 & 0xFF00 == 0xAE00`), the UFFD class (`0xAA00` — FC creates the
  userfaultfd itself via `USERFAULTFD_IOC_NEW` and registers regions, then hands
  the fd to our handler), and the specific tap/block/terminal requests FC makes
  (`TUNSETIFF`/`TUNSETOFFLOAD`/`TUNSETVNETHDRSZ`, `FIONBIO`, `TIOCGWINSZ`,
  `TCGETS`/`TCSETS`, `BLKSSZGET`/`BLKDISCARD`/`BLKIOMIN`/`BLKIOOPT`/`BLKPBSZGET`).
  Derived empirically under `SCMP_ACT_LOG` over a full cold-boot + snapshot +
  UFFD-restore + pool run.
- The Phase-2 probe now proves filter death on `ptrace` and on an unlisted
  `ioctl` (`FIONREAD`); `socket`/`TCGETS` are deliberately allowed (FC needs
  both), so they are no longer the fatal calls.

### 15.4 UFFD Handler / Prefault (§§5.2–5.3)
- `uffd_fd` is `O_NONBLOCK` + `poll(100ms)`; shutdown is flag → join →
  release (never close-to-wake). `page_faults`/`destroyed` use `__atomic`
  builtins on plain fields. Manifest page size must equal host page size.
- Production restore does NOT use the LLD `uffd_setup_region()` register path.
  Firecracker owns the uffd fd and passes it plus `[GuestRegionUffdMapping]`
  (`base_host_virt_addr/size/offset/page_size`, multi-region) over a UDS
  (`<jail>/uffd.sock`, `SOCK_STREAM`, `SCM_RIGHTS`, 30s accept timeout,
  `chmod 0777` so jailed uid can connect) via `uffd_accept_handler()`.
  Fault offsets are `region.file_offset + (fault - region.base)`; short
  `UFFDIO_COPY` leaves the page missing for guest refault.
- Both handler and prefault threads start pre-resume so prefault races from t=0
  (LLD shows prefault with no explicit start point).

### 15.5 VMM / Snapshot / Restore (§5.6 + §5.4 flow)
- `vmm_cold_boot()` (diskless templates): `--no-seccomp`;
  **virtio-MMIO by default** — `--enable-pci` only when `SANDBOX_FC_PCI` is
  truthy. On the aarch64 test host PCI boot fails (MSI-X setup fails →
  virtio-blk never registers → `Cannot open root device "vda"`; PCI with
  128 MiB RAM gives no kernel output and an immediate guest shutdown), and the
  6.1 vmlinux exposes virtio-mmio. 15 ms async API settle before
  `InstanceStart`; readiness via serial-log marker poll (default
  `SANDBOX-READY`). A NIC `net1` is attached when `template_config.tap_name` is
  set, so the captured template can be retargeted per-VM on restore.
- `vmm_restore()`: `PUT /snapshot/load {"snapshot_path":"/vmstate",
  "mem_backend":{"backend_path":"/uffd.sock","backend_type":"Uffd"},
  "network_overrides":[{"iface_id":"net1","host_dev_name":"<tap>"}],
  "resume_vm":false}`. **There is no hotplug**: Firecracker only supports
  post-restore device attach on PCI, which is unusable here, so the template is
  captured *with* a NIC and the per-VM tap is swapped in via `network_overrides`
  (works on MMIO). The tap must already exist (FC does not create it on restore
  → `Open tap device failed: Operation not permitted`). FC fixes the guest MAC
  at capture and `network_overrides` cannot change it (tap only), so restored
  VMs share the template MAC. Ordering: send `/snapshot/load` → start the UFFD
  handler (FC faults guest memory *during* load, so accepting first would
  deadlock) → read the response → start prefault → resume. `fc_boot_args()`
  prepends `keep_bootcon` on aarch64 to keep the guest console alive for the
  marker. Full snapshots only.
- **Template store is self-contained.** The published template dir holds
  `vmstate`, `memory.snap`, `manifest.bin` **plus** copies of `vmlinux` and
  `rootfs.ext4` (§5.6 lists only the first three). Restore binds
  `vmstate`/`memory.snap`/`rootfs.ext4` into the restore jail at the same paths
  the snapshot was captured with (`/vmstate`, `/memory.snap`, `/rootfs.ext4`);
  the kernel is not needed on restore (no boot). The rootfs backing must exist
  at that exact jail path or the drive re-open fails.
- `create_snapshot_template()` boots through an **ephemeral `tpl-<name>` jail**
  (reclaimed by `vmm_destroy`) and first brings up a **template NIC**
  (`network_setup("tpl-<name>")`) so the capture carries a retargetable `net1`.
  Signatures differ from §5.6: `vmm_cold_boot(const void* config, vm_id,
  jail_root, out_dir)` (4 args, not 1 — `config` is `void*` to avoid a header
  cycle) and the real restore entry is
  `vmm_restore(template, vm_id, tap_name, guest_ip)`.
- `restore_vm_from_snapshot()`'s real (non-`TEST-DUMMY`) path provisions a fresh
  per-VM network (`network_setup("vm-<n>")`) and calls `vmm_restore`, handing the
  tap to the VM for `vmm_destroy` to reclaim — so the pool delivers fully
  networked, running VMs, not just handles.
- Restore correctness proof is the resumed guest's own serial output
  (`SANDBOX-TICK`); served `page_faults` only prove the *load*, not post-resume
  execution (prefault pre-warms the host page cache).
- Snapshot publish is backup-swap, not plain `rename` (plain rename cannot
  replace a non-empty dir); readers see old → missing → new, never partial.
  `pool_manager.expected_version` field added; `snapshot_check_version()`
  adopts-on-first-sight, drains + adopts on change;
  `pool_manager_flush_and_rebuild()` drains the **live** pool registered via
  `pool_manager_set_live()` and repoints replenishment at the new template
  (no-op when no daemon is running).
- Env overrides (tests/ops, not in LLD): `SANDBOX_SNAPSHOT_ROOT`,
  `SANDBOX_JAIL_ROOT`, `FIRECRACKER_BIN`. Firecracker API is a minimal
  HTTP/1.1 client over `AF_UNIX SOCK_STREAM` (`Content-Length` framing,
  15s poll-bounded, 128KB response cap).
- `restore_vm_from_snapshot()` takes no per-call template (global set by
  `pool_set_restore_source()`); `TEST-DUMMY` returns a dummy handle after
  ~83ms for pool/snapshot tests.

### 15.6 Previously Stubbed Layers — Now Implemented in Phase 8
- The §2.3/§3.1/§3.2/§11 stubs (`src/ipc_server.c`, `src/lifecycle.c` client
  API, `src/daemon/main.c`, `src/cli/main.c`, `src/telemetry.c`,
  `src/cpp/sandbox.cpp`, `lifecycle_track/remove`) were **implemented in
  Phase 8** — see §15.9 for the ground-truth deviations from the LLD.
- pidfd-based VMM crash detection was implemented in **Phase 9** (§15.10), and
  the §11 gauges/counters were wired there too.
- Still not implemented: **per-VM environment injection** (see §15.9/§15.11)
  and a hierarchical config layer (`config/` still ships only `engine.conf` +
  `credentials.conf.example`).

### 15.7 aarch64 / Test Environment (§9)
- Ground truth was verified on a **Raspberry Pi 5** (Ubuntu 24.04 aarch64,
  4 cores, ~7 GiB RAM, `/dev/kvm` + `/dev/userfaultfd` present,
  `unprivileged_userfaultfd=0`, NOPASSWD sudo). All build and test runs happen
  there; the original dev host could not build Firecracker and had no usable
  sudo. Firecracker v1.17.0 is built from source
  (`aarch64-unknown-linux-musl`) with assets under `/opt/sandbox-assets/`.
- **Post-restore arch timer**: after a UFFD restore the guest *does* resume and
  execute (proven by fresh serial output), but the aarch64 arch timer does not
  re-arm on this host, so a guest that `sleep`s hangs in WFI. The rootfs
  heartbeat therefore **busy-spins** (`SANDBOX-TICK` with a bounded loop)
  instead of `sleep 1`, so a fresh marker is executable proof of the restored
  vCPU.
- **Docker `FORWARD` conflict**: the test host runs Docker, whose iptables
  `FORWARD` chain has `policy drop` at the same `filter` hook priority as
  `sandbox_policy`. At equal priority a drop in *any* chain wins regardless of
  our accept, so the `forward_drop` control could never isolate our rule;
  `test_network` now inserts a tap-scoped ACCEPT (`-i`/`-o <tap>`) around that
  section. The test also flushes the `sandbox_policy` chains at start (tap
  names embed a pid; an aborted run can otherwise collide with a later one).
- Jail teardown needs the per-VM bind mounts unmounted before `rm -rf`; stale
  `firecracker` processes leak between runs and must be reaped with
  `pkill -9 -x firecracker` (use `-x`, not `-f`).
- Full `ctest` (10/10: `tmpl_setup`, `pool`, `jailer`, `network`,
  `network_cleanup`, `snapshot`, `vmm`, `uffd`, `broker`, `ipc`) passes twice
  back-to-back with seccomp **on** and MMIO transport, leaving zero leaked taps
  and zero leaked `sandbox_policy` rules. CTest must be run **as root**:
  `pool`/`jailer`/`vmm`/`network`/`ipc` do chroot / uid-drop / tap work, so a
  plain unprivileged `ctest` fails them (the `broker` test alone is
  unprivileged).
- **Long-lived sockets must be `SOCK_CLOEXEC`.** The pool forks Firecracker
  children (`fork`+`exec`) while client sockets are open; a non-`CLOEXEC` fd is
  inherited by the child, so the daemon never observes the peer's EOF and leaks
  the session (and, in-process, the `ipc` test deadlocked joining the
  broker-control thread). The engine listener/accepted fds, the
  broker-control accepted fd and both client sockets are all created
  `SOCK_CLOEXEC`.

### 15.8 Credential Broker (§5.8)
- **Listen address is wildcard `0.0.0.0:8080`, not the LLD's
  `169.254.0.1:8080`.** Phase 3 gave every VM its own /30, so the host side of
  each tap is a different `.1`; no single link-local address can serve them all.
  Overridable via `SANDBOX_BROKER_LISTEN` (`host:port`).
- **Privilege drop (§5.8 step 4) is implemented:** when started as root the
  broker `setgroups`/`setgid`/`setuid`s to `SANDBOX_BROKER_UID`/`SANDBOX_BROKER_GID`
  (default `65534`) *after* loading credentials, connecting to the engine and
  binding the listener. There is no `engine.conf` field for these, so they are
  environment variables.
- **Token-validation wire format is fixed-framing**, not the LLD structs (whose
  `broker_validate_resp_t.allowed_services` is a `char**`, not serializable):
  request = `u8 type` + 32 raw token bytes (`token_hex[65]` decoded to 32);
  response = `u8 status` and, iff valid, `u32 sandbox_id` (BE) +
  `u16 n_services` + `n × (u8 len + bytes)`. Notes are in `include/broker.h`.
  The **engine half is implemented in Phase 8** (broker-control server + token
  issuance — see §15.9); the
  broker's client half (`broker_validate_token`) is implemented and tested
  against a mock engine.
- **Upstream forwarding uses libcurl** (a new dependency — §8.1 lists none;
  `find_package(CURL REQUIRED)` added). Defaults: scheme `https`, certificate
  verification on. `SANDBOX_BROKER_UPSTREAM_SCHEME=…` and
  `SANDBOX_BROKER_TLS_VERIFY=0` exist for tests only. The upstream response is
  relayed **verbatim** (transfer/content decoding disabled) so the guest sees
  the upstream's own `Transfer-Encoding`/`Content-Encoding` framing.
- **Body handling:** request headers are read byte-by-byte so the body is never
  consumed early (the LLD's "no buffering of body"), then the body is streamed
  upstream through a libcurl read callback bounded by `Content-Length`.
  **Chunked request bodies are rejected with 502.** The allow-list and the
  credential lookup both key on the `Host` value with any `:port` stripped and
  case folded; an allowed host with no credential entry gets 403.
- **Extra source file:** `src/broker/core.c` holds the pipeline (the LLD lists
  only `main/http/credentials`). It is compiled into the `sandbox_broker_core`
  static library so `tests/test_broker.c` can drive one request in-process
  (mock engine + mock upstream on an ephemeral loopback port); `main.c` is a
  thin `curl_global_init` + accept-loop shim. The accept loop sets a 30 s
  send/recv timeout so a stalled guest cannot pin the single-threaded
  broker.

### 15.9 Daemon / IPC / Lifecycle (§2.3, §3.1, §3.2, §6.1, §11)
- **Framing:** one `SOCK_SEQPACKET` packet = `u32 big-endian length` + protobuf
  payload (`src/ipc_internal.h`, `sendmsg` with a 2-element iovec so the prefix
  and payload stay one datagram). §2.3's "length-prefixed protobuf" is honored;
  SEQPACKET means exactly one message per `recv`.
- **Protobuf is generated as C++** (`protobuf_generate_cpp` → `sandbox.pb.{h,cc}`),
  so the C engine reaches it through a small bridge: `include/ipc_codec.h` +
  `src/ipc_codec.cpp` (an extra file beyond §8.1) expose `ipc_encode/decode_
  {request,response}` with C linkage. The generated header is never included
  from C.
- **Schema extension (§6.1):** `ServerMessage` gained `PauseResponse` (field 5)
  and `ResumeResponse` (field 6). The LLD schema has no reply for
  pause/resume, so the client would block forever waiting for a frame. The
  addition is backward-compatible.
- **Event loop is epoll-based; Phase 9 added pidfd crash watching** (§15.10) and
  Phase 12 (§15.14) moved pool restores off the loop. A `Create` no longer blocks:
  it is queued and executed by `create_workers` worker threads, and the loop only
  consumes their results via the wake `eventfd`. `epoll` multiplexes the listener,
  the wake `eventfd` and every client fd; SEQPACKET + level-triggered EPOLLIN
  guarantees a whole frame is ready when read. `ipc_server_request_stop()`
  (async-signal-safe) is what a SIGTERM handler calls.
- **Session/token model:** a connection *is* a session; it owns every sandbox it
  created and reclaims them on disconnect (`sandbox_cleanup()` /
  peer EOF). Tokens are 256 bits of `getrandom` (hex-encoded in
  `CreateResponse.session_token`, keyed on the 32 raw bytes). The allow-list
  handed to the broker is a **global** policy (`SANDBOX_ALLOWED_SERVICES` /
  `allowed_services` config), not per-sandbox — `CreateRequest` has no field for
  it. The engine-side broker-control server (`ipc_server_start_broker_control`)
  is the §5.8 counterpart the broker's client half talks to; it reuses the
  broker's fixed framing from `include/broker.h`.
- **`env_vars` are injected into the restored guest** over a per-VM virtio-vsock
  channel (Phase 9b, §15.11). They still round-trip through the protobuf and the
  client API; injection is best-effort and never fails `Create`.
- **Peer authentication (Phase 10.1):** the listener still `chmod 0660`s the
  socket, but every accepted connection is additionally checked with
  `SO_PEERCRED`; if `allowed_uids` is non-empty, any peer whose uid is not in
  the list is closed immediately and a `peer_rejected` log is emitted. The
  peer uid is stored on the session for future per-tenant quotas. An empty
  allowlist preserves the old group-gated behaviour and logs a warning.
  `CreateRequest.template_name` is validated to `[A-Za-z0-9_-]{1,20}` before it
  can reach any path/tap name (Phase 10.5).
- **Ownership of `g.tok_lock`:** the registry is read by the broker-control
  thread and written by the IPC thread; `token_lookup` copies service strings
  under the lock and the socket I/O happens outside it.
- **Config:** flat `key = value` file (no hierarchy) with precedence
  CLI > env > file > defaults. The parser now lives in
  `src/daemon/config.c` + `include/engine_config.h` (extracted for unit
  testing); `[section]` headers are skipped. Keys: `socket(_path)`,
  `broker_control_socket`, `template(_name)`, `pool_size`/`target_size`,
  `max_queue_depth`, `pool_wait_timeout_ms`, `allowed_services`,
  `allowed_uids`, `jailer_uid`, `jailer_gid`, `jail_root`, `snapshot_root`,
  `metrics_port`, `metrics_bind`. Env: `SANDBOX_ENGINE_SOCK`,
  `SANDBOX_BROKER_CONTROL`, `SANDBOX_TEMPLATE`, `SANDBOX_POOL_SIZE`,
  `SANDBOX_ALLOWED_SERVICES`, `SANDBOX_ALLOWED_UIDS`, `SANDBOX_METRICS_PORT`,
  `SANDBOX_METRICS_BIND`, `SANDBOX_MAX_QUEUE_DEPTH`, `SANDBOX_POOL_WAIT_MS`,
  `SANDBOX_JAIL_ROOT`, `SANDBOX_SNAPSHOT_ROOT`, `SANDBOX_JAILER_UID`,
  `SANDBOX_JAILER_GID`, plus the pre-existing `SANDBOX_FC_*`,
  `FIRECRACKER_BIN`. `--version` prints `SANDBOX_VERSION` (CMake var, fallback
  `include/version.h`); `--validate-config` prints a pre-flight report and
  exits non-zero on error (used as `ExecStartPre`).
- **Observability (§11):** `telemetry_render()` emits the §11.1 metric names in
  Prometheus text; the daemon serves them on `127.0.0.1:<metrics_port>` only
  when `--metrics-port` is set (`telemetry_serve` in a detached thread).
  Counters are `atomic` and bumped on the create path; `sandbox_vmm_crashes_total`
  is bumped on VMM exit and the pool gauges/uffd counter are pushed from their
  owners (Phase 9, §15.10). **Structured logs are JSON lines on stderr from
  the component that owns the event** (`daemon`, `ipc_server`, `broker`) — there
  is no separate logger object.
- **C++ wrapper (§3.2):** `Engine`'s constructor throws `SandboxError` if
  `sandbox_init` fails; `Sandbox`'s constructor throws on create failure (RAII).
  `Sandbox::id()` performs an `inspect` round-trip (the C API has no id
  accessor). `Spec::to_c_struct()` needs a stable `const char**`, so a
  `mutable std::vector<const char*> env_ptrs_` member backs it. `Sandbox` is
  move-only; the move-assignment destroys the existing handle first.
- **Extra files/symbols beyond §8.1/§3.1:** `src/ipc_codec.cpp`,
  `include/ipc_codec.h`, `src/ipc_internal.h`. `lifecycle.h` adds internal
  helpers `lifecycle_get`, `lifecycle_count`, `sandbox_handle_token` (test
  helper — not part of public `libsandbox.h`). `ipc_server.h` adds
  `ipc_server_set_pool/template/allowed_services`, `ipc_server_request_stop`,
  `ipc_server_start/stop_broker_control`, `ipc_server_token_count`.

### 15.10 Phase 9 — Packaging, Metrics, pidfd Crash Detection (§§4.2, 10, 11)
- **Install rules (§10.2/§10.3).** `CMakeLists.txt` previously had **no
  `install()` rules**; it now installs `sandboxd`/`sandbox-broker`/`sandbox-cli`
  → `${CMAKE_INSTALL_BINDIR}`, `libsandbox.so`/`libsandbox++.so` →
  `${CMAKE_INSTALL_LIBDIR}`, `libsandbox.h`/`libsandbox.hpp` → `include/`,
  creates the data/run dirs (`/var/lib/sandbox-engine/{jail,snapshots,config}`,
  `/var/run/sandbox-engine`), installs `config/engine.conf` →
  `/var/lib/sandbox-engine/config`, `config/credentials.conf.example` →
  `/etc/sandbox-engine`, and `systemd/sandboxd.service` →
  `${CMAKE_INSTALL_LIBDIR}/systemd/system`. The absolute roots are cache vars
  (`SANDBOX_STATE_DIR`/`SANDBOX_ETC_DIR`/`SANDBOX_RUN_DIR`); `DESTDIR=` stages
  them. `CMAKE_INSTALL_RPATH=$ORIGIN/../lib` makes the installed `sandboxd`
  resolve the installed `libsandbox.so`. The daemon now falls back to
  `/var/lib/sandbox-engine/config/engine.conf` when `--config` is absent, so the
  unit's bare `ExecStart=/usr/local/bin/sandboxd` picks up the packaged config.
- **Metrics wired (§11.1).** `telemetry_pool_state()` is pushed from the pool at
  every state change (fast-path hit, overflow enqueue/dequeue/timeout, each
  replenish result, drain, destroy, init) while holding `pool->lock`, and
  `telemetry_uffd_fault()` is bumped by the UFFD handler for every served page
  (`UFFDIO_COPY` *and* `UFFDIO_ZEROPAGE`). Previously only
  `telemetry_provision_latency`/`telemetry_pool_exhausted` were called, so the
  warm/restoring/overflow gauges and the fault counter always scraped as 0.
- **pidfd VMM crash detection (§4.2).** The IPC loop's epoll set now tags each
  registration via `data.u64` (`EP_LISTEN`/`EP_WAKE`/`EP_CLIENT`/`EP_PIDFD`)
  instead of `data.fd`. Every **handed-out** VM is tracked with
  `pidfd_open(vmm_pid, 0)` (CLOEXEC) and its pidfd added to epoll; warm-pool VMs
  are never tracked (internal destroys handle themselves). On exit the loop
  `waitid(P_PIDFD, …, WEXITED|WNOHANG)`-reaps the VMM (idempotent with
  `vmm_destroy`'s own `kill`+`waitpid`), bumps `sandbox_vmm_crashes_total`, logs
  `{"component":"ipc_server","event":"vmm_crash","sandbox_id":N}`, and reclaims
  engine state — `vmm_destroy`, `lifecycle_remove`, `token_revoke`,
  `session_disown` — so a later inspect/destroy reports the sandbox is gone
  (`PERMISSION_DENIED`: the session no longer owns a dead id). The normal destroy
  path calls `pidfd_untrack()` before killing. Table is `IPC_MAX_PIDFDS=256`;
  if `pidfd_open` fails the sandbox still works (crash detection degraded) and a
  warning is logged.
- **Test coverage.** `tests/test_ipc.c` gained a crash case: create a second
  sandbox, `SIGKILL` its VMM via `lifecycle_get()->vmm_pid`, then assert the
  client observes reclaim, the registry clears, the token no longer validates,
  and the rendered metrics show `sandbox_vmm_crashes_total 1` and a non-zero
  `sandbox_uffd_faults_total` (proving the Phase-9 wiring). The metrics scrape
  also verifies the pool gauges are now live.

### 15.11 Phase 9b — Per-VM Env Injection via virtio-vsock (§6.1 `env_vars`)
- **Channel = virtio-vsock.** The restored guest is pre-baked by a snapshot, so
  there is no boot-time env plumbing; the only supported post-restore paths into
  the guest are the devices carried in the snapshot. virtio-vsock was chosen
  because its host backend is a **per-VM Unix socket** that the restore request
  can retarget (`vsock_override.uds_path`), exactly like the NIC's
  `network_overrides` — no hot-plug needed. (A `mem_backend`/UFFD or
  `block_overrides` route would still have to be captured at snapshot time.)
- **Template now carries a vsock device.** `vmm_cold_boot` configures
  `PUT /vsock` before `InstanceStart`:
  `{"vsock_id":"vsock0","guest_cid":3,"uds_path":"/vsock.sock"}` (jail-view
  path). The snapshot captures the live device, so every restore re-creates it.
  Firecracker logs `vsock_id field is deprecated` (harmless).
- **Restore retargets the host backend.** The `/snapshot/load` body gains
  `"vsock_override":{"uds_path":"/vsock.sock"}` (next to `network_overrides`);
  the host run of the socket is `<jail>/vsock.sock`, stored on the handle as
  `vm->vsock_uds` and unlinked before load.
- **Guest agent (`scripts/sandbox-agent.c`, new — beyond §8.1).** A static
  aarch64 binary baked into the test rootfs by
  `scripts/build-custom-rootfs.sh` at `/bin/sandbox-agent`. The guest `/init`
  now **`exec`s** it as the foreground process. It binds an `AF_VSOCK`
  listener on **port 5001**, prints `SANDBOX-READY` (the template readiness
  marker), then busy-loops: it serves the host's connection and periodically
  prints `SANDBOX-TICK`. On a connection it reads to EOF, writes the payload to
  `/tmp/sandbox-env` (**mode `0600`**, Phase 10.2), and prints a delimited
  `SANDBOX-ENV-BEGIN`/…/`SANDBOX-ENV-END` block to the serial console that
  contains **only the key names** — values are never echoed because the serial
  log is persistent and may hold credentials (Phase 10.2).
- **The agent, not a shell, owns the heartbeat loop.** After a UFFD restore the
  aarch64 arch timer does not re-arm on this host (§15.7), so the scheduler tick
  stops: a CPU-hogging shell loop would starve every other guest process and a
  `sleep` would hang in WFI. One process that both polls the socket and emits
  the heartbeat keeps working with no timer interrupts. The agent uses
  `poll(…, 0)` (zero-timeout) rather than a blocking `accept()` so the loop
  never blocks even though `SOCK_NONBLOCK` on the AF_VSOCK listener proved
  unreliable here; a pending connection makes `poll` report `POLLIN` and the
  following `accept` returns at once. Incoming vsock data is delivered by the
  device interrupt and queued in the guest kernel, so `poll` sees it without any
  timer help.
- **Host side = hybrid-vsock handshake (`vmm_inject_env`).** Connect to
  `vm->vsock_uds`, send `CONNECT 5001\n`, read the `OK <host_port>\n` line, then
  stream `KEY=VALUE\n` lines and close (FIN = EOF, which the agent reads to).
  Called from `handle_create` after the VM is restored and the pidfd is tracked.
- **1 s muxer settle before the first CONNECT.** A host connection issued while
  Firecracker's vsock muxer is still setting up its restored endpoint is
  accepted but never answered, and that stuck half-open state wedges the port:
  measured ~10–20% of immediate connects wedged *all* subsequent retries (8×
  5 s timeouts, then `env_inject_failed`), while waiting 1 s after resume before
  the first attempt succeeds in ~1 ms (10/10 at 1 s, 2 s, 8 s and 45 s delays).
  So `vmm_inject_env` sleeps 1 s first; only creates *with* env pay it (the
  pool-hit path carries no env). Cost: a `Create` with env takes ~1 s.
- **Guest re-announces its listener (~5 s, until env lands).** Post-restore
  Firecracker resets the vsock transport and the guest must re-announce its
  listener on the event queue; if that one-shot announcement is lost the host
  can handshake forever without the guest seeing anything. Until the env is
  received the agent therefore closes and re-binds its listener about every
  5 s; each fresh `listen()` re-emits the port-announce (a guest→host MMIO
  write, no rx interrupt needed). The interval is deliberately long: a rebind
  drops any in-flight host connection, and ~100 ms rebinds guillotined every
  attempt, while 5 s windows let one complete undisturbed. First `POLLIN` after
  each bind prints `SANDBOX-VSOCK-POLLIN`, each rebind prints
  `SANDBOX-VSOCK-RELISTEN` (diagnostics, serial).
- **Best-effort, bounded, retried.** A `Create` **never fails** because of
  injection: any error logs
  `{"component":"ipc_server","event":"env_inject_failed","sandbox_id":N}` and the
  sandbox is returned usable (success logs `env_injected`). Past the settle,
  the whole connect+handshake+write sequence retries up to 8× (250 ms apart);
  the socket carries `SO_RCVTIMEO`/`SO_SNDTIMEO` of 5 s so a stalled muxer can
  never block the create path (worst case ~45 s, then failure, never a hang).
- **Stale-jail hardening.** `vmm_restore` now calls `jail_cleanup()` before
  `mkdir_recursive()`. A previous run killed before `vmm_destroy` left a stale
  `<jail>/api.sock`; Firecracker cannot rebind it, `wait_for_file` passes on the
  stale file, and every `connect` then fails `ECONNREFUSED`. Clearing first makes
  repeated create/destroy cycles reliable.
- **Debug artifact:** `snapshot_manager` copies the template VM's boot serial to
  `<template>/boot-serial.log` (best-effort) so the guest agent's
  `SANDBOX-AGENT-*`/`SANDBOX-READY` lines survive for inspection.
- **Test coverage.** `tests/test_ipc.c`'s create carries
  `env_vars = {MYKEY=myvalue, SANDBOX_MODE=test}`; after `Create` it polls the
  restored VM's `serial.log` (via `lifecycle_get`) for the `MYKEY` key name and
  the `SANDBOX-ENV-BEGIN` marker, and asserts the value `myvalue` is **absent**
  (redaction). `test_vmm`'s restore case waits for a fresh `SANDBOX-TICK`, which
  now proves the agent (and thus the device) is alive post-restore.

### 15.12 Phase 10 — Security Hardening (§12)
- **IPC peer authentication (§15.9).** New `ipc_server_set_allowed_uids()`
  (config `allowed_uids` / env `SANDBOX_ALLOWED_UIDS` / `--allowed-uids`); an
  empty list keeps the previous group-only gate and warns at startup.
- **Input validation (Phase 10.5).** `template_name` is constrained to
  `[A-Za-z0-9_-]{1,20}` at `handle_create` before it reaches tap/path names.
  This complements replacing the `system()` nftables shell-outs.
- **nftables via libnftables, not `system()`.** `network_manager.c` now runs
  every rule/cleanup/`list` command through `libnftables`
  (`nft_ctx_new`/`nft_run_cmd_from_buffer`, output captured with the
  `NFT_CTX_OUTPUT_HANDLE` flag for `# handle` parsing). A `system()`/`popen()`
  fallback remains behind `SANDBOX_HAVE_LIBNFTABLES` for builds without the
  library; CMake auto-detects it. No shell is involved on the normal path, so a
  malformed name cannot inject a command.
- **`PR_SET_NO_NEW_PRIVS` in the daemon, ambient CAP_SYS_PTRACE in the jailer**
  (§15.3). Set after `network_manager_init()` and before the pool spawns, so
  every forked jailer inherits it. Because file caps are ignored under
  no_new_privs, the jailer re-grants `CAP_SYS_PTRACE` as an ambient capability
  after `setuid` (verified: `CapAmb`/effective/permitted = `0x80000` at uid
  65534).
- **Secret hygiene.** Guest agent echoes env **key names only** to serial;
  `/tmp/sandbox-env` is `0600`; `serial.log` is opened `0600`; the jail dir is
  `0700`.
- **Deferred (§15.12 non-goals).** Privilege *separation* (a privileged setup
  helper + unprivileged event loop) is not done: the daemon must keep
  `CAP_NET_ADMIN`/`CAP_SYS_ADMIN`/`CAP_MKNOD`/`CAP_CHOWN`/`CAP_SETUID`/
  `CAP_SETGID`/`CAP_SYS_CHROOT` to create taps, device nodes and jailers at
  runtime, so a blanket capability drop would break per-VM provisioning.
  `no_new_privs` + uid allowlist + name validation + no-shell nftables are the
  Phase-10 subset. vsock payload HMAC and per-tenant quotas remain V2.

### 15.13 Phase 11 — Config & Packaging Correctness (§10)
- **Config parser recognises every packaged key.** Previously the daemon
  warned "unknown config key" for `max_queue_depth`, `pool_wait_timeout_ms`,
  `jail_root`, `snapshot_root`, `jailer_uid`, `jailer_gid`; those are now
  parsed (sections already ignored). `config/engine.conf` was rewritten to the
  flat format with the full key set (plus `template`, `allowed_services`,
  `allowed_uids`, `broker_control_socket`, `metrics_*`). Default pool size in
  code is now `5` to match §5.1 and the packaged file.
- **Wiring.** `jail_root`/`snapshot_root`/`jailer_uid`/`jailer_gid` are
  published to the environment (the VMM layer already read
  `SANDBOX_JAIL_ROOT`/`SNAPSHOT_ROOT`; it now also reads
  `SANDBOX_JAILER_UID`/`GID`). `max_queue_depth` is applied via
  `pool_manager_set_max_queue_depth()` — the overflow arrays stay fixed at
  `POOL_MAX_QUEUE_DEPTH` and the *effective* depth is the configured value
  (clamped). `pool_wait_timeout_ms` becomes the default `Create` wait when the
  request sends `0` (`ipc_server_set_default_pool_wait_ms()`).
- **Parser is unit-tested.** Extracted to `src/daemon/config.c` +
  `include/engine_config.h`; `tests/test_config.c` parses a synthetic file
  (all keys, unknown key ignored) and the shipped `config/engine.conf`, and
  checks env precedence. New ctest `config`.
- **`--version` / `--validate-config`.** `--version` prints `SANDBOX_VERSION`.
  `--validate-config` prints the resolved config and checks pool/queue/metrics
  ranges, jailer ids, and that the template manifest exists; exits 1 on error.
  Wired as `ExecStartPre=-` in the unit (leading `-` = non-fatal so a
  first-run install without a template still starts).
- **`Type=notify` readiness + watchdog.** CMake auto-detects libsystemd; the
  daemon calls `sd_notify(READY=1)` after the pool/broker/metrics are up and
  `STOPPING=1` on exit, and starts a watchdog thread (`WATCHDOG=1` every 10 s)
  when `NOTIFY_SOCKET` is set. The unit uses `Type=notify` + `WatchdogSec=30s`.
  Builds without libsystemd compile the calls to no-ops (then use
  `Type=simple` — noted in the unit).
- **Unit resource limits.** `LimitNOFILE=65536`, `TasksMax=512`; capability
  set tightened to the runtime minimum (§15.12) including `CAP_SETPCAP`
  (needed by the jailer's bounding-set drop) and `CAP_SYS_PTRACE` (ambient UFFD
  cap).

### 15.14 Phase 12 — Reliability (§10.8–§10.11)
- **Async `Create` (§10.8).** The epoll loop no longer runs the pool restore
  inline. A `Create` is copied into a `create_job_t` (env `strdup`'d) and handed
  to a small worker pool; the worker does `pool_provision` + env inject +
  `token_issue`, posts a `create_result_t` to a mutex-guarded queue, and wakes
  the loop through the existing `eventfd`. The loop consumes results on
  `EP_WAKE` and does all lifecycle mutation (`lifecycle_track`, `session_own`,
  `pidfd_track`, response send) — those structures stay single-threaded. Per
  session, only the head of a FIFO is dispatched at a time, so a client's
  responses remain in request order; a stale result is matched by
  `(session_fd, epoch)` so a reused fd slot is never misattributed. New config
  keys `create_workers` (default 4), `max_creates_per_session` (16),
  `max_creates_per_uid` (64) bound concurrency (over-limit → `POOL_EXHAUSTED`).
  Note the protocol still has no request-id, hence the per-session
  serialization; true concurrent creates from one session would need one.
- **Env-inject readiness + confirmation (§10.9).** The unconditional 1 s sleep
  before the first vsock `CONNECT` is gone. Instead the daemon polls the
  restored VM's `serial.log` for a post-restore guest marker
  (`SANDBOX-TICK`/`SANDBOX-VSOCK-`) for up to `SANDBOX_VSOCK_SETTLE_MS`
  (default 1000, config `vsock_settle_ms`) and falls back to that fixed settle
  only if nothing appears. After a successful write it waits up to
  `SANDBOX_VSOCK_CONFIRM_MS` (default 2000) for the agent's `SANDBOX-ENV-END`
  echo, turning best-effort injection into confirmed delivery; the marker is
  emitted *after* the agent applies the payload. (Deviation: the plan said poll
  `SANDBOX-READY`, but a restored guest resumes *past* that line — the agent
  prints it once at cold boot — so a liveness marker it re-emits on the busy
  loop is used instead.)
- **Snapshot integrity (§10.10).** `snap_manifest_t` gains `header_size`
  (format guard, validated on every read) and 32-byte SHA-256 digests of
  `memory.snap` and `vmstate`. `build_manifest()` hashes the memory file while
  scanning it; `create_snapshot_template()` hashes the captured vmstate. A new
  self-contained SHA-256 (`src/sha256.c`) backs it (no OpenSSL dependency).
  `snapshot_verify()` / `snapshot_verify_manifest()` recompute and compare;
  `vmm_restore()` refuses a mismatched snapshot before the UFFD handler can
  serve garbage pages, and `sandbox-cli verify --template NAME` +
  `--validate-config` expose the same check. Verification can be skipped with
  `SANDBOX_VERIFY_SNAPSHOT=0`. Existing manifests are rejected cleanly (the
  header guard), so templates must be rebuilt.
- **Per-VM cgroups (§10.11).** New `src/cgroup.c` owns a cgroup v2 hierarchy
  `<root>/sandboxd/active/<vm-id>/`. `cgroup_init()` creates it and enables
  `memory`/`cpu`/`pids` down the chain (`cgroup.subtree_control`); `vmm_restore`
  creates one leaf per VM and passes its `cgroup.procs` to the jailer (which
  already wrote it pre-chroot), so Firecracker lands in its own group.
  `memory.max = guest size + slack` (default 64 MiB, `cgroup_slack_mib`),
  `memory.swap.max = 0`, `memory.oom.group = 1` (OOM kills the VMM, never the
  daemon), `cpu.max` from `cgroup_cpu_max` (default `max` = unlimited).
  `vmm_destroy` removes the leaf after reaping. Best-effort: unavailable →
  unmetered with a log. Verified on the Pi: the restored Firecracker pid appears
  in `<jail>/../active/<vm-id>/cgroup.procs`. New config keys `cgroup_enable`,
  `cgroup_slack_mib`, `cgroup_cpu_max`; new ctest `cgroup`.

### 15.15 Phase 13 — Observability, Hardening & Docs (§10.12–§10.15)
- **Structured logging (§10.12).** New `include/log.h` + `src/log.c`. One JSON
  line per event with standardised fields (`ts` = RFC3339 UTC ms, `level`,
  `component`, `event`, plus per-event fields). `log_level` is
  `debug|info|warn|error` from `engine.conf`, `--log-level`, or
  `SANDBOX_LOG_LEVEL`. Migrated the daemon/broker/ipc-server JSON logs (10
  call sites) from ad-hoc `fprintf` to `LOGF(...)`; journald captures/rotates
  stderr (`StandardError=journal`). `log.c` is compiled into both `sandbox` and
  `sandbox_broker_core`.
- **Metrics/health/ready (§10.13).** `telemetry_serve()` now routes
  `/health` (always 200), `/ready` (200 iff warm pool non-empty, else 503),
  `/metrics`, else 404. The metrics port is on by default
  (`0.0.0.0:9180`; empty `metrics_bind` disables). Added process self-stats
  (`sandbox_process_open_fds`, `..._virtual_memory_bytes`,
  `..._resident_memory_bytes`). The broker gained
  `broker_requests_total{status}` + a `broker_upstream_latency_seconds`
  histogram, exposed on an optional `SANDBOX_BROKER_METRICS_PORT` listener.
  New ctest `metrics`; `test_broker` asserts the broker counters render.
- **CI + sanitizers + fuzzing + chunked bodies (§10.14).** `.github/workflows/ci.yml`
  runs three jobs: build+test, ASan+UBSan
  (`-DSANDBOX_SANITIZE=address,undefined`), and a libFuzzer smoke job (clang).
  New CMake options `SANDBOX_SANITIZE` and `SANDBOX_BUILD_FUZZERS`; `fuzz/`
  holds three harnesses (`fuzz_http`, `fuzz_config`, `fuzz_proto`) with seed
  corpora. Without clang they build with a standalone file/stdin driver, so the
  same corpus runs under ASan/UBSan (verified on the Pi). `config_parse_buffer()`
  was extracted so the config parser is fuzzable in memory. The broker now
  **decodes chunked request bodies** (bounded to 8 MiB), re-frames them with a
  `Content-Length`, and forwards them; malformed input returns 400.
- **Operations docs (§10.15).** `docs/RUNBOOK.md` (daily checks, failure
  playbook, cleanup), `docs/UPGRADE.md` (drain → install → **rebuild templates**
  → verify → rollback; manifest compatibility table), `docs/BACKUP.md` (what to
  back up, integrity, secrets, cadence).
