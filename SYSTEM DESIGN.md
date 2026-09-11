# Sandbox Engine — Technical Handoff for Implementation Session

**Project:** A sandboxing engine for isolating AI agent execution, built as a portfolio piece targeting Dedalus Labs (YC S25) — a company building persistent compute infrastructure for AI agents.

**Author's stated project intent (in their words):** A lightweight and extremely secure engine that interacts with and manages namespace calls directly, provisioning sandboxes according to requirements from a frontend, usable within milli- or microseconds. The engine exposes an API to programmatically provision sandboxes and all functionality in C and C++. A simple desktop layer bundles the engine (like Docker Desktop bundles Docker Engine), but the engine itself is separately installable and usable.

---

## 1. The Core Tension This Project Must Resolve

Every decision below flows from one unresolved tension, stated plainly:

**Isolation strength and provisioning latency trade against each other, and the "right" point on that curve depends entirely on what you assume about the workload's trust level — and AI agents complicate that assumption in a specific way.**

- Traditional sandboxing assumes you can classify workloads as "trusted" (code you wrote/reviewed) or "untrusted" (arbitrary user-submitted code), and pick isolation strength accordingly.
- AI agents break this classification because an agent's *runtime behavior* is decided by an LLM at inference time, based on inputs (documents, web pages, tool outputs) that were never reviewed. Prompt injection means author-trusted code can still take attacker-directed actions. This pushes toward treating agent execution as adversarial by default, which argues for hardware isolation (VMs) rather than shared-kernel isolation (namespaces) — even for "internal" agents.
- **This is a real, unresolved debate, not a settled fact.** A reasonable engineer could argue the opposite: that namespace + seccomp + cgroups is sufficient defense-in-depth for the actual blast radius of a compromised agent (bounded by capability drop, resource limits, and credential brokering), and that VM-grade isolation is overengineering for a threat that mostly manifests as "unwanted actions within granted permissions" rather than "kernel escape." **The implementation session should not treat the microVM direction as settled — it should treat it as the leading hypothesis, pending validation against real Dedalus practice (see §7).**

---

## 2. Option Space: Isolation Backends

These are the isolation mechanisms researched, presented as options with their actual trade-offs — not ranked as a recommendation.

### 2.1 Linux Namespaces (unshare + seccomp-bpf + cgroups v2)

**Mechanism:** `CLONE_NEWPID/NEWNS/NEWNET/NEWIPC/NEWUTS/NEWUSER` for process/filesystem/network/IPC/hostname isolation; seccomp-bpf whitelist for syscall filtering; cgroups v2 for CPU/memory/PID/IO limits.

**Measured/documented characteristics:**
- Cold start: ~20ms baseline (unoptimized)
- Memory overhead: ~3MB per sandbox
- Isolation boundary: shared host kernel

**Known strengths:**
- Fastest possible provisioning at native process-creation speed
- Smallest memory footprint of any option
- Direct, well-documented kernel APIs (`man 7 namespaces`, `man 2 seccomp`, `cgroups(7)`)
- Battle-tested (namespaces since Linux 2.4/2.6, seccomp-bpf since 2012, cgroups v2 since 2015) — underlies Docker, systemd-nspawn, runc/crun
- Full compatibility with arbitrary Linux binaries — no compilation constraint on the workload

**Known limitations:**
- Shared kernel means a kernel-level vulnerability (in namespace code, seccomp code, or an allowed syscall's implementation) has a blast radius across all sandboxes on the host, not just the compromised one
- Vulnerable to hardware side-channels (Spectre/Meltdown-class, cache-timing) since sandboxes share physical CPU cache/TLB/branch predictor state
- Mandatory user namespace (the single highest-leverage escape mitigation) is frequently skipped in practice for implementation simplicity — a documented pitfall to avoid
- Historical real-world escapes exist (Dirty COW 2016, OverlayFS+SETNS 2016, various CVEs) — always via kernel bugs, not "design flaws" in the sandbox's whitelist logic per se

**Research sources to read:**
- `man 7 namespaces`, `man 2 unshare`, `man 2 clone`, `man 2 seccomp`, `man 7 cgroups`
- LWN "Namespaces in operation" series (https://lwn.net/Articles/531114/ through /531819/)
- libseccomp documentation (https://github.com/seccomp/libseccomp)
- Linux kernel cgroup v2 docs (https://docs.kernel.org/admin-guide/cgroup-v2.html)
- Docker/runc/crun source for real-world seccomp policy examples

---

### 2.2 gVisor (Userspace Kernel / "Sentry")

**Mechanism:** Intercepts syscalls from a container and reimplements their logic in a userspace process ("Sentry," written in Go), passing only a small, heavily-audited subset of calls to the real host kernel.

**Documented characteristics:**
- Boot/init latency: 50–100ms
- Memory overhead: ~20–30MB per sandbox (non-shareable floor)
- Network throughput penalty: up to 33% reduction vs. native, due to syscall interception overhead

**Known strengths:**
- Meaningfully shrinks the host kernel's exposed attack surface (hundreds of syscalls down to a small audited set)
- Memory-safe implementation language (Go) closes some vulnerability classes common in C
- Production-proven at scale (backs Google Cloud Run, GKE Sandbox)

**Known limitations:**
- Still no true hardware isolation boundary — a Sentry vulnerability or an exploitable path through the reduced syscall set can still reach the host kernel
- Significant I/O and network throughput penalty makes it a poor fit for data-heavy or I/O-heavy agent workloads (e.g., agents streaming large tool outputs or model weights)
- Larger memory floor than namespaces or microVMs
- Boot latency alone (50-100ms) consumes most or all of a sub-100ms budget before any application-level init

**Research sources to read:**
- gVisor architecture guide (https://gvisor.dev/docs/architecture_guide/)
- gVisor GitHub (runsc implementation)

---

### 2.3 Firecracker MicroVM (KVM-backed, minimal device model)

**Mechanism:** A minimal Virtual Machine Monitor (VMM) written in Rust, using KVM for hardware-accelerated virtualization. Deliberately strips legacy device emulation (no full PCI bus, no BIOS, no USB/floppy emulation) down to a small device set: virtio-net, virtio-block, virtio-vsock, entropy source, serial console, minimal keyboard controller for reset signals.

**Documented characteristics:**
- Cold boot to userspace: ~125ms (note: some benchmarking methodologies measure a narrower slice of "boot" than true end-to-end readiness — worth scrutinizing any specific number's methodology)
- Memory overhead: <5MB per instance
- Guest compatibility: full, unmodified Linux kernel/userspace — arbitrary binaries run normally inside

**Known strengths:**
- True hardware isolation boundary (KVM) — a guest kernel compromise is contained to that guest, doesn't reach the host kernel or sibling guests
- Memory-safe implementation (Rust) eliminates entire classes of VMM-level bugs (buffer overflows, use-after-free) that have historically affected C-based VMMs (QEMU)
- Full Linux compatibility means arbitrary agent code (Python, arbitrary tool binaries) runs unmodified — no compilation constraint
- Production-proven at extreme scale (powers AWS Lambda, Fargate)
- Independent academic benchmarking found Cloud Hypervisor (a close architectural cousin) actually outperforming Firecracker on rigorous end-to-end measurement in at least one replication study — worth reading before assuming Firecracker's numbers are definitively best-in-class

**Known limitations:**
- Cold boot alone (~125ms) exceeds a strict <100ms target — the latency win requires an additional technique (snapshot/restore, see §2.3.1)
- VMM process itself runs in host userspace and is a potential attack surface if compromised (addressed via the "Jailer" pattern, see §4)
- Requires `/dev/kvm` access — doesn't work in deeply nested virtualization environments where KVM access is restricted
- Some cited numbers (e.g., the commonly-quoted ~125ms) come from benchmarks measuring guest-kernel-writes-to-a-special-device mid-boot with a patched kernel — not full end-to-end process creation to termination time. Worth independently verifying before quoting.

**Research sources to read:**
- Firecracker design document and GitHub (https://github.com/firecracker-microvm/firecracker)
- Firecracker's own published design/security docs
- AWS's original Firecracker paper ("Firecracker: Lightweight Virtualization for Serverless Applications," NSDI 2020) — primary source for the architecture's original performance claims
- Independent academic benchmarking of microVM cold-start (search for recent NSDI/OSDI/EuroSys papers comparing Firecracker/Cloud Hypervisor/gVisor — at least one known replication study challenges the "Firecracker is always fastest" narrative)

#### 2.3.1 Snapshot + Restore (required to hit sub-100ms with Firecracker)

**The problem:** Cold boot (~125ms) plus application-level initialization (loading a Python interpreter, importing AI libraries, establishing network connections) can add hundreds of milliseconds to seconds — this dominates over the raw VMM boot time and must be solved separately.

**The technique:** Boot a "template" VM in the background, let it fully complete OS boot and application initialization, pause its vCPUs, and dump the exact machine state (vCPU registers, virtio device state, guest physical memory) to disk. New requests "restore" from this snapshot instead of booting from scratch, resuming execution at the exact paused instruction.

**The remaining bottleneck — eager vs. lazy memory loading:**
- **Eager loading** (naive restore): read the entire memory snapshot from disk into RAM before resuming. Documented cost: ~7,140ms to restore a 2GB guest — completely non-viable for sub-100ms targets, and the cost scales linearly with guest memory size.
- **Lazy loading via `userfaultfd`:** register the guest's memory region with the kernel's `userfaultfd` mechanism so that page faults on unpopulated memory are delegated to a userspace handler thread instead of being silently resolved by the kernel. The VMM resumes vCPUs immediately without reading any snapshot data; the guest's first memory access triggers a page fault, which a dedicated handler thread resolves on-demand via `UFFDIO_COPY` (inject the correct page from the snapshot file) or `UFFDIO_ZEROPAGE` (map an efficient zero page if the snapshot metadata says the page is empty). Documented cost: ~83ms restore-to-resume for a 2GB guest (vs. ~7,140ms eager), with per-page-fault overhead of ~1-10µs (vs. ~1µs for an ordinary kernel-resolved fault).
- **The throughput trade-off:** lazy loading trades upfront latency for a runtime tax — if the guest immediately touches large swaths of memory (e.g., a garbage collection sweep, hashing a large buffer), it pays many sequential micro-penalties. Mitigation: background pre-faulting threads asynchronously stream the remainder of the snapshot into memory after resume, so the on-demand cost is only paid for pages touched before the background stream catches up.

**Research sources to read:**
- `man 2 userfaultfd`
- Linux kernel documentation on userfaultfd (Documentation/admin-guide/mm/userfaultfd.rst)
- Firecracker's own snapshot/restore documentation and any published benchmarks on their implementation
- AWS Lambda's published engineering blog posts on Firecracker snapshot optimization (if available — search for these directly, not from training data)

---

### 2.4 Cloud Hypervisor (KVM-backed, PCI-based device model)

**Mechanism:** A close architectural cousin to Firecracker — Rust-based, KVM-backed — but supports full PCI device emulation, VFIO passthrough, and vhost-user device backends, at the cost of paying full PCI bus enumeration during guest boot (versus Firecracker/virtio-mmio designs that skip this).

**Documented characteristics:**
- Boot time: commonly cited ~200ms (vs. Firecracker's ~125ms) — though see the caveat below and in §2.3, since at least one independent benchmark found Cloud Hypervisor faster than Firecracker on a different measurement methodology; the "Firecracker is faster" claim is not uniformly settled in the literature
- Memory overhead: ~5MB
- The PCI vs. MMIO transport difference is substantial at the code level: virtio-mmio requires roughly 538 lines of kernel code across 1 file, versus virtio-pci's roughly 78,000+ lines across 161 files — this is the likely mechanical source of most of the boot-time gap between Cloud Hypervisor and Firecracker, not an efficiency difference in the hypervisors themselves.

**Known strengths:**
- GPU passthrough (VFIO) — relevant if agent workloads need direct hardware access for local model inference/training rather than calling out to external LLM APIs
- Broader guest OS/hardware compatibility than Firecracker's deliberately minimal model
- Shares Firecracker's Rust memory-safety and KVM hardware-isolation properties

**Known limitations:**
- PCI-only transport (no virtio-mmio support in the current device model, as of research date) structurally costs tens of milliseconds of boot time that Firecracker avoids by design — there was a public GitHub issue proposing MMIO as a build option, unclear if/when it landed
- Same snapshot/restore + userfaultfd considerations as Firecracker apply (this is a KVM-level technique, not VMM-specific), but less publicly documented for Cloud Hypervisor specifically — worth verifying whether their snapshot/restore implementation supports lazy loading as maturely as Firecracker's

**Research sources to read:**
- Cloud Hypervisor GitHub and documentation (https://github.com/cloud-hypervisor/cloud-hypervisor)
- rust-vmm project docs (Cloud Hypervisor is built on shared rust-vmm crates with Firecracker — worth understanding the shared foundation)
- Search for the specific GitHub issue/PR history on virtio-mmio support for Cloud Hypervisor to get current status (this is very likely to have changed since initial research — verify freshly)

---

### 2.5 Unikraft (Unikernel)

**Mechanism:** Compiles the application (agent code) together with only the specific OS micro-libraries it actually needs into a single specialized bootable binary — no general-purpose OS, no user/kernel space separation, single address space. Uses a ported musl libc and POSIX-compatible interfaces (via the `kraft` toolchain) to allow largely unmodified applications (Python runtimes, C++ engines, SQLite) to be compiled into unikernel images.

**Documented characteristics:**
- Cold boot: <10ms
- Image/memory size: ~1MB image, <10MB RAM at runtime
- Boots atop KVM (retains hardware isolation boundary)

**Known strengths:**
- An order of magnitude faster boot than Firecracker's standard path, without needing userfaultfd/snapshot complexity to get there
- No user/kernel space context-switch overhead (single address space) — significant throughput gains for I/O-heavy workloads
- Enables "stateful scale-to-zero": an idle agent (e.g., blocked on an external API call) can be fully suspended at effectively zero cost and resumed in milliseconds when a response arrives
- Retains KVM hardware isolation — not a weaker security model than Firecracker, just a different execution model

**Known limitations:**
- Requires compiling the target application into a unikernel image ahead of time via `kraft` — not suitable for open-ended, arbitrary agent code where the shape of what needs to run isn't known until runtime
- Best fit is a narrow, fixed-shape component (e.g., a specific tool-execution microservice), not a general "run whatever the agent decides to run" sandbox
- Smaller ecosystem/community than Firecracker; fewer production war stories to learn from

**Research sources to read:**
- Unikraft project site and docs (https://unikraft.org)
- Unikraft's papers (it's a Linux Foundation project with published academic work — search for "Unikraft: Fast, Specialized Unikernels the Easy Way," EuroSys 2021, as a starting primary source)
- `kraft` toolchain documentation for the actual compilation workflow

---

### 2.6 WebAssembly / WasmEdge (WASI-NN)

**Mechanism:** Executes code in a memory-safe, stack-based virtual machine with mathematically-provable fault isolation — the runtime controls all memory access and restricts execution to validated bytecode, independent of Linux kernel namespaces or cgroups entirely.

**Documented characteristics:**
- Cold start: <1ms
- Memory footprint: <1MB
- WASI-NN (WebAssembly System Interface for Neural Networks): allows a sandboxed Wasm module to request hardware-accelerated inference (PyTorch/TensorFlow/OpenVINO/llama.cpp backends) from the host, without the sandboxed code ever getting direct GPU/memory access — the host retains control of the actual model weights and returns only requested tensors/tokens

**Known strengths:**
- Fastest and smallest option by a wide margin
- Isolation boundary is independent of Linux kernel security state entirely — sidesteps namespace/seccomp vulnerability classes altogether
- WASI-NN's brokered-inference model is architecturally distinct from GPU passthrough (Cloud Hypervisor) in an important way: the device never leaves host control, only results cross the boundary — a meaningfully different trust model worth considering on its own merits, not just as a speed option

**Known limitations:**
- Cannot run arbitrary, unmodified Linux binaries — requires a Wasm compilation target
- Only suitable for the subset of "agent actions" that are narrow, deterministic functions (e.g., a calculator tool, a JSON validator, a scoped API-calling shim) — not a general-purpose "run whatever code the agent decides to run" sandbox
- Least mature option for running full agent orchestration loops as opposed to individual tool calls

**Research sources to read:**
- WasmEdge documentation (https://wasmedge.org)
- WASI-NN specification (https://github.com/WebAssembly/wasi-nn)
- WebAssembly Component Model documentation (WASI 0.2+) for current state of the ecosystem

---

## 3. Architecture Shape — DECIDED: Single-Backend, Maximum Depth

**Decision:** Single-backend design. The entire engine is built around one isolation mechanism, with no abstraction layer between the public API and the isolation primitives.

**Rationale:** Depth over breadth. A shallow multi-backend abstraction that only honestly supports one backend is architecturally worse than a single-backend design that owns its surface area cleanly. For a portfolio targeting Dedalus, a deeply correct, secure, and performant single-backend implementation with a well-reasoned API demonstrates more engineering judgment than a multi-backend skeleton with one real backend and two stubs.

**LLD consequences of this decision:**
- `SandboxSpec` is the public API struct — it expresses mechanism-level configuration directly (memory limits, seccomp policy, rootfs path, capability set, network config). No intent/mechanism indirection layer.
- The component graph is flat: `Public API → LifecycleManager → [backend-specific managers]`. No `BackendRegistry`, no `IsolationDriver` interface.
- Every component in the design is built to production depth for the chosen backend. Nothing is stubbed.
- The chosen backend's constraints (e.g., kernel version requirements, KVM availability, specific syscall requirements) are first-class documented requirements, not footnotes.

**What this decision does not foreclose:** The Jailer pattern (§4) and credential brokering (§5) are still in scope as separate workstreams — they are orthogonal to backend choice and remain fully valid under a single-backend design.

**Backend decision:** Firecracker + userfaultfd snapshot/restore — resolved below in §2.3 and §6.

---

## 4. The "Jailer" Pattern (Applies Regardless of Backend Choice)

Independent of which isolation backend is primary, there's a separable design pattern worth implementing: hardening the isolation mechanism's own host-side process, not just the workload it isolates.

**The problem it solves:** A VMM (Firecracker/Cloud Hypervisor) or a namespace-setup process runs as a host userspace process. If that process itself has a vulnerability (e.g., a bug in how it parses guest-provided data, like a virtio ring buffer), an attacker who compromises the isolation mechanism from inside the guest/sandbox could potentially reach the host if the isolation mechanism's own process is unconfined.

**The pattern (documented for Firecracker's actual production "Jailer" component):**
1. Cgroup placement for the VMM/isolation-setup process itself (CPU/memory/PID limits, applied before the guest/sandbox boots)
2. Filesystem confinement via chroot/pivot_root into a minimal jail containing only strictly necessary device nodes (e.g., `/dev/kvm`, `/dev/net/tun`)
3. Privilege dropping (setuid/setgid transition from root to unprivileged identity once setup completes)
4. A restrictive seccomp-bpf filter on the VMM/setup process itself, whitelisting only the syscalls it legitimately needs, with complex calls like `ioctl` argument-filtered to specific safe operations

**Why this matters for scoping:** this pattern reuses namespace + seccomp + cgroup mechanics regardless of which backend is primary — meaning implementing this well is valuable even if the final decision is "Firecracker is the primary agent-execution backend," because the Jailer around that Firecracker process is itself a namespace-sandboxing problem.

**Research sources to read:**
- Firecracker's own Jailer documentation and source (part of the Firecracker GitHub repo)
- Look specifically for how Firecracker's Jailer handles the cgroup v1 vs v2 compatibility question, since that's a real-world detail worth matching

---

## 5. Secure Data/Credential Brokering (Orthogonal to Isolation Backend)

Regardless of isolation mechanism, a separable and arguably equally important design question: how does a sandboxed agent get access to credentials/APIs/storage it needs, without holding anything valuable enough to be worth exfiltrating if compromised?

**The pattern discussed (not yet decided/scoped in detail):**
- No long-lived credentials inside any sandbox — only short-lived, narrowly-scoped session tokens
- Outbound calls to external services proxied through a host-side control-plane component that validates the session token and injects real credentials (held only on the host) before forwarding
- Storage access via scoped, pre-signed URLs rather than direct cloud IAM roles

**Why this is listed as orthogonal:** this is a control-plane/API design question, not an isolation-mechanism question — it applies identically whether the backend is namespaces, Firecracker, or anything else. Worth scoping as a distinct workstream rather than conflating with the isolation-backend decision.

**Research needed (not yet done):** how existing serverless/agent platforms actually implement this pattern in practice (e.g., how AWS Lambda's execution role model or various "agent sandbox as a service" startups handle credential scoping) — this hasn't been researched yet and is a genuine gap.

---

## 6. Open Questions for the Implementation Session to Resolve

These are explicitly unresolved. The implementation session should make calls on these (ideally informed by real Dedalus engineering input — see §7) rather than inheriting an assumed answer from this document:

1. **Single-backend or multi-backend?** — **DECIDED: Single-backend. See §3.**
2. **Which backend?** — **DECIDED: Firecracker + userfaultfd snapshot/restore. See §10.**
3. **Default seccomp action** — **DECIDED: Build-time toggle. `SCMP_ACT_KILL_PROCESS` in release builds, `SCMP_ACT_ERRNO(EPERM)` in debug builds. See §10.7.**
4. **Rootless vs. rootful daemon** — **DECIDED: Rootful daemon. See §10.5.**
5. **IPC transport for daemon mode** — **DECIDED: `SOCK_SEQPACKET` + protobuf, persistent per-client-session connections. See §10.8.**
6. **How much of the multi-tier vision to actually build vs. document** — **RESOLVED by §3: nothing is stubbed; the one backend is built to full depth.**
7. **Credential brokering implementation** (§5) — essentially unscoped; needs its own research pass before any implementation decision.

---

## 10. Finalized Architecture — Firecracker + userfaultfd

**Decision:** Firecracker + userfaultfd snapshot/restore as the sole isolation backend.

**Rationale:** Firecracker provides a true hardware VM isolation boundary (KVM) — a guest kernel compromise is contained to that guest and cannot reach the host kernel or sibling guests. The userfaultfd-based lazy restore solves the core hard problem of sub-100ms VM provisioning without eager memory loading. For a portfolio targeting Dedalus (persistent compute for AI agents, where fast VM resume is the central technical challenge), this path directly demonstrates the relevant skill. The `uffd_handler` is kernel-adjacent code that is rare in portfolios and hard to fake.

**Why not namespaces:** Namespace isolation shares the host kernel. A kernel-level vulnerability (in namespace code, seccomp code, or an allowed syscall's implementation) has a blast radius across all sandboxes. For AI agent workloads where prompt injection can direct "trusted" code to take adversarial actions at runtime, hardware isolation is the correct default posture. Namespaces remain relevant as the hardening mechanism for the Jailer layer around the Firecracker VMM process itself (§4).

### 10.1 Component Map

```
SandboxEngine (C library + C++ RAII wrapper)
│
├── vmm_manager         — Firecracker process lifecycle; spawns Firecracker via Jailer;
│                         communicates via REST API over Unix domain socket; owns the
│                         per-VM socket path and process handle
│
├── snapshot_manager    — guest vCPU pause; state serialization to disk (memory snapshot +
│                         microVM state file); snapshot versioning and integrity checksums;
│                         template VM lifecycle (boot once, snapshot, reuse N times)
│
├── uffd_handler        — registers guest physical memory region with userfaultfd;
│                         owns the fault-handling thread; dispatches UFFDIO_COPY (copy
│                         page from snapshot file) and UFFDIO_ZEROPAGE (map zero page
│                         for empty pages) on page faults; races safely with vCPU resume
│
├── prefault_worker     — background thread pool that streams remaining snapshot pages
│                         into guest memory after vCPU resume; prevents long-tail latency
│                         spikes when guest touches memory the uffd_handler hasn't served yet
│
├── network_manager     — tap device creation per VM; IP allocation from a managed pool;
│                         iptables/nftables rules for network policy; CNI-style cleanup on destroy
│
├── jailer              — wraps every Firecracker invocation: cgroup placement of VMM process,
│                         chroot into minimal jail (only /dev/kvm, /dev/net/tun, snapshot files),
│                         privilege drop (root → unprivileged uid), seccomp-bpf filter on the
│                         VMM process itself
│
├── pool_manager        — maintains N pre-restored warm VMs (restored from snapshot, vCPUs
│                         paused, uffd_handler armed); on provision request, unpauses a pool
│                         VM and hands off; asynchronously replenishes the pool
│
├── lifecycle           — state machine per VM: COLD → SNAPSHOTTED → RESTORING →
│                         RUNNING → PAUSED → DESTROYED; owns transitions and error paths
│
└── telemetry           — per-restore latency breakdown (uffd fault rate, pages faulted,
                          prefault progress, time-to-first-instruction); resource accounting
                          per VM; structured logging for pool health
```

### 10.2 Critical Path: Provisioning a Sandbox (from warm pool)

```
Client calls sandbox_create()
  → pool_manager dequeues a pre-restored VM (vCPUs paused, uffd armed)
  → network_manager assigns IP, configures tap device
  → vmm_manager sends "resume vCPUs" command via Firecracker API socket
  → guest resumes at the exact paused instruction
  → page faults served on-demand by uffd_handler (UFFDIO_COPY from snapshot)
  → prefault_worker begins streaming remaining pages in background
  → pool_manager asynchronously boots + snapshots a replacement VM
  → sandbox_create() returns handle to caller
Target: < 100ms end-to-end from call to guest-running
```

### 10.3 Critical Path: Snapshot Template Creation (done once, reused N times)

```
vmm_manager spawns Firecracker via jailer (full cold boot ~125ms)
  → guest OS boots, application init completes (Python runtime loaded, etc.)
  → snapshot_manager issues pause-vCPUs via Firecracker API
  → snapshot_manager serializes: microVM state file + guest memory snapshot to disk
  → snapshot_manager checksums both files and writes manifest
  → vmm_manager tears down the template VM
Template is now on disk. All future provisions restore from this snapshot.
```

### 10.5 Privilege Model — Rootful Daemon

**Decision:** The engine daemon runs as root. Firecracker VMM processes are privilege-dropped by the Jailer after setup.

**Rationale:** The Jailer already handles the most critical privilege reduction — Firecracker (the process with the largest attack surface from guest-provided input) runs as an unprivileged uid inside a chroot with a seccomp-bpf filter, regardless of what the engine daemon's own privilege level is. A rootful daemon with a correctly implemented Jailer is a defensible, production-like choice (this is the same model Docker Engine uses). Rootless adds meaningful security depth but also meaningful implementation complexity that is better spent on the `uffd_handler` and Jailer correctness.

**Privilege flow:**
```
Engine daemon (root)
  → writes cgroup hierarchy for VMM process (requires root)
  → creates tap device via TUNSETIFF (requires CAP_NET_ADMIN, held by root)
  → spawns Firecracker via Jailer binary (root → Jailer setups chroot + seccomp → drops to unprivileged uid)
  → Firecracker VMM process runs as unprivileged uid, confined in chroot, seccomp-filtered
  → guest kernel and guest workload run entirely inside KVM hardware boundary
```

**Security boundary this establishes:**
- Guest workload is isolated by KVM hardware virtualization — cannot reach host kernel directly
- Firecracker VMM (the guest's only reach into host userspace) runs unprivileged + chrooted + seccomp-filtered via Jailer
- Engine daemon itself is root but has no guest-controlled input paths — all guest interaction is mediated through Firecracker's API socket, which the daemon owns

**What this does NOT protect against:** A bug in the engine daemon itself reachable from the public API (e.g., a path traversal in snapshot file handling, a format-string bug in the REST handler) lands an attacker in a root process. Mitigations: strict input validation on all API inputs, no user-controlled data in file paths without sanitization, daemon runs with `PR_SET_NO_NEW_PRIVS` set after startup, seccomp filter on the daemon process itself (whitelist of syscalls the daemon legitimately needs).

### 10.7 Jailer Seccomp Policy

**Decision:** Build-time toggle for the seccomp default action on the Firecracker VMM process.

```c
// jailer/seccomp.h
#ifdef NDEBUG
  // Release build: unwhitelisted syscall kills the VMM process immediately.
  // No error return, no signal handler, no timing oracle for attackers.
  #define JAILER_SECCOMP_DEFAULT SCMP_ACT_KILL_PROCESS
#else
  // Debug build: unwhitelisted syscall returns EPERM.
  // Allows iterative whitelist development — missing syscalls surface as
  // error returns rather than silent process deaths.
  #define JAILER_SECCOMP_DEFAULT SCMP_ACT_ERRNO(EPERM)
#endif
```

**Whitelist scope (Firecracker VMM process — not the guest):**
The Jailer's seccomp filter applies to the Firecracker process itself, not to the guest kernel. The guest runs its own syscalls through KVM — those never reach the host kernel's seccomp filter. The Firecracker VMM process's legitimate syscall needs are narrow and known:

| Syscall category | Specific calls | Reason |
|---|---|---|
| KVM interaction | `ioctl` (filtered to `KVM_*` ioctls only) | Core VMM operation |
| Memory management | `mmap`, `munmap`, `mprotect`, `mremap` | Guest memory region management |
| File I/O | `read`, `write`, `open`, `close`, `fstat`, `lseek` | Snapshot files, serial console, API socket |
| Signaling | `signalfd`, `sigprocmask`, `rt_sigaction` | VMM shutdown handling |
| Epoll/event | `epoll_create1`, `epoll_ctl`, `epoll_wait`, `eventfd` | Virtio device event loops |
| Threading | `clone` (filtered flags), `futex`, `set_robust_list` | VMM internal threads |
| Process | `exit_group`, `getpid`, `tgkill` | Normal process lifecycle |
| Time | `clock_gettime`, `clock_nanosleep` | Metrics, rate limiting |

`ioctl` gets argument filtering (only `KVM_*` command numbers allowed) — not just presence on the whitelist — because `ioctl` is the highest-surface syscall and blanket-allowing it would undermine the filter entirely.

**Lifecycle consequence:** When `SCMP_ACT_KILL_PROCESS` triggers in production, the Firecracker process dies instantly. The `lifecycle` manager detects this via `pidfd_open` + `epoll` watching the VMM's pidfd — no polling, immediate notification. On VMM death: mark the VM as `DESTROYED`, trigger `network_manager` cleanup of the tap device, and signal `pool_manager` to replenish the pool slot.

### 10.8 IPC Transport — Daemon ↔ Client

**Decision:** Unix domain socket (`SOCK_SEQPACKET`) + length-prefixed protobuf, persistent per-client-session connections.

**Socket path:** `/var/run/sandbox-engine/engine.sock` — compile-time constant, overridable via `SANDBOX_ENGINE_SOCKET` environment variable (useful for tests running as non-root).

**Why `SOCK_SEQPACKET`:**
- Message boundaries are preserved by the kernel — no framing code needed on top, no partial-read handling
- Reliable, ordered, connection-oriented — same guarantees as `SOCK_STREAM` but with datagram semantics
- Each `send()` maps to exactly one `recv()` on the other end — clean request/response pairing

**Wire format:**
```
[ 4 bytes: uint32 message length (big-endian) ][ N bytes: serialized protobuf message ]
```
All messages are framed with a 4-byte length prefix. The protobuf schema owns the message type field (a `oneof` at the top level covering all request and response types).

**Protobuf schema (top-level message types):**
```protobuf
syntax = "proto3";

message ClientMessage {
  oneof payload {
    CreateSandboxRequest  create  = 1;
    DestroySandboxRequest destroy = 2;
    PauseSandboxRequest   pause   = 3;
    ResumeSandboxRequest  resume  = 4;
    InspectSandboxRequest inspect = 5;
  }
}

message ServerMessage {
  oneof payload {
    CreateSandboxResponse  create  = 1;
    DestroySandboxResponse destroy = 2;
    ErrorResponse          error   = 3;
    InspectSandboxResponse inspect = 4;
  }
}

message SandboxSpec {
  uint64 memory_mib        = 1;  // guest memory in MiB
  uint32 vcpu_count        = 2;  // number of vCPUs
  string rootfs_path       = 3;  // path to guest rootfs image
  string snapshot_path     = 4;  // path to memory snapshot (empty = cold boot)
  NetworkSpec network      = 5;
  repeated string env      = 6;  // KEY=VALUE pairs injected via vsock or kernel cmdline
}
```

**Daemon-side event loop (epoll-based):**
```
epoll instance owns:
  - listen socket fd          → accept new client connections
  - per-client connection fds → read requests, write responses
  - per-VM pidfd fds          → detect VMM process death (SCMP_ACT_KILL_PROCESS trigger)
  - eventfd for internal wakeup (pool_manager signals pool replenishment needed)

On client connect:
  → accept(), add client fd to epoll with EPOLLIN
  → allocate per-client session state (pending request, sandbox handle map)

On client fd readable:
  → read 4-byte length prefix
  → read N bytes of protobuf body
  → dispatch to request handler (create/destroy/pause/resume/inspect)
  → write response synchronously on same fd

On client fd hangup (EPOLLHUP):
  → destroy all sandboxes owned by this session
  → free session state, remove fd from epoll

On VM pidfd readable (VMM died):
  → lifecycle: transition VM to DESTROYED
  → network_manager: clean up tap device
  → pool_manager: signal slot available for replenishment
```

**Caller authentication:** `SO_PEERCRED` on accept — the kernel provides the caller's uid/pid/gid without any possibility of spoofing. The daemon checks uid == 0 or uid is in a configured allowlist before processing any request. This is enforced at connection time, not per-request.

**Session ownership model:** All sandboxes created within a session are owned by that session. If the client disconnects (clean close or crash), the daemon destroys all owned sandboxes. No orphaned VMs.

### 10.9 `uffd_handler` — Threading Model and Page Resolution

**Decision:** One dedicated fault-handler thread per VM. Snapshot file is `mmap`'d into the daemon's address space at restore time. Faults are resolved by `UFFDIO_COPY` from the mmap region. A separate `prefault_worker` thread per VM streams the snapshot into page cache in the background.

**Why one thread per VM:** At pool sizes of 5–20 VMs, linear thread scaling is trivially cheap. Each thread blocks silently on `read(uffd_fd)` when idle. A slow page resolution for one VM blocks only that VM's thread — zero cross-VM interference. No locks, no shared state between fault handlers.

**Full restore sequence for one VM:**

```c
// 1. snapshot_manager maps the snapshot into daemon address space at restore time
void* snap_base = mmap(NULL, snap_size, PROT_READ, MAP_SHARED, snap_fd, 0);
// snap_base is now the source for all UFFDIO_COPY operations

// 2. Register guest physical memory region with userfaultfd
struct uffdio_register reg = {
    .range = { .start = (uint64_t)guest_mem_base, .len = guest_mem_size },
    .mode  = UFFDIO_REGISTER_MODE_MISSING,
};
ioctl(uffd_fd, UFFDIO_REGISTER, &reg);

// 3. Resume vCPUs via Firecracker API — guest starts executing immediately,
//    page faults on unmapped pages are delegated to uffd_fd instead of SIGSEGV

// 4. uffd_handler thread (one per VM):
void* uffd_thread_fn(void* arg) {
    vm_t* vm = arg;
    struct uffd_msg msg;
    for (;;) {
        read(vm->uffd_fd, &msg, sizeof(msg));  // blocks until fault
        if (msg.event != UFFD_EVENT_PAGEFAULT) continue;

        uint64_t fault_addr = msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
        uint64_t offset     = fault_addr - (uint64_t)vm->guest_mem_base;

        // Check snapshot page map: is this page non-zero in the snapshot?
        if (snapshot_page_is_present(vm->snap_manifest, offset)) {
            struct uffdio_copy copy = {
                .dst  = fault_addr,
                .src  = (uint64_t)(vm->snap_base + offset),  // from mmap region
                .len  = PAGE_SIZE,
                .mode = 0,
            };
            ioctl(vm->uffd_fd, UFFDIO_COPY, &copy);
        } else {
            struct uffdio_zeropage zero = {
                .range = { .start = fault_addr, .len = PAGE_SIZE },
                .mode  = 0,
            };
            ioctl(vm->uffd_fd, UFFDIO_ZEROPAGE, &zero);
        }
    }
}

// 5. prefault_worker thread (one per VM, starts concurrently with vCPU resume):
void* prefault_worker_fn(void* arg) {
    vm_t* vm = arg;
    // Advise kernel: sequential access pattern, read-ahead aggressively
    madvise(vm->snap_base, vm->snap_size, MADV_SEQUENTIAL);
    // Stream through all pages — pulls them into page cache so uffd_handler
    // hits cache (~1-10µs) instead of disk (~50-200µs) for subsequent faults
    for (size_t off = 0; off < vm->snap_size; off += PAGE_SIZE) {
        volatile uint8_t* p = (uint8_t*)vm->snap_base + off;
        (void)*p;  // touch page to fault it into page cache
        if (vm->destroyed) break;  // VM was destroyed, stop streaming
    }
}
```

**Snapshot page manifest:** The `snapshot_manager` writes a compact bitmap alongside the memory snapshot — one bit per 4KB page, 1 = page has non-zero content in snapshot, 0 = page was zero. The fault handler uses this to dispatch `UFFDIO_COPY` vs `UFFDIO_ZEROPAGE` without reading the page content. `UFFDIO_ZEROPAGE` is significantly cheaper than `UFFDIO_COPY` (kernel zeroes in place vs. copying from mmap) and zero pages are common in a freshly booted guest.

**Race safety:** vCPUs resume before the fault handler thread starts — this is safe because the kernel holds faulting vCPUs blocked on the uffd fd until a handler resolves them. There is no window where the guest can access unmapped memory and get a crash rather than a handled fault. The `uffdio_register` call must complete before vCPU resume for this guarantee to hold.

**Teardown:** On VM destroy, `vm->destroyed` flag is set, the uffd fd is closed (this unblocks the `read()` in the fault handler with an error), and both threads are `pthread_join`'d before the mmap region is unmapped.

**Latency profile with warm page cache (from pool):**
- vCPU resume to first guest instruction: ~1ms (Firecracker API call overhead)
- Per-fault resolution (page in cache): ~1–10µs (`UFFDIO_COPY` from mmap, page already in page cache)
- Per-fault resolution (page cold): ~50–200µs (mmap fault → disk read → `UFFDIO_COPY`)
- `prefault_worker` races to warm cache: most pages cached within 50–200ms depending on snapshot size and NVMe throughput

### 10.10 Pool Manager — Static Pool with Overflow Queue

**Decision:** Static target pool size, runtime-configurable, with a pending-request overflow queue and a configurable drain timeout.

**Configuration (read at daemon startup from config file or env vars):**
```
SANDBOX_POOL_SIZE=5              # target number of warm VMs to maintain
SANDBOX_POOL_WAIT_TIMEOUT_MS=500 # max time a queued request waits before POOL_EXHAUSTED
SANDBOX_POOL_MAX_QUEUE_DEPTH=50  # max pending requests before immediate rejection
```

**Data structures:**
```c
typedef struct {
    // Warm VMs ready to hand off — restored from snapshot, vCPUs paused, uffd armed
    vm_handle_t  warm_queue[POOL_MAX_SIZE];
    int          warm_head, warm_tail, warm_count;

    // Pending requests waiting for a warm VM to become available
    pending_req_t overflow_queue[POOL_MAX_QUEUE_DEPTH];
    int           overflow_head, overflow_tail, overflow_count;

    pthread_mutex_t lock;
    pthread_cond_t  vm_available;   // signaled when a warm VM is enqueued
    pthread_cond_t  slot_available; // signaled when replenishment can start

    int  target_size;
    int  restoring_count;  // VMs currently being restored (in flight)
    bool shutdown;
} pool_manager_t;
```

**Critical invariant:**
```
warm_count + restoring_count <= target_size
```
The pool never starts more restore operations than needed to reach `target_size`. This prevents runaway memory consumption if restores pile up while the pool is draining fast.

**`sandbox_create()` fast path (warm VM available):**
```c
pthread_mutex_lock(&pool->lock);
if (pool->warm_count > 0) {
    vm = dequeue_warm(pool);          // O(1)
    pool->restoring_count++;          // account for replenishment about to start
    pthread_cond_signal(&pool->slot_available);
    pthread_mutex_unlock(&pool->lock);
    // hand vm to caller — network setup, vCPU resume happen outside the lock
    return vm;
}
```

**`sandbox_create()` slow path (pool exhausted — overflow queue):**
```c
if (pool->overflow_count >= POOL_MAX_QUEUE_DEPTH) {
    pthread_mutex_unlock(&pool->lock);
    return SANDBOX_ERR_POOL_EXHAUSTED;  // immediate rejection, queue full
}
pending_req_t req = { .result = NULL, .ready = false };
enqueue_overflow(pool, &req);
struct timespec deadline = now_plus_ms(pool->wait_timeout_ms);
while (!req.ready && !pool->shutdown) {
    int rc = pthread_cond_timedwait(&pool->vm_available, &pool->lock, &deadline);
    if (rc == ETIMEDOUT) {
        dequeue_overflow(pool, &req);
        pthread_mutex_unlock(&pool->lock);
        return SANDBOX_ERR_POOL_EXHAUSTED;  // timed out waiting
    }
}
vm = req.result;
pthread_mutex_unlock(&pool->lock);
return vm;
```

**Replenishment thread (runs continuously in background):**
```c
void* replenishment_fn(void* arg) {
    pool_manager_t* pool = arg;
    for (;;) {
        pthread_mutex_lock(&pool->lock);
        // Wait until we're below target and not already restoring enough
        while ((pool->warm_count + pool->restoring_count >= pool->target_size)
               && !pool->shutdown) {
            pthread_cond_wait(&pool->slot_available, &pool->lock);
        }
        if (pool->shutdown) break;
        pool->restoring_count++;
        pthread_mutex_unlock(&pool->lock);

        // Restore a VM from snapshot (blocking, outside the lock)
        vm_handle_t vm = restore_vm_from_snapshot();  // ~83ms

        pthread_mutex_lock(&pool->lock);
        pool->restoring_count--;
        if (pool->overflow_count > 0) {
            // Hand directly to a waiting caller — don't re-pool
            pending_req_t* req = peek_overflow(pool);
            req->result = vm;
            req->ready  = true;
            dequeue_overflow(pool, req);
            pthread_cond_broadcast(&pool->vm_available);
        } else {
            enqueue_warm(pool, vm);
        }
        pthread_mutex_unlock(&pool->lock);
    }
}
```

**On VM destroy:** the destroyed VM's memory is reclaimed; `restoring_count` does not change (the destroyed VM was already handed off and is no longer counted); `slot_available` is signaled so replenishment can fill the gap.

**On daemon shutdown:** `pool->shutdown = true`, broadcast both condition variables, join the replenishment thread, destroy all warm VMs in the queue.

**Observability:** `telemetry` tracks `pool_warm_count`, `pool_restoring_count`, `pool_overflow_depth`, and `pool_exhaustion_count` as live metrics — these are the primary operational health signals for the pool.

### 10.6 Open LLD Questions (to be resolved in subsequent decisions)

- Credential brokering design (§5 / §6 item 7)
- Snapshot storage layout (single flat file vs. content-addressed page store)

--- (Context, Not Yet Resolved)

The author is planning outreach to a Dedalus Labs engineer with a specific technical question before finalizing architecture, roughly:

> Whether namespace-based isolation is fundamentally insufficient for LLM-driven agent execution given prompt-injection risk (i.e., does Dedalus treat "trusted" agent code as still needing hardware isolation), or whether Dedalus treats that as an acceptable risk tier and reserves microVM isolation for specific workload classes — and separately, whether userfaultfd-based snapshot restore is actually what closes their latency gap in production, or whether application-level initialization dominates regardless.

**This response, if obtained, should materially inform §6's open questions** — particularly #1 and #2. The implementation session should check whether this conversation happened and what was learned before locking in a direction, rather than proceeding purely from the desk research in this document.

---

## 8. Prior Work Already Done (Reusable Regardless of Final Direction)

- Deep study of Linux namespaces, seccomp-bpf, and cgroups v2 fundamentals — completed, notes exist
- A detailed namespace-only engine architecture was previously designed in full (component breakdown: `ns_manager`, `seccomp_manager`, `cgroup_manager`, `rootfs_manager`, `pool_manager`, `capability_manager`, `lifecycle`, `telemetry`; C ABI sketch with opaque handles and builder-pattern `SandboxSpec`; C++ RAII wrapper sketch; daemon vs. embedded deployment modes; pool-based warm-provisioning design for latency) — this remains a valid and detailed starting point for the namespace backend regardless of whether it ends up as the sole backend or one tier among several
- A full threat-model / suitability writeup exists comparing namespace sandboxing to VM-grade isolation in general terms (before the microVM-specific research in this document sharpened the AI-agent-specific argument)
- A comparative table and technical rationale for Firecracker/Cloud Hypervisor/Unikraft/WasmEdge/gVisor exists (this document consolidates and supersedes the narrative version of that research)

**None of this prior work should be treated as a locked decision — it's institutional memory of what's already been explored, provided so the implementation session doesn't have to re-derive it from scratch.**

---

## 9. Suggested First Actions for the Implementation Session

Not a plan, just a suggested entry point:

1. Check whether the Dedalus outreach (§7) produced a response; if so, weigh it heavily in resolving §6.1/6.2.
2. If no response yet, make an explicit, stated assumption about §6.1 (single vs. multi-backend) and §6.2 (which backend), document the reasoning, and proceed — don't let an unanswered outreach block progress indefinitely.
3. Whatever backend is chosen first, treat the "Jailer" pattern (§4) as a near-term follow-on regardless, since it's valuable under every scenario in §6.1/6.2.
4. Treat credential brokering (§5) as a separate, parallel research task — it doesn't block isolation-backend implementation and shouldn't be an afterthought bolted on at the end.