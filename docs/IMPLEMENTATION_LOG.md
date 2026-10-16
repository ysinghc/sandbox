# Implementation Log

Running record of deviations from the LLD, ambiguous points and how they
were resolved, and measured numbers vs. LLD targets. Short pointers live in
code comments; detail lives here.

## Environment (no sudo on this box)

- `cmake` via `pip install --user cmake` (4.4.3).
- `protoc` + protobuf headers via `apt-get download` + `dpkg-deb -x` of
  `libprotobuf-dev`, `libprotoc-dev`, `protobuf-compiler`, `libprotoc32t64`
  (3.21.12) under `/tmp/opencode/protodebs/local`, wired via `PROTO_ROOT`.
  The dev .deb ships a dangling `libprotobuf.so` symlink plus non-PIC
  static `.a`s; symlinked the shared runtime from the system
  `libprotobuf32t64` package and moved the `.a`s aside so
  `find_package(Protobuf)` resolves the shared lib.
- AppArmor blocks userns id-mapping here (`uid_map` writes fail), so
  chroot/setuid effects are only testable where privileged; tests SKIP
  those paths here (see Phase 2).
- GCC 13 TSan needs `setarch -R` on kernel 7.0.0 (shadow-mapping conflict
  with ASLR); without it the TSan runtime FATALS at init.

## Phase 0 — Scaffolding

- `CMakeLists.txt`: added `target_include_directories` (LLD snippet omits
  them), a `PROTO_ROOT` hint for the no-sudo protobuf location, and tests
  wiring. Target/file list, flags, and linkage otherwise verbatim.
- Client API stubs (`sandbox_init/create/...`) live in `src/lifecycle.c` —
  the LLD file list has no dedicated client file, so this was the only
  in-list home. Real implementation in Phase 8.
- Missing includes the LLD snippets omit: `<stdbool.h>` (snapshot),
  `<stdint.h>` (network header).
- `config/credentials.conf.example` ships a placeholder, never a secret.

## Phase 1 — Pool Manager (§5.1)

- DEVIATION (correctness): dropped the fast-path `restoring_count++`
  reservation. Kept verbatim, it double-counts with the replenishment
  thread's own increment, pinning `warm + restoring == target` forever so
  the pool never refills. Replenishment solely owns `restoring_count`.
- `pool_manager_t` gains `pthread_t replenish_thread` (join on destroy);
  all LLD fields exact.
- Completions: `target_size` clamped to `POOL_MAX_SIZE`, `init` rejects
  `target <= 0`, `wait_ms == 0`/NULL spec fails immediately (§3.1),
  shutdown waiters get `INTERNAL`, NULL restore hands off NULL or retries
  after 10ms backoff. `vmm_destroy` stub frees the dummy handle.
- Test bug: `assert(pool_manager_init(...))` deadlocked under Release —
  NDEBUG strips the call, leaving the mutex uninitialized. Tests now use
  `CHECK_RC` (never side effects inside `assert`).
- Measured: pool self-fills 0→5 in ~0.5s; 12 workers × 6 provisions =
  72/72 OK, 0 failures, ~35k invariant samples, TSan clean.

## Phase 3 — Network Manager (§5.7)

- Rules are verbatim §5.7 (`iifname` accept for `.1:8080`, then drop), via
  `system()` per LLD (libnftables TODO kept). Chain auto-created as
  `type filter hook forward priority 0; policy accept` (LLD assumes it
  exists). Rule handles resolved at cleanup by parsing `nft -a list`, so
  `vm_network_t` is unchanged.
- Bare `SIOCSIFADDR` leaves a /32 with no connected route (replies to .2
  escape via the default interface); the lib also sets 255.255.0.0 via
  `SIOCSIFNETMASK`. Without this the design cannot function.
- Verified at packet level from the guest side (frames through the tap fd):
  `.1:8080` answers SYN-ACK; non-local destinations are silent; deleting
  only the drop rule lets the SYN-ACK through and restoring it re-silences
  (control proves the rule does the dropping). nftrace confirms
  drop-verdict vs policy-accept per phase.
- Test-topology notes (not production issues): the netns "internet" needs a
  static `.2` neighbor pointing at VH's MAC (foreign dst MAC dies as
  PACKET_OTHERHOST on veth ingress); the guest ARP on the tap is answered
  by the test like a real guest would. Test checksums are byte-wise (an
  earlier `uint16_t`-cast version misbehaved under `-O3`).
- FINDING (security-relevant, needs a decision): the specified rules live
  only in the `forward` chain, so host-LOCAL destinations bypass them.
  Measured: SYN `.2`→`.1:9999` gets RST,ACK — the guest can probe every
  host-local port (open ones would handshake). "Only 8080 reachable" holds
  for forwarded traffic, not for host-local. Fix would be input-chain
  rules (`iifname tap-*` → only `.1:8080` accept, rest drop) — not added
  without approval since it changes the design.
- Multi-tap: duplicate `.1` assignment succeeds on the ioctl path (no
  EEXIST), so pool-of-5 setup won't fail at assignment; guest `.2`
  collisions across taps need a Phase 6 answer. Tap names must stay under
  `IFNAMSIZ` (test uses `vmt<PID>`; daemon vm IDs must stay short).
- Hygiene: `tests/net_cleanup.sh` runs as a CTest FIXTURES_CLEANUP (leaked
  netns/routes/rules poison later runs — learned the hard way); the test
  also pre-cleans and saves/restores `ip_forward`.
- Follow-up fixes (approved): per-VM /30 subnets via FNV-1a hash of vm_id
  (`network_subnet_addrs()`; hash keeps string IDs stable, 16384 slots),
  input-chain accept+drop per tap (closes the host port-scan hole —
  verified: closed local ports now silent, was RST,ACK), `vm_network_t`
  unchanged (handles resolved at cleanup for both chains),
  `network_manager_init()` added for daemon startup (setup ensures chains
  too). Broker endpoint is now per-VM (host IP of its /30); Phase 7 must
  bind per-tap or wildcard. Test uses fd-injection (host-side sockets
  would not traverse `iifname` rules) and covers two-VM no-crosstalk.

## Phase 5 — UFFD Handler + Prefault Worker (§5.2, §5.3)

- Setup order per LLD (mmap snap, `UFFDIO_API`, `UFFDIO_REGISTER`, spawn
  handler, then resume); handler + prefault both start pre-resume.
  Copy-vs-zero branch on the manifest bit; short copies left missing for
  guest refault. fd is NONBLOCK + 100ms poll so destroy is clean.
- `page_faults`/`destroyed` use `__atomic` builtins on the plain fields
  (no struct-type change); manifest page size must match the host page.
- Measured: setup (mmap+uffd+register) 0–1ms — far inside the 83ms budget,
  which Firecracker load will dominate in Phase 6. 64/64 pages faulted
  exactly once with per-word data match; prefault early-exit 1ms.
- TSan caught 2 shutdown races (close-vs-inflight-read, `-1` write vs
  poll setup); fixed by ordering flag → join → release instead of
  close-to-wake. TSan silent on uffd + pool afterwards.

## Phase 4 — Snapshot Manager (§5.6)

- Manifest I/O (`build_`/`write_`/`read_manifest`, page-present bit ops)
  with validation (magic, 4K pages, exact bitmap size; corrupt/truncated
  manifests refused, never exposed). `SANDBOX_SNAPSHOT_ROOT` overrides the
  LLD path for tests.
- Publish is backup-swap on rebuild (plain `rename` cannot replace a
  non-empty dir): readers see old, missing, then new — never partial
  (168k concurrent reads, 0 bad). Same-dir rename keeps atomicity.
- `snapshot_check_version()` adopts on first sight, drains + adopts on
  change (`expected_version` field added to the pool); create-flow hygiene
  verified with stubbed VMM (fails clean, no temp residue, final intact).
- VMM seams (`cold_boot` returns NULL until Phase 6) keep the LLD
  orchestration line-for-line; real Firecracker capture + `wait_ready`
  land in Phase 6. `pool_manager_flush_and_rebuild` is a no-op hook for
  the Phase 8 daemon.

## Phase 2 — Jailer + Seccomp (§5.4, §5.5)

- Order follows the spec text: cgroup → chroot → caps → setuid/setgid →
  seccomp → exec (the pseudocode places cgroup after chroot, which cannot
  work — `/sys/fs/cgroup` is unreachable post-chroot).
- `drop_capabilities()` retains `CAP_SETUID`/`CAP_SETGID` across the drop
  (the subsequent setuid/setgid per LLD order requires them), drops
  everything else including the bounding set; the uid transition clears the
  rest. Bounding drops run BEFORE the `capset` clear — the first version did
  it after, which strips `CAP_SETPCAP` from the effective set and makes every
  `PR_CAPBSET_DROP` fail EPERM (production spawns would all `_exit(127)`);
  caught by the sequence test via strace. Implemented via raw
  `capget`/`capset` (`<linux/capability.h>`, no libcap on this box).
- Internal `spawn_jailed()` takes jail root, binary, argv, and
  mount/seccomp toggles; public `spawn_firecracker_jailed()` pins the
  canonical root, `/firecracker`, mounts on, seccomp on. Test-only splits
  (seccomp loaded in-probe after pre-filter checks) exercise the same code
  in the same order — a static probe cannot start under the filter
  (`arch_prctl` is not whitelisted).
- Seccomp whitelist is verbatim §5.5, including the KVM-only `ioctl` mask.
  No syscalls added. *(Superseded in Phase 6: the real Firecracker needs far
  more — see below and `SYSTEM DESIGN.md` §15.3.)*
- Verified in a multipass jammy VM (8c/8G, system protobuf 3.12, all
  builds/tests run there, never on the host): `ctest` 2/2 as both `ubuntu`
  and root. Seccomp kills verified (`socket`, non-KVM `ioctl` → SIGSYS)
  *(the Phase 6 filter allows `socket`; the probe now uses `ptrace` + `FIONREAD`)*.
  Sequence test forks: child unshares, parent writes `/proc/<pid>/uid_map`
  from outside (self-writes from inside fail under AppArmor/restricted
  kernels — the first version did that and always SKIPped). Root maps the
  full range: real chroot + uid-drop to 65534 verified end to end. Non-root
  maps itself once and runs a uid-0 variant (chroot still real; the uid
  transition is a no-op there).

## Phase 6 — VMM / Snapshot / Restore + aarch64 bring-up (§5.6, §5.4 flow)

- **Test host = Raspberry Pi 5**, not multipass. Ubuntu 24.04 aarch64, 4c/7G,
  `/dev/kvm` + `/dev/userfaultfd`, `unprivileged_userfaultfd=0`. Firecracker
  v1.17.0 built from source (`aarch64-unknown-linux-musl`); assets in
  `/opt/sandbox-assets/` (`firecracker`, `vmlinux` 6.1.188, `rootfs.ext4`
  128 MiB). Repo syncs to `~/sandbox`, builds into `~/sb-build`.
- **Transport is virtio-MMIO, not PCI.** `--enable-pci` on this host fails:
  MSI-X setup fails → virtio-blk never registers → `Cannot open root device
  "vda"`; with 128 MiB RAM PCI gives no kernel output and an immediate guest
  shutdown. `pci_enabled()` now defaults to MMIO and `--enable-pci` is opt-in
  via `SANDBOX_FC_PCI=1`; both capture and restore honour it. `fc_boot_args()`
  prepends `keep_bootcon` on aarch64.
- **Per-VM tap via `/snapshot/load` `network_overrides`, not hotplug.** FC only
  supports post-restore device attach on PCI, so the template is captured
  *with* a NIC (`net1`) and each restore retargets it
  (`[{"iface_id":"net1","host_dev_name":"<tap>"}]`). FC fixes the guest MAC at
  capture and `network_overrides` cannot change it, so restored VMs share the
  template MAC. The restore tap must pre-exist (FC won't create it).
- **Persistent tap + released fd.** `network_setup()` now sets `TUNSETPERSIST`
  and closes its fd (`tap_fd = -1`); holding a non-multiqueue fd made FC's own
  `TUNSETIFF` fail `EBUSY (os error 16)`. `network_tap_open()` reopens for
  tests; `network_cleanup()` deletes by name. Bug found here: `TUNSETPERSIST`
  takes its argument **by value** — `&zero` *set* the flag, leaking every tap
  (`tun_flags = 0x1802`); fixed to pass `1`/`0` directly.
- **Restore deadlock fix.** FC faults guest memory *during* `/snapshot/load`,
  so the order is: `fc_send_request(load)` → start the UFFD handler → then
  `fc_read_response` → start prefault → resume. HTTP client split into
  `fc_connect`/`fc_send_request`/`fc_read_response`/`fc_transact`.
- **Post-restore timer.** The restored guest executes (fresh serial output),
  but the aarch64 arch timer does not re-arm on this host, so a `sleep`ing
  guest hangs in WFI. The rootfs `/init` heartbeat busy-spins (`SANDBOX-TICK`
  with a bounded loop); `test_vmm` waits for a fresh tick as execution proof.
- **Seccomp rebuilt from Firecracker's own policy** (union of
  `resources/seccomp/aarch64-unknown-linux-musl.json` vmm/api/vcpu filters) plus
  the pre-filter calls (`socket/bind/listen/accept4`, `connect/sendmsg/recvmsg`,
  `ppoll`, `uname`, `prctl`, `clone`, `dup3`, `epoll_create1`, `prlimit64`,
  `getpid`, `set_robust_list`, `set_tid_address`) and a broadened `ioctl` filter
  (KVM class `0xAE` + UFFD class `0xAA` incl. `USERFAULTFD_IOC_NEW` + specific
  `TUN*`/`FIONBIO`/`TIOCGWINSZ`/`TCGETS`/`BLK*`). Derived under `SCMP_ACT_LOG`
  (kernel audit, rate limits raised) and iterated via SIGSYS `syscall=` in
  `dmesg`. Temp `SANDBOX_SECCOMP_LOG` hook removed. Probe now dies on `ptrace`
  and `FIONREAD` (both genuinely forbidden).
- **Network test hardened for the host.** Docker's iptables `FORWARD`
  `policy drop` sits at the same filter priority as `sandbox_policy`, so
  `forward_drop` never isolated our rule; the test now inserts a tap-scoped
  accept (`-i`/`-o <tap>`) around that section and flushes the `sandbox_policy`
  chains at start (pid-embedding tap names can collide across aborted runs).
- Full `ctest` **8/8** (`tmpl_setup`, `pool`, `jailer`, `network`,
  `network_cleanup`, `snapshot`, `vmm`, `uffd`) passes twice back-to-back with
  seccomp **on** and MMIO, leaving **zero** leaked taps / rules.
- **Doc/code sync pass.** Audited every component against `SYSTEM DESIGN.md`
  and closed the remaining gaps in §15: the template store is self-contained
  (bundles `vmlinux`+`rootfs.ext4`, restore binds `vmstate`/`memory.snap`/
  `rootfs.ext4`), `create_snapshot_template` uses an ephemeral `tpl-<name>` jail
  + template NIC, `vmm_cold_boot`/`vmm_restore` signatures differ from the LLD,
  `restore_vm_from_snapshot` now provisions a real per-VM network, there is no
  separate jailer binary (in-daemon `fork`) and cgroup placement is unused in
  the VMM paths, and `src/cpp/sandbox.cpp` + `lifecycle_track/remove` are stubs.

## Phase 7 — Credential Broker (§5.8, §2.4, §7.2)

- Added `include/broker.h` and split the broker into a static library
  `sandbox_broker_core` (`src/broker/{http,credentials,core}.c`) so the request
  pipeline is testable in-process; `src/broker/main.c` is a thin
  `curl_global_init` + `broker_run()` shim. New dependency: libcurl
  (`find_package(CURL REQUIRED)`; installed `libcurl4-openssl-dev` on the Pi).
- `credentials.c`: lenient INI parser (`[host]` + `credential = …`, `#`/`;`
  comments); lookup strips `:port` and folds case.
- `http.c`: byte-by-byte request-line+header reader (stops at CRLFCRLF so the
  body stays in the socket — the LLD's "no buffering of body"), plus
  case-insensitive get/set/remove and a minimal JSON error sender.
- `core.c`: token-validation client, allow-list, libcurl forwarding, the
  request pipeline, and the accept loop.
- **Listen address is wildcard `0.0.0.0:8080`, not `169.254.0.1:8080`.** With
  Phase 3's per-VM /30 each tap's host side is a distinct `.1`, so no one
  link-local address serves all VMs. Overridable via `SANDBOX_BROKER_LISTEN`.
- **Validation wire format is fixed-framing**, not the LLD structs
  (`broker_validate_resp_t.allowed_services` is a `char**` — not serializable):
  req = `u8 type` + 32 raw token bytes; resp = `u8 status`, and iff valid
  `u32 sandbox_id` (BE) + `u16 n_services` + `n×(u8 len + bytes)`. The engine
  half is Phase 8; tests drive a **mock engine**.
- **Forwarding via libcurl** with defaults `https` + cert verification on; the
  upstream response is relayed verbatim (transfer/content decoding off). Request
  body is streamed via a libcurl read callback bounded by `Content-Length`;
  chunked request bodies return 502. `SANDBOX_BROKER_UPSTREAM_SCHEME` /
  `SANDBOX_BROKER_TLS_VERIFY=0` exist for tests.
- New test `tests/test_broker.c` (`broker`, unprivileged): credential parsing,
  HTTP parse/munge, token decode, allow-list, and an end-to-end proxy over an
  ephemeral loopback mock upstream — asserts the real credential is injected,
  the session token stripped, and the body streamed; plus the 401/403/400
  reject paths.
- **CTest must run as root** (`sudo -E ctest`): `pool`/`jailer`/`vmm`/`network`
  do chroot / uid-drop / tap work. An unprivileged `ctest` shows spurious
  `pool`/`jailer` failures (chroot exit 9); the per-test `sudo` commands in
  `tests/CMakeLists.txt` only cover some targets.
- Full `ctest` **9/9** (adds `broker`) passes twice back-to-back, seccomp on,
  MMIO, zero leaked taps/rules.

## Phase 8 — Daemon / IPC / Lifecycle (§2.3, §3.1, §3.2, §6.1, §11)

- Implemented the layers that were stubs after Phase 7: `src/ipc_server.c`
  (engine socket + engine-side broker-control), `src/lifecycle.c` (live-VM
  registry + full `libsandbox` client API), `src/daemon/main.c`,
  `src/cli/main.c`, `src/telemetry.c`, and `src/cpp/sandbox.cpp`.
- **Wire format:** `SOCK_SEQPACKET`, one frame = `u32 big-endian length` +
  protobuf payload (`src/ipc_internal.h`, `sendmsg` iovec). Generated protobuf
  is **C++**, so a C bridge was added: `include/ipc_codec.h` +
  `src/ipc_codec.cpp` (extra files beyond §8.1) expose
  `ipc_encode/decode_{request,response}` with C linkage.
- **Schema extension:** `ServerMessage` gained `PauseResponse`/`ResumeResponse`
  (fields 5/6) because §6.1 has no pause/resume reply (the client would block).
- **Loop:** single-threaded `epoll` (listener + wake `eventfd` + client fds);
  `ipc_server_request_stop()` is async-signal-safe for a SIGTERM handler. No
  pidfd crash-watching yet.
- **Sessions & tokens:** a connection owns its sandboxes and reclaims them on
  disconnect. Tokens are 256-bit `getrandom`, hex in `session_token`, keyed on
  the 32 raw bytes; the allow-list is a **global** policy
  (`SANDBOX_ALLOWED_SERVICES`). The engine-side broker-control server is the
  §5.8 counterpart to the broker's `broker_validate_token` (shared fixed
  framing from `include/broker.h`).
- **`env_vars`** round-trip through the protobuf/client API but are not injected
  into the restored guest (the snapshot is pre-baked).
- Daemon: flat `key = value` config (CLI > env > file > defaults),
  `network_manager_init`, `pool_set_restore_source`, `pool_manager_set_live`
  (so `pool_manager_flush_and_rebuild` drains the live pool), signal handling.
- Telemetry: atomic Prometheus counters (`telemetry_render`) + optional
  `--metrics-port` listener; structured logs are JSON lines on stderr from the
  owning component.
- **Bug found & fixed — fork/exec fd inheritance.** The pool forks Firecracker
  children while client sockets are open; non-`CLOEXEC` sockets were inherited
  by the child, so the daemon never saw the peer's EOF. In the in-process `ipc`
  test this deadlocked `ipc_server_stop()` joining the broker-control thread
  (the bc connection's EOF never arrived). Engine listener/accepted fds,
  broker-control accepted fd and both client sockets now use `SOCK_CLOEXEC`.
- New test `tests/test_ipc.c` (`ipc`; root + template fixture): create →
  inspect → pause → resume → inspect → destroy over the real warm pool, plus
  broker-control token validate/revoke and bad-token rejection.
- Full `ctest` **10/10** (adds `ipc`) passes twice back-to-back, seccomp on,
  MMIO, zero leaked taps/rules. `sandboxd` + `sandbox-cli run` smoke-tested
  end-to-end (create → hold → SIGTERM → destroy → clean daemon stop).

## Phase 9 — Packaging, Metrics Wiring, pidfd Crash Detection (§§4.2, 10, 11)

Closes the top gaps left after Phase 8. Phase 9a covers packaging, metrics and
crash detection; Phase 9b covers per-VM environment injection (§15.11).

- **Packaging (§10.2/§10.3).** Added the `install()` rules the project never had:
  binaries → `bin`, `libsandbox.so`/`libsandbox++.so` → `lib`, headers →
  `include`, data/run dirs created, `config/engine.conf` →
  `/var/lib/sandbox-engine/config`, `credentials.conf.example` →
  `/etc/sandbox-engine`, `systemd/sandboxd.service` →
  `lib/systemd/system`. Absolute roots are cache vars
  (`SANDBOX_STATE_DIR`/`SANDBOX_ETC_DIR`/`SANDBOX_RUN_DIR`); `DESTDIR=` stages.
  The daemon now defaults `--config` to the packaged
  `/var/lib/sandbox-engine/config/engine.conf` when present. Verified with
  `DESTDIR=/tmp/instroot cmake --install`: layout matches §10.2 and the staged
  `sandboxd` resolves `libsandbox.so` via `$ORIGIN/../lib`.
- **Metrics (§11.1).** `telemetry_pool_state()` is pushed from the pool under
  `pool->lock` at every transition; `telemetry_uffd_fault()` is bumped per served
  page in the UFFD handler. Before this, `sandbox_pool_{warm,restoring,overflow}`
  and `sandbox_uffd_faults_total` always read 0.
- **pidfd crash detection (§4.2).** The IPC epoll loop now uses tagged
  `data.u64`; each handed-out VM gets a `pidfd_open` registered in epoll. On VMM
  exit the loop reaps it (`waitid(P_PIDFD,..,WNOHANG)`), bumps
  `sandbox_vmm_crashes_total`, logs `vmm_crash`, and reclaims engine state
  (`vmm_destroy`/`lifecycle_remove`/`token_revoke`/`session_disown`). Normal
  destroy calls `pidfd_untrack` first. New `test_ipc.c` case kills the VMM and
  asserts reclaim + token revoke + `sandbox_vmm_crashes_total 1` + non-zero
  `sandbox_uffd_faults_total`.
- `ctest` 10/10 with the new assertions (root, seccomp on, MMIO).

### Phase 9b — Per-VM Env Injection (§6.1 `env_vars`, §15.11)

- **Mechanism = virtio-vsock.** The channel is a device carried in the snapshot;
  each restore retargets its host backend via `vsock_override.uds_path` (like
  `network_overrides`, so no hot-plug). `vmm_cold_boot` configures `PUT /vsock`
  (`guest_cid=3`, `uds_path=/vsock.sock`) before `InstanceStart`.
- **New guest agent** `scripts/sandbox-agent.c`, built static by
  `scripts/build-custom-rootfs.sh` and baked in as `/bin/sandbox-agent`. The
  guest `/init` now `exec`s it; it binds `AF_VSOCK` :5001, prints
  `SANDBOX-READY`, then busy-loops serving connections and emitting
  `SANDBOX-TICK`.
- **The agent, not the shell, ticks.** After a UFFD restore the arch timer does
  not re-arm (§15.7), so the scheduler tick stops and a CPU-hogging shell loop
  starves every other guest process. The agent is the single CPU consumer and
  polls with `poll(…,0)` (never blocks — `SOCK_NONBLOCK` on an `AF_VSOCK`
  listener proved unreliable here).
- **Host side** `vmm_inject_env()`: connect `<jail>/vsock.sock`, hybrid-vsock
  handshake (`CONNECT 5001\n` → `OK <port>\n`), stream `KEY=VALUE\n`, close.
  `handle_create` calls it after restore — best-effort (logs
  `env_injected`/`env_inject_failed`; never fails `Create`). Sleeps 1 s before
  the first attempt (muxer settle — an immediate CONNECT races resume and
  wedges the port, failing all retries; measured 10/10×1 ms after the settle),
  then retries 8× and bounds the socket with `SO_RCVTIMEO`/`SO_SNDTIMEO` so a
  stalled muxer cannot block forever.
- **Guest re-announces (~5 s) until the env lands**, covering a lost
  post-restore port announcement; quiet windows let a host connection complete
  (100 ms rebinds guillotined every attempt).
- **Hardening.** `vmm_restore` now `jail_cleanup()`s before `mkdir_recursive()`,
  so a stale `<jail>/api.sock` left by a killed run can no longer wedge the
  restore with permanent `ECONNREFUSED`.
- **Debug artifact.** `snapshot_manager` copies the template VM boot serial to
  `<template>/boot-serial.log`.
- **Tests.** `test_ipc.c` create carries `MYKEY=myvalue`/`SANDBOX_MODE=test` and
  polls the restored serial for the guest echo; `test_vmm`'s restore waits for a
  fresh `SANDBOX-TICK` (now emitted by the agent).
- `ctest` 10/10 (root, seccomp on, MMIO); `test_ipc` 30/30 consecutive with
  zero injection failures and zero slow runs after the 1 s settle (before it:
  ~10–20% failed or burned the full 45 s retry budget).
