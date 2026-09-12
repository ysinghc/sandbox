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
  No syscalls added.
- Verified in a multipass jammy VM (8c/8G, system protobuf 3.12, all
  builds/tests run there, never on the host): `ctest` 2/2 as both `ubuntu`
  and root. Seccomp kills verified (`socket`, non-KVM `ioctl` → SIGSYS).
  Sequence test forks: child unshares, parent writes `/proc/<pid>/uid_map`
  from outside (self-writes from inside fail under AppArmor/restricted
  kernels — the first version did that and always SKIPped). Root maps the
  full range: real chroot + uid-drop to 65534 verified end to end. Non-root
  maps itself once and runs a uid-0 variant (chroot still real; the uid
  transition is a no-op there).
