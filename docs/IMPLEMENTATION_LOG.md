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

## Phase 2 — Jailer + Seccomp (§5.4, §5.5)

- Order follows the spec text: cgroup → chroot → caps → setuid/setgid →
  seccomp → exec (the pseudocode places cgroup after chroot, which cannot
  work — `/sys/fs/cgroup` is unreachable post-chroot).
- `drop_capabilities()` retains `CAP_SETUID`/`CAP_SETGID` across the drop
  (the subsequent setuid/setgid per LLD order requires them), drops
  everything else including the bounding set; the uid transition clears the
  rest. Implemented via raw `capget`/`capset` (`<linux/capability.h>`, no
  libcap on this box).
- Internal `spawn_jailed()` takes jail root, binary, argv, and
  mount/seccomp toggles; public `spawn_firecracker_jailed()` pins the
  canonical root, `/firecracker`, mounts on, seccomp on. Test-only splits
  (seccomp loaded in-probe after pre-filter checks) exercise the same code
  in the same order — a static probe cannot start under the filter
  (`arch_prctl` is not whitelisted).
- Seccomp whitelist is verbatim §5.5, including the KVM-only `ioctl` mask.
  No syscalls added.
