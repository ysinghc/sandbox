# Tests must actually assert.
#
# CMake's Release flags (the default in CI) add -DNDEBUG, which compiles every
# assert() out. test_snapshot alone relies on 34 of them, so its "PASS" under
# Release was proving nothing. Undefine it for the test binaries: an assertion
# that cannot fire is worse than no test, because it reads like coverage.
add_compile_options(-UNDEBUG)

# Phase 15: session workspace registry + TTL (#23). No root, no KVM.
add_executable(test_workspace test_workspace.c)
target_include_directories(test_workspace PRIVATE ../include)
target_link_libraries(test_workspace sandbox)
add_test(NAME workspace COMMAND ${CMAKE_BINARY_DIR}/tests/test_workspace)
set_tests_properties(workspace PROPERTIES TIMEOUT 120)

# Phase 1: pool concurrency + invariant test (run under TSan via build-tsan).
add_executable(test_pool test_pool.c)
target_include_directories(test_pool PRIVATE ../include)
target_link_libraries(test_pool sandbox)
add_test(NAME pool COMMAND test_pool)
set_tests_properties(pool PROPERTIES TIMEOUT 120)

# Phase 2: jailer + seccomp tests. The probe must be fully static: it runs
# inside an empty chroot with no loader or shared libs.
find_library(SECCOMP_STATIC_LIB libseccomp.a PATHS /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu REQUIRED)
add_executable(jailer_probe jailer_probe.c ../src/seccomp.c)
target_include_directories(jailer_probe PRIVATE ../include)
target_link_libraries(jailer_probe ${SECCOMP_STATIC_LIB})
target_link_options(jailer_probe PRIVATE -static)
# A sanitizer build cannot link a fully-static binary (no sanitizer runtime is
# available statically), which the probe requires to run inside an empty chroot.
# It is a tiny seccomp harness, so build it unsanitized in sanitizer builds.
if(SANDBOX_SANITIZE)
    target_compile_options(jailer_probe PRIVATE -fno-sanitize=all)
    target_link_options(jailer_probe PRIVATE -fno-sanitize=all)
endif()
add_executable(test_jailer test_jailer.c)
target_include_directories(test_jailer PRIVATE ../include)
target_link_libraries(test_jailer sandbox)
add_test(NAME jailer COMMAND test_jailer)
set_tests_properties(jailer PROPERTIES TIMEOUT 120)

# Phase 2: seccomp allow-list regression. Unprivileged (installing a filter
# needs no root), so it also runs on the hosted CI — see tests/test_seccomp.c.
add_executable(test_seccomp test_seccomp.c)
target_include_directories(test_seccomp PRIVATE ../include)
target_link_libraries(test_seccomp sandbox)
add_test(NAME seccomp COMMAND test_seccomp)
set_tests_properties(seccomp PROPERTIES TIMEOUT 60)

# #10: the guest control channel may only be driven by the host. Unprivileged
# (it needs no VM), so the decision table runs on the hosted CI too; the
# integration half additionally needs host vsock loopback and SKIPs without it.
# ../src/vsock_peer.c is compiled in directly: the guest agent links the same
# file, and nothing in the engine itself calls it.
add_executable(test_vsock_peer test_vsock_peer.c ../src/vsock_peer.c)
target_include_directories(test_vsock_peer PRIVATE ../include)
add_test(NAME vsock_peer COMMAND test_vsock_peer)
set_tests_properties(vsock_peer PROPERTIES TIMEOUT 60)

# #24: guest exec / file RPC. The real guest server (the code the agent links)
# runs against the real host client over socketpairs, so processes are forked and
# files written for real, with no VM, root or KVM -- it runs on the hosted CI too.
add_executable(test_guest_rpc test_guest_rpc.c
               ../src/guest_rpc_server.c ../src/guest_rpc_wire.c)
target_include_directories(test_guest_rpc PRIVATE ../include)
target_link_libraries(test_guest_rpc sandbox pthread)
add_test(NAME guest_rpc COMMAND test_guest_rpc)
set_tests_properties(guest_rpc PROPERTIES TIMEOUT 180)

# #24: the same guest server, reached through the whole IPC stack (libsandbox ->
# daemon -> worker pool -> a hybrid-vsock-style UDS). Only the VM is faked.
add_executable(test_ipc_guest test_ipc_guest.c
               ../src/guest_rpc_server.c ../src/guest_rpc_wire.c)
target_include_directories(test_ipc_guest PRIVATE ../include ../src)
target_link_libraries(test_ipc_guest sandbox pthread)
add_test(NAME ipc_guest COMMAND test_ipc_guest)
set_tests_properties(ipc_guest PROPERTIES TIMEOUT 240)

# Phase 3: network manager test (root only: tap + nftables; SKIPs otherwise).
# The cleanup fixture runs even if the test aborts, so leaked netns/routes/
# nft rules can never poison later runs.
add_executable(test_network test_network.c)
target_include_directories(test_network PRIVATE ../include)
target_link_libraries(test_network sandbox)
add_test(NAME network COMMAND ${CMAKE_BINARY_DIR}/tests/test_network)
set_tests_properties(network PROPERTIES TIMEOUT 180 FIXTURES_SETUP netfix)
add_test(NAME network_cleanup
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/net_cleanup.sh)
set_tests_properties(network_cleanup PROPERTIES FIXTURES_CLEANUP netfix)

# Phase 4: snapshot manager tests (no root needed: tmp dirs only).
add_executable(test_snapshot test_snapshot.c)
target_include_directories(test_snapshot PRIVATE ../include)
target_link_libraries(test_snapshot sandbox)
add_test(NAME snapshot COMMAND test_snapshot)
set_tests_properties(snapshot PROPERTIES TIMEOUT 120)

# Phase 6: template fixture (builds "e2e" once; consumers REQUIRE it).
# Roots live on LOCAL disk: the workspace mount (9p) rejects Unix socket
# creation (api.sock/uffd.sock bind fails with EPERM there), and the jail
# mknod()s /dev/kvm + /dev/net/tun, which fails with EACCES on a `nodev` mount.
# /tmp is `nodev` on many hosts (including the self-hosted CI runner), so the
# parent is overridable:
#
#     cmake -S . -B build -DSANDBOX_TEST_TMPDIR=/var/tmp
#
set(SANDBOX_TEST_TMPDIR "/tmp" CACHE PATH
    "Parent dir for test workspaces (must permit device nodes, i.e. not `nodev`)")

# ── Privileged tests and the environment ──────────────────────────────────────
# The tests below (network, tmpl_setup, vmm, pool, ipc, cgroup) need real root,
# /dev/kvm and the guest assets, and several of them read their workspace roots
# from the environment, which ctest supplies through the ENVIRONMENT property.
#
# They therefore must NOT be wrapped in `sudo`: sudo resets the environment, so
# the ENVIRONMENT property never arrives, and a test whose roots are missing
# SKIPs (exit 0) instead of failing -- a silent, green no-op. That is exactly
# the failure mode this comment exists to prevent: the labs job spent its first
# runs "passing" while `tmpl_setup` exited in 0.01 s without booting anything.
#
# Instead, run the whole suite as root (`sudo ctest ...`, which is what
# .github/workflows/privileged-e2e-run.yml does); each test SKIPs cleanly when
# it is not root, so an unprivileged `ctest` stays honest rather than red.

get_filename_component(TEST_BDIR ${CMAKE_CURRENT_BINARY_DIR} NAME)
set(TEST_TMPROOT "${SANDBOX_TEST_TMPDIR}/sbtest-${TEST_BDIR}")

# Guest assets are part of the test definition, not of the shell that launched
# ctest. The override exists so CI can build and test its own guest image
# (SANDBOX_ROOTFS) instead of the operator's /opt/sandbox-assets copy -- and if
# the override is silently lost, every test still *runs*, against an image that
# predates the code under test. That is exactly what happened on the aarch64
# runner: its user is not root, so the workflow's `sudo ctest` reset the
# environment, the override vanished, and the leg "ran" a three-day-old guest
# with none of the markers the new agent prints (no workspace probe, no clock
# line, no vsock peer line) while the host side was current. Baking the paths
# into ENVIRONMENT makes them survive any launcher, sudo included.
#
# They are baked as <NAME>_DEFAULT, not <NAME>. ctest applies ENVIRONMENT on
# top of the environment it inherited, so a baked SANDBOX_ROOTFS would override
# a later `sudo env SANDBOX_ROOTFS=... ctest` -- which is exactly how the Debian
# suite asks for a different guest. That failed as a green no-op: the Debian run
# booted the busybox fixture, all four tests passed, and only the workflow's
# image assertion noticed. A _DEFAULT is consulted only when the runtime
# environment carries no explicit value, so both launchers work.
set(TEST_ASSET_ENV "")
if(DEFINED ENV{SANDBOX_ROOTFS} AND NOT "$ENV{SANDBOX_ROOTFS}" STREQUAL "")
    string(APPEND TEST_ASSET_ENV ";SANDBOX_ROOTFS_DEFAULT=$ENV{SANDBOX_ROOTFS}")
endif()
if(DEFINED ENV{SANDBOX_KERNEL} AND NOT "$ENV{SANDBOX_KERNEL}" STREQUAL "")
    string(APPEND TEST_ASSET_ENV ";SANDBOX_KERNEL_DEFAULT=$ENV{SANDBOX_KERNEL}")
endif()
set(TEST_SNAPROOT "${TEST_TMPROOT}/snapshots")
set(TEST_JAILROOT "${TEST_TMPROOT}/jails")
set(TEST_WSROOT "${TEST_TMPROOT}/workspaces")
add_executable(make_template make_template.c)
target_include_directories(make_template PRIVATE ../include)
target_link_libraries(make_template sandbox)
add_test(NAME tmpl_setup COMMAND ${CMAKE_BINARY_DIR}/tests/make_template)
set_tests_properties(tmpl_setup PROPERTIES
    TIMEOUT 300
    FIXTURES_SETUP tmplfix
    ENVIRONMENT "SANDBOX_SNAPSHOT_ROOT=${TEST_SNAPROOT};SANDBOX_JAIL_ROOT=${TEST_JAILROOT};SANDBOX_WORKSPACE_ROOT=${TEST_WSROOT};SANDBOX_TEST_ROOT=${TEST_TMPROOT}${TEST_ASSET_ENV}")

add_executable(test_vmm test_vmm.c)
target_include_directories(test_vmm PRIVATE ../include)
target_link_libraries(test_vmm sandbox)
add_test(NAME vmm COMMAND ${CMAKE_BINARY_DIR}/tests/test_vmm)
set_tests_properties(vmm PROPERTIES
    TIMEOUT 300
    FIXTURES_REQUIRED tmplfix
    ENVIRONMENT "SANDBOX_SNAPSHOT_ROOT=${TEST_SNAPROOT};SANDBOX_JAIL_ROOT=${TEST_JAILROOT};SANDBOX_WORKSPACE_ROOT=${TEST_WSROOT}${TEST_ASSET_ENV}")

# Pool now restores real VMs: same fixture + env (longer timeout for boots).
set_tests_properties(pool PROPERTIES
    TIMEOUT 300
    FIXTURES_REQUIRED tmplfix
    ENVIRONMENT "SANDBOX_SNAPSHOT_ROOT=${TEST_SNAPROOT};SANDBOX_JAIL_ROOT=${TEST_JAILROOT};SANDBOX_WORKSPACE_ROOT=${TEST_WSROOT}${TEST_ASSET_ENV}")

# Phase 5: uffd lazy-restore tests (SKIPs where userfaultfd is denied).
add_executable(test_uffd test_uffd.c)
target_include_directories(test_uffd PRIVATE ../include)
target_link_libraries(test_uffd sandbox)
add_test(NAME uffd COMMAND test_uffd)
set_tests_properties(uffd PROPERTIES TIMEOUT 120)

# Phase 7: credential broker request pipeline (no root). In-process mock
# engine + mock upstream over an ephemeral loopback port; upstream scheme is
# forced to http for the test.
add_executable(test_broker test_broker.c)
target_include_directories(test_broker PRIVATE ../include)
target_link_libraries(test_broker sandbox_broker_core)
add_test(NAME broker COMMAND test_broker)
set_tests_properties(broker PROPERTIES TIMEOUT 120)

# Phase 8: daemon IPC server + client API + engine-side broker-control.
# Root + template fixture (restores through the real warm pool).
add_executable(test_ipc test_ipc.c)
target_include_directories(test_ipc PRIVATE ../include)
target_link_libraries(test_ipc sandbox sandbox_broker_core)
add_test(NAME ipc COMMAND ${CMAKE_BINARY_DIR}/tests/test_ipc)
set_tests_properties(ipc PROPERTIES
    TIMEOUT 300
    FIXTURES_REQUIRED tmplfix
    ENVIRONMENT "SANDBOX_SNAPSHOT_ROOT=${TEST_SNAPROOT};SANDBOX_JAIL_ROOT=${TEST_JAILROOT};SANDBOX_WORKSPACE_ROOT=${TEST_WSROOT}${TEST_ASSET_ENV}")

# #12: correlation-id encoding contract (no root, no VMs, no transport).
add_executable(test_ipc_codec test_ipc_codec.c)
target_include_directories(test_ipc_codec PRIVATE ../include ../src)
target_link_libraries(test_ipc_codec sandbox)
add_test(NAME ipc_codec COMMAND test_ipc_codec)
set_tests_properties(ipc_codec PROPERTIES TIMEOUT 30)

# #31: startup sweep of jails left by a crashed daemon. Needs root: it creates
# bind mounts and chroots a child to stand in for a live VMM.
add_executable(test_jail_sweep test_jail_sweep.c)
target_include_directories(test_jail_sweep PRIVATE ../include)
target_link_libraries(test_jail_sweep sandbox)
add_test(NAME jail_sweep COMMAND test_jail_sweep)
set_tests_properties(jail_sweep PROPERTIES TIMEOUT 60)

# Phase 11: daemon config parser (no root). Parses the packaged engine.conf.
add_executable(test_config test_config.c)
target_include_directories(test_config PRIVATE ../include)
target_link_libraries(test_config sandbox_config)
target_compile_definitions(test_config PRIVATE
    SANDBOX_TEST_CONFIG_FILE="${CMAKE_SOURCE_DIR}/config/engine.conf")
add_test(NAME config COMMAND test_config)
set_tests_properties(config PROPERTIES TIMEOUT 30)

# Phase 12: per-VM cgroup hierarchy (§10.11). SKIPs when cgroup v2 is not
# writable. Runs as root so the default /sys/fs/cgroup root can be populated.
add_executable(test_cgroup test_cgroup.c)
target_include_directories(test_cgroup PRIVATE ../include)
target_link_libraries(test_cgroup sandbox)
add_test(NAME cgroup COMMAND ${CMAKE_BINARY_DIR}/tests/test_cgroup)
set_tests_properties(cgroup PROPERTIES TIMEOUT 60)

# Phase 13: metrics / health / ready endpoints (§10.13). No root.
add_executable(test_metrics test_metrics.c)
target_include_directories(test_metrics PRIVATE ../include)
target_link_libraries(test_metrics sandbox)
add_test(NAME metrics COMMAND test_metrics)
set_tests_properties(metrics PROPERTIES TIMEOUT 30)

# C++ wrapper linkage: libsandbox.h must expose the C API as extern "C" so the
# wrapper resolves the unmangled symbols (no root, needs no daemon).
add_executable(test_cpp_wrap test_cpp.cpp)
target_include_directories(test_cpp_wrap PRIVATE ../include)
target_link_libraries(test_cpp_wrap sandbox++)
add_test(NAME cpp_wrap COMMAND test_cpp_wrap)
set_tests_properties(cpp_wrap PROPERTIES TIMEOUT 30)
