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
    ENVIRONMENT "SANDBOX_SNAPSHOT_ROOT=${TEST_SNAPROOT};SANDBOX_JAIL_ROOT=${TEST_JAILROOT};SANDBOX_WORKSPACE_ROOT=${TEST_WSROOT}")

add_executable(test_vmm test_vmm.c)
target_include_directories(test_vmm PRIVATE ../include)
target_link_libraries(test_vmm sandbox)
add_test(NAME vmm COMMAND ${CMAKE_BINARY_DIR}/tests/test_vmm)
set_tests_properties(vmm PROPERTIES
    TIMEOUT 300
    FIXTURES_REQUIRED tmplfix
    ENVIRONMENT "SANDBOX_SNAPSHOT_ROOT=${TEST_SNAPROOT};SANDBOX_JAIL_ROOT=${TEST_JAILROOT};SANDBOX_WORKSPACE_ROOT=${TEST_WSROOT}")

# Pool now restores real VMs: same fixture + env (longer timeout for boots).
set_tests_properties(pool PROPERTIES
    TIMEOUT 300
    FIXTURES_REQUIRED tmplfix
    ENVIRONMENT "SANDBOX_SNAPSHOT_ROOT=${TEST_SNAPROOT};SANDBOX_JAIL_ROOT=${TEST_JAILROOT};SANDBOX_WORKSPACE_ROOT=${TEST_WSROOT}")

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
    ENVIRONMENT "SANDBOX_SNAPSHOT_ROOT=${TEST_SNAPROOT};SANDBOX_JAIL_ROOT=${TEST_JAILROOT};SANDBOX_WORKSPACE_ROOT=${TEST_WSROOT}")

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
