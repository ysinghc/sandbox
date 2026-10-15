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
add_executable(test_jailer test_jailer.c)
target_include_directories(test_jailer PRIVATE ../include)
target_link_libraries(test_jailer sandbox)
add_test(NAME jailer COMMAND test_jailer)
set_tests_properties(jailer PROPERTIES TIMEOUT 120)

# Phase 3: network manager test (root only: tap + nftables; SKIPs otherwise).
# The cleanup fixture runs even if the test aborts, so leaked netns/routes/
# nft rules can never poison later runs.
add_executable(test_network test_network.c)
target_include_directories(test_network PRIVATE ../include)
target_link_libraries(test_network sandbox)
add_test(NAME network COMMAND sudo -E ${CMAKE_BINARY_DIR}/tests/test_network)
set_tests_properties(network PROPERTIES TIMEOUT 180 FIXTURES_SETUP netfix)
add_test(NAME network_cleanup
         COMMAND sudo -E sh ${CMAKE_CURRENT_SOURCE_DIR}/net_cleanup.sh)
set_tests_properties(network_cleanup PROPERTIES FIXTURES_CLEANUP netfix)

# Phase 4: snapshot manager tests (no root needed: tmp dirs only).
add_executable(test_snapshot test_snapshot.c)
target_include_directories(test_snapshot PRIVATE ../include)
target_link_libraries(test_snapshot sandbox)
add_test(NAME snapshot COMMAND test_snapshot)
set_tests_properties(snapshot PROPERTIES TIMEOUT 120)

# Phase 6: template fixture (builds "e2e" once; consumers REQUIRE it).
# Roots live on LOCAL disk (/tmp): the workspace mount (9p) rejects Unix
# socket creation (api.sock/uffd.sock bind fails with EPERM there).
get_filename_component(TEST_BDIR ${CMAKE_CURRENT_BINARY_DIR} NAME)
set(TEST_SNAPROOT "/tmp/sbtest-${TEST_BDIR}/snapshots")
set(TEST_JAILROOT "/tmp/sbtest-${TEST_BDIR}/jails")
add_executable(make_template make_template.c)
target_include_directories(make_template PRIVATE ../include)
target_link_libraries(make_template sandbox)
add_test(NAME tmpl_setup COMMAND sudo -E ${CMAKE_BINARY_DIR}/tests/make_template)
set_tests_properties(tmpl_setup PROPERTIES
    TIMEOUT 300
    FIXTURES_SETUP tmplfix
    ENVIRONMENT "SANDBOX_SNAPSHOT_ROOT=${TEST_SNAPROOT};SANDBOX_JAIL_ROOT=${TEST_JAILROOT}")

add_executable(test_vmm test_vmm.c)
target_include_directories(test_vmm PRIVATE ../include)
target_link_libraries(test_vmm sandbox)
add_test(NAME vmm COMMAND sudo -E ${CMAKE_BINARY_DIR}/tests/test_vmm)
set_tests_properties(vmm PROPERTIES
    TIMEOUT 300
    FIXTURES_REQUIRED tmplfix
    ENVIRONMENT "SANDBOX_SNAPSHOT_ROOT=${TEST_SNAPROOT};SANDBOX_JAIL_ROOT=${TEST_JAILROOT}")

# Pool now restores real VMs: same fixture + env (longer timeout for boots).
set_tests_properties(pool PROPERTIES
    TIMEOUT 300
    FIXTURES_REQUIRED tmplfix
    ENVIRONMENT "SANDBOX_SNAPSHOT_ROOT=${TEST_SNAPROOT};SANDBOX_JAIL_ROOT=${TEST_JAILROOT}")

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
