# Phase 1: pool concurrency + invariant test (run under TSan via build-tsan).
add_executable(test_pool test_pool.c)
target_include_directories(test_pool PRIVATE ../include)
target_link_libraries(test_pool sandbox)
add_test(NAME pool COMMAND test_pool)
set_tests_properties(pool PROPERTIES TIMEOUT 120)

# Phase 2: jailer + seccomp tests. The probe must be fully static: it runs
# inside an empty chroot with no loader or shared libs.
find_library(SECCOMP_STATIC_LIB libseccomp.a PATHS /usr/lib/x86_64-linux-gnu REQUIRED)
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
add_test(NAME network COMMAND test_network)
set_tests_properties(network PROPERTIES TIMEOUT 180 FIXTURES_SETUP netfix)
add_test(NAME network_cleanup
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/net_cleanup.sh)
set_tests_properties(network_cleanup PROPERTIES FIXTURES_CLEANUP netfix)
