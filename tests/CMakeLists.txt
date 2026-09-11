# Phase 1: pool concurrency + invariant test (run under TSan via build-tsan).
add_executable(test_pool test_pool.c)
target_include_directories(test_pool PRIVATE ../include)
target_link_libraries(test_pool sandbox)
add_test(NAME pool COMMAND test_pool)
set_tests_properties(pool PROPERTIES TIMEOUT 120)
