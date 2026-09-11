# Phase 0 stub: real pool concurrency test lands in Phase 1.
add_executable(test_pool_placeholder test_pool_placeholder.c)
target_include_directories(test_pool_placeholder PRIVATE ../include)
target_link_libraries(test_pool_placeholder sandbox)
add_test(NAME pool_placeholder COMMAND test_pool_placeholder)
