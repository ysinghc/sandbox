cmake_minimum_required(VERSION 3.20)
project(sandbox-engine C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Build types
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Phase 1: ThreadSanitizer variant for pool concurrency verification.
# Configure a separate dir with -DSANDBOX_TSAN=ON; default build unaffected.
option(SANDBOX_TSAN "Build with ThreadSanitizer (pool concurrency verification)" OFF)
if(SANDBOX_TSAN)
    add_compile_options(-fsanitize=thread -g)
    add_link_options(-fsanitize=thread)
endif()

# Use system protobuf (3.12.4 on Ubuntu 22.04) to avoid GLIBC version mismatches
# Local protobuf in /tmp uses C23 functions not available in GLIBC 2.35
# Use MODULE mode since system package doesn't provide Config.cmake
find_package(Protobuf REQUIRED MODULE)
find_library(SECCOMP_LIB seccomp REQUIRED)
# Phase 7: credential broker proxies upstream calls over HTTPS via libcurl.
find_package(CURL REQUIRED)

# Explicitly use system protobuf libraries
set(Protobuf_LIBRARIES protobuf)
set(Protobuf_LITE_LIBRARIES protobuf-lite)

# Build-time rpath: test binaries live in build-vm/tests/, libsandbox.so in build-vm/
# $ORIGIN/.. resolves to build-vm/ (the library directory at build time).
set(CMAKE_BUILD_RPATH "\$ORIGIN;\$ORIGIN/..")
set(CMAKE_INSTALL_RPATH "\$ORIGIN/../lib")
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

# Protobuf code generation
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS proto/sandbox.proto)

# Core library
add_library(sandbox SHARED
    src/pool_manager.c
    src/uffd_handler.c
    src/prefault_worker.c
    src/vmm_manager.c
    src/snapshot_manager.c
    src/network_manager.c
    src/jailer.c
    src/seccomp.c
    src/lifecycle.c
    src/telemetry.c
    src/ipc_server.c
    src/ipc_codec.cpp
    ${PROTO_SRCS}
)
target_include_directories(sandbox PUBLIC include ${CMAKE_CURRENT_BINARY_DIR} ${Protobuf_INCLUDE_DIRS})
target_link_libraries(sandbox ${SECCOMP_LIB} ${Protobuf_LIBRARIES} pthread)

# Set rpath: at build time libsandbox.so is in build-vm/, install puts it in lib/
set_target_properties(sandbox PROPERTIES
    BUILD_RPATH "\$ORIGIN"
    INSTALL_RPATH "\$ORIGIN/../lib"
)

# C++ wrapper
add_library(sandbox++ SHARED
    src/cpp/sandbox.cpp
)
target_include_directories(sandbox++ PUBLIC include)
target_link_libraries(sandbox++ sandbox)

# Daemon
add_executable(sandboxd
    src/daemon/main.c
)
target_link_libraries(sandboxd sandbox)

# Broker (§5.8). Core split into a library so the request pipeline is testable
# in-process; main.c is a thin shim.
add_library(sandbox_broker_core STATIC
    src/broker/http.c
    src/broker/credentials.c
    src/broker/core.c
)
target_include_directories(sandbox_broker_core PUBLIC include)
target_link_libraries(sandbox_broker_core PUBLIC CURL::libcurl)

add_executable(sandbox-broker
    src/broker/main.c
)
target_link_libraries(sandbox-broker sandbox_broker_core)

# CLI tool
add_executable(sandbox-cli
    src/cli/main.c
)
target_include_directories(sandbox-cli PRIVATE include)
target_link_libraries(sandbox-cli sandbox++)

# Tests
enable_testing()
add_subdirectory(tests)
