cmake_minimum_required(VERSION 3.20)
project(sandbox-engine C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Build types
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Allow locally-extracted protobuf (no sudo) via PROTO_ROOT env/hint.
# Production installs with system protobuf need no extra flags.
if(DEFINED ENV{PROTO_ROOT})
    list(APPEND CMAKE_PREFIX_PATH "$ENV{PROTO_ROOT}/usr")
    set(Protobuf_PROTOC_EXECUTABLE "$ENV{PROTO_ROOT}/usr/bin/protoc" CACHE FILEPATH "protoc compiler")
endif()

# Dependencies
find_package(Protobuf REQUIRED)
find_library(SECCOMP_LIB seccomp REQUIRED)

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
    ${PROTO_SRCS}
)
target_include_directories(sandbox PUBLIC include ${CMAKE_CURRENT_BINARY_DIR} ${Protobuf_INCLUDE_DIRS})
target_link_libraries(sandbox ${SECCOMP_LIB} ${Protobuf_LIBRARIES} pthread)

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

# Broker
add_executable(sandbox-broker
    src/broker/main.c
    src/broker/http.c
    src/broker/credentials.c
)
target_include_directories(sandbox-broker PRIVATE include)

# CLI tool
add_executable(sandbox-cli
    src/cli/main.c
)
target_include_directories(sandbox-cli PRIVATE include)
target_link_libraries(sandbox-cli sandbox++)

# Tests
enable_testing()
add_subdirectory(tests)
