cmake_minimum_required(VERSION 3.20)
project(sandbox-engine C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Build types
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Single version string for --version output and packaging (include/version.h
# carries the same fallback for non-CMake builds).
set(SANDBOX_VERSION "0.14.0" CACHE STRING "Engine version")
add_compile_definitions(SANDBOX_VERSION="${SANDBOX_VERSION}")

# Phase 1: ThreadSanitizer variant for pool concurrency verification.
# Configure a separate dir with -DSANDBOX_TSAN=ON; default build unaffected.
option(SANDBOX_TSAN "Build with ThreadSanitizer (pool concurrency verification)" OFF)
if(SANDBOX_TSAN)
    add_compile_options(-fsanitize=thread -g)
    add_link_options(-fsanitize=thread)
endif()

# §10.14: ASan/UBSan build variant (CI). Comma-separated, e.g.
# -DSANDBOX_SANITIZE=address,undefined. Default build unaffected.
set(SANDBOX_SANITIZE "" CACHE STRING "Comma-separated sanitizers (address,undefined)")
if(SANDBOX_SANITIZE)
    add_compile_options(-fsanitize=${SANDBOX_SANITIZE} -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=${SANDBOX_SANITIZE})
endif()

# §10.14: libFuzzer targets (fuzz/). Off by default; CI enables it with clang.
option(SANDBOX_BUILD_FUZZERS "Build fuzz targets (fuzz/)" OFF)

# Use system protobuf (3.12.4 on Ubuntu 22.04) to avoid GLIBC version mismatches
# Local protobuf in /tmp uses C23 functions not available in GLIBC 2.35
# Use MODULE mode since system package doesn't provide Config.cmake
find_package(Protobuf REQUIRED MODULE)
find_library(SECCOMP_LIB seccomp REQUIRED)
# Phase 7: credential broker proxies upstream calls over HTTPS via libcurl.
find_package(CURL REQUIRED)
# Phase 10.5: run nftables rules via libnftables (no shell) when available;
# network_manager.c falls back to system() otherwise.
find_path(NFTABLES_INCLUDE_DIR nftables/libnftables.h)
find_library(NFTABLES_LIB nftables)

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
    src/template_store.c
    src/network_manager.c
    src/jailer.c
    src/fs_util.c
    src/workspace.c
    src/seccomp.c
    src/sha256.c
    src/cgroup.c
    src/log.c
    src/lifecycle.c
    src/egress_policy.c
    src/telemetry.c
    src/guest_rpc_client.c
    src/ipc_guest.c
    src/ipc_server.c
    src/ipc_codec.cpp
    ${PROTO_SRCS}
)
target_include_directories(sandbox PUBLIC include ${CMAKE_CURRENT_BINARY_DIR} ${Protobuf_INCLUDE_DIRS})
target_link_libraries(sandbox ${SECCOMP_LIB} ${Protobuf_LIBRARIES} pthread)

# Phase 10.5: prefer the libnftables API over shelling out to `nft`.
if(NFTABLES_INCLUDE_DIR AND NFTABLES_LIB)
    target_compile_definitions(sandbox PRIVATE SANDBOX_HAVE_LIBNFTABLES=1)
    target_include_directories(sandbox PRIVATE ${NFTABLES_INCLUDE_DIR})
    target_link_libraries(sandbox ${NFTABLES_LIB})
    message(STATUS "libnftables found: ${NFTABLES_LIB}")
else()
    message(WARNING "libnftables not found: nftables rules will use system()")
endif()

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
# Config parser as a small static lib so it is unit-testable (Phase 11).
add_library(sandbox_config STATIC src/daemon/config.c)
target_include_directories(sandbox_config PUBLIC include)
target_link_libraries(sandboxd sandbox sandbox_config)

# Phase 11: sd_notify readiness/watchdog for Type=notify; optional so the build
# works where libsystemd is absent.
find_library(SYSTEMD_LIB systemd)
if(SYSTEMD_LIB)
    target_compile_definitions(sandboxd PRIVATE SANDBOX_HAVE_SYSTEMD=1)
    target_include_directories(sandboxd PRIVATE ${SYSTEMD_INCLUDE_DIR})
    target_link_libraries(sandboxd ${SYSTEMD_LIB})
    message(STATUS "libsystemd found: ${SYSTEMD_LIB}")
endif()

# Broker (§5.8). Core split into a library so the request pipeline is testable
# in-process; main.c is a thin shim.
add_library(sandbox_broker_core STATIC
    src/broker/http.c
    src/broker/credentials.c
    src/broker/proxy.c
    src/broker/core.c
    src/egress_policy.c
    src/log.c
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
    src/cli/template_cmd.c
)
target_include_directories(sandbox-cli PRIVATE include)
target_link_libraries(sandbox-cli sandbox++)

# --- Installation (§10.2/§10.3) ---
include(GNUInstallDirs)

# Deployment layout (§10.2). Absolute paths by default so a plain
# `cmake --install` lands the daemon where systemd/sandboxd.service expects it;
# override or use DESTDIR= for staging.
set(SANDBOX_STATE_DIR "/var/lib/sandbox-engine" CACHE PATH "Engine state dir")
set(SANDBOX_ETC_DIR   "/etc/sandbox-engine"     CACHE PATH "Engine config dir")
set(SANDBOX_RUN_DIR   "/var/run/sandbox-engine" CACHE PATH "Engine runtime dir")

install(TARGETS sandboxd sandbox-broker sandbox-cli
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS sandbox sandbox++
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/libsandbox.h include/libsandbox.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Data/runtime directories (§10.2 step 4).
install(DIRECTORY DESTINATION ${SANDBOX_STATE_DIR}/jail)
install(DIRECTORY DESTINATION ${SANDBOX_STATE_DIR}/snapshots)
install(DIRECTORY DESTINATION ${SANDBOX_STATE_DIR}/config)
install(DIRECTORY DESTINATION ${SANDBOX_RUN_DIR})

# Config (§10.2 step 5). credentials.conf is 0600 and installed separately.
install(FILES config/engine.conf DESTINATION ${SANDBOX_STATE_DIR}/config)
install(FILES config/credentials.conf.example DESTINATION ${SANDBOX_ETC_DIR})

# systemd unit (§10.3).
install(FILES systemd/sandboxd.service
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system)

# Documentation and license.
install(FILES README.md LICENSE CHANGELOG.md CONTRIBUTING.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(DIRECTORY docs/ DESTINATION ${CMAKE_INSTALL_DOCDIR}/docs
        FILES_MATCHING PATTERN "*.md")
install(FILES "SYSTEM DESIGN.md" DESTINATION ${CMAKE_INSTALL_DOCDIR})

# Tests
enable_testing()
add_subdirectory(tests)

# Fuzz targets (§10.14). Built only when SANDBOX_BUILD_FUZZERS=ON; the CI
# fuzz job configures a separate build dir with clang + libFuzzer.
if(SANDBOX_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()
