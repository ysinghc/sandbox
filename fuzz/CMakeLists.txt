# §10.14 fuzz targets. Configure with -DSANDBOX_BUILD_FUZZERS=ON.
#
# With clang each target links libFuzzer (-fsanitize=fuzzer). Without clang a
# standalone file/stdin driver is used so the same corpus still exercises the
# code (under whatever SANDBOX_SANITIZE flags are configured). CI builds these
# with clang + -DSANDBOX_SANITIZE=address,undefined so library code is
# instrumented too.

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(FUZZ_DRIVER "")
    set(FUZZ_LINK -fsanitize=fuzzer)
    message(STATUS "Fuzzers: clang detected -> libFuzzer targets")
else()
    set(FUZZ_DRIVER standalone_driver.c)
    set(FUZZ_LINK "")
    message(STATUS "Fuzzers: non-clang compiler -> standalone driver (no libFuzzer)")
endif()

function(add_fuzzer name)
    cmake_parse_arguments(FZ "" "" "SOURCES;LIBS" ${ARGN})
    add_executable(${name} ${FZ_SOURCES} ${FUZZ_DRIVER})
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    if(FUZZ_LINK)
        target_link_options(${name} PRIVATE ${FUZZ_LINK})
    endif()
    target_link_libraries(${name} PRIVATE ${FZ_LIBS})
endfunction()

add_fuzzer(fuzz_http SOURCES fuzz_http.c LIBS sandbox_broker_core CURL::libcurl)
add_fuzzer(fuzz_config SOURCES fuzz_config.c LIBS sandbox_config)
add_fuzzer(fuzz_proto SOURCES fuzz_proto.c LIBS sandbox)
set_target_properties(fuzz_proto PROPERTIES LINKER_LANGUAGE CXX)
