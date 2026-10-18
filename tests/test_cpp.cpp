// SPDX-License-Identifier: GPL-2.0-only
// Guards the C++ wrapper <-> C API linkage. sandbox.cpp must reference the
// *unmangled* C symbols, which requires extern "C" in libsandbox.h; without it
// the mangled references cannot be resolved against libsandbox.so. This test
// links the wrapper and drives its error path (daemon unreachable) so a
// regression is caught at link time rather than only in packaging.
#include <cstdio>

#include "libsandbox.hpp"

int main() {
    sandbox::Spec spec(256, "unused-template");
    spec.vcpus(2).env("FOO", "bar").pool_wait(0);

    try {
        sandbox::Engine engine("/nonexistent/sandbox-engine-test.sock");
        std::fprintf(stderr, "FAIL cpp_wrap: Engine ctor did not throw\n");
        return 1;
    } catch (const sandbox::SandboxError& err) {
        if (err.code() != SANDBOX_ERR_DAEMON_UNREACHABLE) {
            std::fprintf(stderr, "FAIL cpp_wrap: unexpected error code %d\n",
                         (int)err.code());
            return 1;
        }
    }

    std::printf("cpp_wrap: PASS\n");
    return 0;
}
