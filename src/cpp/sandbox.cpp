#include "libsandbox.hpp"

namespace sandbox {

const char* SandboxError::error_string(sandbox_error_t code) {
    switch (code) {
        case SANDBOX_OK: return "OK";
        case SANDBOX_ERR_POOL_EXHAUSTED: return "Pool exhausted";
        case SANDBOX_ERR_INVALID_SPEC: return "Invalid spec";
        case SANDBOX_ERR_DAEMON_UNREACHABLE: return "Daemon unreachable";
        case SANDBOX_ERR_PERMISSION_DENIED: return "Permission denied";
        case SANDBOX_ERR_INTERNAL: return "Internal error";
        default: return "Unknown error";
    }
}

sandbox_spec_t Spec::to_c_struct() const {
    sandbox_spec_t spec;
    spec.memory_mib = memory_mib_;
    spec.vcpu_count = vcpu_count_;
    spec.template_name = template_name_.c_str();
    spec.env_vars = nullptr;
    spec.pool_wait_ms = pool_wait_ms_;
    return spec;
}

Sandbox::Sandbox(const Spec& spec) : handle_(nullptr) {
    (void)spec;
}

Sandbox::~Sandbox() {
}

Sandbox::Sandbox(Sandbox&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
}

Sandbox& Sandbox::operator=(Sandbox&& other) noexcept {
    if (this != &other) {
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

void Sandbox::pause() {
}

void Sandbox::resume() {
}

sandbox_status_t Sandbox::inspect() const {
    sandbox_status_t status = {};
    return status;
}

uint32_t Sandbox::id() const {
    return 0;
}

Engine::Engine(const std::string& socket_path) : initialized_(false) {
    (void)socket_path;
}

Engine::~Engine() {
}

std::unique_ptr<Sandbox> Engine::create(const Spec& spec) {
    (void)spec;
    return nullptr;
}

} // namespace sandbox
