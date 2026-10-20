// SPDX-License-Identifier: GPL-2.0-only
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
        case SANDBOX_ERR_SESSION_EXPIRED: return "Session expired";
        case SANDBOX_ERR_SESSION_LIMIT: return "Session at platform maximum lifetime";
        case SANDBOX_ERR_SESSION_UNKNOWN: return "Unknown session";
        default: return "Unknown error";
    }
}

sandbox_spec_t Spec::to_c_struct() const {
    sandbox_spec_t spec = {};
    spec.memory_mib = memory_mib_;
    spec.vcpu_count = vcpu_count_;
    spec.template_name = template_name_.c_str();
    spec.pool_wait_ms = pool_wait_ms_;
    // #23: never leave these as stack garbage -- an uninitialized key would send
    // a random session key over the wire.
    spec.session_key = session_key_.empty() ? nullptr : session_key_.c_str();
    spec.ttl_seconds = ttl_seconds_;
    // env_ptrs_ is mutable: it backs the const char* array for the C call.
    env_ptrs_.clear();
    env_ptrs_.reserve(env_vars_.size() + 1);
    for (const auto& kv : env_vars_) env_ptrs_.push_back(kv.c_str());
    env_ptrs_.push_back(nullptr);
    spec.env_vars = env_ptrs_.data();
    return spec;
}

Sandbox::Sandbox(const Spec& spec) : handle_(nullptr) {
    sandbox_spec_t c = spec.to_c_struct();
    sandbox_error_t rc = sandbox_create(&c, &handle_);
    if (rc != SANDBOX_OK) throw SandboxError(rc);
}

Sandbox::~Sandbox() {
    if (handle_) {
        sandbox_destroy(handle_);
        handle_ = nullptr;
    }
}

Sandbox::Sandbox(Sandbox&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
}

Sandbox& Sandbox::operator=(Sandbox&& other) noexcept {
    if (this != &other) {
        if (handle_) sandbox_destroy(handle_);
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

void Sandbox::pause() {
    sandbox_error_t rc = sandbox_pause(handle_);
    if (rc != SANDBOX_OK) throw SandboxError(rc);
}

void Sandbox::resume() {
    sandbox_error_t rc = sandbox_resume(handle_);
    if (rc != SANDBOX_OK) throw SandboxError(rc);
}

sandbox_status_t Sandbox::inspect() const {
    sandbox_status_t status = {};
    sandbox_error_t rc = sandbox_inspect(handle_, &status);
    if (rc != SANDBOX_OK) throw SandboxError(rc);
    return status;
}

uint32_t Sandbox::id() const {
    sandbox_status_t status = {};
    if (sandbox_inspect(handle_, &status) != SANDBOX_OK) return 0;
    return status.sandbox_id;
}

Engine::Engine(const std::string& socket_path) : initialized_(false) {
    sandbox_error_t rc = sandbox_init(socket_path.c_str());
    if (rc != SANDBOX_OK) throw SandboxError(rc);
    initialized_ = true;
}

Engine::~Engine() {
    if (initialized_) sandbox_cleanup();
}

std::unique_ptr<Sandbox> Engine::create(const Spec& spec) {
    if (!initialized_) throw SandboxError(SANDBOX_ERR_DAEMON_UNREACHABLE);
    return std::unique_ptr<Sandbox>(new Sandbox(spec));
}

uint64_t renew_session(const std::string& session_key, uint32_t extra_seconds) {
    uint64_t expires_at = 0;
    sandbox_error_t rc =
        sandbox_session_renew(session_key.c_str(), extra_seconds, &expires_at);
    if (rc != SANDBOX_OK) throw SandboxError(rc);
    return expires_at;
}

} // namespace sandbox
