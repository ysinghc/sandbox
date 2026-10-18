// SPDX-License-Identifier: GPL-2.0-only
#ifndef LIBSANDBOX_HPP
#define LIBSANDBOX_HPP

#include "libsandbox.h"
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

namespace sandbox {

class SandboxError : public std::runtime_error {
public:
    explicit SandboxError(sandbox_error_t code)
        : std::runtime_error(error_string(code)), code_(code) {}
    sandbox_error_t code() const { return code_; }
private:
    static const char* error_string(sandbox_error_t code);
    sandbox_error_t code_;
};

class Spec {
public:
    Spec(uint64_t memory_mib, const std::string& template_name)
        : memory_mib_(memory_mib), vcpu_count_(1), template_name_(template_name), pool_wait_ms_(500) {}
    
    Spec& vcpus(uint32_t count) { vcpu_count_ = count; return *this; }
    Spec& env(const std::string& key, const std::string& value) {
        env_vars_.push_back(key + "=" + value);
        return *this;
    }
    Spec& pool_wait(uint32_t ms) { pool_wait_ms_ = ms; return *this; }
    
    sandbox_spec_t to_c_struct() const;
private:
    uint64_t memory_mib_;
    uint32_t vcpu_count_;
    std::string template_name_;
    std::vector<std::string> env_vars_;
    uint32_t pool_wait_ms_;
    // Stable backing store for the const char* array handed to the C API.
    mutable std::vector<const char*> env_ptrs_;
};

class Sandbox {
public:
    explicit Sandbox(const Spec& spec);
    ~Sandbox();
    
    // Move-only (no copy — handle is unique)
    Sandbox(Sandbox&& other) noexcept;
    Sandbox& operator=(Sandbox&& other) noexcept;
    Sandbox(const Sandbox&) = delete;
    Sandbox& operator=(const Sandbox&) = delete;
    
    void pause();
    void resume();
    sandbox_status_t inspect() const;
    
    uint32_t id() const;
    
private:
    sandbox_handle_t* handle_;
};

class Engine {
public:
    explicit Engine(const std::string& socket_path = "/var/run/sandbox-engine/engine.sock");
    ~Engine();
    
    std::unique_ptr<Sandbox> create(const Spec& spec);
    
private:
    bool initialized_;
};

} // namespace sandbox

#endif // LIBSANDBOX_HPP
