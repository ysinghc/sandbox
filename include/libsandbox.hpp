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
    // #23: give this sandbox a persistent /workspace volume. Two sandboxes
    // created with the same key share the volume's files (sequentially: one at a
    // time), and the files outlive the sandbox until the TTL expires.
    Spec& session(std::string key, uint32_t ttl_seconds = 0) {
        session_key_ = std::move(key);
        ttl_seconds_ = ttl_seconds;
        return *this;
    }

    // #26: reach `host` (or "host:port", "*.suffix") through the broker. Calling
    // this at all replaces the daemon-wide policy with the listed destinations;
    // each must be allowed by the daemon or the create throws.
    Spec& allow_egress(std::string host) {
        egress_.push_back(std::move(host));
        return *this;
    }
    // #26: no reachable destinations at all.
    Spec& no_egress() {
        egress_deny_all_ = true;
        return *this;
    }

    sandbox_spec_t to_c_struct() const;
private:
    uint64_t memory_mib_;
    uint32_t vcpu_count_;
    std::string template_name_;
    std::vector<std::string> env_vars_;
    uint32_t pool_wait_ms_;
    std::string session_key_;
    uint32_t ttl_seconds_ = 0;
    std::vector<std::string> egress_;
    bool egress_deny_all_ = false;
    mutable std::vector<const char*> egress_ptrs_;
    // Stable backing store for the const char* array handed to the C API.
    mutable std::vector<const char*> env_ptrs_;
};

// #24 guest operations. Plain value types so callers never touch the C buffers.
struct ExecOptions {
    bool shell = false;                // argv[0] is a script for /bin/sh -c
    std::string cwd;                   // empty: /workspace
    std::vector<std::string> env;      // "KEY=VALUE"
    uint32_t timeout_ms = 0;           // 0: 1 hour (the maximum)
    uint32_t max_output = 0;           // agent-side cap, 0: 4 MiB
    std::string stdin_data;            // up to 64 KiB
};

struct ExecResult {
    int exit_code = 0;                 // -1 if killed by a signal
    int term_signal = 0;
    bool timed_out = false;
    bool output_truncated = false;     // the max_output cap killed it
    std::string out, err;              // the *head* of each stream (32 / 16 KiB)
    uint64_t out_total = 0, err_total = 0;  // what the command really wrote
};

struct DirEntry {
    std::string name;
    uint8_t type = 0;                  // 0 other, 1 file, 2 dir, 3 symlink
    uint64_t size = 0;
    int64_t mtime = 0;
};

struct FileStat {
    uint8_t type = 0;
    uint64_t size = 0;
    uint32_t mode = 0;
    int64_t mtime = 0;
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

    // #24. Every call throws SandboxError on failure. exec() returns normally for
    // any command that ran, even with a non-zero exit or a timeout. Paths must be
    // absolute and under /workspace (see libsandbox.h).
    ExecResult exec(const std::vector<std::string>& argv, const ExecOptions& opt = {});
    ExecResult shell(const std::string& script, ExecOptions opt = {});
    std::string read_file(const std::string& path);
    void write_file(const std::string& path, const std::string& data,
                    uint32_t mode = 0, uint32_t flags = 0);
    std::vector<DirEntry> list_dir(const std::string& path, bool* truncated = nullptr);
    FileStat stat(const std::string& path);
    void mkdir(const std::string& path, bool parents = false, uint32_t mode = 0);
    void remove(const std::string& path, bool recursive = false);

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

// Extend a session volume's deadline (#23/D5). Keyed by session key, not by a
// Sandbox: the volume outlives every VM, so this works when nothing is running.
// Returns the resulting deadline in unix seconds; throws SandboxError on refusal
// (expired, unknown, or already at the platform maximum).
uint64_t renew_session(const std::string& session_key, uint32_t extra_seconds = 0);

} // namespace sandbox

#endif // LIBSANDBOX_HPP
