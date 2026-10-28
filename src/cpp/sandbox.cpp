// SPDX-License-Identifier: GPL-2.0-only
#include "libsandbox.hpp"

#include <cstdlib>

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
        case SANDBOX_ERR_GUEST_UNAVAILABLE: return "Guest agent unavailable";
        case SANDBOX_ERR_PATH_DENIED: return "Path denied";
        case SANDBOX_ERR_NOT_FOUND: return "Not found";
        case SANDBOX_ERR_EXISTS: return "Already exists";
        case SANDBOX_ERR_TOO_LARGE: return "Too large";
        case SANDBOX_ERR_GUEST_IO: return "Guest I/O error";
        case SANDBOX_ERR_TIMEOUT: return "Timed out";
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
    egress_ptrs_.clear();
    for (const auto& e : egress_) egress_ptrs_.push_back(e.c_str());
    egress_ptrs_.push_back(nullptr);
    spec.egress_allow = egress_ptrs_.data();
    spec.egress_deny_all = egress_deny_all_ ? 1 : 0;
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

ExecResult Sandbox::exec(const std::vector<std::string>& argv, const ExecOptions& opt) {
    std::vector<const char*> av;
    for (const auto& a : argv) av.push_back(a.c_str());
    av.push_back(nullptr);
    std::vector<const char*> ev;
    for (const auto& e : opt.env) ev.push_back(e.c_str());
    ev.push_back(nullptr);

    sandbox_exec_spec_t sp = {};
    sp.argv = av.data();
    sp.shell = opt.shell;
    sp.cwd = opt.cwd.empty() ? nullptr : opt.cwd.c_str();
    sp.env = opt.env.empty() ? nullptr : ev.data();
    sp.timeout_ms = opt.timeout_ms;
    sp.max_output = opt.max_output;
    sp.stdin_data = reinterpret_cast<const uint8_t*>(opt.stdin_data.data());
    sp.stdin_len = opt.stdin_data.size();

    sandbox_exec_result_t r;
    sandbox_error_t rc = sandbox_exec(handle_, &sp, &r);
    if (rc != SANDBOX_OK) throw SandboxError(rc);
    ExecResult out;
    out.exit_code = r.exit_code;
    out.term_signal = r.term_signal;
    out.timed_out = r.timed_out;
    out.output_truncated = r.output_truncated;
    if (r.out_len) out.out.assign(reinterpret_cast<const char*>(r.out), r.out_len);
    if (r.err_len) out.err.assign(reinterpret_cast<const char*>(r.err), r.err_len);
    out.out_total = r.out_total;
    out.err_total = r.err_total;
    sandbox_exec_result_free(&r);
    return out;
}

ExecResult Sandbox::shell(const std::string& script, ExecOptions opt) {
    opt.shell = true;
    return exec({script}, opt);
}

std::string Sandbox::read_file(const std::string& path) {
    uint8_t* d = nullptr;
    size_t n = 0;
    sandbox_error_t rc = sandbox_read_file(handle_, path.c_str(), &d, &n);
    if (rc != SANDBOX_OK) throw SandboxError(rc);
    std::string s(reinterpret_cast<const char*>(d), n);
    free(d);
    return s;
}

void Sandbox::write_file(const std::string& path, const std::string& data,
                         uint32_t mode, uint32_t flags) {
    sandbox_error_t rc = sandbox_write_file(
        handle_, path.c_str(), reinterpret_cast<const uint8_t*>(data.data()),
        data.size(), mode, flags);
    if (rc != SANDBOX_OK) throw SandboxError(rc);
}

std::vector<DirEntry> Sandbox::list_dir(const std::string& path, bool* truncated) {
    sandbox_dirent_t* e = nullptr;
    size_t n = 0;
    bool tr = false;
    sandbox_error_t rc = sandbox_list_dir(handle_, path.c_str(), &e, &n, &tr);
    if (rc != SANDBOX_OK) throw SandboxError(rc);
    std::vector<DirEntry> out;
    for (size_t i = 0; i < n; i++) out.push_back({e[i].name, e[i].type, e[i].size, e[i].mtime});
    free(e);
    if (truncated) *truncated = tr;
    return out;
}

FileStat Sandbox::stat(const std::string& path) {
    sandbox_fstat_t st = {};
    sandbox_error_t rc = sandbox_stat(handle_, path.c_str(), &st);
    if (rc != SANDBOX_OK) throw SandboxError(rc);
    return {st.type, st.size, st.mode, st.mtime};
}

void Sandbox::mkdir(const std::string& path, bool parents, uint32_t mode) {
    sandbox_error_t rc = sandbox_mkdir(handle_, path.c_str(), mode, parents);
    if (rc != SANDBOX_OK) throw SandboxError(rc);
}

void Sandbox::remove(const std::string& path, bool recursive) {
    sandbox_error_t rc = sandbox_remove(handle_, path.c_str(), recursive);
    if (rc != SANDBOX_OK) throw SandboxError(rc);
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
