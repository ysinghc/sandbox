// SPDX-License-Identifier: GPL-2.0-only
// C bridge over the generated C++ protobuf types (§2.3). Compiled as C++ so it
// can use sandbox.pb.h directly; every entry point has C linkage (ipc_codec.h).

#include "ipc_codec.h"

#include <cstdlib>
#include <cstring>
#include <string>

#include "sandbox.pb.h"

namespace {

void clear_env(ipc_request_t* req) {
    for (int i = 0; i < req->n_env; i++) {
        free(req->env_vars[i]);
        req->env_vars[i] = nullptr;
    }
    req->env_vars[0] = nullptr;
    req->n_env = 0;
}

void clear_egress(ipc_request_t* req) {
    for (int i = 0; i < req->n_egress; i++) {
        free(req->egress[i]);
        req->egress[i] = nullptr;
    }
    req->egress[0] = nullptr;
    req->n_egress = 0;
}

void clear_guest_req(ipc_request_t* req) {
    for (int i = 0; i < req->n_argv; i++) {
        free(req->argv[i]);
        req->argv[i] = nullptr;
    }
    req->argv[0] = nullptr;
    req->n_argv = 0;
    free(req->data);
    req->data = nullptr;
    req->data_len = 0;
}

uint8_t* dup_bytes(const std::string& s) {
    if (s.empty()) return nullptr;
    auto* p = static_cast<uint8_t*>(malloc(s.size()));
    if (p) memcpy(p, s.data(), s.size());
    return p;
}

void set_str(char* dst, size_t n, const std::string& s) {
    if (n == 0) return;
    size_t k = s.size();
    if (k >= n) k = n - 1;
    if (k) memcpy(dst, s.data(), k);
    dst[k] = '\0';
}

}  // namespace

void ipc_request_init(ipc_request_t* req) {
    if (req) memset(req, 0, sizeof(*req));
}

void ipc_request_clear(ipc_request_t* req) {
    if (!req) return;
    clear_env(req);
    clear_egress(req);
    clear_guest_req(req);
    memset(req, 0, sizeof(*req));
}

void ipc_response_clear(ipc_response_t* resp) {
    if (!resp) return;
    free(resp->out);
    free(resp->err);
    free(resp->entries);
    memset(resp, 0, sizeof(*resp));
}

int ipc_encode_request(const ipc_request_t* req, uint8_t* buf, size_t cap,
                       size_t* out_len) {
    if (!req || !buf || !out_len) return -1;
    sandbox::ClientMessage msg;
    switch (req->kind) {
        case IPC_REQ_CREATE: {
            auto* c = msg.mutable_create();
            c->set_memory_mib(req->memory_mib);
            c->set_vcpu_count(req->vcpu_count);
            c->set_template_name(req->template_name);
            c->set_pool_wait_ms(req->pool_wait_ms);
            // #23: session_key/ttl_seconds. Defaults (empty/0) are not written,
            // so an ephemeral create stays byte-identical on the wire.
            if (req->session_key[0]) c->set_session_key(req->session_key);
            if (req->ttl_seconds) c->set_ttl_seconds(req->ttl_seconds);
            // #26: likewise omitted when unset, so an unrestricted create is
            // byte-identical to what older clients send.
            for (int i = 0; i < req->n_egress; i++) {
                if (req->egress[i]) c->add_egress_allow(req->egress[i]);
            }
            if (req->egress_deny_all) c->set_egress_deny_all(true);
            for (int i = 0; i < req->n_env; i++) {
                if (req->env_vars[i]) c->add_env_vars(req->env_vars[i]);
            }
            break;
        }
        case IPC_REQ_DESTROY:
            msg.mutable_destroy()->set_sandbox_id(req->sandbox_id);
            break;
        case IPC_REQ_PAUSE:
            msg.mutable_pause()->set_sandbox_id(req->sandbox_id);
            break;
        case IPC_REQ_RESUME:
            msg.mutable_resume()->set_sandbox_id(req->sandbox_id);
            break;
        case IPC_REQ_INSPECT:
            msg.mutable_inspect()->set_sandbox_id(req->sandbox_id);
            break;
        case IPC_REQ_RENEW: {
            auto* r = msg.mutable_renew();
            r->set_session_key(req->session_key);
            if (req->extra_seconds) r->set_extra_seconds(req->extra_seconds);
            break;
        }
        case IPC_REQ_GUEST: {
            auto* g = msg.mutable_guest();
            g->set_sandbox_id(req->sandbox_id);
            g->set_op(req->guest_op);
            g->set_path(req->path);
            for (int i = 0; i < req->n_argv; i++) {
                if (req->argv[i]) g->add_argv(req->argv[i]);
            }
            for (int i = 0; i < req->n_env; i++) {
                if (req->env_vars[i]) g->add_env(req->env_vars[i]);
            }
            if (req->data_len) g->set_data(req->data, req->data_len);
            g->set_timeout_ms(req->timeout_ms);
            g->set_max_output(req->max_output);
            g->set_offset(req->offset);
            g->set_max_bytes(req->max_bytes);
            g->set_mode(req->mode);
            g->set_shell(req->guest_flags & IPC_GF_SHELL);
            g->set_append(req->guest_flags & IPC_GF_APPEND);
            g->set_exclusive(req->guest_flags & IPC_GF_EXCL);
            g->set_parents(req->guest_flags & IPC_GF_PARENTS);
            g->set_recursive(req->guest_flags & IPC_GF_RECURSIVE);
            break;
        }
        default:
            return -1;
    }
    // #12: one place, every request kind. Zero is the proto default, so a legacy
    // caller that never sets it produces a byte-identical message.
    if (req->request_id) msg.set_request_id(req->request_id);

    size_t n = msg.ByteSizeLong();
    if (n > cap) return -1;
    if (n && !msg.SerializeToArray(buf, static_cast<int>(n))) return -1;
    *out_len = n;
    return 0;
}

int ipc_decode_request(const uint8_t* buf, size_t len, ipc_request_t* out) {
    if (!buf || !out) return -1;
    ipc_request_init(out);
    sandbox::ClientMessage msg;
    if (!msg.ParseFromArray(buf, static_cast<int>(len))) return -1;
    out->request_id = msg.request_id();
    switch (msg.payload_case()) {
        case sandbox::ClientMessage::kCreate: {
            const auto& c = msg.create();
            out->kind = IPC_REQ_CREATE;
            out->memory_mib = c.memory_mib();
            out->vcpu_count = c.vcpu_count();
            set_str(out->template_name, sizeof(out->template_name),
                    c.template_name());
            out->pool_wait_ms = c.pool_wait_ms();
            set_str(out->session_key, sizeof(out->session_key), c.session_key());
            out->ttl_seconds = c.ttl_seconds();
            // A policy is a security statement: refuse one we cannot hold in
            // full rather than keep a prefix of it.
            if (c.egress_allow_size() > IPC_MAX_EGRESS) return -1;
            for (int i = 0; i < c.egress_allow_size(); i++) {
                out->egress[out->n_egress] = strdup(c.egress_allow(i).c_str());
                if (!out->egress[out->n_egress]) return -1;
                out->n_egress++;
            }
            out->egress[out->n_egress] = nullptr;
            out->egress_deny_all = c.egress_deny_all() ? 1 : 0;
            for (int i = 0; i < c.env_vars_size() && out->n_env < IPC_MAX_ENV; i++) {
                out->env_vars[out->n_env] = strdup(c.env_vars(i).c_str());
                if (!out->env_vars[out->n_env]) break;
                out->n_env++;
            }
            out->env_vars[out->n_env] = nullptr;
            break;
        }
        case sandbox::ClientMessage::kDestroy:
            out->kind = IPC_REQ_DESTROY;
            out->sandbox_id = msg.destroy().sandbox_id();
            break;
        case sandbox::ClientMessage::kPause:
            out->kind = IPC_REQ_PAUSE;
            out->sandbox_id = msg.pause().sandbox_id();
            break;
        case sandbox::ClientMessage::kResume:
            out->kind = IPC_REQ_RESUME;
            out->sandbox_id = msg.resume().sandbox_id();
            break;
        case sandbox::ClientMessage::kInspect:
            out->kind = IPC_REQ_INSPECT;
            out->sandbox_id = msg.inspect().sandbox_id();
            break;
        case sandbox::ClientMessage::kRenew:
            out->kind = IPC_REQ_RENEW;
            set_str(out->session_key, sizeof(out->session_key),
                    msg.renew().session_key());
            out->extra_seconds = msg.renew().extra_seconds();
            break;
        case sandbox::ClientMessage::kGuest: {
            const auto& g = msg.guest();
            out->kind = IPC_REQ_GUEST;
            out->sandbox_id = g.sandbox_id();
            out->guest_op = g.op();
            // A path that does not fit is refused, not truncated: a clipped
            // path names a different file.
            if (g.path().size() >= sizeof(out->path)) return -1;
            set_str(out->path, sizeof(out->path), g.path());
            if (g.argv_size() > IPC_MAX_ARGV || g.env_size() > IPC_MAX_ENV) return -1;
            for (int i = 0; i < g.argv_size(); i++) {
                out->argv[out->n_argv] = strdup(g.argv(i).c_str());
                if (!out->argv[out->n_argv]) { ipc_request_clear(out); return -1; }
                out->n_argv++;
            }
            out->argv[out->n_argv] = nullptr;
            for (int i = 0; i < g.env_size(); i++) {
                out->env_vars[out->n_env] = strdup(g.env(i).c_str());
                if (!out->env_vars[out->n_env]) { ipc_request_clear(out); return -1; }
                out->n_env++;
            }
            out->env_vars[out->n_env] = nullptr;
            out->data = dup_bytes(g.data());
            out->data_len = out->data ? g.data().size() : 0;
            out->timeout_ms = g.timeout_ms();
            out->max_output = g.max_output();
            out->offset = g.offset();
            out->max_bytes = g.max_bytes();
            out->mode = g.mode();
            out->guest_flags = (g.shell() ? IPC_GF_SHELL : 0) |
                               (g.append() ? IPC_GF_APPEND : 0) |
                               (g.exclusive() ? IPC_GF_EXCL : 0) |
                               (g.parents() ? IPC_GF_PARENTS : 0) |
                               (g.recursive() ? IPC_GF_RECURSIVE : 0);
            break;
        }
        default:
            return -1;
    }
    return 0;
}

int ipc_encode_response(const ipc_response_t* resp, uint8_t* buf, size_t cap,
                        size_t* out_len) {
    if (!resp || !buf || !out_len) return -1;
    sandbox::ServerMessage msg;
    if (resp->is_error) {
        auto* e = msg.mutable_error();
        e->set_error_code(resp->error_code);
        e->set_error_message(resp->error_message);
    } else {
        switch (resp->kind) {
            case IPC_REQ_CREATE: {
                auto* c = msg.mutable_create();
                c->set_sandbox_id(resp->sandbox_id);
                c->set_session_token(resp->session_token);
                break;
            }
            case IPC_REQ_DESTROY:
                msg.mutable_destroy()->set_sandbox_id(resp->sandbox_id);
                break;
            case IPC_REQ_PAUSE:
                msg.mutable_pause()->set_sandbox_id(resp->sandbox_id);
                break;
            case IPC_REQ_RESUME:
                msg.mutable_resume()->set_sandbox_id(resp->sandbox_id);
                break;
            case IPC_REQ_INSPECT: {
                auto* i = msg.mutable_inspect();
                i->set_sandbox_id(resp->sandbox_id);
                i->set_is_running(resp->is_running);
                i->set_uptime_ms(resp->uptime_ms);
                i->set_memory_rss_mib(resp->memory_rss_mib);
                i->set_page_faults(resp->page_faults);
                break;
            }
            case IPC_REQ_RENEW:
                msg.mutable_renew()->set_expires_at(resp->expires_at);
                break;
            case IPC_REQ_GUEST: {
                auto* g = msg.mutable_guest();
                g->set_sandbox_id(resp->sandbox_id);
                g->set_exit_code(resp->exit_code);
                g->set_term_signal(resp->term_signal);
                g->set_timed_out(resp->timed_out);
                g->set_output_truncated(resp->output_truncated);
                if (resp->out_len) g->set_out(resp->out, resp->out_len);
                if (resp->err_len) g->set_err(resp->err, resp->err_len);
                g->set_out_total(resp->out_total);
                g->set_err_total(resp->err_total);
                g->set_truncated(resp->truncated);
                g->set_size(resp->size);
                for (size_t i = 0; i < resp->n_entries; i++) {
                    auto* e = g->add_entries();
                    e->set_name(resp->entries[i].name);
                    e->set_type(resp->entries[i].type);
                    e->set_size(resp->entries[i].size);
                    e->set_mtime(resp->entries[i].mtime);
                }
                g->set_type(resp->ftype);
                g->set_mode(resp->fmode);
                g->set_mtime(resp->mtime);
                break;
            }
            default:
                return -1;
        }
    }
    if (resp->request_id) msg.set_request_id(resp->request_id);

    size_t n = msg.ByteSizeLong();
    if (n > cap) return -1;
    if (n && !msg.SerializeToArray(buf, static_cast<int>(n))) return -1;
    *out_len = n;
    return 0;
}

int ipc_decode_response(const uint8_t* buf, size_t len, ipc_response_t* out) {
    if (!buf || !out) return -1;
    memset(out, 0, sizeof(*out));
    sandbox::ServerMessage msg;
    if (!msg.ParseFromArray(buf, static_cast<int>(len))) return -1;
    out->request_id = msg.request_id();
    switch (msg.payload_case()) {
        case sandbox::ServerMessage::kError: {
            const auto& e = msg.error();
            out->is_error = true;
            out->error_code = e.error_code();
            set_str(out->error_message, sizeof(out->error_message),
                    e.error_message());
            return 0;
        }
        case sandbox::ServerMessage::kCreate: {
            const auto& c = msg.create();
            out->kind = IPC_REQ_CREATE;
            out->sandbox_id = c.sandbox_id();
            set_str(out->session_token, sizeof(out->session_token),
                    c.session_token());
            return 0;
        }
        case sandbox::ServerMessage::kDestroy:
            out->kind = IPC_REQ_DESTROY;
            out->sandbox_id = msg.destroy().sandbox_id();
            return 0;
        case sandbox::ServerMessage::kPause:
            out->kind = IPC_REQ_PAUSE;
            out->sandbox_id = msg.pause().sandbox_id();
            return 0;
        case sandbox::ServerMessage::kResume:
            out->kind = IPC_REQ_RESUME;
            out->sandbox_id = msg.resume().sandbox_id();
            return 0;
        case sandbox::ServerMessage::kInspect: {
            const auto& i = msg.inspect();
            out->kind = IPC_REQ_INSPECT;
            out->sandbox_id = i.sandbox_id();
            out->is_running = i.is_running();
            out->uptime_ms = i.uptime_ms();
            out->memory_rss_mib = i.memory_rss_mib();
            out->page_faults = i.page_faults();
            return 0;
        }
        case sandbox::ServerMessage::kRenew:
            out->kind = IPC_REQ_RENEW;
            out->expires_at = msg.renew().expires_at();
            return 0;
        case sandbox::ServerMessage::kGuest: {
            const auto& g = msg.guest();
            out->kind = IPC_REQ_GUEST;
            out->sandbox_id = g.sandbox_id();
            out->exit_code = g.exit_code();
            out->term_signal = g.term_signal();
            out->timed_out = g.timed_out();
            out->output_truncated = g.output_truncated();
            out->out = dup_bytes(g.out());
            out->out_len = out->out ? g.out().size() : 0;
            out->err = dup_bytes(g.err());
            out->err_len = out->err ? g.err().size() : 0;
            out->out_total = g.out_total();
            out->err_total = g.err_total();
            out->truncated = g.truncated();
            out->size = g.size();
            out->ftype = g.type();
            out->fmode = g.mode();
            out->mtime = g.mtime();
            if (g.entries_size() > 0) {
                if (g.entries_size() > IPC_MAX_DIRENTS) { ipc_response_clear(out); return -1; }
                out->entries = static_cast<ipc_dirent_t*>(
                    calloc(static_cast<size_t>(g.entries_size()), sizeof(ipc_dirent_t)));
                if (!out->entries) { ipc_response_clear(out); return -1; }
                for (int i = 0; i < g.entries_size(); i++) {
                    const auto& e = g.entries(i);
                    set_str(out->entries[i].name, sizeof(out->entries[i].name), e.name());
                    out->entries[i].type = static_cast<uint8_t>(e.type());
                    out->entries[i].size = e.size();
                    out->entries[i].mtime = e.mtime();
                }
                out->n_entries = static_cast<size_t>(g.entries_size());
            }
            return 0;
        }
        default:
            return -1;
    }
}
