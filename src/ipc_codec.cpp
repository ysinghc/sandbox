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
    memset(req, 0, sizeof(*req));
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
        default:
            return -1;
    }
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
            default:
                return -1;
        }
    }
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
        default:
            return -1;
    }
}
