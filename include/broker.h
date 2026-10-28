// SPDX-License-Identifier: GPL-2.0-only
#ifndef BROKER_H
#define BROKER_H

// Credential Broker (§5.8): validates guest session tokens with the engine
// daemon, injects real upstream credentials, and proxies HTTP requests to the
// allow-listed upstream over HTTPS. Runs as a separate process from the engine
// (the engine holds no credentials).
//
// The core is split into this header + src/broker/{http,credentials,core}.c so
// the request pipeline is testable in-process (src/broker/main.c is a thin
// argv/env shim).

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

// ---------------------------------------------------------------------------
// Credential store (§5.8 / §7.2)
// ---------------------------------------------------------------------------
typedef struct credential_store_t credential_store_t;

// Parse an INI credentials file: "[host]" sections each carrying a
// "credential = VALUE" key; blank lines and '#'/';' comments are ignored.
// Returns NULL with errno set on IO/parse failure.
credential_store_t* credentials_load(const char* path);
void credentials_free(credential_store_t* store);

// Refuse a credentials file that is group/world accessible or not owned by the
// broker's uid: a leaked secret must not be readable by another local user.
// Returns 0 when the file is safe or absent, -1 (errno=EACCES) when unsafe.
// SANDBOX_ALLOW_INSECURE_CREDENTIALS=1 downgrades the refusal to a warning for
// development only.
int credentials_check_permissions(const char* path);

// Look up the credential for a request's Host value. Any ":port" suffix and
// letter case are ignored. Returns a borrowed pointer, or NULL if unset.
const char* credential_store_lookup(const credential_store_t* store, const char* host);

// ---------------------------------------------------------------------------
// Session token validation (broker -> engine, §5.8)
// ---------------------------------------------------------------------------
#define BROKER_MSG_VALIDATE_TOKEN 1
#define BROKER_VALIDATE_REQ_LEN 33  // u8 type + 32-byte raw token
#define BROKER_TOKEN_HEX_LEN 64

typedef struct {
    uint32_t sandbox_id;
    char** allowed_services;  // NULL-terminated array (may be empty)
} session_info_t;

void session_info_free(session_info_t* s);

// Connect to the engine's broker-control Unix socket. Returns fd or -1.
int broker_engine_connect(const char* path);

// Validation result codes.
#define BROKER_VALIDATE_OK 0
#define BROKER_VALIDATE_INVALID (-1)
#define BROKER_VALIDATE_ERROR (-2)

// Ask the engine to validate a 64-hex-char token. Fills *out on success.
int broker_validate_token(int engine_fd, const char* token_hex, session_info_t* out);

// Decode a 64-hex-char token into 32 raw bytes. 0 ok, -1 malformed.
int broker_token_from_hex(const char* hex, uint8_t out[32]);

// ---------------------------------------------------------------------------
// HTTP request parsing (§5.8, "headers only — no buffering of body")
// ---------------------------------------------------------------------------
#define HTTP_MAX_HEADERS 64
#define HTTP_MAX_NAME 128
#define HTTP_MAX_VALUE 4096
#define HTTP_MAX_TARGET 2048
#define HTTP_MAX_HEADER_BYTES 65536

typedef struct {
    char name[HTTP_MAX_NAME];
    char value[HTTP_MAX_VALUE];
} http_header_t;

typedef struct {
    char method[16];
    char target[HTTP_MAX_TARGET];  // origin-form: path [+ "?" query]
    char version[16];
    http_header_t headers[HTTP_MAX_HEADERS];
    size_t nheaders;
} http_request_t;

// Read the request line + header block from fd. Stops at the CRLFCRLF
// terminator; the request body (if any) is left untouched in fd.
// Returns 0 on success, -1 on malformed/oversized/EOF.
int http_parse_headers(int fd, http_request_t* out);

const char* http_get_header(const http_request_t* req, const char* name);
int http_set_header(http_request_t* req, const char* name, const char* value);
int http_remove_header(http_request_t* req, const char* name);

// Write a minimal error response (status line + JSON-ish body).
int send_http_error(int fd, int code, const char* message);

// ---------------------------------------------------------------------------
// Request pipeline (testable in-process)
// ---------------------------------------------------------------------------

// True if host (":port"-stripped, case-folded) is listed, or the list has "*".
bool broker_host_allowed(char* const* allowed_services, const char* host);

// Request bodies are streamed, never buffered: libcurl pulls from `body_fd` a
// buffer at a time, so memory use does not depend on the upload's size. Both
// framings are proxied -- Content-Length as-is, chunked decoded on the fly and
// re-chunked towards the upstream.
//
// A body bigger than broker_max_body() fails with a clear status instead of
// being cut or silently accepted: a declared Content-Length over the limit is
// refused before anything is sent upstream, and a chunked body is cut at the
// limit. Return values of broker_forward_upstream below.
#define BROKER_FWD_BAD_BODY (-2)    // malformed chunking, short body, unsupported coding
#define BROKER_FWD_TOO_LARGE (-3)   // over broker_max_body()
#define BROKER_DEFAULT_MAX_BODY (256ull * 1024 * 1024)

// SANDBOX_BROKER_MAX_BODY (bytes), default 256 MiB.
uint64_t broker_max_body(void);

// Forward an already-credentialed request via libcurl and relay the upstream
// response to client_fd. body_fd supplies the request body, framed as req's
// headers say. Returns the upstream status code, BROKER_FWD_BAD_BODY /
// BROKER_FWD_TOO_LARGE (nothing was relayed to client_fd), or -1 on transport
// failure (an error may already be written to client_fd).
int broker_forward_upstream(const http_request_t* req, int client_fd, int body_fd);

// Handle one proxied request on client_fd (never closes it). Returns the HTTP
// status it sent. engine_fd is the validation socket.
int broker_handle_request(int client_fd, const credential_store_t* creds, int engine_fd);

// Bind + accept loop for the production process. Blocks.
int broker_run(void);

// §10.13: broker metrics (Prometheus text). broker_metrics_serve() blocks,
// answering every connection with the metrics text (run in its own thread).
int broker_metrics_render(char* buf, int cap);
int broker_metrics_serve(int listen_fd);

// Env-derived config (defaults are the production values).
const char* broker_listen_addr(void);       // SANDBOX_BROKER_LISTEN
const char* broker_credentials_path(void);  // SANDBOX_BROKER_CREDENTIALS
const char* broker_control_path(void);      // SANDBOX_BROKER_CONTROL
// The tcp port guests may reach on the host: SANDBOX_BROKER_PORT (default 8080).
// The guest-egress rules in src/network_manager.c allow this exact port, so the
// listener must use it too; broker_listen_addr() derives its default from here.
//
// Defined inline in the header because the two users live in different link
// units that cannot share a symbol: the rules are in libsandbox, while
// src/broker/core.c is the standalone sandbox_broker_core that links no engine
// code. One definition of the rule, no second copy to drift.
static inline int broker_port(void) {
    const char* p = getenv("SANDBOX_BROKER_PORT");
    if (p && *p) {
        int n = atoi(p);
        if (n > 0 && n <= 65535) return n;
    }
    const char* l = getenv("SANDBOX_BROKER_LISTEN");
    if (l && *l) {
        const char* colon = strrchr(l, ':');
        if (colon) {
            int n = atoi(colon + 1);
            if (n > 0 && n <= 65535) return n;
        }
    }
    return 8080;
}

#endif // BROKER_H
