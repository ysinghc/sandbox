#include "lifecycle.h"
#include "libsandbox.h"
#include <stddef.h>

int lifecycle_track(vm_handle_t* vm) {
    (void)vm;
    return 0;
}

int lifecycle_remove(uint32_t sandbox_id) {
    (void)sandbox_id;
    return 0;
}

// Client API stubs (Phase 0 — full implementation in Phase 8).

struct sandbox_handle_t {
    uint32_t sandbox_id;
};

sandbox_error_t sandbox_init(const char* socket_path) {
    (void)socket_path;
    return SANDBOX_OK;
}

sandbox_error_t sandbox_create(const sandbox_spec_t* spec, sandbox_handle_t** out_handle) {
    (void)spec;
    if (out_handle) *out_handle = NULL;
    return SANDBOX_ERR_DAEMON_UNREACHABLE;
}

sandbox_error_t sandbox_pause(sandbox_handle_t* handle) {
    (void)handle;
    return SANDBOX_ERR_DAEMON_UNREACHABLE;
}

sandbox_error_t sandbox_resume(sandbox_handle_t* handle) {
    (void)handle;
    return SANDBOX_ERR_DAEMON_UNREACHABLE;
}

sandbox_error_t sandbox_destroy(sandbox_handle_t* handle) {
    (void)handle;
    return SANDBOX_ERR_DAEMON_UNREACHABLE;
}

sandbox_error_t sandbox_inspect(sandbox_handle_t* handle, sandbox_status_t* out_status) {
    (void)handle; (void)out_status;
    return SANDBOX_ERR_DAEMON_UNREACHABLE;
}

void sandbox_cleanup(void) {
}
