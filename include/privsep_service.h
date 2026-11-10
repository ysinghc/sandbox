// SPDX-License-Identifier: GPL-2.0-only
// privsep_service.h -- #9: the helper side of the daemon<->helper boundary.
//
// Strict request parsers and reply builders for sandbox-privileged. Parsing is
// framing plus shape (exact lengths, present terminators, no trailing garbage,
// vm-id charset); the handlers in src/privileged/main.c add the checks that
// need configuration (path roots, daemon-uid ownership, the child table).
//
// Parsed strings point into the caller's request buffer and stay valid as long
// as it does; nothing here allocates.
#ifndef SANDBOX_PRIVSEP_SERVICE_H
#define SANDBOX_PRIVSEP_SERVICE_H

#include <stddef.h>
#include <stdint.h>

#include "privsep.h"

#ifdef __cplusplus
extern "C" {
#endif

// A request naming one VM (NET_UP, NET_DOWN, POLL, TEARDOWN).
typedef struct {
    char vm_id[PRIVSEP_VM_ID_MAX + 1];
} privsep_req_id_t;

// A parsed SPAWN body. Path pointers are never NULL: an absent path parses as
// "". The handler validates roots and ownership before use.
typedef struct {
    char vm_id[PRIVSEP_VM_ID_MAX + 1];
    uint32_t jailer_uid;
    uint32_t jailer_gid;
    uint32_t flags;
    const char* kernel;
    const char* rootfs;
    const char* vmstate;
    const char* mem;
    const char* outdir;
    const char* workspace;
    const char* serial;
} privsep_req_spawn_t;

// Each returns 0 with *out filled, or -1 (a REQUEST error for the caller to
// report; errno is EINVAL).
int privsep_parse_hello(const uint8_t* body, uint32_t body_len);
int privsep_parse_id(const uint8_t* body, uint32_t body_len,
                     privsep_req_id_t* out);
int privsep_parse_sweep(const uint8_t* body, uint32_t body_len,
                        uint32_t* min_age_s);
int privsep_parse_spawn(const uint8_t* body, uint32_t body_len,
                        privsep_req_spawn_t* out);

// Reply builders: each encodes one full record into out (cap bytes) and
// returns its length, or 0 when out is too small. err() builds the two-
// integer {errno, jail_step} body shared by every nonzero status.
size_t privsep_reply_hello(uint8_t* out, size_t cap);
size_t privsep_reply_ok_empty(uint8_t* out, size_t cap);
size_t privsep_reply_u32(uint8_t* out, size_t cap, uint32_t v);
size_t privsep_reply_net_up(uint8_t* out, size_t cap, const char* tap,
                            uint32_t host_ip, uint32_t guest_ip);
size_t privsep_reply_pid(uint8_t* out, size_t cap, int32_t pid);
size_t privsep_reply_poll(uint8_t* out, size_t cap, uint8_t state,
                          int32_t status, int32_t termsig, int32_t jail_step);
size_t privsep_reply_err(uint8_t* out, size_t cap, uint8_t status, int err_no,
                         int jail_step);

#ifdef __cplusplus
}
#endif

#endif  // SANDBOX_PRIVSEP_SERVICE_H
