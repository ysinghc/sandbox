// SPDX-License-Identifier: GPL-2.0-only
// service.c -- #9: strict privsep request parsers and reply builders.
//
// The boundary rule is fail-closed: anything not exactly the documented shape
// is refused, including trailing garbage after the last field (a smuggled
// second request hiding behind a valid first one must never parse).
#include "privsep_service.h"

#include <errno.h>
#include <net/if.h>
#include <string.h>

typedef struct {
    const uint8_t* p;
    uint32_t left;
} cursor_t;

// Take a NUL-terminated string: NULL when the body ends first. The empty
// string is valid (it encodes an absent SPAWN path).
static const char* cur_str(cursor_t* c) {
    uint32_t i = 0;
    while (i < c->left && c->p[i]) i++;
    if (i >= c->left) return NULL;  // no terminator in the body
    const char* s = (const char*)c->p;
    c->p += i + 1;
    c->left -= i + 1;
    return s;
}

static bool cur_u32(cursor_t* c, uint32_t* out) {
    if (c->left < 4) return false;
    *out = privsep_get_u32(c->p);
    c->p += 4;
    c->left -= 4;
    return true;
}

int privsep_parse_hello(const uint8_t* body, uint32_t body_len) {
    if (!body && body_len) {
        errno = EINVAL;
        return -1;
    }
    if (body_len != 1 || body[0] != PRIVSEP_VERSION) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int privsep_parse_id(const uint8_t* body, uint32_t body_len,
                     privsep_req_id_t* out) {
    if (!body && body_len) {
        errno = EINVAL;
        return -1;
    }
    if (!out) {
        errno = EINVAL;
        return -1;
    }
    cursor_t c = { body, body_len };
    const char* id = cur_str(&c);
    // Exactly one string: nothing may follow it.
    if (!id || c.left != 0 || !privsep_vm_id_ok(id)) {
        errno = EINVAL;
        return -1;
    }
    strcpy(out->vm_id, id);
    return 0;
}

int privsep_parse_sweep(const uint8_t* body, uint32_t body_len,
                        uint32_t* min_age_s) {
    if (!body && body_len) {
        errno = EINVAL;
        return -1;
    }
    if (!min_age_s || body_len != 4) {
        errno = EINVAL;
        return -1;
    }
    *min_age_s = privsep_get_u32(body);
    return 0;
}

int privsep_parse_spawn(const uint8_t* body, uint32_t body_len,
                        privsep_req_spawn_t* out) {
    if (!body && body_len) {
        errno = EINVAL;
        return -1;
    }
    if (!out) {
        errno = EINVAL;
        return -1;
    }
    memset(out, 0, sizeof(*out));
    cursor_t c = { body, body_len };
    const char* id = cur_str(&c);
    if (!id || !privsep_vm_id_ok(id)) {
        errno = EINVAL;
        return -1;
    }
    strcpy(out->vm_id, id);
    if (!cur_u32(&c, &out->jailer_uid) || !cur_u32(&c, &out->jailer_gid) ||
        !cur_u32(&c, &out->flags)) {
        errno = EINVAL;
        return -1;
    }
    const char** paths[] = { &out->kernel,  &out->rootfs, &out->vmstate,
                             &out->mem,     &out->outdir, &out->workspace,
                             &out->serial };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        const char* s = cur_str(&c);
        if (!s) {
            errno = EINVAL;
            return -1;
        }
        *paths[i] = s;
    }
    if (c.left != 0) {  // trailing garbage
        errno = EINVAL;
        return -1;
    }
    return 0;
}

size_t privsep_reply_hello(uint8_t* out, size_t cap) {
    uint8_t body[1] = { PRIVSEP_VERSION };
    size_t n = 0;
    if (privsep_encode(PRIVSEP_VERSION, PRIVSEP_OK, body, sizeof(body), out,
                       cap, &n) != 0)
        return 0;
    return n;
}

size_t privsep_reply_ok_empty(uint8_t* out, size_t cap) {
    size_t n = 0;
    if (privsep_encode(PRIVSEP_VERSION, PRIVSEP_OK, NULL, 0, out, cap, &n) != 0)
        return 0;
    return n;
}

size_t privsep_reply_u32(uint8_t* out, size_t cap, uint32_t v) {
    uint8_t body[4];
    privsep_put_u32(body, v);
    size_t n = 0;
    if (privsep_encode(PRIVSEP_VERSION, PRIVSEP_OK, body, sizeof(body), out,
                       cap, &n) != 0)
        return 0;
    return n;
}

size_t privsep_reply_net_up(uint8_t* out, size_t cap, const char* tap,
                            uint32_t host_ip, uint32_t guest_ip) {
    if (!tap) return 0;
    uint8_t body[IFNAMSIZ + 8];
    size_t tlen = strlen(tap) + 1;
    if (tlen + 8 > sizeof(body)) return 0;
    memcpy(body, tap, tlen);
    privsep_put_u32(body + tlen, host_ip);
    privsep_put_u32(body + tlen + 4, guest_ip);
    size_t n = 0;
    if (privsep_encode(PRIVSEP_VERSION, PRIVSEP_OK, body, (uint32_t)(tlen + 8),
                       out, cap, &n) != 0)
        return 0;
    return n;
}

size_t privsep_reply_pid(uint8_t* out, size_t cap, int32_t pid) {
    uint8_t body[4];
    privsep_put_u32(body, (uint32_t)pid);
    size_t n = 0;
    if (privsep_encode(PRIVSEP_VERSION, PRIVSEP_OK, body, sizeof(body), out,
                       cap, &n) != 0)
        return 0;
    return n;
}

size_t privsep_reply_poll(uint8_t* out, size_t cap, uint8_t state,
                          int32_t status, int32_t termsig, int32_t jail_step) {
    uint8_t body[16];
    body[0] = state;
    body[1] = body[2] = body[3] = 0;
    privsep_put_u32(body + 4, (uint32_t)status);
    privsep_put_u32(body + 8, (uint32_t)termsig);
    privsep_put_u32(body + 12, (uint32_t)jail_step);
    size_t n = 0;
    if (privsep_encode(PRIVSEP_VERSION, PRIVSEP_OK, body, sizeof(body), out,
                       cap, &n) != 0)
        return 0;
    return n;
}

size_t privsep_reply_err(uint8_t* out, size_t cap, uint8_t status, int err_no,
                         int jail_step) {
    uint8_t body[8];
    privsep_put_u32(body, (uint32_t)(int32_t)err_no);
    privsep_put_u32(body + 4, (uint32_t)(int32_t)jail_step);
    size_t n = 0;
    if (privsep_encode(PRIVSEP_VERSION, status, body, sizeof(body), out, cap,
                       &n) != 0)
        return 0;
    return n;
}
