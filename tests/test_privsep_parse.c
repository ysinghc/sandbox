// SPDX-License-Identifier: GPL-2.0-only
// #9: the helper's strict request parsers and reply builders. Every reject
// here is a malformed or hostile request the helper refuses before acting on
// it -- no root, no sockets, so this runs on hosted CI.
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "privsep_service.h"

static int failures;

#define CHECK(cond, what)                       \
    do {                                        \
        if (cond) {                             \
            printf("[test] %-58s PASS\n", what); \
        } else {                                \
            printf("[test] %-58s FAIL\n", what); \
            failures++;                         \
        }                                       \
    } while (0)

static void test_hello(void) {
    uint8_t good[1] = { PRIVSEP_VERSION };
    CHECK(privsep_parse_hello(good, sizeof(good)) == 0, "hello: version 1 parses");
    CHECK(privsep_parse_hello(good, 0) != 0, "hello: empty is refused");
    uint8_t two[2] = { PRIVSEP_VERSION, 0 };
    CHECK(privsep_parse_hello(two, sizeof(two)) != 0,
          "hello: trailing garbage is refused");
    uint8_t wrong[1] = { PRIVSEP_VERSION + 1 };
    CHECK(privsep_parse_hello(wrong, sizeof(wrong)) != 0,
          "hello: wrong version is refused");
    CHECK(privsep_parse_hello(NULL, 0) != 0, "hello: NULL body is refused");
}

static void test_id(void) {
    privsep_req_id_t req;
    CHECK(privsep_parse_id((const uint8_t*)"vm-1", 5, &req) == 0 &&
              !strcmp(req.vm_id, "vm-1"),
          "id: a plain vm id parses");
    CHECK(privsep_parse_id((const uint8_t*)"vm-1", 4, &req) != 0,
          "id: a missing terminator is refused");
    CHECK(privsep_parse_id((const uint8_t*)"vm-1\0x", 7, &req) != 0,
          "id: trailing garbage is refused");
    CHECK(privsep_parse_id((const uint8_t*)"", 1, &req) != 0,
          "id: empty is refused");
    CHECK(privsep_parse_id((const uint8_t*)"..", 3, &req) != 0,
          "id: dot-dot is refused");
    CHECK(privsep_parse_id((const uint8_t*)"vm/1", 5, &req) != 0,
          "id: a slash is refused");
    CHECK(privsep_parse_id((const uint8_t*)"vm 1", 5, &req) != 0,
          "id: a space is refused");
    char over[PRIVSEP_VM_ID_MAX + 2];
    memset(over, 'a', sizeof(over) - 1);
    over[sizeof(over) - 1] = '\0';
    CHECK(privsep_parse_id((const uint8_t*)over, (uint32_t)sizeof(over), &req) != 0,
          "id: overlong is refused");
    char max[PRIVSEP_VM_ID_MAX + 1];
    memset(max, 'b', sizeof(max) - 1);
    max[sizeof(max) - 1] = '\0';
    CHECK(privsep_parse_id((const uint8_t*)max, (uint32_t)sizeof(max), &req) == 0,
          "id: exactly 32 bytes parses");
    CHECK(privsep_parse_id((const uint8_t*)"vm-1", 5, NULL) != 0,
          "id: NULL out is refused");
}

static void test_sweep(void) {
    uint8_t body[4];
    uint32_t age = 0;
    privsep_put_u32(body, 90);
    CHECK(privsep_parse_sweep(body, sizeof(body), &age) == 0 && age == 90,
          "sweep: an age parses");
    CHECK(privsep_parse_sweep(body, 3, &age) != 0, "sweep: short is refused");
    CHECK(privsep_parse_sweep(body, sizeof(body), NULL) != 0,
          "sweep: NULL out is refused");
    uint8_t five[5] = { 90, 0, 0, 0, 0 };
    CHECK(privsep_parse_sweep(five, sizeof(five), &age) != 0,
          "sweep: trailing garbage is refused");
}

// Build a valid SPAWN body into buf; returns its length.
static size_t build_spawn(uint8_t* buf, const char* vm_id, uint32_t uid,
                          uint32_t gid, uint32_t flags, const char* paths[7]) {
    size_t off = 0;
    size_t id_len = strlen(vm_id) + 1;
    memcpy(buf + off, vm_id, id_len);
    off += id_len;
    privsep_put_u32(buf + off, uid);
    off += 4;
    privsep_put_u32(buf + off, gid);
    off += 4;
    privsep_put_u32(buf + off, flags);
    off += 4;
    for (size_t i = 0; i < 7; i++) {
        size_t n = strlen(paths[i]) + 1;
        memcpy(buf + off, paths[i], n);
        off += n;
    }
    return off;
}

static void test_spawn(void) {
    uint8_t buf[2048];
    privsep_req_spawn_t req;
    const char* full[7] = { "/snap/vmlinux", "/snap/rootfs", "/snap/vmstate",
                            "/snap/mem",     "/snap/out",    "/ws/vol",
                            "/jail/vm-1/serial.log" };
    size_t n = build_spawn(buf, "vm-1", 65534, 65534, PRIVSEP_SPAWN_SECCOMP,
                           full);
    CHECK(privsep_parse_spawn(buf, (uint32_t)n, &req) == 0 &&
              !strcmp(req.vm_id, "vm-1") && req.jailer_uid == 65534 &&
              req.jailer_gid == 65534 && req.flags == PRIVSEP_SPAWN_SECCOMP &&
              !strcmp(req.kernel, full[0]) && !strcmp(req.rootfs, full[1]) &&
              !strcmp(req.vmstate, full[2]) && !strcmp(req.mem, full[3]) &&
              !strcmp(req.outdir, full[4]) && !strcmp(req.workspace, full[5]) &&
              !strcmp(req.serial, full[6]),
          "spawn: a full body parses with every field");
    const char* empty[7] = { "", "", "", "", "", "", "" };
    n = build_spawn(buf, "vm-2", 1000, 1000, 0, empty);
    CHECK(privsep_parse_spawn(buf, (uint32_t)n, &req) == 0 &&
              !strcmp(req.vm_id, "vm-2") && req.kernel[0] == '\0' &&
              req.serial[0] == '\0',
          "spawn: absent paths parse as empty strings");
    // Truncations at every structural point.
    CHECK(privsep_parse_spawn(buf, 4, &req) != 0,
          "spawn: truncated inside the vm id is refused");
    size_t id_len = strlen("vm-2") + 1;
    CHECK(privsep_parse_spawn(buf, (uint32_t)(id_len + 8), &req) != 0,
          "spawn: truncated inside the integers is refused");
    CHECK(privsep_parse_spawn(buf, (uint32_t)(n - 1), &req) != 0,
          "spawn: truncated inside the last path is refused");
    buf[n] = 'x';
    CHECK(privsep_parse_spawn(buf, (uint32_t)(n + 1), &req) != 0,
          "spawn: trailing garbage is refused");
    n = build_spawn(buf, "../x", 1000, 1000, 0, empty);
    CHECK(privsep_parse_spawn(buf, (uint32_t)n, &req) != 0,
          "spawn: a bad vm id is refused");
    n = build_spawn(buf, "vm-3", 1000, 1000, 0, empty);
    // Corrupt the serial terminator (last byte of the body).
    buf[n - 1] = 'y';
    CHECK(privsep_parse_spawn(buf, (uint32_t)n, &req) != 0,
          "spawn: a missing path terminator is refused");
    CHECK(privsep_parse_spawn(buf, (uint32_t)n, NULL) != 0,
          "spawn: NULL out is refused");
}

static void test_replies(void) {
    uint8_t out[512];
    uint8_t ver = 0, st = 0;
    const uint8_t* body = NULL;
    uint32_t body_len = 0;

    size_t n = privsep_reply_hello(out, sizeof(out));
    CHECK(n > 8 && privsep_decode(out, n, &ver, &st, &body, &body_len) == 0 &&
              st == PRIVSEP_OK && body_len == 1 && body[0] == PRIVSEP_VERSION,
          "reply: hello carries the version with OK");
    n = privsep_reply_ok_empty(out, sizeof(out));
    CHECK(n == 8 && privsep_decode(out, n, &ver, &st, &body, &body_len) == 0 &&
              st == PRIVSEP_OK && body_len == 0,
          "reply: empty OK is a bare header");
    n = privsep_reply_u32(out, sizeof(out), 7);
    CHECK(n == 12 && privsep_decode(out, n, &ver, &st, &body, &body_len) == 0 &&
              body_len == 4 && privsep_get_u32(body) == 7,
          "reply: u32 carries the count");
    n = privsep_reply_net_up(out, sizeof(out), "tap-vm-1", 0x01020304,
                             0x05060708);
    CHECK(privsep_decode(out, n, &ver, &st, &body, &body_len) == 0 &&
              st == PRIVSEP_OK && !strcmp((const char*)body, "tap-vm-1") &&
              privsep_get_u32(body + 9) == 0x01020304 &&
              privsep_get_u32(body + 13) == 0x05060708,
          "reply: net_up carries tap plus both addrs");
    n = privsep_reply_pid(out, sizeof(out), 4242);
    CHECK(privsep_decode(out, n, &ver, &st, &body, &body_len) == 0 &&
              body_len == 4 && (int32_t)privsep_get_u32(body) == 4242,
          "reply: pid carries the child pid");
    n = privsep_reply_poll(out, sizeof(out), PRIVSEP_POLL_EXITED, 9, 0, 6);
    CHECK(privsep_decode(out, n, &ver, &st, &body, &body_len) == 0 &&
              body_len == 16 && body[0] == PRIVSEP_POLL_EXITED &&
              body[1] == 0 && body[2] == 0 && body[3] == 0 &&
              (int32_t)privsep_get_u32(body + 4) == 9 &&
              (int32_t)privsep_get_u32(body + 12) == 6,
          "reply: poll carries state, status and the jail step");
    n = privsep_reply_err(out, sizeof(out), PRIVSEP_ERR_FAILED, ENOENT, 3);
    CHECK(privsep_decode(out, n, &ver, &st, &body, &body_len) == 0 &&
              st == PRIVSEP_ERR_FAILED && body_len == 8 &&
              (int32_t)privsep_get_u32(body) == ENOENT &&
              (int32_t)privsep_get_u32(body + 4) == 3,
          "reply: errors carry errno plus the jail step");
    CHECK(privsep_reply_pid(out, 8, 1) == 0, "reply: a short buffer fails");
    CHECK(privsep_reply_net_up(out, sizeof(out), NULL, 0, 0) == 0,
          "reply: a NULL tap fails");
}

int main(void) {
    test_hello();
    test_id();
    test_sweep();
    test_spawn();
    test_replies();
    printf(failures ? "[test] privsep_parse: FAIL (%d)\n"
                    : "[test] privsep_parse: PASS\n",
           failures);
    return failures != 0;
}
