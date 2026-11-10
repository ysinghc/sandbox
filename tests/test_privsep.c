// SPDX-License-Identifier: GPL-2.0-only
// #9: the daemon<->helper boundary contract. Validation (vm ids, uids, paths,
// flags) and framing (encode/decode, strict rejects) -- no root, no sockets,
// so this runs on hosted CI. What it pins is the audit story: every field the
// helper acts on is allowlisted here, and anything else is refused.
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "privsep.h"

static int failures;

#define CHECK(cond, what)                                      \
    do {                                                       \
        if (cond) {                                            \
            printf("[test] %-58s PASS\n", what);                \
        } else {                                               \
            printf("[test] %-58s FAIL\n", what);                \
            failures++;                                        \
        }                                                      \
    } while (0)

static void test_framing(void) {
    uint8_t buf[PRIVSEP_MAX_MSG];
    uint8_t out[PRIVSEP_MAX_MSG];
    size_t n = 0;

    // A request round-trips exactly.
    CHECK(privsep_encode(1, PRIVSEP_OP_NET_UP, (const uint8_t*)"vm-1", 5, buf,
                         sizeof(buf), &n) == 0 &&
              n == 8 + 5,
          "frame: a request encodes to header plus body");
    uint8_t ver = 0, op = 0;
    const uint8_t* body = NULL;
    uint32_t body_len = 0;
    CHECK(privsep_decode(buf, n, &ver, &op, &body, &body_len) == 0 && ver == 1 &&
              op == PRIVSEP_OP_NET_UP && body_len == 5 &&
              !memcmp(body, "vm-1", 5),
          "frame: it decodes back to the same fields");
    CHECK(privsep_encode(1, PRIVSEP_OP_HELLO, NULL, 0, buf, sizeof(buf), &n) == 0 &&
              privsep_decode(buf, n, &ver, &op, &body, &body_len) == 0 &&
              body_len == 0,
          "frame: an empty body is a bare header");
    (void)out;

    // Strict rejects: anything off-shape is refused, never parsed loosely.
    CHECK(privsep_decode(buf, n - 1, &ver, &op, &body, &body_len) != 0,
          "frame: a truncated record is refused");
    CHECK(privsep_decode(buf, 7, &ver, &op, &body, &body_len) != 0,
          "frame: shorter than a header is refused");
    uint8_t evil[16] = { 1, PRIVSEP_OP_POLL, 0, 0, 200, 0, 0, 0,
                         'v', 'm', 0, 0, 0, 0, 0, 0 };
    CHECK(privsep_decode(evil, sizeof(evil), &ver, &op, &body, &body_len) != 0,
          "frame: a lying body length is refused");
    evil[0] = 2;
    evil[4] = 8;
    CHECK(privsep_decode(evil, sizeof(evil), &ver, &op, &body, &body_len) != 0,
          "frame: a wrong version is refused");
    evil[0] = 1;
    evil[1] = PRIVSEP_OP_SWEEP;
    evil[2] = 1;
    CHECK(privsep_decode(evil, sizeof(evil), &ver, &op, &body, &body_len) != 0,
          "frame: a nonzero reserved field is refused");
    CHECK(privsep_encode(1, PRIVSEP_OP_HELLO, NULL, PRIVSEP_MAX_MSG, buf,
                         sizeof(buf), &n) != 0,
          "frame: a body past the cap is refused at encode");
    // Op/status ranges are the caller's check (requests and replies share
    // the framing with different ranges).
    CHECK(privsep_op_ok(PRIVSEP_OP_HELLO) && privsep_op_ok(PRIVSEP_OP_SWEEP) &&
              !privsep_op_ok(0) && !privsep_op_ok(99),
          "frame: op range is 1..7");
    CHECK(privsep_status_ok(PRIVSEP_OK) && privsep_status_ok(PRIVSEP_ERR_BUSY) &&
              !privsep_status_ok(99),
          "frame: status range is 0..4");
}

static void test_vm_id(void) {
    CHECK(privsep_vm_id_ok("vm-abc_09.X"), "vm-id: letters, digits, _-.: ok");
    CHECK(!privsep_vm_id_ok(""), "vm-id: empty is refused");
    CHECK(!privsep_vm_id_ok("vm/x"), "vm-id: a slash is refused");
    CHECK(!privsep_vm_id_ok(".."), "vm-id: dot-dot is refused");
    CHECK(!privsep_vm_id_ok("."), "vm-id: a bare dot is refused");
    CHECK(!privsep_vm_id_ok("vm x"), "vm-id: a space is refused");
    CHECK(!privsep_vm_id_ok("vm;x"), "vm-id: a semicolon is refused");
    CHECK(!privsep_vm_id_ok("vm\x01x"), "vm-id: control bytes are refused");
    char max[PRIVSEP_VM_ID_MAX + 1];
    memset(max, 'a', sizeof(max) - 1);
    max[sizeof(max) - 1] = 0;
    CHECK(privsep_vm_id_ok(max), "vm-id: 32 chars is ok");
    char over[PRIVSEP_VM_ID_MAX + 2];
    memset(over, 'a', sizeof(over) - 1);
    over[sizeof(over) - 1] = 0;
    CHECK(!privsep_vm_id_ok(over), "vm-id: 33 chars is refused");
    char tap[64];
    CHECK(privsep_tap_name("vm-1", tap, sizeof(tap)) == 0 &&
              !strcmp(tap, "tap-vm-1"),
          "vm-id: the tap name derives, never arrives on the wire");
    CHECK(privsep_tap_name("vm/x", tap, sizeof(tap)) != 0,
          "vm-id: deriving from an evil id fails");
}

static void test_uids(void) {
    const uint32_t duid = 1001, dgid = 1001;  // the daemon's own
    CHECK(privsep_jail_ids_ok(65534, 65534, duid, dgid),
          "ids: 65534/65534 is ok");
    CHECK(!privsep_jail_ids_ok(0, 65534, duid, dgid),
          "ids: uid 0 is refused");
    CHECK(!privsep_jail_ids_ok(65534, 0, duid, dgid),
          "ids: gid 0 is refused");
    CHECK(!privsep_jail_ids_ok(duid, 65534, duid, dgid),
          "ids: the daemon uid is refused (an escape must not land on it)");
    CHECK(!privsep_jail_ids_ok(65534, dgid, duid, dgid),
          "ids: the daemon gid is refused");
    CHECK(!privsep_jail_ids_ok(0xFFFFFFFFu, 65534, duid, dgid),
          "ids: -1 is refused");
    CHECK(!privsep_jail_ids_ok(70000, 65534, duid, dgid),
          "ids: past 65535 is refused");
}

static void test_paths(void) {
    const char* roots[] = { "/snap", "/jail", "/ws" };
    CHECK(privsep_path_ok("/snap/a/b.ext4", roots, 3),
          "path: under a root is ok");
    CHECK(!privsep_path_ok("snap/a", roots, 3),
          "path: a relative path is refused");
    CHECK(!privsep_path_ok("", roots, 3), "path: empty is refused");
    CHECK(!privsep_path_ok("/snap/../etc/passwd", roots, 3),
          "path: dot-dot is refused");
    CHECK(!privsep_path_ok("/snap//a", roots, 3),
          "path: an empty component is refused");
    CHECK(!privsep_path_ok("/snap/./a", roots, 3),
          "path: a dot component is refused");
    CHECK(!privsep_path_ok("/snap/a/", roots, 3),
          "path: a trailing slash is refused");
    CHECK(!privsep_path_ok("/other/a", roots, 3),
          "path: outside every root is refused");
    CHECK(!privsep_path_ok("/snap", roots, 3),
          "path: a root itself is refused (must nest under one)");
    CHECK(!privsep_path_ok("/snap/a\x01" "b", roots, 3),
          "path: control bytes are refused");
    // Spaces stay allowed: every consumer takes the path as one string (no
    // word splitting anywhere on the privileged path), and an operator's
    // state-dir roots may legitimately contain one.
    CHECK(privsep_path_ok("/snap/a b", roots, 3),
          "path: a space is allowed (consumed whole, never split)");
    char over[PRIVSEP_MAX_PATH + 8];
    memset(over, 'a', sizeof(over) - 1);
    over[sizeof(over) - 1] = 0;
    over[0] = '/';
    CHECK(!privsep_path_ok(over, roots, 3),
          "path: past the length cap is refused");
    CHECK(!privsep_path_ok(NULL, roots, 3), "path: NULL is refused");
    CHECK(!privsep_path_ok("/snap/a", NULL, 0),
          "path: no roots configured is refused");
}

static void test_flags(void) {
    CHECK(privsep_spawn_flags_ok(0), "flags: zero is ok");
    CHECK(privsep_spawn_flags_ok(PRIVSEP_SPAWN_SECCOMP | PRIVSEP_SPAWN_PCI),
          "flags: the two known bits are ok");
    CHECK(!privsep_spawn_flags_ok(0x4), "flags: an unknown bit is refused");
    CHECK(!privsep_spawn_flags_ok(0xFFFFFFFFu),
          "flags: all bits is refused");
}

static void test_u32(void) {
    uint8_t b[4];
    privsep_put_u32(b, 0x01020304u);
    CHECK(b[0] == 0x04 && b[1] == 0x03 && b[2] == 0x02 && b[3] == 0x01 &&
              privsep_get_u32(b) == 0x01020304u,
          "u32: little-endian put/get round-trips");
}

// ---- client transport: scripted fake helper over a socketpair -------------

typedef struct {
    int fd;
    int mode;  // 0: scripted reply, 1: sleep (timeout), 2: garbage, 3: record only
    uint8_t status;
    uint8_t body[512];
    size_t body_len;
    int got_message;
    uint8_t seen_op;
    uint8_t seen_req[2048];
    size_t seen_len;
} fake_args_t;

static void* fake_thread(void* a) {
    fake_args_t* f = a;
    if (f->mode == 1) {
        // Silent helper: block without replying until the client goes away.
        // (A detached sleep here would read f after the caller reuses its
        // stack; the join below plus EOF makes the lifetime exact.)
        uint8_t blk[64];
        recv(f->fd, blk, sizeof(blk), 0);
        return NULL;
    }
    if (f->mode == 3) {  // record-only: wait briefly, then report silence
        struct timeval tv = { .tv_sec = 0, .tv_usec = 300000 };
        setsockopt(f->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    uint8_t buf[PRIVSEP_MAX_MSG];
    ssize_t n = recv(f->fd, buf, sizeof(buf), 0);
    if (n <= 0) return NULL;
    f->got_message = 1;
    uint8_t ver, op;
    const uint8_t* body;
    uint32_t blen;
    if (privsep_decode(buf, (size_t)n, &ver, &op, &body, &blen) == 0) {
        f->seen_op = op;
        size_t take = blen < sizeof(f->seen_req) ? blen : sizeof(f->seen_req);
        memcpy(f->seen_req, body, take);
        f->seen_len = blen;
    }
    if (f->mode == 3) return NULL;
    if (f->mode == 2) {
        static const uint8_t garbage[] = { 9, 9, 9 };
        send(f->fd, garbage, sizeof(garbage), 0);
        return NULL;
    }
    uint8_t rep[PRIVSEP_MAX_MSG];
    size_t rn = 0;
    privsep_encode(1, f->status, f->body, f->body_len, rep, sizeof(rep), &rn);
    send(f->fd, rep, rn, 0);
    return NULL;
}

static void fake_start(fake_args_t* f, int* client_fd) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) {
        *client_fd = -1;
        return;
    }
    memset(f, 0, sizeof(*f));
    f->fd = sv[1];
    *client_fd = sv[0];
}

static void test_client(void) {
    // HELLO against a version-echoing helper.
    {
        fake_args_t f;
        int cfd;
        fake_start(&f, &cfd);
        uint8_t vbody[1] = { PRIVSEP_VERSION };
        memcpy(f.body, vbody, 1);
        f.body_len = 1;
        f.status = PRIVSEP_OK;
        pthread_t t;
        pthread_create(&t, NULL, fake_thread, &f);
        CHECK(privsep_hello(cfd) == 0 && f.seen_op == PRIVSEP_OP_HELLO,
              "client: HELLO succeeds and arrives as op 1");
        pthread_join(t, NULL);
        close(cfd);
        close(f.fd);
    }
    // NET_UP decodes tap + addrs.
    {
        fake_args_t f;
        int cfd;
        fake_start(&f, &cfd);
        uint8_t* b = f.body;
        memcpy(b, "tap-vm-1", 9);
        privsep_put_u32(b + 9, 0x01020304u);
        privsep_put_u32(b + 13, 0x05060708u);
        f.body_len = 17;
        f.status = PRIVSEP_OK;
        pthread_t t;
        pthread_create(&t, NULL, fake_thread, &f);
        char tap[64];
        uint32_t hip = 0, gip = 0;
        CHECK(privsep_net_up(cfd, "vm-1", tap, sizeof(tap), &hip, &gip) == 0 &&
                  !strcmp(tap, "tap-vm-1") && hip == 0x01020304u &&
                  gip == 0x05060708u,
              "client: NET_UP decodes tap and both addrs");
        pthread_join(t, NULL);
        close(cfd);
        close(f.fd);
    }
    // Server errors map to errno.
    {
        fake_args_t f;
        int cfd;
        fake_start(&f, &cfd);
        privsep_put_u32(f.body, (uint32_t)EIO);
        privsep_put_u32(f.body + 4, 0);
        f.body_len = 8;
        f.status = PRIVSEP_ERR_FAILED;
        pthread_t t;
        pthread_create(&t, NULL, fake_thread, &f);
        char tap[64];
        uint32_t hip, gip;
        CHECK(privsep_net_up(cfd, "vm-1", tap, sizeof(tap), &hip, &gip) != 0 &&
                  errno == EIO,
              "client: FAILED surfaces the server errno");
        pthread_join(t, NULL);
        close(cfd);
        close(f.fd);
    }
    {
        fake_args_t f;
        int cfd;
        fake_start(&f, &cfd);
        f.status = PRIVSEP_ERR_NOT_FOUND;
        pthread_t t;
        pthread_create(&t, NULL, fake_thread, &f);
        int st, ec, ts, js;
        CHECK(privsep_poll(cfd, "vm-1", &st, &ec, &ts, &js) != 0 &&
                  errno == ENOENT,
              "client: NOT_FOUND becomes ENOENT");
        pthread_join(t, NULL);
        close(cfd);
        close(f.fd);
    }
    // A silent helper trips the deadline; garbage trips EBADMSG.
    {
        fake_args_t f;
        int cfd;
        fake_start(&f, &cfd);
        f.mode = 1;
        pthread_t t;
        pthread_create(&t, NULL, fake_thread, &f);
        uint8_t rep[64];
        uint32_t rlen = 0;
        uint8_t status = 0;
        CHECK(privsep_rpc(cfd, PRIVSEP_OP_POLL, (const uint8_t*)"vm-1", 5, rep,
                          sizeof(rep), &rlen, &status, 100) != 0 &&
                  errno == ETIMEDOUT,
              "client: a silent helper trips the deadline");
        close(cfd);  // EOF wakes the silent thread, then join it
        pthread_join(t, NULL);
        close(f.fd);
    }
    {
        fake_args_t f;
        int cfd;
        fake_start(&f, &cfd);
        f.mode = 2;
        pthread_t t;
        pthread_create(&t, NULL, fake_thread, &f);
        uint8_t rep[64];
        uint32_t rlen = 0;
        uint8_t status = 0;
        CHECK(privsep_rpc(cfd, PRIVSEP_OP_POLL, (const uint8_t*)"vm-1", 5, rep,
                          sizeof(rep), &rlen, &status, 2000) != 0 &&
                  errno == EBADMSG,
              "client: a garbage reply is EBADMSG");
        pthread_join(t, NULL);
        close(cfd);
        close(f.fd);
    }
    // Client-side validation refuses before sending: the helper hears nothing.
    {
        fake_args_t f;
        int cfd;
        fake_start(&f, &cfd);
        f.mode = 3;
        pthread_t t;
        pthread_create(&t, NULL, fake_thread, &f);
        char tap[64];
        uint32_t hip, gip;
        CHECK(privsep_net_up(cfd, "vm/../x", tap, sizeof(tap), &hip, &gip) != 0 &&
                  errno == EINVAL,
              "client: an evil vm id is refused before sending");
        pthread_join(t, NULL);
        CHECK(!f.got_message, "client: ...and nothing was sent");
        close(cfd);
        close(f.fd);
    }
    // SPAWN args encode in field order with validated paths; evil paths stop it.
    {
        fake_args_t f;
        int cfd;
        fake_start(&f, &cfd);
        privsep_put_u32(f.body, 4242u);
        f.body_len = 4;
        f.status = PRIVSEP_OK;
        pthread_t t;
        pthread_create(&t, NULL, fake_thread, &f);
        privsep_spawn_args_t a = {
            .vm_id = "vm-9",
            .jailer_uid = 65534,
            .jailer_gid = 65534,
            .flags = PRIVSEP_SPAWN_SECCOMP,
            .kernel = "/snap/vmlinux",
            .rootfs = "/snap/rootfs",
            .vmstate = "",
            .mem = NULL,
            .workspace = "/ws/vol.ext4",
            .outdir = NULL,
            .serial = "/jail/vm-9/serial.log",
        };
        pid_t pid = 0;
        int step = -1;
        int rc = privsep_spawn(cfd, &a, "/snap", "/ws", "/jail", &pid, &step);
        CHECK(rc == 0 && pid == 4242 && step == 0 &&
                  f.seen_op == PRIVSEP_OP_SPAWN,
              "client: SPAWN encodes, sends, and decodes the pid");
        // Field order on the wire: vm, uid, gid, flags, then the 7 paths.
        const uint8_t* p = f.seen_req;
        int order_ok = f.seen_len > 5 && !memcmp(p, "vm-9", 5);
        p += 5;
        order_ok = order_ok && privsep_get_u32(p) == 65534;
        p += 4;
        order_ok = order_ok && privsep_get_u32(p) == 65534;
        p += 4;
        order_ok = order_ok && privsep_get_u32(p) == PRIVSEP_SPAWN_SECCOMP;
        p += 4;
        order_ok = order_ok && !strcmp((const char*)p, "/snap/vmlinux");
        CHECK(order_ok, "client: SPAWN wire order is vm, uid, gid, flags, paths");
        pthread_join(t, NULL);
        close(cfd);
        close(f.fd);
    }
    {
        fake_args_t f;
        int cfd;
        fake_start(&f, &cfd);
        f.mode = 3;
        pthread_t t;
        pthread_create(&t, NULL, fake_thread, &f);
        privsep_spawn_args_t a = {
            .vm_id = "vm-9",
            .jailer_uid = 0,  // evil: root in the jail
            .jailer_gid = 65534,
            .kernel = "/snap/vmlinux",
        };
        pid_t pid = 0;
        int step = 0;
        CHECK(privsep_spawn(cfd, &a, "/snap", "/ws", "/jail", &pid, &step) != 0 &&
                  errno == EINVAL,
              "client: uid 0 in SPAWN is refused before sending");
        pthread_join(t, NULL);
        CHECK(!f.got_message, "client: ...and nothing was sent");
        close(cfd);
        close(f.fd);
    }
    // TEARDOWN and SWEEP shapes.
    {
        fake_args_t f;
        int cfd;
        fake_start(&f, &cfd);
        f.status = PRIVSEP_OK;
        pthread_t t;
        pthread_create(&t, NULL, fake_thread, &f);
        CHECK(privsep_teardown(cfd, "vm-1") == 0 &&
                  f.seen_op == PRIVSEP_OP_TEARDOWN,
              "client: TEARDOWN sends the vm id");
        pthread_join(t, NULL);
        close(cfd);
        close(f.fd);
    }
    {
        fake_args_t f;
        int cfd;
        fake_start(&f, &cfd);
        privsep_put_u32(f.body, 3u);
        f.body_len = 4;
        f.status = PRIVSEP_OK;
        pthread_t t;
        pthread_create(&t, NULL, fake_thread, &f);
        uint32_t swept = 0;
        CHECK(privsep_sweep(cfd, 60, &swept) == 0 && swept == 3,
              "client: SWEEP sends the age and decodes the count");
        pthread_join(t, NULL);
        close(cfd);
        close(f.fd);
    }
}

int main(void) {
    test_framing();
    test_vm_id();
    test_uids();
    test_paths();
    test_flags();
    test_u32();
    test_client();
    if (failures) {
        printf("[test] privsep: %d FAILED\n", failures);
        return 1;
    }
    printf("[test] privsep: PASS\n");
    return 0;
}
