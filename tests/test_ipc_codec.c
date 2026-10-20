// SPDX-License-Identifier: GPL-2.0-only
//
// #12: the wire protocol carries a client-supplied correlation id, and replies
// echo it. These checks are deliberately unprivileged and transport-free: they
// pin the encoding contract that the daemon's out-of-order replies rely on.
//
// What matters here:
//   - an id survives a request round trip, for every request kind that has one;
//   - a reply can be decoded *out of order* and still be matched by id -- the
//     framing does not smuggle an implicit sequence position;
//   - id 0 is byte-identical to the old message, so a legacy peer (and an old
//     daemon reading a new client) sees exactly the bytes it used to.

#include <stdio.h>
#include <string.h>

#include "ipc_codec.h"
#include "ipc_internal.h"
#include "libsandbox.h"

static int failures;

#define CHECK(cond, what)                                    \
    do {                                                     \
        if (cond) {                                          \
            printf("[test] %s PASS\n", (what));              \
        } else {                                             \
            printf("[test] %s FAIL\n", (what));              \
            failures++;                                      \
        }                                                    \
    } while (0)

static bool bytes_equal(const uint8_t* a, size_t na, const uint8_t* b,
                        size_t nb) {
    return na == nb && memcmp(a, b, na) == 0;
}

int main(void) {
    // --- request round trip -------------------------------------------------
    ipc_request_t req;
    ipc_request_init(&req);
    req.kind = IPC_REQ_CREATE;
    req.request_id = 7;  // fits in one varint byte, so the size delta is exact
    req.memory_mib = 128;
    req.vcpu_count = 1;
    snprintf(req.template_name, sizeof(req.template_name), "e2e");
    snprintf(req.session_key, sizeof(req.session_key), "sess-12");
    req.ttl_seconds = 60;

    uint8_t buf[IPC_FRAME_MAX];
    size_t n = 0;
    CHECK(ipc_encode_request(&req, buf, sizeof(buf), &n) == 0,
          "encode create with id");
    ipc_request_t back;
    CHECK(ipc_decode_request(buf, n, &back) == 0, "decode create with id");
    CHECK(back.request_id == req.request_id, "request id survives round trip");
    CHECK(back.kind == IPC_REQ_CREATE && back.memory_mib == 128,
          "payload survives round trip");
    CHECK(strcmp(back.template_name, "e2e") == 0 &&
              strcmp(back.session_key, "sess-12") == 0,
          "strings survive round trip");

    // --- legacy compatibility: id 0 adds nothing to the wire ----------------
    req.request_id = 0;
    uint8_t legacy[IPC_FRAME_MAX];
    size_t n_legacy = 0;
    CHECK(ipc_encode_request(&req, legacy, sizeof(legacy), &n_legacy) == 0,
          "encode legacy create");
    CHECK(!bytes_equal(buf, n, legacy, n_legacy),
          "an id actually changes the bytes");
    // tag (2 bytes: field 100, varint) + value (1 byte for 7)
    CHECK(n == n_legacy + 3, "id 0 adds nothing to the wire (only the id field grew)");
    ipc_request_t legacy_back;
    CHECK(ipc_decode_request(legacy, n_legacy, &legacy_back) == 0 &&
              legacy_back.request_id == 0,
          "legacy request decodes with id 0");

    // --- replies decode in any order ---------------------------------------
    ipc_response_t r_create, r_error;
    memset(&r_create, 0, sizeof(r_create));
    r_create.request_id = 7;
    r_create.kind = IPC_REQ_CREATE;
    r_create.sandbox_id = 41;
    snprintf(r_create.session_token, sizeof(r_create.session_token), "deadbeef");

    memset(&r_error, 0, sizeof(r_error));
    r_error.request_id = 9;
    r_error.is_error = true;
    r_error.error_code = SANDBOX_ERR_POOL_EXHAUSTED;
    snprintf(r_error.error_message, sizeof(r_error.error_message), "busy");

    uint8_t b_create[IPC_FRAME_MAX], b_error[IPC_FRAME_MAX];
    size_t n_create = 0, n_error = 0;
    CHECK(ipc_encode_response(&r_create, b_create, sizeof(b_create), &n_create) == 0,
          "encode create reply");
    CHECK(ipc_encode_response(&r_error, b_error, sizeof(b_error), &n_error) == 0,
          "encode error reply");

    // Deliberately reverse arrival order: the later request's reply first.
    ipc_response_t got_error, got_create;
    CHECK(ipc_decode_response(b_error, n_error, &got_error) == 0,
          "decode error reply first");
    CHECK(ipc_decode_response(b_create, n_create, &got_create) == 0,
          "decode create reply second");
    CHECK(got_error.request_id == 9 && got_error.is_error &&
              got_error.error_code == SANDBOX_ERR_POOL_EXHAUSTED,
          "out-of-order error reply keeps its id and payload");
    CHECK(got_create.request_id == 7 && !got_create.is_error &&
              got_create.sandbox_id == 41,
          "out-of-order create reply keeps its id and payload");
    CHECK(strcmp(got_create.session_token, "deadbeef") == 0,
          "out-of-order reply keeps its token");

    // --- a zero id is absent from the bytes, not encoded as 0 --------------
    ipc_response_t r_legacy;
    memset(&r_legacy, 0, sizeof(r_legacy));
    r_legacy.kind = IPC_REQ_DESTROY;
    r_legacy.sandbox_id = 5;
    uint8_t b_legacy[IPC_FRAME_MAX];
    size_t n_legacy_reply = 0;
    CHECK(ipc_encode_response(&r_legacy, b_legacy, sizeof(b_legacy),
                              &n_legacy_reply) == 0,
          "encode legacy reply");
    ipc_response_t got_legacy;
    CHECK(ipc_decode_response(b_legacy, n_legacy_reply, &got_legacy) == 0 &&
              got_legacy.request_id == 0,
          "legacy reply decodes with id 0");

    ipc_request_clear(&req);
    ipc_request_clear(&back);
    ipc_request_clear(&legacy_back);

    printf(failures ? "[test] ipc_codec: FAIL\n" : "[test] ipc_codec: PASS\n");
    return failures ? 1 : 0;
}
