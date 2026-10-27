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
#include <stdlib.h>
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

    // --- #24 guest ops ------------------------------------------------------
    {
        ipc_request_t gq;
        ipc_request_init(&gq);
        gq.kind = IPC_REQ_GUEST;
        gq.request_id = 77;
        gq.sandbox_id = 12;
        gq.guest_op = 3;
        snprintf(gq.path, sizeof(gq.path), "/workspace/a b/ü.txt");
        gq.argv[0] = strdup("sh"); gq.argv[1] = strdup("-c"); gq.n_argv = 2;
        gq.env_vars[0] = strdup("K=V"); gq.n_env = 1;
        // Binary payload with NULs and every byte value: protobuf `bytes`, not a string.
        gq.data_len = 256;
        gq.data = malloc(gq.data_len);
        for (int i = 0; i < 256; i++) gq.data[i] = (uint8_t)i;
        gq.timeout_ms = 1500; gq.max_output = 9; gq.offset = 1ull << 40;
        gq.max_bytes = 4096; gq.mode = 0640;
        gq.guest_flags = IPC_GF_SHELL | IPC_GF_APPEND | IPC_GF_RECURSIVE;

        uint8_t gb[IPC_FRAME_MAX];
        size_t gn = 0;
        CHECK(ipc_encode_request(&gq, gb, sizeof(gb), &gn) == 0, "guest: encode request");
        ipc_request_t gr;
        CHECK(ipc_decode_request(gb, gn, &gr) == 0 && gr.kind == IPC_REQ_GUEST &&
                  gr.request_id == 77 && gr.sandbox_id == 12 && gr.guest_op == 3,
              "guest: request decodes with kind, id, target and op");
        CHECK(strcmp(gr.path, gq.path) == 0 && gr.n_argv == 2 && !strcmp(gr.argv[1], "-c") &&
                  gr.n_env == 1 && !strcmp(gr.env_vars[0], "K=V"),
              "guest: path, argv and env survive");
        CHECK(gr.data_len == 256 && gr.data && !memcmp(gr.data, gq.data, 256),
              "guest: binary data (NULs included) survives");
        CHECK(gr.timeout_ms == 1500 && gr.max_output == 9 && gr.offset == (1ull << 40) &&
                  gr.max_bytes == 4096 && gr.mode == 0640 &&
                  gr.guest_flags == (IPC_GF_SHELL | IPC_GF_APPEND | IPC_GF_RECURSIVE),
              "guest: numeric fields and flag bits survive");
        ipc_request_clear(&gr);

        // A path that does not fit is refused, never silently clipped: a clipped
        // path names a different file. The C struct cannot even hold one, so the
        // message is built by hand: ClientMessage.guest (field 7) wrapping
        // GuestRequest.path (field 3) with IPC_MAX_PATH + 10 bytes.
        {
            size_t plen = IPC_MAX_PATH + 10;
            uint8_t raw[IPC_MAX_PATH + 64];
            size_t o = 0, inner_hdr;
            uint8_t inner[IPC_MAX_PATH + 32];
            size_t io = 0;
            inner[io++] = 0x1a;  // field 3, length-delimited
            for (size_t v = plen; ; ) {  // varint length
                uint8_t byte = v & 0x7f;
                v >>= 7;
                inner[io++] = byte | (v ? 0x80 : 0);
                if (!v) break;
            }
            inner_hdr = io;
            memset(inner + io, 'p', plen);
            io += plen;
            raw[o++] = 0x3a;     // field 7, length-delimited
            for (size_t v = io; ; ) {
                uint8_t byte = v & 0x7f;
                v >>= 7;
                raw[o++] = byte | (v ? 0x80 : 0);
                if (!v) break;
            }
            memcpy(raw + o, inner, io);
            o += io;
            (void)inner_hdr;
            ipc_request_t lr;
            CHECK(ipc_decode_request(raw, o, &lr) < 0,
                  "guest: a path longer than the buffer is rejected, not truncated");
        }
        ipc_request_clear(&gq);

        // Response: entries, bytes and the exec counters.
        ipc_response_t gp;
        memset(&gp, 0, sizeof(gp));
        gp.kind = IPC_REQ_GUEST; gp.request_id = 77; gp.sandbox_id = 12;
        gp.exit_code = -1; gp.term_signal = 9; gp.timed_out = true; gp.output_truncated = true;
        gp.out = malloc(4); memcpy(gp.out, "a\0b\n", 4); gp.out_len = 4;
        gp.out_total = 9999999999ull; gp.err_total = 5;
        gp.entries = calloc(2, sizeof(ipc_dirent_t)); gp.n_entries = 2;
        snprintf(gp.entries[0].name, sizeof(gp.entries[0].name), "one"); gp.entries[0].type = 1; gp.entries[0].size = 7;
        snprintf(gp.entries[1].name, sizeof(gp.entries[1].name), "two"); gp.entries[1].type = 2; gp.entries[1].mtime = -5;
        gp.truncated = true; gp.ftype = 2; gp.fmode = 0755; gp.size = 1ull << 33;
        size_t pn = 0;
        CHECK(ipc_encode_response(&gp, gb, sizeof(gb), &pn) == 0, "guest: encode response");
        ipc_response_t gpr;
        CHECK(ipc_decode_response(gb, pn, &gpr) == 0 && gpr.kind == IPC_REQ_GUEST &&
                  gpr.request_id == 77 && gpr.exit_code == -1 && gpr.term_signal == 9 &&
                  gpr.timed_out && gpr.output_truncated,
              "guest: response flags and signed exit code survive");
        CHECK(gpr.out_len == 4 && !memcmp(gpr.out, "a\0b\n", 4) && gpr.out_total == 9999999999ull &&
                  gpr.err_total == 5 && gpr.err == NULL,
              "guest: output bytes and 64-bit totals survive");
        CHECK(gpr.n_entries == 2 && !strcmp(gpr.entries[0].name, "one") && gpr.entries[0].size == 7 &&
                  gpr.entries[1].type == 2 && gpr.entries[1].mtime == -5 && gpr.truncated &&
                  gpr.ftype == 2 && gpr.fmode == 0755 && gpr.size == (1ull << 33),
              "guest: directory entries and stat fields survive");
        ipc_response_clear(&gpr);
        ipc_response_clear(&gp);

        // The worst case the daemon can produce must still fit one frame.
        ipc_response_t big;
        memset(&big, 0, sizeof(big));
        big.kind = IPC_REQ_GUEST; big.request_id = UINT64_MAX; big.sandbox_id = UINT32_MAX;
        big.out = malloc(IPC_EXEC_OUT_KEEP); memset(big.out, 0xff, IPC_EXEC_OUT_KEEP); big.out_len = IPC_EXEC_OUT_KEEP;
        big.err = malloc(IPC_EXEC_ERR_KEEP); memset(big.err, 0xff, IPC_EXEC_ERR_KEEP); big.err_len = IPC_EXEC_ERR_KEEP;
        big.out_total = big.err_total = UINT64_MAX;
        size_t bn = 0;
        CHECK(ipc_encode_response(&big, gb, sizeof(gb), &bn) == 0 && bn + 4 <= IPC_FRAME_MAX,
              "guest: a full exec reply (32 KiB + 16 KiB) fits one IPC frame");
        ipc_response_clear(&big);
        ipc_response_t ch;
        memset(&ch, 0, sizeof(ch));
        ch.kind = IPC_REQ_GUEST; ch.request_id = UINT64_MAX;
        ch.out = malloc(IPC_GUEST_CHUNK); memset(ch.out, 0xff, IPC_GUEST_CHUNK); ch.out_len = IPC_GUEST_CHUNK;
        ch.size = UINT64_MAX; ch.truncated = true;
        CHECK(ipc_encode_response(&ch, gb, sizeof(gb), &bn) == 0 && bn + 4 <= IPC_FRAME_MAX,
              "guest: a full 48 KiB read chunk fits one IPC frame");
        ipc_response_clear(&ch);
    }

    ipc_request_clear(&req);
    ipc_request_clear(&back);
    ipc_request_clear(&legacy_back);

    printf(failures ? "[test] ipc_codec: FAIL\n" : "[test] ipc_codec: PASS\n");
    return failures ? 1 : 0;
}
