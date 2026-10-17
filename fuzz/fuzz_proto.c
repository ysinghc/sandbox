// §10.14 fuzz target: protobuf wire decoder (src/ipc_codec.cpp via ipc_codec.h).
// Covers both request and response decode paths with arbitrary bytes.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ipc_codec.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ipc_request_t req;
    ipc_request_init(&req);
    (void)ipc_decode_request(data, size, &req);
    ipc_request_clear(&req);

    ipc_response_t resp;
    memset(&resp, 0, sizeof(resp));
    (void)ipc_decode_response(data, size, &resp);
    return 0;
}
