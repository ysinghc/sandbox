// §10.14 fuzz target: HTTP request header parser (src/broker/http.c).
//
// The parser reads from a socket, so the fuzz input is fed through a
// socketpair and parsed from the read end. Bounded to keep the (synchronous)
// write inside the default socketpair buffer.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "broker.h"

#define MAX_INPUT 8192

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    if (size > MAX_INPUT) size = MAX_INPUT;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 0;

    // Push the bytes first: the socketpair buffer holds MAX_INPUT, so this
    // cannot deadlock against the parser that reads afterwards.
    size_t off = 0;
    while (off < size) {
        ssize_t w = write(sv[1], data + off, size - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    close(sv[1]);  // EOF for the parser after the input

    http_request_t req;
    memset(&req, 0, sizeof(req));
    if (http_parse_headers(sv[0], &req) == 0) {
        // Exercise the header-munging helpers on parsed output too.
        (void)http_get_header(&req, "Host");
        (void)http_get_header(&req, "X-Sandbox-Token");
        http_set_header(&req, "X-Fuzz", "1");
        http_remove_header(&req, "Host");
    }
    close(sv[0]);
    return 0;
}
