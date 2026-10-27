// SPDX-License-Identifier: GPL-2.0-only
// guest_rpc_wire.c -- #24 path policy shared by the guest agent and the tests.
// Freestanding (libc only): linked into the static guest agent.
#include <string.h>

#include "guest_rpc.h"

int grpc_path_canon(const char* path, char* out, size_t cap) {
    if (!path || !out || cap < 2 || path[0] != '/') return -1;
    size_t o = 0;
    const char* p = path;
    while (*p) {
        while (*p == '/') p++;  // a doubled or trailing slash adds no component
        if (!*p) break;
        const char* c = p;
        while (*p && *p != '/') p++;
        size_t n = (size_t)(p - c);
        // "." and ".." are refused, not resolved: lexically collapsing ".." is
        // wrong in the presence of symlinks, and no caller needs it.
        if ((n == 1 && c[0] == '.') || (n == 2 && c[0] == '.' && c[1] == '.')) return -1;
        if (o + 1 + n + 1 > cap) return -1;
        out[o++] = '/';
        memcpy(out + o, c, n);
        o += n;
    }
    if (o == 0) out[o++] = '/';
    out[o] = '\0';
    return 0;
}

int grpc_path_within(const char* canon, const char* root) {
    size_t rl = strlen(root);
    if (strcmp(root, "/") == 0) return canon[0] == '/';
    if (strncmp(canon, root, rl) != 0) return 0;
    // "/workspace2" must not count as inside "/workspace".
    return canon[rl] == '\0' || canon[rl] == '/';
}
