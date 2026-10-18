// SPDX-License-Identifier: GPL-2.0-only
#ifndef IPC_INTERNAL_H
#define IPC_INTERNAL_H

// §2.3 framing: length-prefixed protobuf over SOCK_SEQPACKET. One packet is
// [u32 big-endian payload length][payload]. SEQPACKET preserves the boundary,
// so a single sendmsg/recv moves exactly one frame. sendmsg with an iovec
// keeps the length prefix adjacent to the payload without a copy.

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define IPC_FRAME_MAX (64 * 1024)

static inline int ipc_send_frame(int fd, const uint8_t* payload, size_t len) {
    if (len + 4 > IPC_FRAME_MAX) return -1;
    uint8_t hdr[4] = {
        (uint8_t)(len >> 24),
        (uint8_t)(len >> 16),
        (uint8_t)(len >> 8),
        (uint8_t)len,
    };
    struct iovec iov[2] = {
        { (void*)hdr, 4 },
        { (void*)payload, len },
    };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = iov;
    mh.msg_iovlen = len ? 2 : 1;
    ssize_t w;
    do {
        w = sendmsg(fd, &mh, MSG_NOSIGNAL);
    } while (w < 0 && errno == EINTR);
    return (w == (ssize_t)(len + 4)) ? 0 : -1;
}

// Reads one frame. Returns 0 on success, -1 on EOF/error/malformed/oversized.
static inline int ipc_recv_frame(int fd, uint8_t* payload, size_t cap,
                                 size_t* out_len) {
    uint8_t pkt[IPC_FRAME_MAX];
    ssize_t r;
    do {
        r = recv(fd, pkt, sizeof(pkt), 0);
    } while (r < 0 && errno == EINTR);
    if (r <= 0) return -1;
    if (r < 4) return -1;
    uint32_t n = ((uint32_t)pkt[0] << 24) | ((uint32_t)pkt[1] << 16) |
                 ((uint32_t)pkt[2] << 8) | (uint32_t)pkt[3];
    if ((ssize_t)(n + 4) != r || n > cap) return -1;
    if (n) memcpy(payload, pkt + 4, n);
    *out_len = n;
    return 0;
}

#endif // IPC_INTERNAL_H
