// SPDX-License-Identifier: GPL-2.0-only
// vsock_peer.c -- see include/vsock_peer.h.
//
// Deliberately freestanding: libc plus <linux/vm_sockets.h> only. This file is
// linked both into the engine-side unit test and into the guest agent, which is
// built static with no engine runtime (scripts/build-custom-rootfs.sh), so it
// must not grow dependencies.
#include <linux/vm_sockets.h>
#include <sys/socket.h>

#include "vsock_peer.h"

int vsock_peer_cid_is_host(unsigned cid) {
    return cid == VSOCK_PEER_HOST_CID;
}

int vsock_peer_is_host(int fd) {
    struct sockaddr_vm peer;
    socklen_t len = sizeof(peer);
    if (fd < 0) return 0;
    if (getpeername(fd, (struct sockaddr*)&peer, &len) != 0) return 0;
    if (peer.svm_family != AF_VSOCK) return 0;
    return vsock_peer_cid_is_host(peer.svm_cid);
}
