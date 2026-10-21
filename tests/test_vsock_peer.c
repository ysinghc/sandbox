// SPDX-License-Identifier: GPL-2.0-only
// test_vsock_peer.c -- #10: the guest control channel's peer classifier.
//
// The agent's listener is reachable by any process inside the guest, so it must
// refuse anything that is not the host. The *positive* direction ("the host's
// connection is accepted and classified as CID_HOST") is observed in-guest by
// tests/test_ipc.c. The *negative* direction cannot be produced inside the
// sandbox guest at all: the pinned 6.18 kernel is new enough for
// VMADDR_CID_LOCAL (Linux 5.6), but Firecracker's CI config ships
// `# CONFIG_VSOCKETS_LOOPBACK is not set`, so an in-guest connection to our own
// listener has no local transport to complete on. It is therefore checked here,
// on the host, against a real non-host AF_VSOCK peer.
//
// The integration half needs a host with vsock loopback and SKIPs loudly
// without one; the decision table always runs.

#include <errno.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "vsock_peer.h"

static int g_fail;
static int g_total;

static void check(int cond, const char* msg) {
    g_total++;
    printf("[test] %-52s %s\n", msg, cond ? "PASS" : "FAIL");
    if (!cond) g_fail++;
}

// Complete a non-blocking connect() to a loopback vsock port, bounded so a
// kernel without loopback support can never wedge the test.
static int connect_local(int cfd, unsigned port) {
    struct sockaddr_vm sa;
    memset(&sa, 0, sizeof(sa));
    sa.svm_family = AF_VSOCK;
    sa.svm_cid = VMADDR_CID_LOCAL;
    sa.svm_port = port;
    if (connect(cfd, (struct sockaddr*)&sa, sizeof(sa)) == 0) return 0;
    if (errno != EINPROGRESS) return -1;
    struct pollfd p = {.fd = cfd, .events = POLLOUT};
    if (poll(&p, 1, 2000) <= 0) return -1;
    int err = 0;
    socklen_t el = sizeof(err);
    if (getsockopt(cfd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) return -1;
    return 0;
}

// 1 = a loopback peer was offered and refused, 0 = it was accepted (a bug),
// -1 = loopback is unavailable on this host (or the test could not set up).
static int loopback_peer_refused(void) {
    int lfd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0) return -1;
    struct sockaddr_vm sa;
    memset(&sa, 0, sizeof(sa));
    sa.svm_family = AF_VSOCK;
    sa.svm_cid = VMADDR_CID_ANY;
    sa.svm_port = VMADDR_PORT_ANY;
    if (bind(lfd, (struct sockaddr*)&sa, sizeof(sa)) != 0 || listen(lfd, 1) != 0) {
        close(lfd);
        return -1;
    }
    socklen_t sl = sizeof(sa);
    if (getsockname(lfd, (struct sockaddr*)&sa, &sl) != 0) {
        close(lfd);
        return -1;
    }
    unsigned port = sa.svm_port;

    int cfd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (cfd < 0 || connect_local(cfd, port) != 0) {
        int e = errno;
        fprintf(stderr, "  loopback setup failed at connect: errno=%d (%s)\n",
                e, strerror(e));
        if (cfd >= 0) close(cfd);
        close(lfd);
        return -1;
    }
    struct pollfd p = {.fd = lfd, .events = POLLIN};
    int afd = -1;
    if (poll(&p, 1, 2000) > 0) afd = accept(lfd, NULL, NULL);
    int out = -1;
    if (afd >= 0) {
        if (vsock_peer_is_host(afd)) out = 0;  // accepted a non-host peer: bug
        else out = 1;
        close(afd);
    } else {
        fprintf(stderr, "  loopback setup failed at accept\n");
    }
    close(cfd);
    close(lfd);
    return out;
}

int main(void) {
    // Decision table: only the host's CID may drive the channel.
    check(vsock_peer_cid_is_host(VSOCK_PEER_HOST_CID), "cid 2 (host) is accepted");
    check(vsock_peer_cid_is_host(VMADDR_CID_HOST), "VMADDR_CID_HOST is the host cid");
    check(!vsock_peer_cid_is_host(VMADDR_CID_LOCAL), "cid 1 (loopback) is refused");
    check(!vsock_peer_cid_is_host(VMADDR_CID_ANY), "cid any is refused");
    check(!vsock_peer_cid_is_host(3), "a guest's own cid is refused");

    // Wiring: a socket with no peer, and an invalid fd, are both refused.
    check(!vsock_peer_is_host(-1), "an invalid fd is refused");
    int s = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s >= 0) {
        check(!vsock_peer_is_host(s), "an unconnected vsock socket is refused");
        close(s);
    }

    int r = loopback_peer_refused();
    if (r < 0) {
        printf("SKIP integration: no usable vsock loopback on this host\n");
    } else {
        check(r == 1, "a real loopback (cid 1) peer is refused");
    }

    printf("[test] vsock_peer: %s (%d checks, %d failed)\n",
           g_fail ? "FAIL" : "PASS", g_total, g_fail);
    return g_fail ? 1 : 0;
}
