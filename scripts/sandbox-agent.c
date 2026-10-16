// sandbox-agent — guest-side env receiver + heartbeat (Phase 9b).
//
// This is the guest's foreground process (the init execs it). It:
//   * binds an AF_VSOCK listener on ENV_PORT,
//   * prints "SANDBOX-READY" (the template readiness marker),
//   * then busy-loops: zero-timeout poll() + accept() serves the host's per-VM
//     env injection, and it periodically prints "SANDBOX-TICK". Until the env
//     lands it also re-binds the listener about every 5 s so Firecracker's
//     muxer re-learns the port after a post-restore transport reset.
//
// Why the agent owns the busy loop: after a UFFD restore the aarch64 arch timer
// does not re-arm on this host, so the scheduler tick stops and a CPU-hogging
// shell loop (or a `sleep`) would starve every other guest process (and WFI).
// One process that polls the socket AND emits the heartbeat keeps working
// without timer interrupts; incoming vsock data is delivered by the device
// interrupt and picked up by the next non-blocking accept().
//
// Built static (no libc in the rootfs) by scripts/build-custom-rootfs.sh.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ENV_PORT 5001
#define ENV_FILE "/tmp/sandbox-env"
#define MAX_PAYLOAD 8192

static int g_console = -1;

static void say(const char* s) {
    size_t n = strlen(s);
    ssize_t w = write(g_console, s, n);
    (void)w;
}

static int got_env = 0;

static int bind_listen(void) {
    int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    struct sockaddr_vm sa;
    memset(&sa, 0, sizeof(sa));
    sa.svm_family = AF_VSOCK;
    sa.svm_cid = VMADDR_CID_ANY;
    sa.svm_port = ENV_PORT;
    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) == 0 && listen(fd, 4) == 0)
        return fd;
    close(fd);
    return -1;
}

// Read the whole connection (host half-closes after the env), apply it, and
// echo a delimited marker so the host can observe the injection.
static void serve(int cfd) {
    char buf[MAX_PAYLOAD];
    size_t off = 0;
    for (;;) {
        if (off >= sizeof(buf) - 1) break;
        ssize_t r = read(cfd, buf + off, sizeof(buf) - 1 - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        off += (size_t)r;
    }
    close(cfd);
    buf[off] = '\0';

    int fd = open(ENV_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        ssize_t w = write(fd, buf, off);
        (void)w;
        close(fd);
    }
    say("\nSANDBOX-ENV-BEGIN\n");
    say(buf);
    say("\nSANDBOX-ENV-END\n");
    got_env = 1;
}

int main(void) {
    // fd 1 is the init's stdout = the kernel console (ttyS0) = the Firecracker
    // serial backend. Opening /dev/console can block on carrier, so don't.
    g_console = 1;

    // The virtio-vsock device may probe after init starts; retry bind briefly.
    int lfd = -1;
    for (int i = 0; i < 200 && lfd < 0; i++) {
        lfd = bind_listen();
        if (lfd < 0) usleep(50000);
    }
    if (lfd < 0) {
        say("SANDBOX-AGENT-FAIL\n");
        return 1;
    }

    // Signal host readiness; the snapshot is taken after this marker.
    say("SANDBOX-READY\n");

    // Busy-loop with a *zero-timeout* poll(): it never blocks, so the heartbeat
    // keeps running regardless of timer/interrupt behaviour after a restore.
    // When the vsock device delivers the host's connection the kernel queues it
    // and poll() reports POLLIN; the following accept() then returns at once.
    //
    // Post-restore, Firecracker resets the vsock transport and the guest must
    // re-announce its listener; if that one-shot announcement is lost the host
    // can connect and handshake forever without the guest seeing anything
    // (ticks flow, no connection arrives). Until the env is received, therefore,
    // periodically close and re-bind the listener: each fresh listen() emits a
    // port-announce event on the guest->host event queue (an MMIO write, no rx
    // interrupt needed), which re-syncs Firecracker's muxer from the guest side.
    // Once the env lands the listener stays put so an in-flight connection is
    // never dropped.
    struct pollfd pfd;
    pfd.fd = lfd;
    pfd.events = POLLIN;
    unsigned long tick = 0;
    unsigned long rl = 0;
    int announced = 0;
    for (;;) {
        pfd.fd = lfd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = (lfd >= 0) ? poll(&pfd, 1, 0) : -1;
        if (pr > 0 && (pfd.revents & POLLIN)) {
            if (!announced) {
                say("SANDBOX-VSOCK-POLLIN\n");
                announced = 1;
            }
            int cfd = accept(lfd, NULL, NULL);
            if (cfd >= 0) {
                serve(cfd);
                continue;
            }
        }
        // Re-announce rarely (~5 s): each rebind closes the listener and drops
        // any in-flight host connection, so back-to-back rebinds would
        // guillotine every injection attempt. A long quiet window lets one
        // complete undisturbed. (~20M iterations at ~4M/s.)
        if (!got_env && ++rl % 20000000 == 0) {
            // Close first: a second bind of the same vsock port while the old
            // listener lives always fails with EADDRINUSE, so bind-then-close
            // could never recreate the listener.
            if (lfd >= 0) close(lfd);
            lfd = -1;
            for (int bi = 0; bi < 1000 && lfd < 0; bi++)
                lfd = bind_listen();
            if (lfd >= 0) {
                announced = 0;
                say("SANDBOX-VSOCK-RELISTEN\n");
            } else {
                say("SANDBOX-VSOCK-REBIND-FAIL\n");
            }
        }
        if (++tick % 200000 == 0) say("SANDBOX-TICK\n");
    }
    return 0;
}
