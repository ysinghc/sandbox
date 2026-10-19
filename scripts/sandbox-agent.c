// SPDX-License-Identifier: GPL-2.0-only
// sandbox-agent — guest-side env receiver + heartbeat (Phase 9b).
//
// This is the guest's foreground process (the init execs it). It:
//   * binds an AF_VSOCK listener on ENV_PORT,
//   * authenticates every accepted peer: only the host (VMADDR_CID_HOST) may
//     drive this channel, so an in-guest process cannot impersonate it (#10);
//     the classifier is shared with the host unit test (include/vsock_peer.h),
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
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "vsock_peer.h"

#define ENV_PORT 5001
#define ENV_FILE "/tmp/sandbox-env"
#define MAX_PAYLOAD 8192

// #23: the session workspace. The probe below is a *diagnostic*: it lets the
// host observe, from inside the guest, that /workspace is this session's own
// volume and that it survives a destroy + re-create. It never writes the payload
// itself (env values may be credentials) -- only a checksum of it.
#define WS_PROBE_FILE "/workspace/.sandbox-probe"
#define WS_PROBE_MAX 4096

static int g_console = -1;

static void say(const char* s) {
    size_t n = strlen(s);
    ssize_t w = write(g_console, s, n);
    (void)w;
}

static int got_env = 0;

// FNV-1a. Chosen because it is trivially reproducible by eye and the test only
// cares that different payloads give different lines.
static unsigned probe_sum(const char* b, size_t n) {
    unsigned s = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        s ^= (unsigned char)b[i];
        s *= 16777619u;
    }
    return s;
}

// Append a checksum of this injection to the workspace probe file and report the
// file's shape on the serial console:
//
//   SANDBOX-WORKSPACE-PROBE mounted=1 lines=2 first=1a2b3c4d last=5e6f7a8b
//
// `mounted=0` means the probe file could not be opened, which is what a guest
// without a workspace drive (or an unwritable volume) looks like.
//
// `first` is the point: after a destroy + re-create of the *same* session, the
// first line is still the checksum written before, while a *different* session
// starts with one line and a different value. That is the whole persistence
// claim, observed from inside the guest rather than inferred by the host.
static void workspace_probe(const char* payload, size_t n) {
    char line[16];
    int ln = snprintf(line, sizeof(line), "%08x\n", probe_sum(payload, n));
    if (ln <= 0) return;

    int fd = open(WS_PROBE_FILE, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        say("SANDBOX-WORKSPACE-PROBE mounted=0\n");
        return;
    }
    ssize_t w = write(fd, line, (size_t)ln);
    close(fd);
    if (w != ln) {
        say("SANDBOX-WORKSPACE-PROBE mounted=1 write_failed=1\n");
        return;
    }

    fd = open(WS_PROBE_FILE, O_RDONLY);
    if (fd < 0) {
        say("SANDBOX-WORKSPACE-PROBE mounted=1 read_failed=1\n");
        return;
    }
    char buf[WS_PROBE_MAX + 1];
    ssize_t r = read(fd, buf, WS_PROBE_MAX);
    close(fd);
    if (r < 0) r = 0;
    buf[r] = '\0';

    int lines = 0;
    for (ssize_t i = 0; i < r; i++) {
        if (buf[i] == '\n') lines++;
    }
    char first[9] = "--------", last[9] = "--------";
    if (r >= 9) memcpy(first, buf, 8);
    // The last complete line: scan back over the final newline.
    if (r >= 9 && buf[r - 1] == '\n') memcpy(last, buf + r - 9, 8);

    char m[128];
    int k = snprintf(m, sizeof(m),
                     "SANDBOX-WORKSPACE-PROBE mounted=1 lines=%d first=%s last=%s\n",
                     lines, first, last);
    if (k > 0) {
        ssize_t wr = write(g_console, m, (size_t)k);
        (void)wr;
    }
}

// ── #10: authenticate the host ───────────────────────────────────────────────
//
// The classifier lives in include/vsock_peer.h (+ src/vsock_peer.c) so it can be
// unit tested on the host, where a real non-host vsock peer can be produced.
// In-guest that is impossible: this guest kernel is 4.14, and guest-local vsock
// (VMADDR_CID_LOCAL) only exists from Linux 5.6, so a self-test connection into
// our own listener would block in connect() rather than complete. The positive
// direction is still observable here via the logged peer CID below.
static void log_peer(int cfd, const char* tag) {
    struct sockaddr_vm peer;
    socklen_t len = sizeof(peer);
    unsigned cid = 0;
    if (getpeername(cfd, (struct sockaddr*)&peer, &len) == 0) cid = peer.svm_cid;
    char m[80];
    int n = snprintf(m, sizeof(m), "%s cid=%u\n", tag, cid);
    if (n > 0) {
        ssize_t w = write(g_console, m, (size_t)n);
        (void)w;
    }
}

// In-guest the *positive* direction is observable: the host's connection is
// classified and its CID logged (see log_peer usage below). The negative
// direction cannot be produced here at all -- see include/vsock_peer.h.

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

    int fd = open(ENV_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        ssize_t w = write(fd, buf, off);
        (void)w;
        close(fd);
    }
    // Log only the *key names* to the (persistent) serial console: values may
    // be credentials and serial output is retained. The full payload still
    // reaches the guest via ENV_FILE (0600).
    say("\nSANDBOX-ENV-BEGIN\n");
    for (size_t i = 0; i < off;) {
        size_t j = i;
        while (j < off && buf[j] != '\n' && buf[j] != '\0') j++;
        size_t eq = i;
        while (eq < j && buf[eq] != '=') eq++;
        if (eq > i) {
            ssize_t w = write(g_console, buf + i, eq - i);
            (void)w;
        }
        say("\n");
        i = (j < off) ? j + 1 : off;
    }
    say("SANDBOX-ENV-END\n");
    got_env = 1;

    // #23: observe the session workspace from inside the guest (see above).
    workspace_probe(buf, off);

    // #22: report the guest's wall clock once per injection. After a restore the
    // guest resumes with whatever the snapshot captured, so this line is the
    // in-guest evidence that the host's clock_realtime load field did its job
    // (tests/test_ipc.c compares it against host time).
    //
    // Deliberately the syscall, not clock_gettime(3): the libc call reads the
    // vDSO, whose data page was captured in the snapshot, and a restored vDSO
    // can leave the pvclock seqlock reading as in-flux -- the read then spins or
    // fails, which is exactly the kind of silent no-marker flake this test hit
    // once. The syscall goes to the kernel timekeeper and cannot be stale.
    {
        struct timespec ts;
        char m[96];
        long rc = syscall(SYS_clock_gettime, CLOCK_REALTIME, &ts);
        int n;
        if (rc == 0) {
            n = snprintf(m, sizeof(m), "SANDBOX-GUEST-CLOCK epoch=%lld\n",
                         (long long)ts.tv_sec);
        } else {
            n = snprintf(m, sizeof(m), "SANDBOX-GUEST-CLOCK-FAIL errno=%d\n",
                         errno);
        }
        if (n > 0) {
            ssize_t w = write(g_console, m, (size_t)n);
            (void)w;
        }
    }
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
    int logged_host = 0;
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
                // #10: only the host may drive this channel. Anything else --
                // an in-guest process, a peer whose CID we cannot read -- is
                // dropped and logged instead of applied.
                if (vsock_peer_is_host(cfd)) {
                    // Log the CID actually observed, once: positive in-guest
                    // evidence that the classification input is real and is the
                    // host's CID (tests/test_ipc.c asserts on this line).
                    if (!logged_host) {
                        logged_host = 1;
                        log_peer(cfd, "SANDBOX-VSOCK-HOST");
                    }
                    serve(cfd);
                } else {
                    log_peer(cfd, "SANDBOX-VSOCK-REJECT");
                    close(cfd);
                }
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
