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
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "guest_rpc.h"
#include "vsock_peer.h"

#define ENV_PORT 5001
#define ENV_FILE "/tmp/sandbox-env"
#define MAX_PAYLOAD 8192

// #23: the engine's pre-teardown flush request. It is *not* an env var: it is a
// control verb that happens to arrive on the env channel, and it is matched
// exactly so no user-supplied KEY=VALUE can trigger it.
#define CONTROL_FLUSH "SANDBOX_CONTROL=flush"

// #26: network bring-up. The host assigns each VM a /30 on its own tap and
// tells the guest which address to use inside the env payload (a restored guest
// cannot be given one any other way: the snapshot is shared and carries no
// address). The guest then has exactly one reachable peer, the host end of that
// /30, where the broker listens; the host's nft rules drop everything else.
static void say(const char* s);

#define NET_KEY_ADDR "SANDBOX_NET_ADDR="
#define NET_KEY_MASK "SANDBOX_NET_MASK="

static int net_set_flags(int s, const char* name, short set) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) return -1;
    ifr.ifr_flags |= set;
    return ioctl(s, SIOCSIFFLAGS, &ifr);
}

static int net_set_addr(int s, const char* name, int req, const char* dotted) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    struct sockaddr_in* a = (struct sockaddr_in*)&ifr.ifr_addr;
    a->sin_family = AF_INET;
    if (inet_pton(AF_INET, dotted, &a->sin_addr) != 1) return -1;
    return ioctl(s, req, &ifr);
}

// Loopback up (a bare init leaves it down, and workloads expect 127.0.0.1).
static void net_loopback_up(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    net_set_flags(s, "lo", IFF_UP | IFF_RUNNING);
    close(s);
}

// Find the value of KEY in the payload ("KEY=VALUE" lines); copies into out.
static int payload_get(const char* buf, size_t n, const char* key, char* out, size_t cap) {
    size_t kl = strlen(key);
    for (size_t i = 0; i < n;) {
        size_t j = i;
        while (j < n && buf[j] != '\n' && buf[j] != '\0') j++;
        if (j - i > kl && memcmp(buf + i, key, kl) == 0) {
            size_t vl = j - i - kl;
            if (vl >= cap) return -1;
            memcpy(out, buf + i + kl, vl);
            out[vl] = '\0';
            return 0;
        }
        i = j + 1;
    }
    return -1;
}

static void net_configure(const char* buf, size_t n) {
    char addr[32], mask[32];
    if (payload_get(buf, n, NET_KEY_ADDR, addr, sizeof(addr)) != 0 ||
        payload_get(buf, n, NET_KEY_MASK, mask, sizeof(mask)) != 0)
        return;  // no network for this sandbox: the NIC stays unconfigured
    // The first interface that is not loopback (virtio-net: eth0).
    char name[IFNAMSIZ] = "";
    struct if_nameindex* ni = if_nameindex();
    for (struct if_nameindex* p = ni; p && p->if_index; p++)
        if (strcmp(p->if_name, "lo") != 0) {
            snprintf(name, sizeof(name), "%s", p->if_name);
            break;
        }
    if (ni) if_freenameindex(ni);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0 || !name[0]) {
        say("SANDBOX-NET-FAIL no-interface\n");
        if (s >= 0) close(s);
        return;
    }
    int rc = net_set_addr(s, name, SIOCSIFADDR, addr);
    if (rc == 0) rc = net_set_addr(s, name, SIOCSIFNETMASK, mask);
    if (rc == 0) rc = net_set_flags(s, name, IFF_UP | IFF_RUNNING);
    close(s);
    say(rc == 0 ? "SANDBOX-NET-OK\n" : "SANDBOX-NET-FAIL ioctl\n");
}

static grpc_server_t* g_rpc;  // the exec/file server; takes the base env from serve()

// #23: the session workspace. The probe below is a *diagnostic*: it lets the
// host observe, from inside the guest, that /workspace is this session's own
// volume and that it survives a destroy + re-create. It never writes the payload
// itself (env values may be credentials) -- only a checksum of it.
#define WS_PROBE_FILE "/workspace/.sandbox-probe"
#define WS_PROBE_MAX 4096
#define WS_DEVICE "/dev/vdb"
#define WS_DIR "/workspace"

// #23: mount the session volume on first use *after* a restore.
//
// The template snapshots this process with the volume unmounted (see
// scripts/build-custom-rootfs.sh for why: a mount captured in the template bakes
// the base image's metadata and page cache into the snapshot, and a restore
// serves the session's own file behind the same device). So the mount has to
// happen here, once, after each restore -- which also means ext4 replays the
// journal of a session whose VM was killed mid-write, so a persisted volume
// cannot come back with a torn filesystem.
//
// `g_ws_mounted` lives in snapshot memory and is 0 at capture time, because no
// env injection happens before the snapshot is taken.
static int g_ws_mounted = 0;

static int ws_ensure_mount(void) {
    if (g_ws_mounted) return 0;
    if (mount(WS_DEVICE, WS_DIR, "ext4", 0, NULL) == 0) {
        g_ws_mounted = 1;
        return 0;
    }
    if (errno == EBUSY) {  // already mounted by an earlier life of this process
        g_ws_mounted = 1;
        return 0;
    }
    return -1;
}

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
    if (ws_ensure_mount() < 0) {
        char m[96];
        int k = snprintf(m, sizeof(m),
                         "SANDBOX-WORKSPACE-PROBE mounted=0 errno=%d\n", errno);
        if (k > 0) { ssize_t wr = write(g_console, m, (size_t)k); (void)wr; }
        return;
    }
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
// In-guest that is impossible: the pinned 6.18 kernel supports
// VMADDR_CID_LOCAL, but Firecracker's CI config disables
// CONFIG_VSOCKETS_LOOPBACK, so a self-test connection into our own listener has
// no local transport to complete on. The positive direction is still observable
// here via the logged peer CID below.
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

static int bind_listen(unsigned port) {
    int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    struct sockaddr_vm sa;
    memset(&sa, 0, sizeof(sa));
    sa.svm_family = AF_VSOCK;
    sa.svm_cid = VMADDR_CID_ANY;
    sa.svm_port = port;
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

    // #23: writes to the session volume live in this guest's page cache until
    // the guest writes them back, and the engine tears a VM down with SIGKILL --
    // so without this request, a file the workload had already written is simply
    // absent when the next VM mounts the volume. (Observed, not theorised: the
    // re-created session saw only its own new line.) sync() flushes every
    // filesystem in the guest, which is what makes this cover the workload's
    // writes and not just this agent's.
    {
        size_t m = strlen(CONTROL_FLUSH);
        if (off == m + 1 && memcmp(buf, CONTROL_FLUSH, m) == 0 &&
            buf[m] == '\n') {
            sync();
            say("SANDBOX-FLUSH-OK\n");
            return;
        }
    }

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
    // #26: bring the NIC up if the host assigned one, and make the injected env
    // the base of every exec (until now it only reached a file nobody read).
    // Both happen before the end marker the host waits for, so by the time
    // Create returns the guest is ready to use them.
    net_configure(buf, off);
    if (g_rpc) grpc_server_set_base_env(g_rpc, buf, off);
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
    // fd 1 is the init's stdout = the kernel console (ttyS0 on both
    // architectures; Firecracker's aarch64 UART is 8250-compatible) = the
    // Firecracker serial backend. Opening /dev/console can block on carrier, so
    // don't.
    g_console = 1;

    // The virtio-vsock device may probe after init starts; retry bind briefly.
    int lfd = -1;
    for (int i = 0; i < 200 && lfd < 0; i++) {
        lfd = bind_listen(ENV_PORT);
        if (lfd < 0) usleep(50000);
    }
    if (lfd < 0) {
        say("SANDBOX-AGENT-FAIL\n");
        return 1;
    }

    // #24: the exec / file RPC. Same authentication as the env channel (only the
    // host CID is served), its own port, and file ops confined to the workspace
    // volume, which is mounted on first use exactly as for the env probe.
    int rfd = bind_listen(GRPC_PORT);
    grpc_server_t* rpc = grpc_server_new(WS_DIR, ws_ensure_mount);
    g_rpc = rpc;
    if (rfd < 0 || !rpc) say("SANDBOX-RPC-FAIL\n");
    net_loopback_up();
    int rpc_live = 0;
    unsigned long rpc_idle = 0;

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
        // #24: serve the RPC listener the same way (zero-timeout, never blocking).
        // An idle server is only stepped now and then, to reap orphaned children
        // (this process is PID 1); a busy one is stepped every iteration.
        if (rfd >= 0 && rpc) {
            struct pollfd rp = { .fd = rfd, .events = POLLIN };
            if (poll(&rp, 1, 0) > 0 && (rp.revents & POLLIN)) {
                int cfd = accept(rfd, NULL, NULL);
                if (cfd >= 0) {
                    if (vsock_peer_is_host(cfd)) {
                        grpc_server_adopt(rpc, cfd);
                        rpc_live = 1;
                    } else {
                        log_peer(cfd, "SANDBOX-VSOCK-REJECT");
                        close(cfd);
                    }
                }
            }
            if (rpc_live > 0 || ++rpc_idle % 4096 == 0)
                rpc_live = grpc_server_step(rpc);
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
                lfd = bind_listen(ENV_PORT);
            // The RPC listener is re-announced with it; the host only connects
            // after the env has landed, so there is nothing in flight to drop.
            if (rfd >= 0) close(rfd);
            rfd = -1;
            for (int bi = 0; bi < 1000 && rfd < 0; bi++)
                rfd = bind_listen(GRPC_PORT);
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
