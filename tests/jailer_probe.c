// SPDX-License-Identifier: GPL-2.0-only
// Static probe executed inside the jail. Args: <outside_path> <expected_uid>
// <ptrace|ioctl|allowed>
// Exit 10: outside path reachable (chroot broken). Exit 11: uid mismatch.
// Exit 13: allowed syscall failed post-filter. Exit 14: filter load failed.
// Exit 0: "allowed" mode — every permitted syscall (incl. the jailer's dup2,
//         musl's arch_prctl, and Firecracker's startup poll) succeeded.
//         Otherwise dies by SIGSYS on the fatal call (Release), or exits with
//         errno (Debug).
//
// NOTE: socket()/TCGETS are deliberately *not* probed as fatal — Firecracker's
// runtime set needs both (UDS API server, UFFD handshake, terminal restore), so
// the filter allows them. ptrace and an unlisted ioctl request stand in as
// genuinely-forbidden calls.

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#if defined(__x86_64__)
#include <asm/prctl.h>
#include <sys/syscall.h>
#endif

#include "sandbox_seccomp.h"

int main(int argc, char** argv) {
    if (argc != 4) return 15;
    const char* outside_path = argv[1];
    uid_t expected_uid = (uid_t)atoi(argv[2]);
    bool mode_ioctl = strcmp(argv[3], "ioctl") == 0;
    bool mode_allowed = strcmp(argv[3], "allowed") == 0;

    int fd = open(outside_path, O_RDONLY);
    if (fd >= 0) { close(fd); return 10; }

    if (getuid() != expected_uid) return 11;

    printf("PROBE ok uid=%d\n", (int)getuid());
    fflush(stdout);

    if (apply_seccomp_filter() < 0) return 14;

    if (getpid() <= 0) return 13;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) return 13;
    int efd = epoll_create1(EPOLL_CLOEXEC);
    if (efd < 0) return 13;
    close(efd);
    // Firecracker polls stdin/stdout/stderr during startup; with nfds == 0 this
    // returns immediately and just proves the syscall is permitted.
    if (poll(NULL, 0, 0) < 0) return 13;

    // dup2() must be permitted: the jailer dup2s its serial fd *after*
    // installing this filter (jailer.c). x86_64 has a dup2 syscall distinct
    // from dup3; aarch64 lowers dup2() to dup3. Regression guard for the
    // x86_64 SIGSYS where Firecracker's aarch64-only allow-list lacked dup2.
    if (dup2(STDOUT_FILENO, STDOUT_FILENO) < 0) return 13;
#if defined(__x86_64__)
    // static-pie musl installs the thread pointer via arch_prctl(ARCH_SET_FS)
    // at startup; x86_64's Firecracker calls it before any of its own filters
    // would land. A GET_FS is a side-effect-free proof the syscall is allowed.
    unsigned long fs = 0;
    if (syscall(SYS_arch_prctl, ARCH_GET_FS, (unsigned long)&fs) < 0) return 13;
#endif

    if (mode_allowed) _exit(0);  // all permitted syscalls succeeded

    if (mode_ioctl) {
        // FIONREAD is not in the ioctl allow-list (KVM 0xAE / UFFD 0xAA classes
        // plus specific tap/block/terminal requests) — must be killed.
        int n = 0;
        int rc = ioctl(STDOUT_FILENO, FIONREAD, &n);
        _exit(rc >= 0 ? 12 : errno);
    }
    long prc = ptrace(PTRACE_TRACEME, 0, 0, 0);  // not in Firecracker's set
    _exit(prc >= 0 ? 12 : errno);
}
