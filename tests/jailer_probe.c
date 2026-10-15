// Static probe executed inside the jail. Args: <outside_path> <expected_uid> <ptrace|ioctl>
// Exit 10: outside path reachable (chroot broken). Exit 11: uid mismatch.
// Exit 13: allowed syscall failed post-filter. Exit 14: filter load failed.
// Otherwise dies by SIGSYS on the fatal call (Release), or exits with errno (Debug).
//
// NOTE: socket()/TCGETS are deliberately *not* probed as fatal — Firecracker's
// runtime set needs both (UDS API server, UFFD handshake, terminal restore), so
// the filter allows them. ptrace and an unlisted ioctl request stand in as
// genuinely-forbidden calls.

#include <errno.h>
#include <fcntl.h>
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

#include "sandbox_seccomp.h"

int main(int argc, char** argv) {
    if (argc != 4) return 15;
    const char* outside_path = argv[1];
    uid_t expected_uid = (uid_t)atoi(argv[2]);
    int use_ioctl = strcmp(argv[3], "ioctl") == 0;

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

    if (use_ioctl) {
        // FIONREAD is not in the ioctl allow-list (KVM 0xAE / UFFD 0xAA classes
        // plus specific tap/block/terminal requests) — must be killed.
        int n = 0;
        int rc = ioctl(STDOUT_FILENO, FIONREAD, &n);
        _exit(rc >= 0 ? 12 : errno);
    }
    long prc = ptrace(PTRACE_TRACEME, 0, 0, 0);  // not in Firecracker's set
    _exit(prc >= 0 ? 12 : errno);
}
