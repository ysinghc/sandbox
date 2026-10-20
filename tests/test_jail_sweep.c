// SPDX-License-Identifier: GPL-2.0-only
//
// #31: the startup sweep must reclaim jails left by a daemon that died without
// vmm_destroy, and must not touch one that is still in use.
//
// The failure this prevents is not "a directory stays behind": it is that the
// jail's bind mounts live in the kernel, so after a SIGKILL every rm_rf of that
// directory fails EBUSY *forever*. The disk leaks one session per crash and the
// workspace reaper can never free those volumes. Only root can bind-mount, so
// this runs in the privileged suite.

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sandbox_fs.h"
#include "vmm_manager.h"

static int failures;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        if (cond) {                                                          \
            printf("[test] %s PASS\n", (what));                              \
        } else {                                                             \
            printf("[test] %s FAIL\n", (what));                              \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static int mkdir_p(const char* path) {
    return mkdir(path, 0700) == 0 || errno == EEXIST ? 0 : -1;
}

static int make_file(const char* path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    ssize_t w = write(fd, "x", 1);
    close(fd);
    return w == 1 ? 0 : -1;
}

// A jail the way spawn_jailed leaves it: a directory with bind-mounted files.
static int fake_jail(const char* root, const char* name, char* dir, size_t n) {
    snprintf(dir, n, "%s/%s", root, name);
    if (mkdir(dir, 0700) != 0) return -1;
    static const char* binds[] = { "/workspace.ext4", "/rootfs.ext4" };
    for (size_t i = 0; i < sizeof(binds) / sizeof(binds[0]); i++) {
        char dst[PATH_MAX];
        snprintf(dst, sizeof(dst), "%s%s", dir, binds[i]);
        if (make_file(dst) != 0) return -1;
        if (mount(dst, dst, NULL, MS_BIND, NULL) != 0) return -1;
    }
    return 0;
}

static int backdate(const char* path, int seconds) {
    struct timespec ts[2];
    ts[0].tv_sec = ts[1].tv_sec = time(NULL) - seconds;
    ts[0].tv_nsec = ts[1].tv_nsec = 0;
    return utimensat(AT_FDCWD, path, ts, 0);
}

int main(void) {
    if (geteuid() != 0) {
        printf("SKIP (requires root for bind mounts and chroot)\n");
        return 0;
    }

    const char* tmp = getenv("SANDBOX_TEST_TMPDIR");
    if (!tmp || !*tmp) tmp = "/tmp";
    char base[PATH_MAX], root[PATH_MAX];
    snprintf(base, sizeof(base), "%s/jailsweep.XXXXXX", tmp);
    if (!mkdtemp(base)) {
        fprintf(stderr, "FAIL: mkdtemp: %s\n", strerror(errno));
        return 1;
    }
    snprintf(root, sizeof(root), "%s/jails", base);
    if (mkdir_p(root) != 0) {
        fprintf(stderr, "FAIL: mkdir %s: %s\n", root, strerror(errno));
        return 1;
    }

    char dead[PATH_MAX], live[PATH_MAX], young[PATH_MAX], foreign[PATH_MAX];
    if (fake_jail(root, "vm-dead", dead, sizeof(dead)) != 0 ||
        fake_jail(root, "vm-live", live, sizeof(live)) != 0) {
        fprintf(stderr, "FAIL: setting up fake jails: %s\n", strerror(errno));
        return 1;
    }
    snprintf(young, sizeof(young), "%s/vm-young", root);
    snprintf(foreign, sizeof(foreign), "%s/lost+found", root);
    mkdir(young, 0700);
    mkdir(foreign, 0700);
    // Older than the sweep's in-flight guard, so the dead one is eligible.
    backdate(dead, 60);
    backdate(live, 60);

    // A live VMM is a process rooted in the jail (the jailer chroots before
    // exec). Fork, chroot, report readiness, then sit there.
    int ready[2];
    if (pipe(ready) != 0) return 1;
    pid_t child = fork();
    if (child == 0) {
        close(ready[0]);
        if (chroot(live) != 0 || chdir("/") != 0) _exit(1);
        ssize_t w = write(ready[1], "r", 1);
        (void)w;
        for (;;) pause();
    }
    close(ready[1]);
    char byte = 0;
    if (read(ready[0], &byte, 1) != 1) {
        fprintf(stderr, "FAIL: child did not chroot\n");
        kill(child, SIGKILL);
        return 1;
    }
    close(ready[0]);

    int removed = 0;
    if (vmm_jail_sweep(root, JAIL_SWEEP_MIN_AGE_SECONDS, &removed) != 0) {
        fprintf(stderr, "FAIL: sweep: %s\n", strerror(errno));
        kill(child, SIGKILL);
        return 1;
    }

    CHECK(removed == 1, "sweep removes exactly the dead jail");
    CHECK(access(dead, F_OK) != 0, "dead jail and its mounts are gone");
    CHECK(access(live, F_OK) == 0, "jail with a live VMM is kept");
    CHECK(access(young, F_OK) == 0, "jail younger than the guard is kept");
    CHECK(access(foreign, F_OK) == 0, "non-VM directory is never touched");

    // The kept jail must still be a working jail, not a half-unmounted one: its
    // bind is intact while the process lives.
    char probe[PATH_MAX];
    snprintf(probe, sizeof(probe), "%s/workspace.ext4", live);
    CHECK(access(probe, F_OK) == 0, "live jail keeps its mounts");

    // Kill the "VMM": the jail becomes stale, and the next sweep (a daemon
    // restart) must reclaim it.
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    backdate(live, 60);
    removed = 0;
    if (vmm_jail_sweep(root, JAIL_SWEEP_MIN_AGE_SECONDS, &removed) != 0) {
        fprintf(stderr, "FAIL: second sweep: %s\n", strerror(errno));
        return 1;
    }
    CHECK(removed == 1, "sweep reclaims a jail once its VMM is gone");
    CHECK(access(live, F_OK) != 0, "reclaimed jail is gone");

    sandbox_rm_rf(base);

    printf(failures ? "[test] jail_sweep: FAIL\n" : "[test] jail_sweep: PASS\n");
    return failures ? 1 : 0;
}
