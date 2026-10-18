// SPDX-License-Identifier: GPL-2.0-only
// Phase 2 regression: the jailer seccomp policy (src/seccomp.c).
//
// The policy is installed in a forked child and then exercised:
//
//   * every syscall the allow-list claims to permit must actually be callable
//     — the child reaches the end instead of dying;
//   * a syscall the policy deliberately omits (getuid) must NOT succeed. In a
//     Release build (NDEBUG) the default action is SCMP_ACT_KILL_PROCESS, so
//     the child dies with SIGSYS; in a Debug build it is SCMP_ACT_ERRNO(EPERM),
//     so the call returns -1/EPERM.
//
// No root is required — installing a seccomp filter is unprivileged — so this
// runs on the hosted CI as well as the privileged runners.
//
// The allow-list is not the whole story: a firecracker upgrade that starts
// calling a new syscall turns a live sandbox into a SIGSYS kill. This test
// pins the calls the engine's correctness depends on (time, entropy, mmap,
// file/stat), so a regression there fails in CI rather than in production.

#define _GNU_SOURCE

#include "sandbox_seccomp.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int g_fail = 0;

#define CHECK(cond, msg)                              \
    do {                                              \
        if (!(cond)) {                                \
            fprintf(stderr, "  FAIL: %s\n", (msg));   \
            g_fail++;                                 \
        }                                             \
    } while (0)

static void report(const char* name, int before) {
    printf("[test] %-14s %s\n", name, (g_fail == before) ? "PASS" : "FAIL");
    fflush(stdout);
}

// Child body: install the filter and touch the permitted surface. Any syscall
// missing from the allow-list kills us here (Release) or returns EPERM (Debug).
static void child_allowed(void) {
    if (apply_seccomp_filter() < 0) _exit(10);

    struct utsname u;
    (void)syscall(SYS_uname, &u);
    (void)syscall(SYS_getpid);
    (void)syscall(SYS_gettid);

    // The two calls #22 (determinism/time) depends on, plus entropy.
    struct timespec ts;
    (void)syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
    uint8_t rnd[16];
    (void)syscall(SYS_getrandom, rnd, sizeof rnd, 0);

    void* p = (void*)syscall(SYS_mmap, NULL, 4096, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) {
        (void)syscall(SYS_madvise, p, 4096, MADV_DONTNEED);
        (void)syscall(SYS_munmap, p, 4096);
    }

    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY, 0);
    if (fd >= 0) {
        struct stat st;
        (void)syscall(SYS_newfstatat, fd, "", &st, AT_EMPTY_PATH);
        (void)syscall(SYS_lseek, fd, 0, SEEK_SET);
        (void)syscall(SYS_close, fd);
    }

    (void)syscall(SYS_sched_yield);
    (void)syscall(SYS_brk, 0);
    (void)syscall(SYS_read, -1, rnd, 0);   // EBADF, but the call must be allowed
    (void)syscall(SYS_write, -1, "x", 1);  // EBADF, but the call must be allowed

    _exit(0);
}

// Child body: getuid is absent from the policy. Exit 2 means it was allowed.
static void child_forbidden(void) {
    if (apply_seccomp_filter() < 0) _exit(10);
    errno = 0;
    long r = syscall(SYS_getuid);
    if (r >= 0) _exit(2);  // policy regression
    _exit(0);              // EPERM (Debug default action)
}

// Run a child body; returns its exit status, and sets *sigsys if it was killed
// by SIGSYS (the Release default action).
static int run_child(void (*body)(void), int* sigsys) {
    *sigsys = 0;
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(2);
    }
    if (pid == 0) body();  // body never returns

    int st = 0;
    if (waitpid(pid, &st, 0) < 0) return -1;
    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS) {
        *sigsys = 1;
        return 128 + SIGSYS;
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int main(void) {
    int sigsys = 0;
    int before = g_fail;

    // 1. Every allowed syscall the engine relies on is reachable.
    int rc = run_child(child_allowed, &sigsys);
    CHECK(rc == 0, "allowed syscalls reachable (child must not be killed)");
    if (rc != 0) {
        fprintf(stderr, "  child_allowed rc=%d%s\n", rc,
                sigsys ? " (killed by SIGSYS — a needed syscall is missing "
                         "from the allow-list)" : "");
    }
    report("allowed", before);

    // 2. A syscall outside the policy must not succeed.
    before = g_fail;
    rc = run_child(child_forbidden, &sigsys);
    CHECK(rc == 2 || rc == 0 || sigsys,
          "getuid is refused (EPERM or SIGSYS), never allowed");
    CHECK(rc != 2, "getuid must not be permitted by the policy");
    report("forbidden", before);

    printf("[test] seccomp        %s\n", g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
