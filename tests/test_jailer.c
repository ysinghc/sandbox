// SPDX-License-Identifier: GPL-2.0-only
// Phase 2 verification: seccomp enforcement (always runs) plus the full
// jailer sequence under a user namespace when id-mapping is available
// (SKIPs where the environment forbids it, e.g. AppArmor without sudo).
#define _GNU_SOURCE  // unshare, CLONE_NEWUSER

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "jailer.h"
#include "sandbox_seccomp.h"

#define CHECK_RC(rc, what) do { int _rc = (rc); if (_rc != 0) { \
    fprintf(stderr, "FAIL %s: rc=%d (%s:%d)\n", (what), _rc, __FILE__, __LINE__); \
    abort(); } } while (0)

#define SKIP_CODE 77

static void probe_path(char* out, size_t n) {
    ssize_t len = readlink("/proc/self/exe", out, n - 32);
    if (len <= 0 || (size_t)len >= n - 32) { strcpy(out, "./jailer_probe"); return; }
    out[len] = '\0';
    char* slash = strrchr(out, '/');
    strcpy(slash ? slash + 1 : out, "jailer_probe");
}

// Fork+exec the probe directly (no jail): checks pre-filter assertions,
// loads the real filter, then must be denied on the fatal call. The probe opts
// into ERRNO mode explicitly so the denial is observable; the filter's default
// is KILL_PROCESS (see the jailer sequence, which asserts the SIGSYS).
static int run_probe_bare(const char* mode) {
    char probe[PATH_MAX];
    probe_path(probe, sizeof(probe));
    char missing[PATH_MAX], uid[16];
    snprintf(missing, sizeof(missing), "/tmp/jailer-bare-%d-missing", (int)getpid());
    snprintf(uid, sizeof(uid), "%d", (int)getuid());
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); abort(); }
    if (pid == 0) {
        setenv("SANDBOX_SECCOMP_ACTION", "errno", 1);
        char* const argv[] = { probe, missing, uid, (char*)mode, NULL };
        execv(probe, argv);
        _exit(127);
    }
    int status = 0;
    CHECK_RC(waitpid(pid, &status, 0) < 0 ? -1 : 0, "waitpid");
    return status;
}

// KILL_PROCESS: the child must die by SIGSYS. ERRNO (the explicit opt-in above):
// the child exits with EPERM from the fatal call. Anything else is a failure.
static void check_filter_death(int status, const char* what) {
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
        printf("[test] %s: PASS (SIGSYS)\n", what);
        return;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == EPERM) {
        printf("[test] %s: PASS (EPERM, SANDBOX_SECCOMP_ACTION=errno)\n", what);
        return;
    }
    if (WIFEXITED(status))
        fprintf(stderr, "FAIL %s: probe exit=%d\n", what, WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        fprintf(stderr, "FAIL %s: signal=%d\n", what, WTERMSIG(status));
    else
        fprintf(stderr, "FAIL %s: status=%d\n", what, status);
    abort();
}

static void test_seccomp_forbidden_syscall(void) {
    printf("[test] seccomp_forbidden_syscall...\n");
    fflush(stdout);
    check_filter_death(run_probe_bare((char*)"ptrace"), "seccomp_forbidden_syscall");
}

static void test_seccomp_ioctl_args(void) {
    printf("[test] seccomp_ioctl_args...\n");
    fflush(stdout);
    check_filter_death(run_probe_bare((char*)"ioctl"), "seccomp_ioctl_args");
}

// Positive guard: every permitted syscall — including the jailer's dup2() and
// (on x86_64) musl's arch_prctl() at process startup — must succeed after the
// filter is installed. A missing allow surfaces as SIGSYS (Release) or exit 13
// (Debug). This is the regression test for the x86_64 SIGSYS where the filter,
// originally copied from Firecracker's aarch64 policy, omitted dup2/arch_prctl.
static void test_seccomp_allowed_syscalls(void) {
    printf("[test] seccomp_allowed_syscalls...\n");
    fflush(stdout);
    int status = run_probe_bare((char*)"allowed");
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("[test] seccomp_allowed_syscalls: PASS\n");
        fflush(stdout);
        return;
    }
    if (WIFSIGNALED(status))
        fprintf(stderr, "FAIL seccomp_allowed_syscalls: killed by signal=%d "
                        "(a permitted syscall was denied)\n", WTERMSIG(status));
    else
        fprintf(stderr, "FAIL seccomp_allowed_syscalls: exit=%d\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    abort();
}

static void test_helpers(void) {
    printf("[test] helpers...\n");
    fflush(stdout);
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "/tmp/jailtest-%d", (int)getpid());
    char nested[PATH_MAX];
    snprintf(nested, sizeof(nested), "%s/a/b/c", tmp);
    CHECK_RC(mkdir_recursive(nested, 0755), "mkdir_recursive");
    struct stat st;
    CHECK_RC(stat(nested, &st) < 0 ? -1 : 0, "stat nested");
    char cg[PATH_MAX];
    snprintf(cg, sizeof(cg), "%s/cgroup.procs", tmp);
    int fd = open(cg, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) abort();
    close(fd);
    CHECK_RC(write_cgroup_procs(cg, getpid()), "write_cgroup_procs");
    char buf[32] = {0};
    fd = open(cg, O_RDONLY);
    if (fd < 0) abort();
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0 || atoi(buf) != (int)getpid()) abort();
    if (write_cgroup_procs("/nonexistent/cgroup.procs", getpid()) == 0) abort();
    if (mkdir_recursive(NULL, 0755) == 0) abort();
    if (geteuid() != 0 && mount_jail_devices(tmp) == 0) abort();  // no privs: must fail
    printf("[test] helpers: PASS\n");
    fflush(stdout);
}

// --- privileged sequence: userns + full spawn_jailed + static probe ---

static int write_file(const char* path, const char* content) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    size_t n = strlen(content);
    ssize_t w = write(fd, content, n);
    close(fd);
    return (w == (ssize_t)n) ? 0 : -1;
}

static int copy_file(const char* src, const char* dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out < 0) { close(in); return -1; }
    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        if (write(out, buf, (size_t)n) != n) { close(in); close(out); return -1; }
    }
    close(in);
    close(out);
    return (n < 0) ? -1 : 0;
}

// Runs spawn_jailed + probe inside a userns. A (this process) writes B's id
// maps from the outside, the only pattern the kernel accepts. Root maps the
// full range (real uid-drop to 65534); non-root maps itself once and runs a
// uid-0 variant (chroot still real). _exit(SKIP_CODE) when mapping is denied.
static void userns_sequence_child(const char* jail, const char* probe_in_jail,
                                  const char* sentinel, int out_fd) {
    int notify[2], go[2];
    if (pipe(notify) < 0 || pipe(go) < 0) _exit(2);
    pid_t b = fork();
    if (b < 0) _exit(2);
    if (b == 0) {
        // B: enter userns, wait for A's mapping, run the jailed probe.
        close(notify[0]);
        close(go[1]);
        if (unshare(CLONE_NEWUSER) < 0) {
            (void)write(notify[1], "x", 1);
            _exit(SKIP_CODE);
        }
        if (write(notify[1], "x", 1) != 1) _exit(2);
        char cmd = 0;
        if (read(go[0], &cmd, 1) != 1) _exit(2);
        if (cmd == 'S') _exit(SKIP_CODE);
        if (cmd != 'G' && cmd != 'U') _exit(2);
        // Map fullness comes from A: B is uid 0 in-ns either way.
        // 'G' = full map, real uid-drop to 65534; 'U' = single-map variant.
        uid_t juid = (cmd == 'G') ? 65534 : 0;
        char juid_s[16], marker[64];
        snprintf(juid_s, sizeof(juid_s), "%d", (int)juid);
        snprintf(marker, sizeof(marker), "PROBE ok uid=%d", (int)juid);
        int pipefd[2];
        if (pipe(pipefd) < 0) _exit(2);
        pid_t inner = fork();
        if (inner < 0) _exit(2);
        if (inner == 0) {
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]);  // stdout now holds the only write end in this process
            jailer_config_t cfg = { .jailer_uid = juid, .jailer_gid = juid,
                                    .cgroup_path = NULL };
            char* const argv[] = { (char*)probe_in_jail, (char*)sentinel, juid_s,
                                   (char*)"ptrace", NULL };
            // Same steps as production, seccomp deferred to the probe (a static
            // binary cannot start under the filter: arch_prctl is not whitelisted).
            pid_t jailed = spawn_jailed(jail, &cfg, probe_in_jail, argv, false, false,
                                          NULL, NULL);
            int st = 0;
            if (jailed < 0 || waitpid(jailed, &st, 0) < 0) _exit(3);
            close(STDOUT_FILENO);  // last writer (grandchild is dead) -> EOF
            char out[256] = {0};
            size_t off = 0;
            ssize_t n;
            while (off < sizeof(out) - 1 &&
                   (n = read(pipefd[0], out + off, sizeof(out) - 1 - off)) > 0)
                off += (size_t)n;
            if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS) {
                if (!strstr(out, marker)) _exit(5);
                _exit(0);
            }
            if (WIFEXITED(st) && WEXITSTATUS(st) != 0) {
                // Diagnose from inside the same user namespace the jailer child
                // had: if it could not create the jail, say why, instead of
                // relaying a bare step number.
                int mk = mkdir(jail, 0700);
                int me = errno;
                fprintf(stderr,
                        "[jailer-test] probe/jailer exit=%d; userns mkdir(%s)=%d "
                        "errno=%d (%s)\n",
                        WEXITSTATUS(st), jail, mk, mk < 0 ? me : 0,
                        mk < 0 ? strerror(me) : "ok");
                if (out[0]) fprintf(stderr, "[jailer-test] probe output: %s\n", out);
            }
            if (WIFEXITED(st)) _exit(100 + WEXITSTATUS(st));  // probe/child exit code
            _exit(200 + WTERMSIG(st));  // unexpected signal
        }
        close(pipefd[1]);
        int st = 0;
        if (waitpid(inner, &st, 0) < 0) _exit(2);
        if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
            const char msg[] = "SEQUENCE ok\n";
            (void)write(out_fd, msg, sizeof(msg) - 1);
            _exit(0);
        }
        // Relay inner's diagnostic code directly.
        if (WIFEXITED(st)) _exit(WEXITSTATUS(st));
        _exit(6);
    }
    // A: map B from the outside, then release it.
    close(notify[1]);
    close(go[0]);
    char c = 0;
    if (read(notify[0], &c, 1) != 1) _exit(2);
    char procdir[64], map[64], path[96];
    snprintf(procdir, sizeof(procdir), "/proc/%d", (int)b);
    bool full = (geteuid() == 0);
    if (full)
        snprintf(map, sizeof(map), "0 0 65536");
    else
        snprintf(map, sizeof(map), "0 %d 1", (int)geteuid());
    snprintf(path, sizeof(path), "%s/setgroups", procdir);
    int ok = (write_file(path, "deny") == 0);
    snprintf(path, sizeof(path), "%s/uid_map", procdir);
    ok = ok && (write_file(path, map) == 0);
    if (!full) snprintf(map, sizeof(map), "0 %d 1", (int)getegid());
    snprintf(path, sizeof(path), "%s/gid_map", procdir);
    ok = ok && (write_file(path, map) == 0);
    (void)write(go[1], !ok ? "S" : (full ? "G" : "U"), 1);
    int st = 0;
    if (waitpid(b, &st, 0) < 0) _exit(2);
    if (WIFEXITED(st)) _exit(WEXITSTATUS(st));  // relay B's code (0, 77=SKIP, or step id)
    _exit(7);
}

// Ubuntu 24.04 restricts unprivileged user namespaces via AppArmor
// (kernel.apparmor_restrict_unprivileged_userns=1): unshare(CLONE_NEWUSER) may
// still succeed, but chroot() is then denied, so the unprivileged jailer
// sequence cannot run. Detect that and SKIP rather than fail. As root the
// restriction does not apply, so the full sequence runs for real.
static bool unprivileged_userns_restricted(void) {
    if (geteuid() == 0) return false;
    FILE* f = fopen("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "r");
    if (!f) return false;
    char b[8] = {0};
    size_t n = fread(b, 1, sizeof(b) - 1, f);
    fclose(f);
    return n > 0 && b[0] == '1';
}

static void test_jailer_sequence(void) {
    printf("[test] jailer_sequence...\n");
    fflush(stdout);
    // The sequence asserts the *default* filter: a forbidden syscall must kill
    // the process (SIGSYS). Keep an inherited opt-in from changing that.
    unsetenv("SANDBOX_SECCOMP_ACTION");
    if (unprivileged_userns_restricted()) {
        printf("[test] jailer_sequence: SKIP (unprivileged user namespaces are "
               "restricted on this host, e.g. AppArmor; run as root for full "
               "coverage)\n");
        fflush(stdout);
        return;
    }
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "/tmp/jailseq-%d", (int)getpid());
    CHECK_RC(mkdir_recursive(tmp, 0755), "tmpdir");
    char jail[PATH_MAX], sentinel[PATH_MAX], probe_src[PATH_MAX], probe_dst[PATH_MAX];
    snprintf(jail, sizeof(jail), "%s/j/vmid-001", tmp);
    snprintf(sentinel, sizeof(sentinel), "%s/sentinel", tmp);
    CHECK_RC(mkdir_recursive(jail, 0755), "jail dir");
    probe_path(probe_src, sizeof(probe_src));
    snprintf(probe_dst, sizeof(probe_dst), "%s/probe", jail);
    CHECK_RC(copy_file(probe_src, probe_dst), "copy probe");
    CHECK_RC(chmod(probe_dst, 0755), "chmod probe");
    int fd = open(sentinel, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) abort();
    if (write(fd, "secret", 6) != 6) abort();
    close(fd);

    pid_t pid = fork();
    if (pid < 0) abort();
    if (pid == 0) {
        userns_sequence_child(jail, "/probe", sentinel, STDOUT_FILENO);
        _exit(6);
    }
    int status = 0;
    CHECK_RC(waitpid(pid, &status, 0) < 0 ? -1 : 0, "waitpid");
    if (WIFEXITED(status) && WEXITSTATUS(status) == SKIP_CODE) {
        printf("[test] jailer_sequence: SKIP (no userns id-mapping in this environment)\n");
        fflush(stdout);
        return;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("[test] jailer_sequence: PASS\n");
        fflush(stdout);
        return;
    }
    fprintf(stderr, "FAIL jailer_sequence: status=%d", status);
    if (WIFEXITED(status)) {
        int c = WEXITSTATUS(status);
        if (c >= 100 && c < 200)
            fprintf(stderr, " (jailer step or probe exit %d)", c - 100);
        else if (c >= 200)
            fprintf(stderr, " (killed by signal %d)", c - 200);
        else
            fprintf(stderr, " (harness exit %d)", c);
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, " (killed by signal %d)", WTERMSIG(status));
    }
    fprintf(stderr, "\n");
    abort();
}

int main(void) {
    test_seccomp_forbidden_syscall();
    test_seccomp_ioctl_args();
    test_seccomp_allowed_syscalls();
    test_helpers();
    test_jailer_sequence();
    printf("ALL JAILER TESTS PASSED\n");
    return 0;
}
