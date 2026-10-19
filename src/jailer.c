// SPDX-License-Identifier: GPL-2.0-only
// Jailer (§5.4): confine and privilege-drop the VMM process.
// Order: setup (mkdir, device mounts) → cgroup → chroot → caps →
// setuid/setgid → seccomp → exec.

#include "jailer.h"
#include "sandbox_seccomp.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

extern char** environ;

// The jailed child cannot return an error, and a bare _exit(N) leaves an
// operator (or a CI log) with a number and no reason — which is exactly how a
// "step 1 failed" report cost a debugging cycle. Say which step failed and why
// on stderr, which is still the inherited daemon/CI log at this point.
static void jail_fail(int step) {
    int e = errno;
    fprintf(stderr, "[jailer] step %d failed: errno=%d (%s)\n", step, e,
            strerror(e));
    _exit(step);
}
#define JAIL_FAIL(step) jail_fail(step)

int mkdir_recursive(const char* path, unsigned mode) {
    if (!path || !*path) { errno = EINVAL; return -1; }
    char tmp[PATH_MAX];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) { errno = ENAMETOOLONG; return -1; }
    strcpy(tmp, path);
    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -1;
    return 0;
}

static int touch(const char* path) {
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

static int copy_file(const char* src, const char* dst, unsigned mode) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out < 0) { close(in); return -1; }
    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w < 0) {
                if (errno == EINTR) continue;
                close(in);
                close(out);
                return -1;
            }
            off += w;
        }
    }
    close(in);
    if (close(out) < 0) return -1;
    return (n < 0) ? -1 : 0;
}

// Bind-mount a host file at a jail path (target created first).
static int bind_file(const char* src, const char* dst) {
    if (touch(dst) < 0) {
        fprintf(stderr, "[jailer] bind: cannot create target %s: errno=%d (%s)\n",
                dst, errno, strerror(errno));
        return -1;
    }
    if (mount(src, dst, NULL, MS_BIND, NULL) < 0) {
        // ENOENT from mount() means the *source* is missing, but "step 6
        // failed: ENOENT" alone does not say which of five binds, or which
        // path -- so name both and say whether the source is there.
        struct stat sst;
        fprintf(stderr,
                "[jailer] bind %s -> %s failed: errno=%d (%s); source %s\n", src,
                dst, errno, strerror(errno),
                stat(src, &sst) == 0 ? "exists" : "MISSING");
        return -1;
    }
    return 0;
}

static int jail_bind_files(const char* jail_root, const jail_files_t* files,
                             uid_t uid, gid_t gid) {
    char dst[PATH_MAX];
    if (files->kernel_path) {
        snprintf(dst, sizeof(dst), "%s/vmlinux", jail_root);
        if (bind_file(files->kernel_path, dst) < 0) return -1;
    }
    if (files->rootfs_path) {
        snprintf(dst, sizeof(dst), "%s/rootfs.ext4", jail_root);
        if (bind_file(files->rootfs_path, dst) < 0) return -1;
    }
    if (files->snap_state_src) {
        snprintf(dst, sizeof(dst), "%s/vmstate", jail_root);
        if (bind_file(files->snap_state_src, dst) < 0) return -1;
    }
    if (files->snap_mem_src) {
        snprintf(dst, sizeof(dst), "%s/memory.snap", jail_root);
        if (bind_file(files->snap_mem_src, dst) < 0) return -1;
    }
    if (files->workspace_path) {
        // The workspace is the one *writable* file we hand the VMM, so unlike
        // the read-only binds above it must be owned by the jailed uid before
        // the mount: a bind propagates the source inode's DAC attributes, and
        // Firecracker opens this one read-write. 0600 keeps every other local
        // user out; the session store is also 0700.
        snprintf(dst, sizeof(dst), "%s" JAIL_WORKSPACE_PATH, jail_root);
        if (chown(files->workspace_path, uid, gid) < 0) {
            fprintf(stderr, "[jailer] workspace chown(%s): errno=%d (%s)\n",
                    files->workspace_path, errno, strerror(errno));
            return -1;
        }
        if (chmod(files->workspace_path, 0600) < 0) {
            fprintf(stderr, "[jailer] workspace chmod(%s): errno=%d (%s)\n",
                    files->workspace_path, errno, strerror(errno));
            return -1;
        }
        if (bind_file(files->workspace_path, dst) < 0) return -1;
    }
    if (files->out_dir) {
        snprintf(dst, sizeof(dst), "%s/out", jail_root);
        if (mkdir_recursive(dst, 0755) < 0) return -1;
        // Ownership AND mode must be set on the SOURCE before bind-mounting.
        // A bind mount propagates the source inode's DAC attributes into the
        // jail; chown/chmod after mount on the mount point is a no-op for
        // directory bind mounts on the same fs (it re-runs on the source inode
        // which is correct but redundant, and provides no fix if omitted here).
        // chmod 0700: jailed uid needs rwx for itself; root can always access.
        if (chown(files->out_dir, uid, gid) < 0) return -1;
        if (chmod(files->out_dir, 0700) < 0) return -1;
        if (mount(files->out_dir, dst, NULL, MS_BIND, NULL) < 0) return -1;
    }
    // /dev/userfaultfd for kernels exposing it (6.1+); absent is fine.
    // Fresh node like kvm/tun (bind would keep root-only perms).
    struct stat ust;
    if (stat("/dev/userfaultfd", &ust) == 0 && S_ISCHR(ust.st_mode)) {
        snprintf(dst, sizeof(dst), "%s/dev/userfaultfd", jail_root);
        unlink(dst);
        if (mknod(dst, S_IFCHR | 0600, ust.st_rdev) == 0)
            chown(dst, uid, gid);
    }
    return 0;
}

int make_jail_devices(const char* jail_root, uid_t uid, gid_t gid) {
    // Fresh device nodes (not bind mounts): the jail uid needs to OPEN
    // /dev/kvm and /dev/net/tun, but bind-mounting preserves the host's
    // root-owned modes. mknod+chown gives access without touching host perms.
    char devdir[PATH_MAX], netdir[PATH_MAX];
    snprintf(devdir, sizeof(devdir), "%s/dev", jail_root);
    snprintf(netdir, sizeof(netdir), "%s/dev/net", jail_root);
    if (mkdir_recursive(netdir, 0755) < 0) return -1;
    const struct { const char* src; const char* rel; } devs[] = {
        { "/dev/kvm", "dev/kvm" },
        { "/dev/net/tun", "dev/net/tun" },
    };
    for (size_t i = 0; i < sizeof(devs) / sizeof(devs[0]); i++) {
        struct stat st;
        if (stat(devs[i].src, &st) < 0) return -1;
        if (!S_ISCHR(st.st_mode)) { errno = ENODEV; return -1; }
        char dst[PATH_MAX];
        snprintf(dst, sizeof(dst), "%s/%s", jail_root, devs[i].rel);
        unlink(dst);
        if (mknod(dst, S_IFCHR | 0600, st.st_rdev) < 0) return -1;
        if (chown(dst, uid, gid) < 0) return -1;
    }
    return 0;
}

// Legacy entry point (bind-mount variant); kept for the unit test's
// fail-unprivileged contract. Production path uses make_jail_devices.
int mount_jail_devices(const char* jail_root) {
    char dst[PATH_MAX], devdir[PATH_MAX], netdir[PATH_MAX];
    snprintf(devdir, sizeof(devdir), "%s/dev", jail_root);
    snprintf(netdir, sizeof(netdir), "%s/dev/net", jail_root);
    if (mkdir_recursive(netdir, 0755) < 0) return -1;

    snprintf(dst, sizeof(dst), "%s/dev/kvm", jail_root);
    if (touch(dst) < 0) return -1;
    if (mount("/dev/kvm", dst, NULL, MS_BIND, NULL) < 0) return -1;

    snprintf(dst, sizeof(dst), "%s/dev/net/tun", jail_root);
    if (touch(dst) < 0) return -1;
    if (mount("/dev/net/tun", dst, NULL, MS_BIND, NULL) < 0) return -1;
    return 0;
}

// cgroup_path is the target cgroup's cgroup.procs file.
int write_cgroup_procs(const char* cgroup_path, pid_t pid) {
    if (!cgroup_path) { errno = EINVAL; return -1; }
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", (int)pid);
    int fd = open(cgroup_path, O_WRONLY);
    if (fd < 0) return -1;
    size_t n = strlen(buf);
    ssize_t w = write(fd, buf, n);
    close(fd);
    return (w == (ssize_t)n) ? 0 : -1;
}

// Drops everything except CAP_SETUID/CAP_SETGID (needed for the setuid/setgid
// step that follows per LLD order) and CAP_SYS_PTRACE (Firecracker must create
// UFFD objects; unprivileged_userfaultfd=0 here. Safe: our seccomp filter
// blocks ptrace() itself, so the cap only opens the userfaultfd gate).
// The uid transition clears the rest; file caps re-grant SYS_PTRACE at exec.
int drop_capabilities(void) {
    const uint32_t keep = (1u << CAP_SETUID) | (1u << CAP_SETGID) |
                          (1u << CAP_SYS_PTRACE);
    for (int c = 0; c <= CAP_LAST_CAP; c++) {
        if (c < 32 && ((keep >> c) & 1u)) continue;  // retained
        if (prctl(PR_CAPBSET_DROP, c, 0, 0, 0) < 0 && errno != EINVAL) return -1;
    }

    struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2];
    if (syscall(SYS_capget, &hdr, data) < 0) return -1;

    data[0].effective &= keep;
    data[0].permitted &= keep;
    data[0].inheritable = 0;
    data[1].effective = data[1].permitted = data[1].inheritable = 0;
    if (syscall(SYS_capset, &hdr, data) < 0) return -1;
    return 0;
}

// Re-grant CAP_SYS_PTRACE as an *ambient* capability after the uid transition.
// Firecracker needs it to create UFFD objects (unprivileged_userfaultfd=0).
// Ambient caps are carried across execve() even when PR_SET_NO_NEW_PRIVS is
// set (unlike setuid/file caps, which no_new_privs silently ignores), so this
// replaces the previous security.capability xattr delivery and lets the whole
// daemon run with no_new_privs.
static int raise_ambient_sys_ptrace(void) {
    struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2];
    if (syscall(SYS_capget, &hdr, data) < 0) return -1;
    data[0].effective |= (1u << CAP_SYS_PTRACE);
    data[0].permitted |= (1u << CAP_SYS_PTRACE);
    data[0].inheritable |= (1u << CAP_SYS_PTRACE);
    data[1].effective = data[1].permitted = data[1].inheritable = 0;
    if (syscall(SYS_capset, &hdr, data) < 0) return -1;
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_PTRACE, 0, 0) < 0)
        return -1;
    return 0;
}

pid_t spawn_jailed(const char* jail_root, const jailer_config_t* config,
                   const char* bin, char* const argv[],
                   bool mount_devices, bool apply_seccomp,
                   const jail_files_t* files, const char* serial_log) {
    if (!jail_root || !config || !bin) { errno = EINVAL; return -1; }
    pid_t pid = fork();
    if (pid != 0) return pid;  // Parent returns child PID

    // Child becomes the Jailer, then execs. Never returns; _exit(N) on error:
    // 1=mkdir, 2=chown, 3=copy_fc, 5=devices, 6=bind_files,
    // 7=cgroup, 8=serial_open, 9=chroot, 10=chdir, 11=caps, 12=setgid,
    // 13=setuid, 16=ambient_cap, 14=seccomp, 15=execve_fail
    if (mkdir_recursive(jail_root, 0700) < 0) JAIL_FAIL(1);
    // The jailed uid must create sockets/files at the jail top level
    // (api.sock, uffd.sock). chown normally; 0777 fallback where chown is
    // unsupported (e.g. 9p test mounts); fatal only if both fail.
    if (chown(jail_root, config->jailer_uid, config->jailer_gid) < 0 &&
        chmod(jail_root, 0777) < 0)
        JAIL_FAIL(2);
    if (files && files->firecracker_bin) {
        char dst[PATH_MAX];
        snprintf(dst, sizeof(dst), "%s/firecracker", jail_root);
        if (copy_file(files->firecracker_bin, dst, 0755) < 0) JAIL_FAIL(3);
    }
    if (mount_devices && make_jail_devices(jail_root, config->jailer_uid,
                                                 config->jailer_gid) < 0)
        JAIL_FAIL(5);
    if (files && jail_bind_files(jail_root, files, config->jailer_uid,
                                  config->jailer_gid) < 0)
        JAIL_FAIL(6);
    if (config->cgroup_path && write_cgroup_procs(config->cgroup_path, getpid()) < 0)
        JAIL_FAIL(7);
    int serial_fd = -1;
    if (serial_log) {
        // Opened pre-chroot on the host path and dup2'd post-setuid. The fd
        // is already write-capable (checked at open), so the chown is only
        // ownership hygiene and best-effort (9p mounts reject chown).
        serial_fd = open(serial_log, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (serial_fd < 0) JAIL_FAIL(8);
        fchown(serial_fd, config->jailer_uid, config->jailer_gid);
    }
    if (chroot(jail_root) < 0) JAIL_FAIL(9);
    if (chdir("/") < 0) JAIL_FAIL(10);
    if (drop_capabilities() < 0) JAIL_FAIL(11);
    // Retain the permitted set across the uid transition so CAP_SYS_PTRACE can
    // be re-raised as ambient below.
    if (prctl(PR_SET_KEEPCAPS, 1) < 0) JAIL_FAIL(11);
    if (setgid(config->jailer_gid) < 0) JAIL_FAIL(12);
    if (setuid(config->jailer_uid) < 0) JAIL_FAIL(13);
    if (raise_ambient_sys_ptrace() < 0) JAIL_FAIL(16);
    if (apply_seccomp && apply_seccomp_filter() < 0) JAIL_FAIL(14);
    if (serial_fd >= 0) {
        dup2(serial_fd, STDOUT_FILENO);
        dup2(serial_fd, STDERR_FILENO);
        if (serial_fd != STDOUT_FILENO && serial_fd != STDERR_FILENO)
            close(serial_fd);
    }
    execve(bin, argv, environ);
    JAIL_FAIL(15);  // exec failed
}

int spawn_firecracker_jailed(const char* vm_id, const jailer_config_t* config) {
    if (!vm_id || !config) { errno = EINVAL; return -1; }
    char jail_root[PATH_MAX];
    snprintf(jail_root, sizeof(jail_root), "/var/lib/sandbox-engine/jail/%s", vm_id);
    char* const argv[] = { (char*)"/firecracker", NULL };
    return spawn_jailed(jail_root, config, "/firecracker", argv, true, true,
                        NULL, NULL);
}
