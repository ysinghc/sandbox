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
// step that follows per LLD order); the uid transition clears the rest.
int drop_capabilities(void) {
    struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2];
    if (syscall(SYS_capget, &hdr, data) < 0) return -1;

    const uint32_t keep = (1u << CAP_SETUID) | (1u << CAP_SETGID);
    data[0].effective &= keep;
    data[0].permitted &= keep;
    data[0].inheritable = 0;
    data[1].effective = data[1].permitted = data[1].inheritable = 0;
    if (syscall(SYS_capset, &hdr, data) < 0) return -1;

    for (int c = 0; c <= CAP_LAST_CAP; c++) {
        if (prctl(PR_CAPBSET_DROP, c, 0, 0, 0) < 0 && errno != EINVAL) return -1;
    }
    return 0;
}

pid_t spawn_jailed(const char* jail_root, const jailer_config_t* config,
                   const char* bin, char* const argv[],
                   bool mount_devices, bool apply_seccomp) {
    if (!jail_root || !config || !bin) { errno = EINVAL; return -1; }
    pid_t pid = fork();
    if (pid != 0) return pid;  // Parent returns child PID

    // Child becomes the Jailer, then execs. Never returns; _exit(127) on error.
    if (mkdir_recursive(jail_root, 0755) < 0) _exit(127);
    if (mount_devices && mount_jail_devices(jail_root) < 0) _exit(127);
    if (config->cgroup_path && write_cgroup_procs(config->cgroup_path, getpid()) < 0)
        _exit(127);
    if (chroot(jail_root) < 0) _exit(127);
    if (chdir("/") < 0) _exit(127);
    if (drop_capabilities() < 0) _exit(127);
    if (setgid(config->jailer_gid) < 0) _exit(127);
    if (setuid(config->jailer_uid) < 0) _exit(127);
    if (apply_seccomp && apply_seccomp_filter() < 0) _exit(127);
    execve(bin, argv, environ);
    _exit(127);  // exec failed
}

int spawn_firecracker_jailed(const char* vm_id, const jailer_config_t* config) {
    if (!vm_id || !config) { errno = EINVAL; return -1; }
    char jail_root[PATH_MAX];
    snprintf(jail_root, sizeof(jail_root), "/var/lib/sandbox-engine/jail/%s", vm_id);
    char* const argv[] = { (char*)"/firecracker", NULL };
    return spawn_jailed(jail_root, config, "/firecracker", argv, true, true);
}
