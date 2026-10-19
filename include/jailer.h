// SPDX-License-Identifier: GPL-2.0-only
#ifndef JAILER_H
#define JAILER_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    uid_t jailer_uid;       // e.g., 65534
    gid_t jailer_gid;       // e.g., 65534
    const char* cgroup_path;  // cgroup.procs file, or NULL to skip placement
} jailer_config_t;

// Jail-view path of the writable workspace volume (#23). Fixed because the
// guest kernel is told about this device when the template is captured, and a
// restore may not move it.
#define JAIL_WORKSPACE_PATH "/workspace.ext4"

// Optional jail contents. NULL fields are skipped. Jail-view paths are fixed
// (/firecracker, /vmlinux, /rootfs.ext4, /vmstate, /memory.snap,
// /workspace.ext4) so snapshot state stays valid across template/restore jails.
typedef struct {
    const char* firecracker_bin;  // host path, copied to $jail/firecracker
    const char* kernel_path;      // host path, bound at $jail/vmlinux
    const char* rootfs_path;      // host path, bound at $jail/rootfs.ext4
    const char* snap_state_src;   // host path, bound at $jail/vmstate (restore)
    const char* snap_mem_src;     // host path, bound at $jail/memory.snap (restore)
    const char* out_dir;          // host dir, bound at $jail/out (template capture)
    // Host path bound at $jail/workspace.ext4. Unlike everything else here this
    // one is writable (the guest's /workspace), so it is chowned to the jailed
    // uid before the mount. NULL for templates captured without a workspace.
    const char* workspace_path;
} jail_files_t;

int spawn_firecracker_jailed(const char* vm_id, const jailer_config_t* config);

// Testable core: explicit jail root/binary plus mount/seccomp toggles.
// Production path (above) pins the canonical root, /firecracker, both on.
pid_t spawn_jailed(const char* jail_root, const jailer_config_t* config,
                   const char* bin, char* const argv[],
                   bool mount_devices, bool apply_seccomp,
                   const jail_files_t* files, const char* serial_log);
int mkdir_recursive(const char* path, unsigned mode);
int mount_jail_devices(const char* jail_root);  // legacy bind variant (tests)
int make_jail_devices(const char* jail_root, uid_t uid, gid_t gid);
int write_cgroup_procs(const char* cgroup_path, pid_t pid);
int drop_capabilities(void);

#endif // JAILER_H
