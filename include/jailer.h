#ifndef JAILER_H
#define JAILER_H

#include <stdint.h>
#include <sys/types.h>

typedef struct {
    uid_t jailer_uid;       // e.g., 65534
    gid_t jailer_gid;       // e.g., 65534
    const char* cgroup_path;
} jailer_config_t;

int spawn_firecracker_jailed(const char* vm_id, const jailer_config_t* config);
int mkdir_recursive(const char* path, unsigned mode);
int mount_jail_devices(const char* jail_root);
int write_cgroup_procs(const char* cgroup_path, pid_t pid);
int drop_capabilities(void);

#endif // JAILER_H
