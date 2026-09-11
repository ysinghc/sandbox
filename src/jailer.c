#include "jailer.h"
#include <stddef.h>

int spawn_firecracker_jailed(const char* vm_id, const jailer_config_t* config) {
    (void)vm_id; (void)config;
    return 0;
}

int mkdir_recursive(const char* path, unsigned mode) {
    (void)path; (void)mode;
    return 0;
}

int mount_jail_devices(const char* jail_root) {
    (void)jail_root;
    return 0;
}

int write_cgroup_procs(const char* cgroup_path, pid_t pid) {
    (void)cgroup_path; (void)pid;
    return 0;
}

int drop_capabilities(void) {
    return 0;
}
