// CTest FIXTURES_SETUP: build the "e2e" template once per build dir.
// SKIPs (exit 0, no READY marker) without root/KVM/assets; hard-fails only
// on real errors so consumers never run against half-built state.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "snapshot_manager.h"

#define ASSET_KERNEL "/opt/sandbox-assets/vmlinux"
#define ASSET_ROOTFS "/opt/sandbox-assets/rootfs.ext4"

static int have_file(const char* p) {
    struct stat st;
    return stat(p, &st) == 0;
}

int main(void) {
    const char* snap_root = getenv("SANDBOX_SNAPSHOT_ROOT");
    if (!snap_root || !*snap_root) {
        fprintf(stderr, "SKIP template setup: no SANDBOX_SNAPSHOT_ROOT\n");
        return 0;
    }
    if (geteuid() != 0 || access("/dev/kvm", R_OK | W_OK) < 0 ||
        !have_file(ASSET_KERNEL) || !have_file(ASSET_ROOTFS)) {
        fprintf(stderr, "SKIP template setup: need root + /dev/kvm + assets\n");
        return 0;
    }
    // Detach bind mounts leaked by killed runs, then clear stale state.
    const char* jail_root = getenv("SANDBOX_JAIL_ROOT");
    char clean[8192];
    snprintf(clean, sizeof(clean),
             "for m in $(mount | grep -F '%s' | awk '{print $3}'); do "
             "umount -l \"$m\" 2>/dev/null; done; "
             "for m in $(mount | grep -F '%s' | awk '{print $3}'); do "
             "umount -l \"$m\" 2>/dev/null; done; true",
             snap_root, jail_root ? jail_root : "/nonexistent-jail-root");
    if (system(clean) != 0) return 1;
    template_config_t cfg = { .memory_mib = 128, .vcpu_count = 1,
                              .kernel_path = ASSET_KERNEL,
                              .rootfs_path = ASSET_ROOTFS,
                              .ready_marker = "SANDBOX-READY" };
    // Rebuild unconditionally so consumers never use a stale template.
    char stale[4096], stale_ready[4096];
    snprintf(stale, sizeof(stale), "%s/e2e", snap_root);
    snprintf(stale_ready, sizeof(stale_ready), "%s/READY", snap_root);
    char rm[8192];
    snprintf(rm, sizeof(rm), "rm -rf %s %s", stale, stale_ready);
    if (system(rm) != 0) return 1;
    if (create_snapshot_template("e2e", &cfg) < 0) {
        fprintf(stderr, "FAIL template setup: create_snapshot_template\n");
        return 1;
    }
    char ready[4096];
    snprintf(ready, sizeof(ready), "%s/READY", snap_root);
    FILE* f = fopen(ready, "w");
    if (!f) return 1;
    fputs("e2e\n", f);
    fclose(f);
    printf("template setup: e2e ready\n");
    return 0;
}
