// SPDX-License-Identifier: GPL-2.0-only
// CTest FIXTURES_SETUP: build the "e2e" template once per build dir.
// SANDBOX_TEMPLATE_NAME overrides the name (default "e2e"); the daemon must be
// configured to restore the same name. SKIPs (exit 0, no READY marker) without
// root/KVM/assets; hard-fails only on real errors so consumers never run
// against half-built state.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sandbox_fs.h"
#include "snapshot_manager.h"
#include "template_store.h"

#define ASSET_KERNEL "/opt/sandbox-assets/vmlinux"
#define ASSET_ROOTFS "/opt/sandbox-assets/rootfs.ext4"

// Same overrides as scripts/benchmark.sh, so CI can build and use its own guest
// image (scripts/build-custom-rootfs.sh) instead of the operator's asset.
//
// <env>_DEFAULT is what ctest bakes in at configure time (tests/CMakeLists.txt).
// It is a *fallback*: an explicit runtime value must win, because the Debian
// suite runs the same build dir with `sudo env SANDBOX_ROOTFS=...`.
static const char* asset_path(const char* env, const char* def_env,
                              const char* fallback) {
    const char* v = getenv(env);
    if (v && *v) return v;
    v = getenv(def_env);
    return (v && *v) ? v : fallback;
}

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
    const char* asset_kernel =
        asset_path("SANDBOX_KERNEL", "SANDBOX_KERNEL_DEFAULT", ASSET_KERNEL);
    const char* asset_rootfs =
        asset_path("SANDBOX_ROOTFS", "SANDBOX_ROOTFS_DEFAULT", ASSET_ROOTFS);
    if (geteuid() != 0 || access("/dev/kvm", R_OK | W_OK) < 0 ||
        !have_file(asset_kernel) || !have_file(asset_rootfs)) {
        fprintf(stderr, "SKIP template setup: need root + /dev/kvm + assets\n");
        return 0;
    }
    // Record the guest image this run actually used. The override can be lost by
    // a launcher that resets the environment (sudo on a non-root runner did), and
    // the suite would then run happily against the operator's older image -- so
    // the privileged workflow asserts on this line.
    printf("[tmpl] assets: kernel=%s rootfs=%s\n", asset_kernel, asset_rootfs);
    fflush(stdout);
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
    // The test root must *start* clean. This suite is re-run on the same runner,
    // and what lives under here is deliberately durable (a session volume
    // outlives its VM by design, and the template is rebuilt only with an
    // explicit rm below), so an un-wiped root hands this run the previous run's
    // session volumes. That is not hypothetical: a session image written by the
    // older, broken restore path was reused as this run's "empty" volume, and
    // the guest then failed to mount it. tests/CMakeLists.txt passes
    // SANDBOX_TEST_ROOT as the common parent of the snapshot, jail and workspace
    // roots; refuse to act on anything that is not a real subdirectory.
    const char* test_root = getenv("SANDBOX_TEST_ROOT");
    if (test_root && *test_root && strlen(test_root) > 1 &&
        strcmp(test_root, "/") != 0) {
        if (sandbox_rm_rf(test_root) < 0) {
            fprintf(stderr, "FAIL template setup: cannot clear %s\n", test_root);
            return 1;
        }
        fprintf(stderr, "[tmpl] cleared test root %s\n", test_root);
    }
    // Default "e2e" keeps the CTest fixture unchanged; scripts/benchmark.sh
    // sets SANDBOX_TEMPLATE_NAME so the stamped template matches the name the
    // daemon is told to restore (otherwise the daemon finds no such template
    // and silently restores nothing).
    const char* tmpl = getenv("SANDBOX_TEMPLATE_NAME");
    if (!tmpl || !*tmpl) tmpl = "e2e";
    // #23: the fixture template carries a session workspace so the privileged
    // tests exercise a real /workspace mount and the persistence path. The size
    // is deliberately small: the volume is sparse, and this only has to be big
    // enough to hold the test's files.
    template_config_t cfg = { .memory_mib = 128, .vcpu_count = 1,
                              .kernel_path = asset_kernel,
                              .rootfs_path = asset_rootfs,
                              .ready_marker = "SANDBOX-READY",
                              .workspace_size_mb = 64 };
    // Rebuild unconditionally so consumers never use a stale template.
    char stale[4096], stale_ready[4096];
    snprintf(stale, sizeof(stale), "%s/%s", snap_root, tmpl);
    snprintf(stale_ready, sizeof(stale_ready), "%s/READY", snap_root);
    char rm[8192];
    snprintf(rm, sizeof(rm), "rm -rf %s %s", stale, stale_ready);
    if (system(rm) != 0) return 1;
    // Build it the way an operator does (#25): staged, then published into the
    // content-addressed store, so every consumer of this fixture -- the daemon
    // and the whole privileged suite -- restores through the name symlink.
    char staged[128];
    snprintf(staged, sizeof(staged), ".build-%s", tmpl);
    char stale_stage[4096];
    snprintf(stale_stage, sizeof(stale_stage), "%s/%s", snap_root, staged);
    chmod(stale_stage, 0755);
    sandbox_rm_rf(stale_stage);
    if (create_snapshot_template(staged, &cfg) < 0) {
        fprintf(stderr, "FAIL template setup: create_snapshot_template\n");
        return 1;
    }
    char digest[TSTORE_DIGEST_LEN + 1];
    if (tstore_publish(tmpl, staged, NULL, digest) < 0) {
        fprintf(stderr, "FAIL template setup: tstore_publish: %s\n", strerror(errno));
        return 1;
    }
    printf("[tmpl] published %s as %s\n", tmpl, digest);
    if (tstore_verify(tmpl) < 0) {
        fprintf(stderr, "FAIL template setup: the published template does not verify\n");
        return 1;
    }
    char ready[4096];
    snprintf(ready, sizeof(ready), "%s/READY", snap_root);
    FILE* f = fopen(ready, "w");
    if (!f) return 1;
    fputs(tmpl, f);
    fputc('\n', f);
    fclose(f);
    printf("template setup: %s ready\n", tmpl);
    return 0;
}
