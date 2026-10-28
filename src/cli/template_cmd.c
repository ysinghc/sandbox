// SPDX-License-Identifier: GPL-2.0-only
// sandbox-cli template ...: operate the content-addressed template store (#25).

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <stdint.h>

#include "sandbox_fs.h"
#include "sha256.h"
#include "snapshot_manager.h"
#include "template_store.h"

void template_usage(void) {
    printf("  sandbox-cli template build --name NAME --kernel PATH --rootfs PATH\n"
           "                             [--memory MIB] [--vcpus N] [--workspace-mb MIB]\n"
           "                             [--spec NAME] [--spec-sha256 HEX]\n"
           "      cold-boots the image, snapshots it and publishes it as NAME (needs\n"
           "      root and /dev/kvm). The build is staged as .build-NAME, so the\n"
           "      template being served is untouched until the new one is complete.\n"
           "  sandbox-cli template list\n"
           "      every published name with its digest, then store entries nothing\n"
           "      points at (JSON, one object per line)\n"
           "  sandbox-cli template publish --name NAME --staged DIR [--spec NAME]\n"
           "                               [--spec-sha256 HEX] [--kernel-sha256 HEX]\n"
           "      DIR is a built template under the snapshot root (e.g. \".build-NAME\");\n"
           "      it is verified, moved into the store and NAME is pointed at it.\n"
           "  sandbox-cli template rollback --name NAME\n"
           "  sandbox-cli template unpublish --name NAME\n"
           "  sandbox-cli template verify --name NAME|DIGEST\n"
           "  sandbox-cli template gc [--keep N] [--min-age SECONDS] [--apply]\n"
           "      removes store entries nothing points at (default: report only;\n"
           "      --keep 2 retains the previous version for rollback, --min-age 86400)\n");
}

static int fail(const char* what) {
    fprintf(stderr, "template %s: %s\n", what, strerror(errno));
    return 1;
}

int template_main(int argc, char** argv) {
    if (argc < 1) {
        template_usage();
        return 2;
    }
    const char* sub = argv[0];
    const char *name = NULL, *staged = NULL, *spec = NULL, *spec_sha = NULL, *kernel_sha = NULL;
    const char *kernel = NULL, *rootfs = NULL;
    unsigned long memory = 256, vcpus = 1, workspace_mb = 512;
    unsigned keep = 2;
    long min_age = 86400;
    int apply = 0;
    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        const char* v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (!strcmp(a, "--name") && v) name = argv[++i];
        else if (!strcmp(a, "--staged") && v) staged = argv[++i];
        else if (!strcmp(a, "--spec") && v) spec = argv[++i];
        else if (!strcmp(a, "--spec-sha256") && v) spec_sha = argv[++i];
        else if (!strcmp(a, "--kernel-sha256") && v) kernel_sha = argv[++i];
        else if (!strcmp(a, "--keep") && v) keep = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--min-age") && v) min_age = strtol(argv[++i], NULL, 10);
        else if (!strcmp(a, "--kernel") && v) kernel = argv[++i];
        else if (!strcmp(a, "--rootfs") && v) rootfs = argv[++i];
        else if (!strcmp(a, "--memory") && v) memory = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--vcpus") && v) vcpus = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--workspace-mb") && v) workspace_mb = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--apply")) apply = 1;
        else {
            fprintf(stderr, "template %s: unknown argument %s\n", sub, a);
            return 2;
        }
    }

    char dg[TSTORE_DIGEST_LEN + 1];
    if (!strcmp(sub, "list")) return tstore_list(stdout) == 0 ? 0 : fail("list");
    if (!strcmp(sub, "gc")) {
        tstore_gc_result_t r;
        if (min_age < 0) min_age = 0;
        if (tstore_gc(keep, (time_t)min_age, !apply, stdout, &r) < 0) return fail("gc");
        printf("{\"event\":\"gc\",\"applied\":%s,\"removed\":%u,\"kept_referenced\":%u,"
               "\"kept_young\":%u,\"bytes\":%llu}\n",
               apply ? "true" : "false", r.removed, r.kept_referenced, r.kept_young,
               (unsigned long long)r.bytes_reclaimed);
        return 0;
    }
    if (!name) {
        template_usage();
        return 2;
    }
    if (!strcmp(sub, "build")) {
        if (!kernel || !rootfs || !tstore_name_valid(name) || memory == 0 || vcpus == 0) {
            template_usage();
            return 2;
        }
        char staged[80], sp[4200];
        snprintf(staged, sizeof(staged), ".build-%s", name);
        snprintf(sp, sizeof(sp), "%s/%s", snapshot_root_dir(), staged);
        chmod(sp, 0755);
        sandbox_rm_rf(sp);  // a crashed earlier build
        template_config_t cfg = {.memory_mib = memory,
                                 .vcpu_count = (uint32_t)vcpus,
                                 .kernel_path = kernel,
                                 .rootfs_path = rootfs,
                                 .ready_marker = "SANDBOX-READY",
                                 .workspace_size_mb = (uint32_t)workspace_mb};
        if (create_snapshot_template(staged, &cfg) < 0) return fail("build");
        uint8_t kd[32];
        char khex[65];
        if (sha256_file(kernel, kd) < 0) return fail("build (hash kernel)");
        sha256_hex(kd, khex);
        tstore_meta_t meta = {.spec_sha256 = spec_sha, .kernel_sha256 = khex,
                              .spec_name = spec};
        if (tstore_publish(name, staged, &meta, dg) < 0) return fail("publish");
        printf("{\"event\":\"built\",\"name\":\"%s\",\"digest\":\"%s\"}\n", name, dg);
        return 0;
    }
    if (!strcmp(sub, "publish")) {
        if (!staged) {
            template_usage();
            return 2;
        }
        tstore_meta_t meta = {.spec_sha256 = spec_sha, .kernel_sha256 = kernel_sha,
                              .spec_name = spec};
        if (tstore_publish(name, staged, &meta, dg) < 0) return fail("publish");
        printf("{\"event\":\"published\",\"name\":\"%s\",\"digest\":\"%s\"}\n", name, dg);
        return 0;
    }
    if (!strcmp(sub, "rollback")) {
        if (tstore_rollback(name, dg) < 0) return fail("rollback");
        printf("{\"event\":\"rolled_back\",\"name\":\"%s\",\"digest\":\"%s\"}\n", name, dg);
        return 0;
    }
    if (!strcmp(sub, "unpublish")) {
        if (tstore_unpublish(name) < 0) return fail("unpublish");
        printf("{\"event\":\"unpublished\",\"name\":\"%s\"}\n", name);
        return 0;
    }
    if (!strcmp(sub, "verify")) {
        if (tstore_verify(name) < 0) return 1;
        printf("{\"event\":\"verified\",\"template\":\"%s\"}\n", name);
        return 0;
    }
    template_usage();
    return 2;
}
