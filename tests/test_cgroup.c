// SPDX-License-Identifier: GPL-2.0-only
// §10.11 verification: per-VM cgroup hierarchy creation, limit-file contents,
// vm_id sanitization, and removal. SKIPs when cgroup v2 is unavailable (or the
// test is not root, since the default root needs privilege to populate).

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cgroup.h"

static int read_file(const char* path, char* out, size_t n) {
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(out, (int)n, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    size_t l = strlen(out);
    if (l && out[l - 1] == '\n') out[l - 1] = '\0';
    return 0;
}

int main(void) {
    // Use a private hierarchy root so the test never disturbs the real one and
    // can run unprivileged if the directory is writable (e.g. a delegated
    // cgroup). Falls back to the default root under root.
    const char* root = getenv("SANDBOX_TEST_CGROUP_ROOT");
    if (root && *root) setenv("SANDBOX_CGROUP_ROOT", root, 1);

    cgroup_init();
    if (!cgroup_enabled()) {
        printf("SKIP (cgroup v2 unavailable/not permitted)\n");
        return 0;
    }

    cgroup_limits_t lim;
    memset(&lim, 0, sizeof(lim));
    lim.memory_max_mib = 192;  // 128 guest + 64 slack
    lim.memory_swap_max_mib = 0;
    lim.cpu_max = "20000 100000";
    lim.oom_group = true;

    char dir[PATH_MAX] = "";
    if (cgroup_add_vm("vm-7", &lim, dir, sizeof(dir)) != 0 || !dir[0]) {
        fprintf(stderr, "FAIL: cgroup_add_vm returned no dir\n");
        return 1;
    }
    printf("[test] cgroup dir=%s\n", dir);

    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "FAIL: %s not a directory\n", dir);
        return 1;
    }

    char v[128];
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/memory.max", dir);
    if (read_file(p, v, sizeof(v)) != 0 || strcmp(v, "201326592") != 0) {
        fprintf(stderr, "FAIL: memory.max=%s want 201326592\n", v);
        return 1;
    }
    snprintf(p, sizeof(p), "%s/memory.swap.max", dir);
    if (read_file(p, v, sizeof(v)) != 0 || strcmp(v, "0") != 0) {
        fprintf(stderr, "FAIL: memory.swap.max=%s want 0\n", v);
        return 1;
    }
    snprintf(p, sizeof(p), "%s/memory.oom.group", dir);
    if (read_file(p, v, sizeof(v)) != 0 || strcmp(v, "1") != 0) {
        fprintf(stderr, "FAIL: memory.oom.group=%s want 1\n", v);
        return 1;
    }
    snprintf(p, sizeof(p), "%s/cpu.max", dir);
    if (read_file(p, v, sizeof(v)) != 0 || strcmp(v, "20000 100000") != 0) {
        fprintf(stderr, "FAIL: cpu.max=%s want '20000 100000'\n", v);
        return 1;
    }

    cgroup_remove_vm(dir);
    if (stat(dir, &st) == 0) {
        fprintf(stderr, "FAIL: %s still present after remove\n", dir);
        return 1;
    }

    // Sanitization: path-ish / space / slash characters become '_'.
    char sdir[PATH_MAX] = "";
    if (cgroup_add_vm("a b/c", &lim, sdir, sizeof(sdir)) != 0) {
        fprintf(stderr, "FAIL: sanitize add\n");
        return 1;
    }
    if (!strstr(sdir, "/a_b_c")) {
        fprintf(stderr, "FAIL: sanitize dir=%s (want .../a_b_c)\n", sdir);
        return 1;
    }
    cgroup_remove_vm(sdir);

    printf("ALL CGROUP TESTS PASSED\n");
    return 0;
}
