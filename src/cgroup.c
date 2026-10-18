// SPDX-License-Identifier: GPL-2.0-only
// Per-VM cgroup v2 enforcement (§10.11). See include/cgroup.h.
//
// The jailer already accepts a cgroup.procs path in jailer_config_t and writes
// it before chroot; this module owns the hierarchy and the limit files. The
// daemon creates the hierarchy once (cgroup_init) and vmm_restore creates one
// leaf per active VM, which vmm_destroy removes after reaping the VMM.

#define _GNU_SOURCE

#include "cgroup.h"
#include "jailer.h"  // mkdir_recursive

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[PATH_MAX] = "/sys/fs/cgroup";
static char g_active[PATH_MAX];
static bool g_enabled = false;

static const char* env_or(const char* name, const char* dflt) {
    const char* e = getenv(name);
    return (e && *e) ? e : dflt;
}

static int write_str(const char* path, const char* s) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t n = strlen(s);
    ssize_t w = write(fd, s, n);
    close(fd);
    return (w == (ssize_t)n) ? 0 : -1;
}

// cgroup v2: a child cgroup only exposes a controller's interface files
// (memory.max, cpu.max, ...) when that controller is enabled in its parent's
// cgroup.subtree_control. Enable the ones we set on every level of our chain.
static void enable_controllers(const char* dir) {
    char f[PATH_MAX];
    snprintf(f, sizeof(f), "%s/cgroup.subtree_control", dir);
    // Best-effort: the root may already have these, or a level may be a leaf.
    if (write_str(f, "+memory +cpu +pids") < 0) {
        // Fall back to individual writes so a partially-available controller
        // (e.g. no pids) does not block the rest.
        static const char* one[] = { "+memory", "+cpu", "+pids" };
        for (size_t i = 0; i < sizeof(one) / sizeof(one[0]); i++) {
            if (write_str(f, one[i]) < 0) {
                fprintf(stderr, "[cgroup] %s %s: %s\n", f, one[i],
                        strerror(errno));
            }
        }
    }
}

bool cgroup_enabled(void) { return g_enabled; }

int cgroup_init(void) {
    const char* e = getenv("SANDBOX_CGROUP_ENABLE");
    if (e && (strcmp(e, "0") == 0 || strcmp(e, "false") == 0)) {
        g_enabled = false;
        fprintf(stderr, "[cgroup] disabled by config\n");
        return 0;
    }
    snprintf(g_root, sizeof(g_root), "%s",
             env_or("SANDBOX_CGROUP_ROOT", "/sys/fs/cgroup"));
    snprintf(g_active, sizeof(g_active), "%s/sandboxd/active", g_root);
    if (mkdir_recursive(g_active, 0755) < 0) {
        fprintf(stderr, "[cgroup] disabled: cannot create %s: %s\n", g_active,
                strerror(errno));
        g_enabled = false;
        return 0;
    }
    // Delegate memory/cpu/pids down the sandboxd -> active chain so per-VM
    // leaves expose the limit files.
    char base[PATH_MAX];
    snprintf(base, sizeof(base), "%s/sandboxd", g_root);
    enable_controllers(g_root);   // no-op if the init system already did it
    enable_controllers(base);
    enable_controllers(g_active);
    g_enabled = true;
    fprintf(stderr, "[cgroup] enabled at %s\n", g_active);
    return 0;
}

int cgroup_add_vm(const char* vm_id, const cgroup_limits_t* lim,
                  char* dir_out, size_t n) {
    if (dir_out && n) dir_out[0] = '\0';
    if (!g_enabled) return 0;
    if (!vm_id || !*vm_id) return -1;

    // Sanitize: vm_id is daemon-generated ("vm-N") but treat it as untrusted.
    char id[64];
    size_t k = 0;
    for (; vm_id[k] && k < sizeof(id) - 1; k++) {
        char c = vm_id[k];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-';
        id[k] = ok ? c : '_';
    }
    id[k] = '\0';
    if (k == 0) return -1;

    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/%s", g_active, id);
    if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
        fprintf(stderr, "[cgroup] mkdir %s: %s\n", dir, strerror(errno));
        return -1;
    }

    char f[PATH_MAX];
    char v[32];
    if (lim) {
        if (lim->memory_max_mib) {
            snprintf(f, sizeof(f), "%s/memory.max", dir);
            snprintf(v, sizeof(v), "%llu",
                     (unsigned long long)lim->memory_max_mib * 1024ull * 1024ull);
            if (write_str(f, v) < 0)
                fprintf(stderr, "[cgroup] write %s: %s\n", f, strerror(errno));
        }
        snprintf(f, sizeof(f), "%s/memory.swap.max", dir);
        snprintf(v, sizeof(v), "%llu",
                 (unsigned long long)lim->memory_swap_max_mib * 1024ull * 1024ull);
        if (write_str(f, v) < 0)
            fprintf(stderr, "[cgroup] write %s: %s\n", f, strerror(errno));
        snprintf(f, sizeof(f), "%s/memory.oom.group", dir);
        if (write_str(f, lim->oom_group ? "1" : "0") < 0)
            fprintf(stderr, "[cgroup] write %s: %s\n", f, strerror(errno));
        if (lim->cpu_max && *lim->cpu_max) {
            snprintf(f, sizeof(f), "%s/cpu.max", dir);
            if (write_str(f, lim->cpu_max) < 0)
                fprintf(stderr, "[cgroup] write %s: %s\n", f, strerror(errno));
        }
    }
    if (dir_out && n) snprintf(dir_out, n, "%s", dir);
    return 0;
}

void cgroup_remove_vm(const char* dir) {
    if (!dir || !*dir) return;
    if (rmdir(dir) < 0 && errno != ENOENT) {
        fprintf(stderr, "[cgroup] rmdir %s: %s\n", dir, strerror(errno));
    }
}
