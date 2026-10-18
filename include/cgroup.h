// SPDX-License-Identifier: GPL-2.0-only
#ifndef CGROUP_H
#define CGROUP_H

// Per-VM resource enforcement (§10.11). cgroup v2 hierarchy:
//   <root>/sandboxd/active/<vm-id>/cgroup.procs
// The jailer writes cgroup.procs before chroot, so the VMM lands in its own
// cgroup with memory/CPU limits + OOM isolation. All calls are best-effort:
// when cgroup v2 is unavailable the engine runs unmetered (logged once).

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t memory_max_mib;       // 0 = no limit
    uint64_t memory_swap_max_mib;  // 0 = swap disabled
    const char* cpu_max;           // e.g. "100000 200000"; NULL/"max" = unlimited
    bool oom_group;                // kill the whole cgroup on OOM
} cgroup_limits_t;

// Create the sandboxd hierarchy. Honours SANDBOX_CGROUP_ENABLE=0 and
// SANDBOX_CGROUP_ROOT. Always returns 0; check cgroup_enabled().
int cgroup_init(void);

bool cgroup_enabled(void);

// Create/enable the per-VM cgroup and write its limit files. Fills dir_out with
// the cgroup directory (empty when disabled). Returns 0 (even when disabled) or
// -1 if an enabled hierarchy could not be created.
int cgroup_add_vm(const char* vm_id, const cgroup_limits_t* lim,
                  char* dir_out, size_t n);

// Remove a per-VM cgroup directory (call after the VMM has exited).
void cgroup_remove_vm(const char* dir);

#endif // CGROUP_H
