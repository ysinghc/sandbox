// SPDX-License-Identifier: GPL-2.0-only
#ifndef VMM_MANAGER_H
#define VMM_MANAGER_H

#include <limits.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "network_manager.h"

// Opaque manifest forward declaration (full definition in snapshot_manager.h)
typedef struct snap_manifest_t snap_manifest_t;

// One guest-memory region as sent by Firecracker over the UDS
// (GuestRegionUffdMapping): host address range + offset into the mem file.
typedef struct {
    uint64_t base_host_addr;
    uint64_t size;
    uint64_t file_offset;
} uffd_region_t;

typedef struct vm_handle_t {
    uint32_t sandbox_id;
    int vmm_pid;
    int uffd_fd;
    void* guest_mem_base;   // single-region fast path (== regions[0].base)
    uint64_t guest_mem_size;
    void* snap_base;
    uint64_t snap_size;
    snap_manifest_t* manifest;
    uffd_region_t* regions;  // fault-service regions (always >= 1 when uffd up)
    int nregions;
    char api_sock_path[108];  // host view of the jail API socket
    char jail_root[PATH_MAX];
    char vsock_uds[PATH_MAX];  // host path to the per-VM vsock UDS ("" = none)
    char cgroup_dir[PATH_MAX];  // per-VM cgroup dir (§10.11); "" = none
    // #23: an ephemeral workspace cloned for this VM when the caller did not
    // supply a session volume. Owned by the handle: vmm_destroy unlinks it. Empty
    // when the volume belongs to a session (or the template has no workspace).
    char workspace_scratch[PATH_MAX];
    // #23: session key of a persistent volume bound to this VM. Non-empty means
    // the caller holds a workspace lease that vmm_destroy must release.
    char session_key[128];
    vm_network_t net;  // per-VM tap; reclaimed by vmm_destroy
    bool has_net;
    pthread_t uffd_thread;
    pthread_t prefault_thread;
    bool uffd_thread_started;
    bool prefault_thread_started;
    bool destroyed;
    uint32_t page_faults;
    uint64_t resume_time_ms;
} vm_handle_t;

// Restore a VM from the configured template via real Firecracker /snapshot/load.
vm_handle_t* restore_vm_from_snapshot(void);

// #23: same, but with an explicit writable workspace volume (NULL = an ephemeral
// per-VM clone of the template's base image). Used for session-backed creates,
// which cannot come from the warm pool: a pool member's workspace is already
// bound before the request arrives, and Firecracker cannot swap a block device
// after restore.
vm_handle_t* restore_vm_with_workspace(const char* workspace_image);

// Build the /snapshot/load request body. Pure string construction, so the
// fields that decide guest behaviour after resume (tap retarget, per-VM vsock
// UDS, clock) can be asserted without booting a VM. Paths are jail-view paths:
// Firecracker is chrooted, so the host paths never appear in its API.
// Returns the number of bytes written, or -1 on invalid input/overflow.
int vmm_build_load_request(char* buf, size_t cap, const char* tap_name);

// Set the template restore source for pool replenishment (global by design:
// restore_vm_from_snapshot() takes no args per LLD).
void pool_set_restore_source(const char* template_name);

// Cold-boot a template VM into an explicit jail (kernel/rootfs from config).
// out_dir (nullable) is bound at $jail/out for snapshot capture.
// If config->tap_name is set, a NIC (FC_TEMPLATE_IFACE) is attached before
// boot so the snapshot carries it for later network_overrides retargeting.
vm_handle_t* vmm_cold_boot(const void* config, const char* vm_id,
                           const char* jail_root, const char* out_dir);

// Form "$parent/<vm_id>" jail paths (parent defaults per env).
int vmm_jail_path(const char* vm_id, char* out, size_t n);

// #31: reclaim jail directories left behind by a daemon that died without
// running vmm_destroy (SIGKILL, OOM, crash). Their bind mounts live in the
// kernel, so they outlive the process and make rm_rf fail EBUSY forever; the
// next start is the only point where we know no VM of ours is live.
//
// Removes only "vm-*" directories under `jail_root`. A jail whose directory
// mtime is younger than `min_age_seconds` is kept (a jailer may be mid-setup),
// and so is one that still has a process rooted in it (a VMM that outlived its
// daemon). Returns 0 on success (including "nothing to do") and -1 with errno
// on a real failure; `removed_out` receives the number reclaimed.
#define JAIL_SWEEP_MIN_AGE_SECONDS 5u

// Resolved jail root (SANDBOX_JAIL_ROOT or the packaged default). One
// definition, so the socket path, the sweep and the VMM cannot disagree.
const char* vmm_jail_root(void);
int vmm_jail_sweep(const char* jail_root, unsigned min_age_seconds,
                   int* removed_out);

// Restore a template into a new jailed VM; net must already exist (tap device
// by name, retargeted via the load request's network_overrides). UFFD handler
// is up before vCPU resume.
//
// workspace_image (#23): host path of the writable volume to bind at
// /workspace.ext4, or NULL for an ephemeral per-VM volume cloned from the
// template's base image. A template captured without a workspace ignores the
// argument; asking for a session volume on such a template is an error, because
// the guest has nowhere to mount it.
vm_handle_t* vmm_restore(const char* template_name, const char* vm_id,
                         const char* tap_name, uint32_t guest_ip,
                         const char* workspace_image);

// Block until the serial log shows marker (or timeout_ms). 0 ready, -1 timeout.
int vmm_wait_ready(vm_handle_t* vm, const char* marker, int timeout_ms);

// Per-VM env injection (Phase 9b): deliver "KEY=VALUE" strings to the guest's
// vsock env agent over the VM's Firecracker vsock UDS. No-op (0) when env_vars
// is empty; -1 if the VM has no vsock or the injection fails.
int vmm_inject_env(vm_handle_t* vm, const char* const* env_vars);

// #23: flush a session volume's pending writes from the guest to the host file
// before the VM is destroyed. Returns 0 on a confirmed flush, -1 if the guest
// did not acknowledge within SANDBOX_FLUSH_MS (the caller may still destroy the
// VM: a wedged guest must not become an unclearable sandbox).
int vmm_flush_workspace(vm_handle_t* vm);

int vmm_pause_vcpus(vm_handle_t* vm);
int vmm_resume_vcpus(vm_handle_t* vm);

// Current FC state string ("Running", "Paused", ...). 0 ok, -1 error.
int vmm_state(vm_handle_t* vm, char* out, size_t n);

// Snapshot a paused VM's state+memory to jail-view paths.
int vmm_snapshot(vm_handle_t* vm, const char* vmstate_jailview, const char* mem_jailview);
int vmm_destroy(vm_handle_t* vm);

#endif // VMM_MANAGER_H
