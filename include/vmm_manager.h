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

// Restore a VM from snapshot (Phase 1: stub with usleep(83000); Phase 6: real Firecracker restore)
vm_handle_t* restore_vm_from_snapshot(void);

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

// Restore a template into a new jailed VM; net must already exist (tap device
// by name, retargeted via the load request's network_overrides). UFFD handler
// is up before vCPU resume.
vm_handle_t* vmm_restore(const char* template_name, const char* vm_id,
                         const char* tap_name, uint32_t guest_ip);

// Block until the serial log shows marker (or timeout_ms). 0 ready, -1 timeout.
int vmm_wait_ready(vm_handle_t* vm, const char* marker, int timeout_ms);

int vmm_pause_vcpus(vm_handle_t* vm);
int vmm_resume_vcpus(vm_handle_t* vm);

// Current FC state string ("Running", "Paused", ...). 0 ok, -1 error.
int vmm_state(vm_handle_t* vm, char* out, size_t n);

// Snapshot a paused VM's state+memory to jail-view paths (Phase 4 seam).
int vmm_snapshot(vm_handle_t* vm, const char* vmstate_jailview, const char* mem_jailview);
int vmm_destroy(vm_handle_t* vm);

#endif // VMM_MANAGER_H
