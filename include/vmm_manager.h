#ifndef VMM_MANAGER_H
#define VMM_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

// Opaque manifest forward declaration (full definition in snapshot_manager.h)
typedef struct snap_manifest_t snap_manifest_t;

typedef struct vm_handle_t {
    uint32_t sandbox_id;
    int vmm_pid;
    int uffd_fd;
    void* guest_mem_base;
    uint64_t guest_mem_size;
    void* snap_base;
    uint64_t snap_size;
    snap_manifest_t* manifest;
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

// VMM lifecycle (full implementation in Phase 6)
vm_handle_t* vmm_cold_boot(const void* config);
int vmm_pause_vcpus(vm_handle_t* vm);
int vmm_resume_vcpus(vm_handle_t* vm);
int vmm_destroy(vm_handle_t* vm);

#endif // VMM_MANAGER_H
