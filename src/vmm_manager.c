// VMM Manager — Phase 1 stub: dummy handle after usleep(83000) to simulate
// the ~83ms snapshot restore for pool testing (real restore in Phase 5/6).

#define _DEFAULT_SOURCE  // expose usleep() under strict C11

#include "vmm_manager.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

static atomic_uint_fast32_t next_id = 1;

vm_handle_t* restore_vm_from_snapshot(void) {
    usleep(83000);  // simulated restore-to-resume latency (~83ms per LLD)

    vm_handle_t* vm = calloc(1, sizeof(*vm));
    if (!vm) return NULL;
    vm->sandbox_id = atomic_fetch_add(&next_id, 1);
    vm->vmm_pid = -1;
    vm->uffd_fd = -1;
    vm->guest_mem_size = 512u * 1024u * 1024u;  // dummy size only
    return vm;
}

vm_handle_t* vmm_cold_boot(const void* config) {
    (void)config;
    return NULL;
}

int vmm_pause_vcpus(vm_handle_t* vm) {
    (void)vm;
    return 0;
}

int vmm_resume_vcpus(vm_handle_t* vm) {
    (void)vm;
    return 0;
}

// Phase 1 stub semantic: counterpart of the calloc in the restore stub.
int vmm_destroy(vm_handle_t* vm) {
    free(vm);
    return 0;
}
