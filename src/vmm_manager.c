#include "vmm_manager.h"
#include <stddef.h>

vm_handle_t* restore_vm_from_snapshot(void) {
    return NULL;
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

int vmm_destroy(vm_handle_t* vm) {
    (void)vm;
    return 0;
}
