#ifndef UFFD_HANDLER_H
#define UFFD_HANDLER_H

#include <stdint.h>

#include "vmm_manager.h"

void* uffd_thread_fn(void* arg);

// mmap snapshot + init uffd + register guest range. Must complete before
// vmm_resume_vcpus(). Returns 0 with vm fields populated.
int uffd_setup_region(vm_handle_t* vm, const char* snap_path,
                      void* guest_mem, uint64_t guest_mem_size);

// Spawn handler / prefault worker (both before resume). 0 on success.
int uffd_start_handler(vm_handle_t* vm);
int uffd_start_prefault(vm_handle_t* vm);

// Flag destroy, wake + join both threads, release snapshot resources.
void uffd_stop(vm_handle_t* vm);

#endif // UFFD_HANDLER_H
