// Prefault Worker (§5.3): stream snapshot pages into the page cache in
// background after vCPU resume. No coordination with the handler needed —
// both read the same mmap; the worker just warms the cache ahead of faults.

#include "prefault_worker.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

void* prefault_worker_fn(void* arg) {
    vm_handle_t* vm = arg;

    // Advise kernel: sequential read-ahead
    madvise(vm->snap_base, vm->snap_size, MADV_SEQUENTIAL);

    // Touch every page to fault it into page cache
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    for (size_t off = 0; off < vm->snap_size; off += (size_t)ps) {
        if (__atomic_load_n(&vm->destroyed, __ATOMIC_ACQUIRE)) break;  // early exit
        volatile uint8_t touch = *((uint8_t*)vm->snap_base + off);
        (void)touch;  // Suppress unused warning
    }
    return NULL;
}
