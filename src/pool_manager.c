#include "pool_manager.h"
#include <stdlib.h>

int pool_manager_init(pool_manager_t* pool, int target_size) {
    (void)pool; (void)target_size;
    return 0;
}

void pool_manager_destroy(pool_manager_t* pool) {
    (void)pool;
}

sandbox_error_t pool_provision(pool_manager_t* pool, const sandbox_spec_t* spec, vm_handle_t** out_vm) {
    (void)pool; (void)spec;
    if (out_vm) *out_vm = NULL;
    return SANDBOX_ERR_POOL_EXHAUSTED;
}

void* replenishment_thread(void* arg) {
    (void)arg;
    return NULL;
}

int pool_drain(pool_manager_t* pool) {
    (void)pool;
    return 0;
}
