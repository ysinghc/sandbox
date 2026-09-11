#ifndef POOL_MANAGER_H
#define POOL_MANAGER_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include "libsandbox.h"

#define POOL_MAX_SIZE 64
#define POOL_MAX_QUEUE_DEPTH 128

// Forward declaration — full definition in vmm_manager.h
typedef struct vm_handle_t vm_handle_t;

typedef struct {
    vm_handle_t* result;
    bool ready;
} pending_request_t;

typedef struct {
    vm_handle_t* warm_queue[POOL_MAX_SIZE];  // Circular buffer
    int warm_head, warm_tail, warm_count;

    pending_request_t* overflow_queue[POOL_MAX_QUEUE_DEPTH];
    int overflow_head, overflow_tail, overflow_count;

    int target_size;        // Runtime-configurable (from config file)
    int restoring_count;    // VMs currently being restored (not yet warm)

    pthread_mutex_t lock;
    pthread_cond_t vm_available;    // Signaled when warm VM enqueued
    pthread_cond_t slot_available;  // Signaled when replenishment can start
    bool shutdown;

    // Extra (not in LLD): owns the replenishment thread for join on destroy.
    pthread_t replenish_thread;
} pool_manager_t;

// Lifecycle
int pool_manager_init(pool_manager_t* pool, int target_size);
void pool_manager_destroy(pool_manager_t* pool);

// Fast-path provision (<1ms on pool hit); slow-path overflow queue on miss.
// Returns NULL handle wrapped in error: on failure returns error code and *out_vm NULL.
sandbox_error_t pool_provision(pool_manager_t* pool, const sandbox_spec_t* spec, vm_handle_t** out_vm);

// Replenishment thread entry point (daemon lifetime)
void* replenishment_thread(void* arg);

// Test helpers
int pool_drain(pool_manager_t* pool);

#endif // POOL_MANAGER_H
