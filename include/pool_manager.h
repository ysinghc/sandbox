// SPDX-License-Identifier: GPL-2.0-only
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
    int max_queue_depth;    // Effective overflow depth (<= POOL_MAX_QUEUE_DEPTH)

    // Snapshot version this pool was built from (0 = none yet).
    uint32_t expected_version;

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

// Number of VMs currently warm and ready to hand out without a restore.
// "Configured" and "warm" are different states: the replenishment thread fills
// the pool asynchronously, so a caller that must not wait (and a test that
// wants to distinguish a pool hit from a restore) needs to ask.
int pool_manager_warm_count(pool_manager_t* pool);

// Phase 11: set the effective overflow-queue depth (clamped to
// [1, POOL_MAX_QUEUE_DEPTH]). Safe to call after init, before serving.
void pool_manager_set_max_queue_depth(pool_manager_t* pool, int depth);

// Fast-path provision (<1ms on pool hit); slow-path overflow queue on miss.
// Returns NULL handle wrapped in error: on failure returns error code and *out_vm NULL.
sandbox_error_t pool_provision(pool_manager_t* pool, const sandbox_spec_t* spec, vm_handle_t** out_vm);

// Replenishment thread entry point (daemon lifetime)
void* replenishment_thread(void* arg);

// Test helpers
int pool_drain(pool_manager_t* pool);

// Register the daemon's live pool so a snapshot rebuild can drain it
// (pool_manager_flush_and_rebuild). Pass NULL on shutdown.
void pool_manager_set_live(pool_manager_t* pool);

// Snapshot-rebuild hook (called by create_snapshot_template): drains the live
// pool and points replenishment at the new template.
void pool_manager_flush_and_rebuild(const char* template_name, uint32_t version);

#endif // POOL_MANAGER_H
