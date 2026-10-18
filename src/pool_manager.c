// SPDX-License-Identifier: GPL-2.0-only
// Pool Manager (§5.1): fixed-size warm VM pool, overflow queue, replenishment thread.
// NOTE: fast path omits the LLD's restoring_count++ reservation (it double-counts
// with the replenishment thread's own increment and wedges the pool full).
// See docs/IMPLEMENTATION_LOG.md (Phase 1).

#include "pool_manager.h"
#include "vmm_manager.h"
#include "telemetry.h"

#include <errno.h>
#include <stdlib.h>
#include <time.h>

// Push the current pool gauges (§11) into the metrics registry. Caller must
// hold pool->lock so warm/restoring/overflow form a consistent snapshot.
static void push_pool_state(pool_manager_t* pool) {
    telemetry_pool_state(pool->warm_count, pool->restoring_count,
                         pool->overflow_count);
}

// --- overflow queue helpers (ring buffer of pending_request_t*) ---

static void enqueue_overflow(pool_manager_t* pool, pending_request_t* req) {
    pool->overflow_queue[pool->overflow_tail] = req;
    pool->overflow_tail = (pool->overflow_tail + 1) % pool->max_queue_depth;
    pool->overflow_count++;
}

static pending_request_t* peek_overflow(pool_manager_t* pool) {
    if (pool->overflow_count == 0) return NULL;
    return pool->overflow_queue[pool->overflow_head];
}

static void dequeue_head(pool_manager_t* pool) {
    pool->overflow_head = (pool->overflow_head + 1) % pool->max_queue_depth;
    pool->overflow_count--;
}

// Remove a specific request (timeout path). Returns 0 if found, -1 if the
// request was already handed off (caller must re-check req->ready).
static int dequeue_overflow(pool_manager_t* pool, pending_request_t* req) {
    for (int i = 0; i < pool->overflow_count; i++) {
        int idx = (pool->overflow_head + i) % pool->max_queue_depth;
        if (pool->overflow_queue[idx] == req) {
            // Shift the tail segment left to close the gap.
            for (int j = i; j < pool->overflow_count - 1; j++) {
                int dst = (pool->overflow_head + j) % pool->max_queue_depth;
                int src = (pool->overflow_head + j + 1) % pool->max_queue_depth;
                pool->overflow_queue[dst] = pool->overflow_queue[src];
            }
            pool->overflow_tail =
                (pool->overflow_tail - 1 + pool->max_queue_depth) % pool->max_queue_depth;
            pool->overflow_count--;
            return 0;
        }
    }
    return -1;
}

static struct timespec now_plus_ms(uint32_t ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }
    return ts;
}

// --- lifecycle ---

int pool_manager_init(pool_manager_t* pool, int target_size) {
    if (!pool || target_size <= 0) return -1;
    // Mechanically necessary clamp: warm_queue has POOL_MAX_SIZE slots.
    if (target_size > POOL_MAX_SIZE) target_size = POOL_MAX_SIZE;

    pool->warm_head = pool->warm_tail = pool->warm_count = 0;
    pool->overflow_head = pool->overflow_tail = pool->overflow_count = 0;
    pool->target_size = target_size;
    pool->restoring_count = 0;
    pool->max_queue_depth = POOL_MAX_QUEUE_DEPTH;
    pool->expected_version = 0;
    pool->shutdown = false;

    if (pthread_mutex_init(&pool->lock, NULL) != 0) return -1;
    if (pthread_cond_init(&pool->vm_available, NULL) != 0) {
        pthread_mutex_destroy(&pool->lock);
        return -1;
    }
    if (pthread_cond_init(&pool->slot_available, NULL) != 0) {
        pthread_cond_destroy(&pool->vm_available);
        pthread_mutex_destroy(&pool->lock);
        return -1;
    }
    if (pthread_create(&pool->replenish_thread, NULL, replenishment_thread, pool) != 0) {
        pthread_cond_destroy(&pool->slot_available);
        pthread_cond_destroy(&pool->vm_available);
        pthread_mutex_destroy(&pool->lock);
        return -1;
    }
    push_pool_state(pool);
    return 0;
}

void pool_manager_set_max_queue_depth(pool_manager_t* pool, int depth) {
    if (!pool) return;
    if (depth < 1) depth = 1;
    if (depth > POOL_MAX_QUEUE_DEPTH) depth = POOL_MAX_QUEUE_DEPTH;
    pthread_mutex_lock(&pool->lock);
    pool->max_queue_depth = depth;
    pthread_mutex_unlock(&pool->lock);
}

void pool_manager_destroy(pool_manager_t* pool) {
    if (!pool) return;

    pthread_mutex_lock(&pool->lock);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->vm_available);
    pthread_cond_broadcast(&pool->slot_available);
    pthread_mutex_unlock(&pool->lock);

    pthread_join(pool->replenish_thread, NULL);

    // Reclaim any VMs still warm. Destroy outside the lock.
    vm_handle_t* leftover[POOL_MAX_SIZE];
    int n = 0;
    pthread_mutex_lock(&pool->lock);
    while (pool->warm_count > 0 && n < POOL_MAX_SIZE) {
        leftover[n++] = pool->warm_queue[pool->warm_head];
        pool->warm_head = (pool->warm_head + 1) % POOL_MAX_SIZE;
        pool->warm_count--;
    }
    push_pool_state(pool);
    pthread_mutex_unlock(&pool->lock);
    for (int i = 0; i < n; i++) vmm_destroy(leftover[i]);

    pthread_cond_destroy(&pool->slot_available);
    pthread_cond_destroy(&pool->vm_available);
    pthread_mutex_destroy(&pool->lock);
}

// Drain warm queue, destroy all warm VMs from old snapshot (§5.6 version check).
int pool_drain(pool_manager_t* pool) {    if (!pool) return -1;
    vm_handle_t* drained[POOL_MAX_SIZE];
    int n = 0;
    pthread_mutex_lock(&pool->lock);
    while (pool->warm_count > 0 && n < POOL_MAX_SIZE) {
        drained[n++] = pool->warm_queue[pool->warm_head];
        pool->warm_head = (pool->warm_head + 1) % POOL_MAX_SIZE;
        pool->warm_count--;
    }
    // Wake replenishment so it rebuilds from the new snapshot.
    pthread_cond_signal(&pool->slot_available);
    push_pool_state(pool);
    pthread_mutex_unlock(&pool->lock);
    for (int i = 0; i < n; i++) vmm_destroy(drained[i]);
    return n;
}

// Called by create_snapshot_template; the daemon registers its live pool so
// the warm set is rebuilt from the new snapshot. No-op without a live pool
// (e.g. the standalone template-build CLI).
static pool_manager_t* g_live_pool = NULL;
static pthread_mutex_t g_live_lock = PTHREAD_MUTEX_INITIALIZER;

void pool_manager_set_live(pool_manager_t* pool) {
    pthread_mutex_lock(&g_live_lock);
    g_live_pool = pool;
    pthread_mutex_unlock(&g_live_lock);
}

void pool_manager_flush_and_rebuild(const char* template_name, uint32_t version) {
    (void)version;  // informational: drain+replenish rebuilds from the source
    pthread_mutex_lock(&g_live_lock);
    pool_manager_t* pool = g_live_pool;
    pthread_mutex_unlock(&g_live_lock);
    if (!pool) return;
    if (template_name && *template_name) pool_set_restore_source(template_name);
    pool_drain(pool);  // signals replenishment to rebuild from the new source
}

// --- provision ---

sandbox_error_t pool_provision(pool_manager_t* pool, const sandbox_spec_t* spec,
                               vm_handle_t** out_vm) {
    if (!pool || !out_vm) return SANDBOX_ERR_INVALID_SPEC;
    *out_vm = NULL;
    // §3.1: pool_wait_ms 0 = fail immediately. NULL spec => no wait.
    uint32_t wait_ms = spec ? spec->pool_wait_ms : 0;

    pthread_mutex_lock(&pool->lock);

    // 1. Provision from warm pool (fast path)
    if (pool->warm_count > 0) {
        vm_handle_t* vm = pool->warm_queue[pool->warm_head];
        pool->warm_head = (pool->warm_head + 1) % POOL_MAX_SIZE;
        pool->warm_count--;
        // Sum decreases by 1: invariant preserved. Wake replenishment so it
        // observes warm + restoring < target and starts a restore.
        pthread_cond_signal(&pool->slot_available);
        push_pool_state(pool);
        pthread_mutex_unlock(&pool->lock);
        *out_vm = vm;
        return SANDBOX_OK;  // < 1ms on pool hit
    }

    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->lock);
        return SANDBOX_ERR_INTERNAL;
    }

    // 2. Provision with overflow queue (slow path)
    if (wait_ms == 0) {
        pthread_mutex_unlock(&pool->lock);
        return SANDBOX_ERR_POOL_EXHAUSTED;  // fail immediately
    }
    if (pool->overflow_count >= pool->max_queue_depth) {
        pthread_mutex_unlock(&pool->lock);
        return SANDBOX_ERR_POOL_EXHAUSTED;  // Immediate rejection
    }
    pending_request_t req = { .result = NULL, .ready = false };
    enqueue_overflow(pool, &req);
    push_pool_state(pool);
    struct timespec deadline = now_plus_ms(wait_ms);
    while (!req.ready && !pool->shutdown) {
        int rc = pthread_cond_timedwait(&pool->vm_available, &pool->lock, &deadline);
        if (rc == ETIMEDOUT) {
            if (!req.ready) dequeue_overflow(pool, &req);
            push_pool_state(pool);
            pthread_mutex_unlock(&pool->lock);
            return SANDBOX_ERR_POOL_EXHAUSTED;
        }
    }
    vm_handle_t* vm = req.result;
    bool ok = req.ready && !pool->shutdown;
    pthread_mutex_unlock(&pool->lock);
    if (!ok || vm == NULL) return SANDBOX_ERR_INTERNAL;
    *out_vm = vm;
    return SANDBOX_OK;  // Handed off by replenishment thread
}

// --- replenishment thread (daemon lifetime) ---

void* replenishment_thread(void* arg) {
    pool_manager_t* pool = arg;
    for (;;) {
        pthread_mutex_lock(&pool->lock);
        while (pool->warm_count + pool->restoring_count >= pool->target_size &&
               !pool->shutdown) {
            pthread_cond_wait(&pool->slot_available, &pool->lock);
        }
        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->lock);
            return NULL;
        }
        // Sum <= target - 1 here, so restoring++ keeps sum <= target.
        pool->restoring_count++;
        pthread_mutex_unlock(&pool->lock);

        // Restore VM from the configured template (blocking Firecracker restore).
        vm_handle_t* vm = restore_vm_from_snapshot();

        pthread_mutex_lock(&pool->lock);
        pool->restoring_count--;
        if (vm == NULL) {
            // LLD assumes restore never fails; hand NULL to a waiter or retry.
            if (pool->overflow_count > 0) {
                pending_request_t* req = peek_overflow(pool);
                req->result = NULL;
                req->ready = true;
                dequeue_head(pool);
                pthread_cond_broadcast(&pool->vm_available);
            } else {
                pthread_cond_signal(&pool->slot_available);
                push_pool_state(pool);
                pthread_mutex_unlock(&pool->lock);
                struct timespec backoff = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000L };
                nanosleep(&backoff, NULL);
                continue;
            }
        } else if (pool->overflow_count > 0) {
            // Hand directly to waiting caller. Sum decreases by 1
            // (restoring-- above, no warm++): invariant preserved.
            pending_request_t* req = peek_overflow(pool);
            req->result = vm;
            req->ready = true;
            dequeue_head(pool);
            pthread_cond_broadcast(&pool->vm_available);
        } else {
            // Enqueue to warm pool. Sum unchanged (-1 restoring, +1 warm).
            pool->warm_queue[pool->warm_tail] = vm;
            pool->warm_tail = (pool->warm_tail + 1) % POOL_MAX_SIZE;
            pool->warm_count++;
        }
        push_pool_state(pool);
        pthread_mutex_unlock(&pool->lock);
    }
}
