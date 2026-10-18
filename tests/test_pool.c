// SPDX-License-Identifier: GPL-2.0-only
// Phase 1 verification: pool concurrency + invariant test (TSan-clean).
//
// Proves under concurrent provision load that the §5.1 invariant
//   warm_count + restoring_count <= target_size
// never breaks, the pool refills to target, and the overflow slow path
// (timeout + fail-immediate) behaves per §3.1.
//
// NOTE: Release builds define NDEBUG, which strips assert() calls entirely.
// Never put side-effecting calls inside assert — store rc first (CHECK_RC).

#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "pool_manager.h"
#include "vmm_manager.h"

// Real-restore mode (Phase 6): provisions boot real Firecracker VMs from the
// fixture template, so load is reduced vs the stub era. Without the fixture
// template there is nothing to restore -> SKIP.
static bool have_template(void) {
    const char* r = getenv("SANDBOX_SNAPSHOT_ROOT");
    if (!r || !*r) return false;
    char ready[PATH_MAX];
    snprintf(ready, sizeof(ready), "%s/READY", r);
    struct stat st;
    return stat(ready, &st) == 0;
}

#define CHECK_RC(rc, what) do { int _rc = (rc); if (_rc != 0) { \
    fprintf(stderr, "FAIL %s: rc=%d (%s:%d)\n", (what), _rc, __FILE__, __LINE__); \
    abort(); } } while (0)

// Lock-protected invariant snapshot. Aborts loudly on violation so CTest
// and TSan report the failure with a stack trace.
static void check_invariant(pool_manager_t* pool) {
    pthread_mutex_lock(&pool->lock);
    int warm = pool->warm_count;
    int restoring = pool->restoring_count;
    int overflow = pool->overflow_count;
    int target = pool->target_size;
    assert(warm >= 0 && warm <= target);
    assert(warm <= POOL_MAX_SIZE);
    assert(restoring >= 0 && restoring <= target);
    assert(overflow >= 0 && overflow <= POOL_MAX_QUEUE_DEPTH);
    assert(warm + restoring <= target);
    assert(pool->warm_head >= 0 && pool->warm_head < POOL_MAX_SIZE);
    assert(pool->warm_tail >= 0 && pool->warm_tail < POOL_MAX_SIZE);
    pthread_mutex_unlock(&pool->lock);
}

static int warm_count_of(pool_manager_t* pool) {
    pthread_mutex_lock(&pool->lock);
    int w = pool->warm_count;
    pthread_mutex_unlock(&pool->lock);
    return w;
}

// Wait up to timeout_ms for warm_count == want; returns 0 on success.
static int wait_for_warm(pool_manager_t* pool, int want, int timeout_ms) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        check_invariant(pool);
        if (warm_count_of(pool) == want) return 0;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000L +
                       (now.tv_nsec - start.tv_nsec) / 1000000L;
        if (elapsed > timeout_ms) return -1;
        struct timespec nap = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000L };
        nanosleep(&nap, NULL);
    }
}

// --- test 1: pool self-fills to target on init ---

static void test_pool_fills(void) {
    printf("[test] pool_fills_to_target...\n");
    fflush(stdout);
    pool_manager_t pool;
    CHECK_RC(pool_manager_init(&pool, 5), "pool_manager_init");
    CHECK_RC(wait_for_warm(&pool, 5, 60000), "wait_for_warm");
    check_invariant(&pool);
    pool_manager_destroy(&pool);
    printf("[test] pool_fills_to_target: PASS\n");
    fflush(stdout);
}

// --- test 2: N concurrent provision loops + monitor sampling invariant ---

#define N_WORKERS 8
#define ITERS_PER_WORKER 3

typedef struct {
    pool_manager_t* pool;
    atomic_int* failures;
    atomic_int* provisions;
} worker_arg_t;

static void* provision_worker(void* arg) {
    worker_arg_t* wa = arg;
    sandbox_spec_t spec = {
        .memory_mib = 128,
        .vcpu_count = 1,
        .template_name = "e2e",
        .env_vars = NULL,
        .pool_wait_ms = 90000,
    };
    for (int i = 0; i < ITERS_PER_WORKER; i++) {
        check_invariant(wa->pool);
        vm_handle_t* vm = NULL;
        sandbox_error_t rc = pool_provision(wa->pool, &spec, &vm);
        if (rc != SANDBOX_OK || vm == NULL) {
            atomic_fetch_add(wa->failures, 1);
            continue;
        }
        atomic_fetch_add(wa->provisions, 1);
        check_invariant(wa->pool);
        usleep(500);  // widen race windows: hold the VM briefly
        vmm_destroy(vm);
    }
    return NULL;
}

typedef struct {
    pool_manager_t* pool;
    atomic_int* samples;
    atomic_bool* stop;
} monitor_arg_t;

static void* invariant_monitor(void* arg) {
    monitor_arg_t* ma = arg;
    struct timespec nap = { .tv_sec = 0, .tv_nsec = 100 * 1000L };
    while (!atomic_load(ma->stop)) {
        check_invariant(ma->pool);
        atomic_fetch_add(ma->samples, 1);
        nanosleep(&nap, NULL);
    }
    return NULL;
}

static void test_concurrent_provision(void) {
    printf("[test] concurrent_provision (%d workers x %d iters)...\n",
           N_WORKERS, ITERS_PER_WORKER);
    fflush(stdout);
    pool_manager_t pool;
    CHECK_RC(pool_manager_init(&pool, 5), "pool_manager_init");
    CHECK_RC(wait_for_warm(&pool, 5, 60000), "wait_for_warm");

    atomic_int failures = 0, provisions = 0, samples = 0;
    atomic_bool stop = false;

    pthread_t mon;
    monitor_arg_t ma = { .pool = &pool, .samples = &samples, .stop = &stop };
    CHECK_RC(pthread_create(&mon, NULL, invariant_monitor, &ma), "monitor create");

    pthread_t workers[N_WORKERS];
    worker_arg_t wa = { .pool = &pool, .failures = &failures, .provisions = &provisions };
    for (int i = 0; i < N_WORKERS; i++)
        CHECK_RC(pthread_create(&workers[i], NULL, provision_worker, &wa), "worker create");
    for (int i = 0; i < N_WORKERS; i++)
        CHECK_RC(pthread_join(workers[i], NULL), "worker join");

    atomic_store(&stop, true);
    CHECK_RC(pthread_join(mon, NULL), "monitor join");

    printf("[test] provisions=%d failures=%d invariant_samples=%d\n",
           atomic_load(&provisions), atomic_load(&failures), atomic_load(&samples));
    fflush(stdout);
    assert(atomic_load(&failures) == 0);
    assert(atomic_load(&provisions) == N_WORKERS * ITERS_PER_WORKER);
    assert(atomic_load(&samples) > 1000);
    check_invariant(&pool);
    pool_manager_destroy(&pool);
    printf("[test] concurrent_provision: PASS\n");
    fflush(stdout);
}

// --- test 3: overflow slow path — timeout and fail-immediate ---

static void test_overflow_timeout(void) {
    printf("[test] overflow_timeout...\n");
    fflush(stdout);
    pool_manager_t pool;
    CHECK_RC(pool_manager_init(&pool, 2), "pool_manager_init");

    // Pool is empty for the first ~83ms: 1ms wait must time out...
    sandbox_spec_t impatient = {
        .memory_mib = 512, .vcpu_count = 1, .template_name = "test",
        .env_vars = NULL, .pool_wait_ms = 1,
    };
    vm_handle_t* vm = NULL;
    sandbox_error_t rc = pool_provision(&pool, &impatient, &vm);
    assert(rc == SANDBOX_ERR_POOL_EXHAUSTED);
    assert(vm == NULL);

    // ...and wait_ms=0 fails immediately without queueing.
    sandbox_spec_t no_wait = impatient;
    no_wait.pool_wait_ms = 0;
    rc = pool_provision(&pool, &no_wait, &vm);
    assert(rc == SANDBOX_ERR_POOL_EXHAUSTED);
    assert(vm == NULL);

    // Patient caller gets a VM once replenishment lands.
    sandbox_spec_t patient = impatient;
    patient.pool_wait_ms = 60000;
    rc = pool_provision(&pool, &patient, &vm);
    assert(rc == SANDBOX_OK);
    assert(vm != NULL);
    vmm_destroy(vm);

    check_invariant(&pool);
    pool_manager_destroy(&pool);
    printf("[test] overflow_timeout: PASS\n");
    fflush(stdout);
}

int main(void) {
    if (!have_template()) {
        printf("SKIP (template fixture not ready)\n");
        return 0;
    }
    pool_set_restore_source("e2e");
    test_pool_fills();
    test_concurrent_provision();
    test_overflow_timeout();
    printf("ALL POOL TESTS PASSED\n");
    return 0;
}
