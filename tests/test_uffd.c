// Phase 5 verification: userfaultfd lazy restore of a real snapshot.
// A "guest" thread touches pages only after register+handler-start (the
// vmm_resume_vcpus ordering); every byte must match the snapshot pattern,
// page_faults must equal the touched page count, and setup latency is
// reported against the ~83ms restore-to-resume budget (the Firecracker
// /snapshot/load that dominates it is exercised end to end in test_vmm).

#define _DEFAULT_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "prefault_worker.h"
#include "snapshot_manager.h"
#include "uffd_handler.h"
#include "vmm_manager.h"

#define CHECK_RC(rc, what) do { int _rc = (rc); if (_rc != 0) { \
    fprintf(stderr, "FAIL %s: rc=%d errno=%d (%s:%d)\n", (what), _rc, errno, \
            __FILE__, __LINE__); \
    abort(); } } while (0)

#define NPAGES 64
#define PS 4096u

static char g_root[PATH_MAX];
static char g_mempath[PATH_MAX];

// Present pages get 64-bit lane pattern: word[i] = (page << 32) | i.
static void fill_pattern(uint8_t* base, uint64_t file_size) {
    uint32_t npages = (uint32_t)(file_size / PS);
    for (uint32_t p = 0; p < npages; p++) {
        if (p % 8 == 7) continue;  // zero pages: every 8th
        uint64_t* w = (uint64_t*)(base + (uint64_t)p * PS);
        for (size_t i = 0; i < PS / 8; i++) w[i] = ((uint64_t)p << 32) | i;
    }
}

static int expect_present(uint32_t page) {
    return page % 8 != 7;
}

static void check_guest_page(const uint8_t* guest, uint32_t page) {
    const uint64_t* w = (const uint64_t*)(guest + (uint64_t)page * PS);
    for (size_t i = 0; i < PS / 8; i++) {
        uint64_t want = expect_present(page) ? (((uint64_t)page << 32) | i) : 0;
        if (w[i] != want) {
            fprintf(stderr, "FAIL data page %u word %zu: got %lx want %lx\n",
                    page, i, w[i], want);
            abort();
        }
    }
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

typedef struct {
    vm_handle_t* vm;
    uint8_t* guest;
    int step;  // 0 = run when released
    pthread_mutex_t lock;
    pthread_cond_t cond;
} guest_arg_t;

// Simulated vCPUs: block until "resume", then touch every page in order.
static void* guest_fn(void* arg) {
    guest_arg_t* ga = arg;
    pthread_mutex_lock(&ga->lock);
    while (ga->step == 0)
        pthread_cond_wait(&ga->cond, &ga->lock);
    pthread_mutex_unlock(&ga->lock);
    for (uint32_t p = 0; p < NPAGES; p++) check_guest_page(ga->guest, p);
    return NULL;
}

static void test_restore(void) {
    printf("[test] restore...\n");
    fflush(stdout);

    // Build a real snapshot dir: memory.snap + manifest.bin via Phase 4 code.
    snprintf(g_mempath, sizeof(g_mempath), "%s/tpl/memory.snap", g_root);
    char tpldir[PATH_MAX];
    snprintf(tpldir, sizeof(tpldir), "%s/tpl", g_root);
    CHECK_RC(mkdir(tpldir, 0755), "mkdir tpl");
    int fd = open(g_mempath, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) abort();
    CHECK_RC(ftruncate(fd, (off_t)NPAGES * PS), "ftruncate snap");
    uint8_t* sm = mmap(NULL, (size_t)NPAGES * PS, PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, 0);
    if (sm == MAP_FAILED) abort();
    fill_pattern(sm, (uint64_t)NPAGES * PS);
    CHECK_RC(msync(sm, (size_t)NPAGES * PS, MS_SYNC), "msync");
    CHECK_RC(munmap(sm, (size_t)NPAGES * PS), "munmap snap");
    close(fd);
    snap_manifest_t* m = build_manifest(g_mempath);
    if (!m) abort();
    m->version = 1;
    char mpath[PATH_MAX];
    snprintf(mpath, sizeof(mpath), "%s/manifest.bin", tpldir);
    CHECK_RC(write_manifest(mpath, m), "write manifest");
    free(m);

    // Guest memory: private anonymous, never touched (all MISSING).
    uint8_t* guest = mmap(NULL, (size_t)NPAGES * PS, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guest == MAP_FAILED) abort();

    vm_handle_t* vm = calloc(1, sizeof(*vm));
    if (!vm) abort();
    vm->uffd_fd = -1;

    // Register BEFORE "resume": the race-safety ordering.
    uint64_t t0 = now_ms();
    CHECK_RC(uffd_setup_region(vm, g_mempath, guest, (uint64_t)NPAGES * PS),
             "uffd_setup_region");
    uint64_t setup_ms = now_ms() - t0;
    CHECK_RC(uffd_start_handler(vm), "start handler");
    CHECK_RC(uffd_start_prefault(vm), "start prefault");

    guest_arg_t ga;
    ga.vm = vm;
    ga.guest = guest;
    ga.step = 0;
    pthread_mutex_init(&ga.lock, NULL);
    pthread_cond_init(&ga.cond, NULL);
    pthread_t guest_thr;
    CHECK_RC(pthread_create(&guest_thr, NULL, guest_fn, &ga), "guest thread");

    // vmm_resume_vcpus(): release the guest only now that faults are served.
    pthread_mutex_lock(&ga.lock);
    ga.step = 1;
    pthread_cond_signal(&ga.cond);
    pthread_mutex_unlock(&ga.lock);
    CHECK_RC(pthread_join(guest_thr, NULL), "guest join");

    uint32_t faults = __atomic_load_n(&vm->page_faults, __ATOMIC_ACQUIRE);
    printf("[test] setup_ms=%lu page_faults=%u (expect %d)\n",
           (unsigned long)setup_ms, faults, NPAGES);
    fflush(stdout);
    if (faults != NPAGES) {
        fprintf(stderr, "FAIL faults: got %u want %d\n", faults, NPAGES);
        abort();
    }
    if (setup_ms > 100) {
        fprintf(stderr, "FAIL setup latency %lu ms\n", (unsigned long)setup_ms);
        abort();
    }

    uffd_stop(vm);
    CHECK_RC(munmap(guest, (size_t)NPAGES * PS), "munmap guest");
    pthread_mutex_destroy(&ga.lock);
    pthread_cond_destroy(&ga.cond);
    free(vm);
    printf("[test] restore: PASS\n");
    fflush(stdout);
}

static void test_prefault_early_exit(void) {
    printf("[test] prefault_early_exit...\n");
    fflush(stdout);
    // destroyed set before start: worker must exit without touching pages.
    vm_handle_t* vm = calloc(1, sizeof(*vm));
    if (!vm) abort();
    size_t size = 64u * 1024u * 1024u;  // 64MB of snapshot to stream
    uint8_t* snap = mmap(NULL, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (snap == MAP_FAILED) abort();
    memset(snap, 0xAB, size);
    vm->snap_base = snap;
    vm->snap_size = size;
    __atomic_store_n(&vm->destroyed, true, __ATOMIC_RELEASE);
    uint64_t t0 = now_ms();
    CHECK_RC(uffd_start_prefault(vm), "start prefault");
    CHECK_RC(pthread_join(vm->prefault_thread, NULL), "prefault join");
    uint64_t dt = now_ms() - t0;
    vm->prefault_thread_started = false;  // already joined
    if (dt > 2000) {
        fprintf(stderr, "FAIL early exit took %lu ms\n", (unsigned long)dt);
        abort();
    }
    CHECK_RC(munmap(snap, size), "munmap snap");
    free(vm);
    printf("[test] prefault_early_exit: PASS (%lu ms)\n", (unsigned long)dt);
    fflush(stdout);
}

int main(void) {
    // userfaultfd needs privilege or vm.unprivileged_userfaultfd; SKIP if denied.
    int probe = (int)syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (probe < 0 && errno == EPERM) {
        printf("SKIP (userfaultfd not permitted)\n");
        return 0;
    }
    if (probe >= 0) close(probe);

    snprintf(g_root, sizeof(g_root), "/tmp/uffdtest-%d", (int)getpid());
    CHECK_RC(mkdir(g_root, 0755), "mkroot");

    test_restore();
    test_prefault_early_exit();
    printf("ALL UFFD TESTS PASSED\n");
    return 0;
}
