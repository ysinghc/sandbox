// SPDX-License-Identifier: GPL-2.0-only
// Phase 4 verification: manifest bitmap correctness, write/read round-trip,
// versioning, atomic publish under concurrent readers, create-flow hygiene
// (bad config fails clean), and version-check drain. No root needed (tmp dirs).

#define _DEFAULT_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "pool_manager.h"
#include "sha256.h"
#include "snapshot_manager.h"
#include "vmm_manager.h"

#define CHECK_RC(rc, what) do { int _rc = (rc); if (_rc != 0) { \
    fprintf(stderr, "FAIL %s: rc=%d (%s:%d)\n", (what), _rc, __FILE__, __LINE__); \
    abort(); } } while (0)

static char g_root[PATH_MAX];

static void make_root(void) {
    snprintf(g_root, sizeof(g_root), "/tmp/snaptest-%d", (int)getpid());
    CHECK_RC(mkdir(g_root, 0755), "mkroot");
    setenv("SANDBOX_SNAPSHOT_ROOT", g_root, 1);
}

// Write a synthetic guest-memory file: pages listed in present[] get a
// nonzero byte, rest stay holes/zeros. Returns path in buf.
static void make_memory(const char* name, uint32_t npages, const uint32_t* present,
                        int npresent, size_t extra_tail) {
    static char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", g_root, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) abort();
    if (ftruncate(fd, (off_t)npages * 4096 + (off_t)extra_tail) < 0) abort();
    for (int i = 0; i < npresent; i++) {
        uint8_t v = (uint8_t)(i + 1);
        if (pwrite(fd, &v, 1, (off_t)present[i] * 4096 + 100) != 1) abort();
    }
    close(fd);
}

static void test_manifest_bitmap(void) {
    printf("[test] manifest_bitmap...\n");
    fflush(stdout);
    uint32_t present[] = {0, 3, 7};
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/mem1", g_root);
    make_memory("mem1", 8, present, 3, 0);
    // Re-resolve path (make_memory uses a static buffer).
    snprintf(path, sizeof(path), "%s/mem1", g_root);
    snap_manifest_t* m = build_manifest(path);
    if (!m) abort();
    assert(m->magic == SNAP_MAGIC);
    assert(m->page_size == 4096);
    assert(m->page_count == 8);
    assert(m->guest_mem_size == 8u * 4096u);
    for (uint32_t p = 0; p < 8; p++) {
        int want = (p == 0 || p == 3 || p == 7);
        assert(snapshot_page_present(m, (uint64_t)p * 4096) == want);
        assert(snapshot_page_present(m, (uint64_t)p * 4096 + 4095) == want);
    }
    // Out of range is absent, never a crash.
    assert(!snapshot_page_present(m, 8u * 4096u));
    assert(!snapshot_page_present(NULL, 0));
    // Partial trailing page: nonzero tail byte counts as present.
    snprintf(path, sizeof(path), "%s/mem3", g_root);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) abort();
    if (ftruncate(fd, 4096 + 100) < 0) abort();
    uint8_t v = 0xAB;
    if (pwrite(fd, &v, 1, 4096 + 50) != 1) abort();
    close(fd);
    snap_manifest_t* m2 = build_manifest(path);
    if (!m2) abort();
    assert(m2->page_count == 2);  // rounded up
    assert(!snapshot_page_present(m2, 0));
    assert(snapshot_page_present(m2, 4096));
    free(m);
    free(m2);
    printf("[test] manifest_bitmap: PASS\n");
    fflush(stdout);
}

static void test_write_read_roundtrip(void) {
    printf("[test] write_read_roundtrip...\n");
    fflush(stdout);
    char path[PATH_MAX], dir[PATH_MAX];
    snprintf(path, sizeof(path), "%s/mem1", g_root);
    snap_manifest_t* m = build_manifest(path);
    if (!m) abort();
    m->version = 7;
    snprintf(dir, sizeof(dir), "%s/tpl", g_root);
    CHECK_RC(mkdir(dir, 0755), "mkdir tpl");
    char mp[PATH_MAX];
    snprintf(mp, sizeof(mp), "%s/manifest.bin", dir);
    CHECK_RC(write_manifest(mp, m), "write");
    free(m);
    // Point the root at a template dir layout read_manifest understands.
    char tplroot[PATH_MAX], tpldir[PATH_MAX];
    snprintf(tplroot, sizeof(tplroot), "%s/root", g_root);
    CHECK_RC(mkdir(tplroot, 0755), "mkdir root");
    snprintf(tpldir, sizeof(tpldir), "%s/rr", tplroot);
    CHECK_RC(mkdir(tpldir, 0755), "mkdir rr");
    char dst[PATH_MAX];
    snprintf(dst, sizeof(dst), "%s/manifest.bin", tpldir);
    char cp[PATH_MAX * 2 + 16];
    snprintf(cp, sizeof(cp), "cp %s %s", mp, dst);
    CHECK_RC(system(cp), "cp manifest");
    setenv("SANDBOX_SNAPSHOT_ROOT", tplroot, 1);
    snap_manifest_t* back = NULL;
    CHECK_RC(read_manifest("rr", &back), "read");
    assert(back->magic == SNAP_MAGIC);
    assert(back->version == 7);
    assert(back->page_count == 8);
    assert(snapshot_page_present(back, 3u * 4096));
    assert(!snapshot_page_present(back, 1u * 4096));
    free(back);
    assert(read_manifest_version("rr") == 7);
    assert(read_manifest_version("nope") == 0);
    // Corrupt magic -> refused.
    int fd = open(dst, O_WRONLY);
    if (fd < 0) abort();
    uint32_t bad = 0;
    if (pwrite(fd, &bad, 4, 0) != 4) abort();
    close(fd);
    assert(read_manifest("rr", &back) < 0);
    // Truncated bitmap -> refused (never partial state).
    snprintf(cp, sizeof(cp), "cp %s %s", mp, dst);
    CHECK_RC(system(cp), "restore manifest");
    if (truncate(dst, sizeof(snap_manifest_t)) < 0) abort();
    assert(read_manifest("rr", &back) < 0);
    setenv("SANDBOX_SNAPSHOT_ROOT", g_root, 1);
    printf("[test] write_read_roundtrip: PASS\n");
    fflush(stdout);
}

// Concurrent readers must only ever see the complete old or new manifest.
typedef struct {
    const char* name;
    atomic_int* ok_reads;
    atomic_int* bad_reads;
    atomic_bool* stop;
    uint32_t v_old, v_new;
} reader_arg_t;

static void* reader_fn(void* arg) {
    reader_arg_t* ra = arg;
    while (!atomic_load(ra->stop)) {
        snap_manifest_t* m = NULL;
        if (read_manifest(ra->name, &m) == 0) {
            if (m->magic == SNAP_MAGIC && m->page_count == 4 &&
                (m->version == ra->v_old || m->version == ra->v_new) &&
                snapshot_page_present(m, 0) &&
                !snapshot_page_present(m, 3u * 4096))
                atomic_fetch_add(ra->ok_reads, 1);
            else
                atomic_fetch_add(ra->bad_reads, 1);
            free(m);
        }
    }
    return NULL;
}

static void write_version(const char* dir, uint32_t version) {
    char mem[PATH_MAX], mp[PATH_MAX];
    snprintf(mem, sizeof(mem), "%s/mem", dir);
    int fd = open(mem, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) abort();
    if (ftruncate(fd, 4 * 4096) < 0) abort();
    uint8_t v = 0x5A;
    if (pwrite(fd, &v, 1, 100) != 1) abort();
    close(fd);
    snap_manifest_t* m = build_manifest(mem);
    if (!m) abort();
    m->version = version;
    snprintf(mp, sizeof(mp), "%s/manifest.bin", dir);
    CHECK_RC(write_manifest(mp, m), "write version");
    free(m);
}

static void test_atomic_publish(void) {
    printf("[test] atomic_publish...\n");
    fflush(stdout);
    char proot[PATH_MAX], final[PATH_MAX], tmp[PATH_MAX];
    snprintf(proot, sizeof(proot), "%s/pub", g_root);
    CHECK_RC(mkdir(proot, 0755), "mkdir pub");
    snprintf(final, sizeof(final), "%s/tpl", proot);
    snprintf(tmp, sizeof(tmp), "%s/.tmp-tpl", proot);
    CHECK_RC(mkdir(final, 0755), "mkdir final");
    write_version(final, 11);
    setenv("SANDBOX_SNAPSHOT_ROOT", proot, 1);

    atomic_int ok = 0, bad = 0;
    atomic_bool stop = false;
    reader_arg_t ra = { .name = "tpl", .ok_reads = &ok, .bad_reads = &bad,
                        .stop = &stop, .v_old = 11, .v_new = 12 };
    pthread_t readers[4];
    for (int i = 0; i < 4; i++)
        CHECK_RC(pthread_create(&readers[i], NULL, reader_fn, &ra), "reader");

    // Publish the new version repeatedly through the real publish path.
    for (int i = 0; i < 20; i++) {
        char rm[PATH_MAX * 2];
        snprintf(rm, sizeof(rm), "rm -rf %s", tmp);
        CHECK_RC(system(rm), "rm tmp");
        CHECK_RC(mkdir(tmp, 0755), "mkdir tmp");
        write_version(tmp, 12);
        char vmstate[PATH_MAX];
        snprintf(vmstate, sizeof(vmstate), "%s/vmstate", tmp);
        int fd = open(vmstate, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) abort();
        close(fd);
        CHECK_RC(snapshot_publish(tmp, final), "publish");
        // Swap back so readers keep seeing transitions both ways.
        snprintf(rm, sizeof(rm), "rm -rf %s", tmp);
        CHECK_RC(system(rm), "rm tmp2");
        CHECK_RC(mkdir(tmp, 0755), "mkdir tmp2");
        write_version(tmp, 11);
        CHECK_RC(snapshot_publish(tmp, final), "publish2");
    }
    atomic_store(&stop, true);
    for (int i = 0; i < 4; i++)
        CHECK_RC(pthread_join(readers[i], NULL), "join");
    printf("[test] reads ok=%d bad=%d\n", atomic_load(&ok), atomic_load(&bad));
    assert(atomic_load(&bad) == 0);
    assert(atomic_load(&ok) > 100);
    setenv("SANDBOX_SNAPSHOT_ROOT", g_root, 1);
    printf("[test] atomic_publish: PASS\n");
    fflush(stdout);
}

static void test_create_hygiene(void) {
    printf("[test] create_hygiene...\n");
    fflush(stdout);
    // Bad config (no kernel/rootfs) must fail cleanly with no temp residue
    // and no touch to any pre-existing final dir.
    char final[PATH_MAX];
    snprintf(final, sizeof(final), "%s/hyg", g_root);
    CHECK_RC(mkdir(final, 0755), "mkdir hyg");
    write_version(final, 3);
    template_config_t cfg = { .memory_mib = 512, .vcpu_count = 1,
                              .kernel_path = NULL, .rootfs_path = NULL };
    if (create_snapshot_template("hyg", &cfg) == 0) abort();
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s/.tmp-hyg", g_root);
    struct stat st;
    assert(stat(tmp, &st) < 0);  // temp removed
    assert(read_manifest_version("hyg") == 3);  // final untouched
    if (create_snapshot_template(NULL, &cfg) == 0) abort();
    if (create_snapshot_template("hyg", NULL) == 0) abort();
    printf("[test] create_hygiene: PASS\n");
    fflush(stdout);
}

static int wait_warm(pool_manager_t* pool, int want, int timeout_ms) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        pthread_mutex_lock(&pool->lock);
        int w = pool->warm_count;
        pthread_mutex_unlock(&pool->lock);
        if (w == want) return 0;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long ms = (now.tv_sec - start.tv_sec) * 1000L +
                  (now.tv_nsec - start.tv_nsec) / 1000000L;
        if (ms > timeout_ms) return -1;
        struct timespec nap = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000L };
        nanosleep(&nap, NULL);
    }
}

static void test_version_check(void) {
    printf("[test] version_check...\n");
    fflush(stdout);
    pool_set_restore_source("TEST-DUMMY");
    char vroot[PATH_MAX], vdir[PATH_MAX];
    snprintf(vroot, sizeof(vroot), "%s/vers", g_root);
    CHECK_RC(mkdir(vroot, 0755), "mkdir vers");
    snprintf(vdir, sizeof(vdir), "%s/vtpl", vroot);
    CHECK_RC(mkdir(vdir, 0755), "mkdir vtpl");
    write_version(vdir, 1);
    setenv("SANDBOX_SNAPSHOT_ROOT", vroot, 1);

    pool_manager_t pool;
    CHECK_RC(pool_manager_init(&pool, 2), "pool init");
    assert(snapshot_check_version(&pool, "missing") == -1);
    assert(snapshot_check_version(&pool, "vtpl") == 1);  // adopts v1
    assert(snapshot_check_version(&pool, "vtpl") == 0);  // unchanged
    CHECK_RC(wait_warm(&pool, 2, 5000), "pool fill");
    write_version(vdir, 2);
    assert(snapshot_check_version(&pool, "vtpl") == 1);  // drains + adopts
    pthread_mutex_lock(&pool.lock);
    uint32_t ev = pool.expected_version;
    pthread_mutex_unlock(&pool.lock);
    assert(ev == 2);
    CHECK_RC(wait_warm(&pool, 2, 5000), "pool refill");
    pool_manager_destroy(&pool);
    setenv("SANDBOX_SNAPSHOT_ROOT", g_root, 1);
    printf("[test] version_check: PASS\n");
    fflush(stdout);
}

static void test_sha256_kat(void) {
    printf("[test] sha256...\n");
    fflush(stdout);
    uint8_t d[32];
    char hex[65];
    sha256("abc", 3, d);
    sha256_hex(d, hex);
    assert(strcmp(hex,
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
           == 0);
    sha256("", 0, d);
    sha256_hex(d, hex);
    assert(strcmp(hex,
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
           == 0);
    // 56-byte boundary exercises the two-block padding path.
    sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    sha256_hex(d, hex);
    assert(strcmp(hex,
                  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
           == 0);
    printf("[test] sha256: PASS\n");
    fflush(stdout);
}

static void test_verify(void) {
    printf("[test] verify...\n");
    fflush(stdout);
    char vroot[PATH_MAX], vdir[PATH_MAX];
    snprintf(vroot, sizeof(vroot), "%s/ver", g_root);
    CHECK_RC(mkdir(vroot, 0755), "mkdir ver");
    snprintf(vdir, sizeof(vdir), "%s/vtpl", vroot);
    CHECK_RC(mkdir(vdir, 0755), "mkdir vtpl");
    setenv("SANDBOX_SNAPSHOT_ROOT", vroot, 1);

    char mem[PATH_MAX], state[PATH_MAX], mp[PATH_MAX];
    snprintf(mem, sizeof(mem), "%s/memory.snap", vdir);
    int fd = open(mem, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) abort();
    if (ftruncate(fd, 4 * 4096) < 0) abort();
    uint8_t v = 0x33;
    if (pwrite(fd, &v, 1, 50) != 1) abort();
    close(fd);
    snprintf(state, sizeof(state), "%s/vmstate", vdir);
    fd = open(state, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) abort();
    if (write(fd, "VMSTATE-DATA", 12) != 12) abort();
    close(fd);

    snap_manifest_t* m = build_manifest(mem);
    if (!m) abort();
    m->version = 1;
    if (sha256_file(state, m->vmstate_sha256) < 0) abort();
    snprintf(mp, sizeof(mp), "%s/manifest.bin", vdir);
    CHECK_RC(write_manifest(mp, m), "write verify manifest");
    free(m);

    assert(snapshot_verify("vtpl") == 0);
    // Corrupt memory.snap -> mismatch -> refused.
    fd = open(mem, O_WRONLY);
    if (fd < 0) abort();
    uint8_t z = 0x99;
    if (pwrite(fd, &z, 1, 4096) != 1) abort();
    close(fd);
    assert(snapshot_verify("vtpl") < 0);
    setenv("SANDBOX_SNAPSHOT_ROOT", g_root, 1);
    printf("[test] verify: PASS\n");
    fflush(stdout);
}

int main(void) {
    make_root();
    test_sha256_kat();
    test_manifest_bitmap();
    test_write_read_roundtrip();
    test_verify();
    test_atomic_publish();
    test_create_hygiene();
    test_version_check();
    printf("ALL SNAPSHOT TESTS PASSED\n");
    return 0;
}
