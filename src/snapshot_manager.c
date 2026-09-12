// Snapshot Manager (§5.6): manifest format, atomic template publish,
// version checking. VMM seams (cold boot, guest-ready, capture) are Phase 6;
// the orchestration below follows the LLD flow line-for-line.

#define _DEFAULT_SOURCE

#include "snapshot_manager.h"
#include "pool_manager.h"
#include "vmm_manager.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SNAPSHOT_DEFAULT_ROOT "/var/lib/sandbox-engine/snapshots"
#define SNAP_PAGE_SIZE 4096u

static const char* snapshot_root(void) {
    // Test override; production uses the LLD path.
    const char* e = getenv("SANDBOX_SNAPSHOT_ROOT");
    return (e && *e) ? e : SNAPSHOT_DEFAULT_ROOT;
}

static void template_paths(const char* template_name, char* final_dir, size_t n) {
    snprintf(final_dir, n, "%s/%s", snapshot_root(), template_name);
}

static size_t manifest_size(uint32_t page_count) {
    return sizeof(snap_manifest_t) + (page_count + 7u) / 8u;
}

static void manifest_set(snap_manifest_t* m, uint32_t page) {
    m->page_bitmap[page / 8u] |= (uint8_t)(1u << (page % 8u));
}

static int manifest_get(const snap_manifest_t* m, uint32_t page) {
    if (page >= m->page_count) return 0;
    return (m->page_bitmap[page / 8u] >> (page % 8u)) & 1u;
}

bool snapshot_page_present(const snap_manifest_t* manifest, uint64_t offset) {
    if (!manifest) return false;
    uint64_t page = offset / manifest->page_size;
    if (page >= manifest->page_count) return false;
    return manifest_get(manifest, (uint32_t)page) != 0;
}

snap_manifest_t* build_manifest(const char* memory_path) {
    if (!memory_path) { errno = EINVAL; return NULL; }
    int fd = open(memory_path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0) { close(fd); return NULL; }
    uint64_t mem_size = (uint64_t)st.st_size;
    uint32_t pages = (uint32_t)((mem_size + SNAP_PAGE_SIZE - 1) / SNAP_PAGE_SIZE);

    uint8_t* base = mmap(NULL, mem_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return NULL;

    snap_manifest_t* m = calloc(1, manifest_size(pages));
    if (!m) { munmap(base, mem_size); return NULL; }
    m->magic = SNAP_MAGIC;
    m->version = 0;  // caller stamps read_current_version() + 1
    m->guest_mem_size = mem_size;
    m->page_size = SNAP_PAGE_SIZE;
    m->page_count = pages;

    static const uint8_t zero[SNAP_PAGE_SIZE] = {0};
    for (uint32_t p = 0; p < pages; p++) {
        uint64_t off = (uint64_t)p * SNAP_PAGE_SIZE;
        size_t chunk = SNAP_PAGE_SIZE;
        if (off + chunk > mem_size) chunk = (size_t)(mem_size - off);
        if (chunk == SNAP_PAGE_SIZE) {
            if (memcmp(base + off, zero, SNAP_PAGE_SIZE) != 0) manifest_set(m, p);
        } else {
            if (memcmp(base + off, zero, chunk) != 0) manifest_set(m, p);
        }
    }
    munmap(base, mem_size);
    return m;
}

int write_manifest(const char* path, const snap_manifest_t* manifest) {
    if (!path || !manifest || manifest->magic != SNAP_MAGIC) {
        errno = EINVAL;
        return -1;
    }
    size_t n = manifest_size(manifest->page_count);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    const uint8_t* p = (const uint8_t*)manifest;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    int rc = fsync(fd);
    close(fd);
    return rc;
}

// Full load with validation. Returns 0 and *out_manifest on success.
int read_manifest(const char* template_name, snap_manifest_t** out_manifest) {
    if (!template_name || !out_manifest) { errno = EINVAL; return -1; }
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s/manifest.bin", snapshot_root(), template_name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    snap_manifest_t hdr;
    ssize_t n = read(fd, &hdr, sizeof(hdr));
    if (n != (ssize_t)sizeof(hdr) || hdr.magic != SNAP_MAGIC ||
        hdr.page_size != SNAP_PAGE_SIZE || hdr.page_count == 0) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    size_t total = manifest_size(hdr.page_count);
    if (hdr.guest_mem_size / hdr.page_size > hdr.page_count + 1) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    snap_manifest_t* m = malloc(total);
    if (!m) { close(fd); return -1; }
    memcpy(m, &hdr, sizeof(hdr));
    size_t rest = total - sizeof(hdr);
    uint8_t* p = m->page_bitmap;
    while (rest > 0) {
        ssize_t r = read(fd, p, rest);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(m);
            close(fd);
            return -1;
        }
        if (r == 0) break;  // truncated
        p += (size_t)r;
        rest -= (size_t)r;
    }
    close(fd);
    if (rest != 0) {  // truncated bitmap: never expose partial state
        free(m);
        errno = EINVAL;
        return -1;
    }
    *out_manifest = m;
    return 0;
}

static uint32_t read_version_at(const char* manifest_path) {
    int fd = open(manifest_path, O_RDONLY);
    if (fd < 0) return 0;
    snap_manifest_t hdr;
    ssize_t n = read(fd, &hdr, sizeof(hdr));
    close(fd);
    if (n != (ssize_t)sizeof(hdr) || hdr.magic != SNAP_MAGIC) return 0;
    return hdr.version;
}

uint32_t read_manifest_version(const char* template_name) {
    if (!template_name) return 0;
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s/manifest.bin", snapshot_root(), template_name);
    return read_version_at(path);
}

// Version check (§5.6): adopt on first sight, drain + adopt on change.
// Returns 1 changed, 0 unchanged, -1 no snapshot.
int snapshot_check_version(pool_manager_t* pool, const char* template_name) {
    if (!pool || !template_name) { errno = EINVAL; return -1; }
    uint32_t loaded = read_manifest_version(template_name);
    if (loaded == 0) return -1;
    pthread_mutex_lock(&pool->lock);
    uint32_t expected = pool->expected_version;
    pthread_mutex_unlock(&pool->lock);
    if (loaded == expected) return 0;
    pool_drain(pool);  // destroy all warm VMs from the old snapshot
    pthread_mutex_lock(&pool->lock);
    pool->expected_version = loaded;
    pthread_mutex_unlock(&pool->lock);
    return 1;
}

// --- template creation flow (§5.6) ---

// Phase 6 seams (declared here until the VMM/firecracker layer lands).
static int wait_for_guest_ready(vm_handle_t* vm) {
    (void)vm;
    return 0;
}

static int firecracker_create_snapshot(vm_handle_t* vm, const char* vmstate_path,
                                       const char* memory_path) {
    (void)vm;
    (void)vmstate_path;
    (void)memory_path;
    return -1;  // no VMM until Phase 6
}

static int rm_rf(const char* path) {
    char cmd[PATH_MAX + 16];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    int rc = system(cmd);
    return (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) ? 0 : -1;
}

// Atomic publish: fresh templates rename directly; rebuilds swap the old
// dir aside first. Readers see old, missing, then new — never partial.
int snapshot_publish(const char* temp_dir, const char* final_dir) {
    struct stat st;
    if (stat(final_dir, &st) != 0) return rename(temp_dir, final_dir);
    char backup[PATH_MAX + 16];
    snprintf(backup, sizeof(backup), "%s.old-%d", final_dir, (int)getpid());
    rm_rf(backup);
    if (rename(final_dir, backup) < 0) return -1;
    if (rename(temp_dir, final_dir) < 0) {
        rename(backup, final_dir);  // best-effort rollback
        return -1;
    }
    rm_rf(backup);
    return 0;
}

int create_snapshot_template(const char* template_name, const template_config_t* config) {
    if (!template_name || !*template_name || !config) {
        errno = EINVAL;
        return -1;
    }
    char temp_dir[PATH_MAX], final_dir[PATH_MAX];
    snprintf(temp_dir, sizeof(temp_dir), "%s/.tmp-%s", snapshot_root(), template_name);
    template_paths(template_name, final_dir, sizeof(final_dir));

    rm_rf(temp_dir);  // stale temp from a crashed run
    if (mkdir(temp_dir, 0755) < 0) return -1;

    // 1. Boot a fresh VM (cold boot, ~125ms)
    vm_handle_t* vm = vmm_cold_boot(config);
    if (!vm) { rm_rf(temp_dir); return -1; }

    // 2. Wait for application init to complete inside guest
    if (wait_for_guest_ready(vm) < 0) { vmm_destroy(vm); rm_rf(temp_dir); return -1; }

    // 3. Pause vCPUs
    if (vmm_pause_vcpus(vm) < 0) { vmm_destroy(vm); rm_rf(temp_dir); return -1; }

    // 4. Call Firecracker API: create_snapshot
    char vmstate_path[PATH_MAX], memory_path[PATH_MAX];
    snprintf(vmstate_path, sizeof(vmstate_path), "%s/vmstate", temp_dir);
    snprintf(memory_path, sizeof(memory_path), "%s/memory.snap", temp_dir);
    if (firecracker_create_snapshot(vm, vmstate_path, memory_path) < 0) {
        vmm_destroy(vm);
        rm_rf(temp_dir);
        return -1;
    }

    // 5. Scan memory.snap, build page bitmap
    snap_manifest_t* manifest = build_manifest(memory_path);
    if (!manifest) { vmm_destroy(vm); rm_rf(temp_dir); return -1; }
    manifest->version = read_manifest_version(template_name) + 1;

    char manifest_path[PATH_MAX];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.bin", temp_dir);
    int rc = write_manifest(manifest_path, manifest);
    uint32_t new_version = manifest->version;
    free(manifest);
    if (rc < 0) { vmm_destroy(vm); rm_rf(temp_dir); return -1; }

    // 6. Atomic publish to final path (same filesystem)
    if (snapshot_publish(temp_dir, final_dir) < 0) {
        vmm_destroy(vm);
        rm_rf(temp_dir);
        return -1;
    }

    // 7. Destroy template VM
    vmm_destroy(vm);

    // 8. Signal pool manager: new version available
    pool_manager_flush_and_rebuild(template_name, new_version);

    return 0;
}
