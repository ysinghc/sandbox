// SPDX-License-Identifier: GPL-2.0-only
// Snapshot Manager (§5.6): manifest format, atomic template publish,
// version checking. Cold boot, guest-ready wait and capture run on the real
// VMM; the orchestration below follows the LLD flow line-for-line.

#define _DEFAULT_SOURCE

#include "snapshot_manager.h"
#include "pool_manager.h"
#include "sha256.h"
#include "sandbox_fs.h"
#include "vmm_manager.h"
#include "jailer.h"
#include "workspace.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
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

const char* snapshot_root_dir(void) { return snapshot_root(); }

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
    m->header_size = (uint32_t)sizeof(snap_manifest_t);
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
    // §10.10: bind the page bitmap to the exact bytes it describes.
    if (sha256_file(memory_path, m->memory_sha256) < 0) {
        free(m);
        return NULL;
    }
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
        hdr.header_size != (uint32_t)sizeof(snap_manifest_t) ||
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

// §10.10: compare the manifest's recorded hashes against the files on disk.
static int verify_files(const char* template_name, const snap_manifest_t* m) {
    char path[PATH_MAX];
    uint8_t digest[32];
    char got[65], want[65];

    snprintf(path, sizeof(path), "%s/%s/memory.snap", snapshot_root(), template_name);
    if (sha256_file(path, digest) < 0) {
        fprintf(stderr, "[snapshot] verify %s: cannot read %s\n", template_name, path);
        return -1;
    }
    if (memcmp(digest, m->memory_sha256, 32) != 0) {
        sha256_hex(digest, got);
        sha256_hex(m->memory_sha256, want);
        fprintf(stderr,
                "[snapshot] verify %s: memory.snap hash mismatch (got %s want %s)\n",
                template_name, got, want);
        return -1;
    }

    snprintf(path, sizeof(path), "%s/%s/vmstate", snapshot_root(), template_name);
    if (sha256_file(path, digest) < 0) {
        fprintf(stderr, "[snapshot] verify %s: cannot read %s\n", template_name, path);
        return -1;
    }
    if (memcmp(digest, m->vmstate_sha256, 32) != 0) {
        sha256_hex(digest, got);
        sha256_hex(m->vmstate_sha256, want);
        fprintf(stderr,
                "[snapshot] verify %s: vmstate hash mismatch (got %s want %s)\n",
                template_name, got, want);
        return -1;
    }

    // #22: the disk image is part of the template. A restored guest keeps the
    // page cache and inode state of the image it booted from, so a swapped
    // rootfs changes the sandbox without touching memory.snap or vmstate.
    snprintf(path, sizeof(path), "%s/%s/rootfs.ext4", snapshot_root(), template_name);
    struct stat rst;
    if (stat(path, &rst) < 0) {
        fprintf(stderr, "[snapshot] verify %s: cannot stat %s\n", template_name, path);
        return -1;
    }
    if (m->rootfs_size && (uint64_t)rst.st_size != m->rootfs_size) {
        fprintf(stderr,
                "[snapshot] verify %s: rootfs.ext4 is %lld bytes, snapshot expects %llu\n",
                template_name, (long long)rst.st_size,
                (unsigned long long)m->rootfs_size);
        return -1;
    }
    if (sha256_file(path, digest) < 0) {
        fprintf(stderr, "[snapshot] verify %s: cannot read %s\n", template_name, path);
        return -1;
    }
    if (memcmp(digest, m->rootfs_sha256, 32) != 0) {
        sha256_hex(digest, got);
        sha256_hex(m->rootfs_sha256, want);
        fprintf(stderr,
                "[snapshot] verify %s: rootfs hash mismatch (got %s want %s)\n",
                template_name, got, want);
        return -1;
    }

    // #23: the base image new sessions are cloned from. Not captured state, but
    // it decides what every future session's /workspace starts as.
    snprintf(path, sizeof(path), "%s/%s/base_workspace.ext4", snapshot_root(),
             template_name);
    if (m->workspace_size) {
        struct stat wst;
        if (stat(path, &wst) < 0) {
            fprintf(stderr, "[snapshot] verify %s: cannot stat %s\n", template_name,
                    path);
            return -1;
        }
        if ((uint64_t)wst.st_size != m->workspace_size) {
            fprintf(stderr,
                    "[snapshot] verify %s: base_workspace.ext4 is %lld bytes, "
                    "snapshot expects %llu\n",
                    template_name, (long long)wst.st_size,
                    (unsigned long long)m->workspace_size);
            return -1;
        }
        if (sha256_file(path, digest) < 0) {
            fprintf(stderr, "[snapshot] verify %s: cannot read %s\n", template_name,
                    path);
            return -1;
        }
        if (memcmp(digest, m->workspace_sha256, 32) != 0) {
            sha256_hex(digest, got);
            sha256_hex(m->workspace_sha256, want);
            fprintf(stderr,
                    "[snapshot] verify %s: workspace base hash mismatch "
                    "(got %s want %s)\n",
                    template_name, got, want);
            return -1;
        }
    }
    return 0;
}

// §10.10 verification re-hashes the whole memory.snap (hundreds of MiB). That is
// far too slow to repeat on every restore (measured: ~640 ms per restore for a
// 256 MiB guest, vs an 8 ms snapshot-load). A published snapshot is immutable —
// publishing renames a freshly built directory into place, so a rebuild changes
// the inodes — therefore remember a successful verification keyed by the two
// files' (dev, ino, size, mtime). A rebuilt snapshot misses the cache and is
// re-verified; an untouched one is not hashed again. This keeps the corruption
// check without paying it in the restore hot path.
#define VERIFY_CACHE_MAX 8
typedef struct {
    char   name[64];
    dev_t  mem_dev; ino_t mem_ino; off_t mem_size; time_t mem_mtime;
    dev_t  vms_dev; ino_t vms_ino; off_t vms_size; time_t vms_mtime;
    dev_t  rfs_dev; ino_t rfs_ino; off_t rfs_size; time_t rfs_mtime;
    dev_t  ws_dev;  ino_t ws_ino;  off_t ws_size;  time_t ws_mtime;
    bool   valid;
} verify_cache_t;

static verify_cache_t g_verify_cache[VERIFY_CACHE_MAX];
static size_t g_verify_cache_len;
static pthread_mutex_t g_verify_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static bool verify_sig_eq(dev_t dev, ino_t ino, off_t size, time_t mtime,
                          const struct stat* st) {
    return dev == st->st_dev && ino == st->st_ino &&
           size == st->st_size && mtime == st->st_mtime;
}

static bool verify_cache_hit(const char* name, const struct stat* ms,
                             const struct stat* vs, const struct stat* rs,
                             const struct stat* ws) {
    bool hit = false;
    pthread_mutex_lock(&g_verify_cache_lock);
    for (size_t i = 0; i < g_verify_cache_len; i++) {
        verify_cache_t* c = &g_verify_cache[i];
        if (c->valid && strcmp(c->name, name) == 0 &&
            verify_sig_eq(c->mem_dev, c->mem_ino, c->mem_size, c->mem_mtime, ms) &&
            verify_sig_eq(c->vms_dev, c->vms_ino, c->vms_size, c->vms_mtime, vs) &&
            verify_sig_eq(c->rfs_dev, c->rfs_ino, c->rfs_size, c->rfs_mtime, rs) &&
            verify_sig_eq(c->ws_dev, c->ws_ino, c->ws_size, c->ws_mtime, ws)) {
            hit = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_verify_cache_lock);
    return hit;
}

static void verify_cache_put(const char* name, const struct stat* ms,
                             const struct stat* vs, const struct stat* rs,
                             const struct stat* ws) {
    pthread_mutex_lock(&g_verify_cache_lock);
    verify_cache_t* c = NULL;
    for (size_t i = 0; i < g_verify_cache_len; i++) {
        if (strcmp(g_verify_cache[i].name, name) == 0) {
            c = &g_verify_cache[i];
            break;
        }
    }
    if (!c) {
        c = (g_verify_cache_len < VERIFY_CACHE_MAX)
                ? &g_verify_cache[g_verify_cache_len++]
                : &g_verify_cache[0];  // few templates; evict slot 0
    }
    snprintf(c->name, sizeof(c->name), "%s", name);
    c->mem_dev = ms->st_dev; c->mem_ino = ms->st_ino;
    c->mem_size = ms->st_size; c->mem_mtime = ms->st_mtime;
    c->vms_dev = vs->st_dev; c->vms_ino = vs->st_ino;
    c->vms_size = vs->st_size; c->vms_mtime = vs->st_mtime;
    c->rfs_dev = rs->st_dev; c->rfs_ino = rs->st_ino;
    c->rfs_size = rs->st_size; c->rfs_mtime = rs->st_mtime;
    c->ws_dev = ws->st_dev; c->ws_ino = ws->st_ino;
    c->ws_size = ws->st_size; c->ws_mtime = ws->st_mtime;
    c->valid = true;
    pthread_mutex_unlock(&g_verify_cache_lock);
}

int snapshot_verify_manifest(const char* template_name,
                             const snap_manifest_t* manifest) {
    if (!template_name || !manifest) { errno = EINVAL; return -1; }
    const char* e = getenv("SANDBOX_VERIFY_SNAPSHOT");
    if (e && (strcmp(e, "0") == 0 || strcmp(e, "false") == 0)) return 0;

    char mpath[PATH_MAX], vpath[PATH_MAX], rpath[PATH_MAX], wpath[PATH_MAX];
    struct stat ms, vs, rs, ws;
    snprintf(mpath, sizeof(mpath), "%s/%s/memory.snap", snapshot_root(), template_name);
    snprintf(vpath, sizeof(vpath), "%s/%s/vmstate", snapshot_root(), template_name);
    snprintf(rpath, sizeof(rpath), "%s/%s/rootfs.ext4", snapshot_root(), template_name);
    // The base workspace image is optional (pre-#23 templates have none). A
    // missing one leaves the signature zeroed, which cannot match a cached
    // entry, so a template that gains a workspace is re-verified once.
    snprintf(wpath, sizeof(wpath), "%s/%s/base_workspace.ext4", snapshot_root(),
             template_name);
    memset(&ws, 0, sizeof(ws));
    bool have_ws = stat(wpath, &ws) == 0;
    bool have_sig = stat(mpath, &ms) == 0 && stat(vpath, &vs) == 0 &&
                    stat(rpath, &rs) == 0 && (have_ws || manifest->workspace_size == 0);
    if (have_sig && verify_cache_hit(template_name, &ms, &vs, &rs, &ws)) return 0;

    int rc = verify_files(template_name, manifest);
    if (rc == 0 && have_sig) verify_cache_put(template_name, &ms, &vs, &rs, &ws);
    return rc;
}

int snapshot_verify(const char* template_name) {
    if (!template_name || !*template_name) { errno = EINVAL; return -1; }
    snap_manifest_t* m = NULL;
    if (read_manifest(template_name, &m) < 0) {
        fprintf(stderr, "[snapshot] verify %s: manifest missing/corrupt\n",
                template_name);
        return -1;
    }
    int rc = verify_files(template_name, m);
    if (rc == 0) {
        fprintf(stderr, "[snapshot] verify %s: OK (v%u, %u pages)\n",
                template_name, m->version, m->page_count);
    }
    free(m);
    return rc;
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

// VMM seams (real Firecracker; static shims keep the LLD call shape).
static int wait_for_guest_ready(vm_handle_t* vm, const template_config_t* config) {
    const char* marker = (config && config->ready_marker) ? config->ready_marker
                                                          : "SANDBOX-READY";
    return vmm_wait_ready(vm, marker, 60000);
}

static int firecracker_create_snapshot(vm_handle_t* vm, const char* vmstate_path,
                                       const char* memory_path) {
    (void)vmstate_path;
    (void)memory_path;
    // temp_dir is bound at $jail/out, so capture lands in the staging dir.
    return vmm_snapshot(vm, "/out/vmstate", "/out/memory.snap");
}

static int rm_rf(const char* path) {
    return sandbox_rm_rf(path);
}

static int copy_into(const char* src, const char* dst) {
    return sandbox_copy_file(src, dst);
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
    if (mkdir_recursive(snapshot_root(), 0755) < 0) return -1;
    if (mkdir(temp_dir, 0755) < 0) return -1;

    // Template jail is ephemeral: capture binds temp_dir at $jail/out, and
    // vmm_destroy below reclaims the whole jail (product stays in temp_dir).
    char tjail[PATH_MAX], tvm_id[128];
    // The VM id has to be a legal Firecracker id ([A-Za-z0-9-]) *and* short: the
    // template's tap device is "tap-<id>" and an interface name holds 15
    // characters, so the id holds 11. A template name can hold '.'/'_' and be 64
    // long (and the store stages builds as ".build-<name>"), so derive the id from
    // a hash of the name. Two templates being built at once would need a 28-bit
    // collision to share it.
    uint32_t h = 2166136261u;  // FNV-1a
    for (const char* c = template_name; *c; c++) h = (h ^ (uint8_t)*c) * 16777619u;
    snprintf(tvm_id, sizeof(tvm_id), "tpl-%07x", h & 0x0fffffffu);
    if (vmm_jail_path(tvm_id, tjail, sizeof(tjail)) < 0) {
        rm_rf(temp_dir);
        return -1;
    }
    rm_rf(tjail);  // stale jail from a crashed run

    // #23/D7: format the session workspace's base image *here*, once, at template
    // build time. Sessions clone it (reflink or a sparse copy) instead of
    // running mkfs, which is what keeps session creation inside the latency
    // budget. The drive is attached for the boot below, but the guest does not
    // mount it before the capture -- a captured mount would bake the base
    // image's ext4 state and page cache into the snapshot, and a restore serves a
    // different file behind the same device. The guest agent mounts the volume
    // after each restore instead.
    char ws_base[PATH_MAX];
    ws_base[0] = '\0';
    if (config->workspace_size_mb) {
        snprintf(ws_base, sizeof(ws_base), "%s/base_workspace.ext4", temp_dir);
        if (workspace_format_base(ws_base, config->workspace_size_mb) < 0) {
            fprintf(stderr, "[snapshot] cannot format %s: %s\n", ws_base,
                    strerror(errno));
            rm_rf(temp_dir);
            return -1;
        }
    }

    // Templates carry a NIC so restores can retarget its host tap via the load
    // request's network_overrides (§5.7). The tap must exist at boot: the
    // template VM opens it during InstanceStart. A NIC-less template would
    // leave restores unable to reach the guest at all.
    vm_network_t tpl_net;
    memset(&tpl_net, 0, sizeof(tpl_net));
    bool tpl_net_up = false;
    template_config_t local = *config;
    local.tap_name = NULL;
    local.workspace_path = ws_base[0] ? ws_base : NULL;
    if (network_setup(tvm_id, &tpl_net) == 0) {
        local.tap_name = tpl_net.tap_name;
        tpl_net_up = true;
    } else {
        fprintf(stderr, "[snapshot] WARN: template NIC setup failed (errno=%d); "
                        "restores will lack networking\n", errno);
    }

    // 1. Boot a fresh VM (cold boot, ~125ms).
    vm_handle_t* vm = vmm_cold_boot(&local, tvm_id, tjail, temp_dir);
    if (!vm) {
        if (tpl_net_up) network_cleanup(&tpl_net);
        rm_rf(temp_dir); rm_rf(tjail);
        return -1;
    }
    if (tpl_net_up) {  // hand the tap to the VM: vmm_destroy reclaims it
        vm->net = tpl_net;
        vm->has_net = true;
        tpl_net_up = false;
    }

    // 2. Wait for application init to complete inside guest
    if (wait_for_guest_ready(vm, config) < 0) {
        vmm_destroy(vm);
        rm_rf(temp_dir);
        return -1;
    }

    // 3. Pause vCPUs
    if (vmm_pause_vcpus(vm) < 0) { vmm_destroy(vm); rm_rf(temp_dir); return -1; }

    // 4. Call Firecracker API: create_snapshot (lands in temp_dir via /out)
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
    // §10.10: bind the captured vmstate too (memory.snap was hashed in
    // build_manifest). A truncated/corrupt capture is refused at restore.
    if (sha256_file(vmstate_path, manifest->vmstate_sha256) < 0) {
        fprintf(stderr, "[snapshot] failed to hash %s\n", vmstate_path);
        free(manifest);
        vmm_destroy(vm);
        rm_rf(temp_dir);
        return -1;
    }

    uint32_t new_version = manifest->version;

    // Bundle kernel+rootfs so restores are store-contained (same jail paths).
    char dst[PATH_MAX];
    snprintf(dst, sizeof(dst), "%s/vmlinux", temp_dir);
    if (copy_into(config->kernel_path, dst) < 0) {
        free(manifest);
        vmm_destroy(vm);
        rm_rf(temp_dir);
        return -1;
    }
    char rootfs_dst[PATH_MAX];
    snprintf(rootfs_dst, sizeof(rootfs_dst), "%s/rootfs.ext4", temp_dir);
    if (copy_into(config->rootfs_path, rootfs_dst) < 0) {
        free(manifest);
        vmm_destroy(vm);
        rm_rf(temp_dir);
        return -1;
    }
    // #22: pin the image the captured memory state booted from. Computed here,
    // at build time, so the restore path only has to hash it once (the
    // verify-once cache) instead of on every restore.
    struct stat rst;
    if (stat(rootfs_dst, &rst) < 0 ||
        sha256_file(rootfs_dst, manifest->rootfs_sha256) < 0) {
        fprintf(stderr, "[snapshot] failed to hash %s\n", rootfs_dst);
        free(manifest);
        vmm_destroy(vm);
        rm_rf(temp_dir);
        return -1;
    }
    manifest->rootfs_size = (uint64_t)rst.st_size;

    // #23: pin the base workspace image too. It is not captured state, but it
    // decides what every future session's /workspace starts as, so a silent
    // substitution would change new sandboxes of this template.
    if (config->workspace_size_mb) {
        struct stat wst;
        if (stat(ws_base, &wst) < 0 ||
            sha256_file(ws_base, manifest->workspace_sha256) < 0) {
            fprintf(stderr, "[snapshot] failed to hash %s\n", ws_base);
            free(manifest);
            vmm_destroy(vm);
            rm_rf(temp_dir);
            return -1;
        }
        manifest->workspace_size = (uint64_t)wst.st_size;
    }

    char manifest_path[PATH_MAX];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.bin", temp_dir);
    int rc = write_manifest(manifest_path, manifest);
    free(manifest);
    if (rc < 0) { vmm_destroy(vm); rm_rf(temp_dir); return -1; }

    // Debug artifact: preserve the template VM's boot serial (guest init +
    // Firecracker device logs before capture). Best-effort.
    {
        char tserial[PATH_MAX], dserial[PATH_MAX];
        snprintf(tserial, sizeof(tserial), "%s/serial.log", tjail);
        snprintf(dserial, sizeof(dserial), "%s/boot-serial.log", temp_dir);
        copy_into(tserial, dserial);
    }

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
