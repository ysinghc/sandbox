#ifndef SNAPSHOT_MANAGER_H
#define SNAPSHOT_MANAGER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "pool_manager.h"

#define SNAP_MAGIC 0x534E4150u  // "SNAP"

typedef struct snap_manifest_t {
    uint32_t magic;          // 0x534E4150 ("SNAP")
    uint32_t version;        // Incremented on every template rebuild
    uint64_t guest_mem_size; // Total guest memory bytes
    uint32_t page_size;      // Always 4096
    uint32_t page_count;     // guest_mem_size / page_size
    uint8_t  page_bitmap[];  // 1 bit per page: 1=present, 0=zero (packed)
} snap_manifest_t;

typedef struct {
    uint64_t memory_mib;
    uint32_t vcpu_count;
    const char* kernel_path;
    const char* rootfs_path;
    const char* ready_marker;  // serial marker, NULL = "SANDBOX-READY"
    // Host tap for the template's NIC ("net1"). Set by create_snapshot_template;
    // NULL builds a network-less template (which restores cannot retarget).
    const char* tap_name;
} template_config_t;

int create_snapshot_template(const char* template_name, const template_config_t* config);
snap_manifest_t* build_manifest(const char* memory_path);
int write_manifest(const char* path, const snap_manifest_t* manifest);
// Full validated load (mallocs *out_manifest). 0 ok, -1 missing/corrupt.
int read_manifest(const char* template_name, snap_manifest_t** out_manifest);
uint32_t read_manifest_version(const char* template_name);
bool snapshot_page_present(const snap_manifest_t* manifest, uint64_t offset);
// Version check: 1 changed (drained), 0 unchanged, -1 no snapshot.
int snapshot_check_version(pool_manager_t* pool, const char* template_name);
// Atomic publish of a staged temp dir (direct rename or backup-swap).
int snapshot_publish(const char* temp_dir, const char* final_dir);

#endif // SNAPSHOT_MANAGER_H
