// SPDX-License-Identifier: GPL-2.0-only
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
    uint32_t header_size;    // sizeof(snap_manifest_t) — format guard (§10.10)
    uint64_t guest_mem_size; // Total guest memory bytes
    uint32_t page_size;      // Always 4096
    uint32_t page_count;     // guest_mem_size / page_size
    uint8_t  memory_sha256[32];   // SHA-256 of memory.snap (§10.10)
    uint8_t  vmstate_sha256[32];  // SHA-256 of vmstate (§10.10)
    // #22: the rootfs is part of the captured state, not a bystander. The
    // guest's page cache, mount state and inode expectations all refer to the
    // image it booted from, so swapping rootfs.ext4 under a snapshot silently
    // changes the sandbox. Bound at capture, verified at restore.
    uint8_t  rootfs_sha256[32];   // SHA-256 of rootfs.ext4
    uint64_t rootfs_size;         // bytes, checked before hashing
    // #23: the base image every session workspace is cloned from. It is not
    // captured guest state, but it decides what a *new* session's /workspace
    // contains, so substituting it silently changes every future sandbox of this
    // template. workspace_size == 0 means the template has no workspace drive.
    uint8_t  workspace_sha256[32];  // SHA-256 of base_workspace.ext4
    uint64_t workspace_size;        // bytes, checked before hashing
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
    // #23: size of the session workspace base image. 0 builds a template with no
    // workspace drive (the pre-#23 shape). Any other value formats a sparse ext4
    // of that many MiB at build time and attaches it, so the guest mounts
    // /workspace and every restore has a device to bind a session image to.
    uint32_t workspace_size_mb;
    // Host path of that base image. Internal: create_snapshot_template formats
    // the image inside the staging directory and sets this before the boot, so
    // the caller never has to produce one.
    const char* workspace_path;
} template_config_t;

// The template store root (SANDBOX_SNAPSHOT_ROOT, else the installed default).
const char* snapshot_root_dir(void);

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

// §10.10: recompute SHA-256 of memory.snap and vmstate and compare against the
// manifest. Returns 0 if intact, -1 if missing/corrupt/unreadable. Verbose
// reason goes to stderr.
int snapshot_verify(const char* template_name);

// Same checks but against an already-loaded manifest (used on the restore
// path). Honours SANDBOX_VERIFY_SNAPSHOT=0 to skip the (expensive) hash pass;
// returns 0 when disabled.
int snapshot_verify_manifest(const char* template_name,
                             const snap_manifest_t* manifest);

#endif // SNAPSHOT_MANAGER_H
