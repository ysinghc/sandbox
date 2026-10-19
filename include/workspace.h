// SPDX-License-Identifier: GPL-2.0-only
//
// workspace — per-session writable /workspace volumes (#23).
//
// Firecracker cannot swap a block device on restore (only network/vsock
// overrides exist), so a session's writable disk must be present at the *same
// in-jail path* the template was captured with. The engine therefore
// bind-mounts `/workspace.ext4` into the jail, exactly as it already does for
// `/rootfs.ext4`; the per-session image behind that path is what makes files
// survive a destroy + re-create of the same session.
//
// This module owns the image and its registry. It never mounts and never
// formats: the base image is formatted once at template-build time (D7) and
// cloned per session, so the create path stays inside the latency budget.

#ifndef WORKSPACE_H
#define WORKSPACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// Fixed jail path. The guest kernel was told about this device at capture time,
// so it must not change between the template and every restore of it.
#define WORKSPACE_JAILVIEW "/workspace.ext4"

#define WORKSPACE_DEFAULT_ROOT "/var/lib/sandbox-engine/workspaces"

// TTL policy (D5): absolute from creation, configurable per session by the
// creator, clamped to a platform maximum. Never renewed automatically.
#define WORKSPACE_DEFAULT_TTL_SECONDS 604800u      // 7 days
#define WORKSPACE_MIN_TTL_SECONDS 60u
#define WORKSPACE_DEFAULT_MAX_TTL_SECONDS 2592000u // 30 days

#define WORKSPACE_DEFAULT_SIZE_MB 512u

// One registry row. `id` is sha256_hex(session_key): using the digest as the
// directory name both isolates sessions by construction and makes a
// caller-supplied key (which becomes a path) impossible to traverse with.
typedef struct {
    char      id[65];
    char      session_key[128];
    uid_t     owner_uid;
    uint32_t  size_mb;
    int64_t   created_at;   // unix seconds
    int64_t   expires_at;   // absolute, measured from creation
    int64_t   renewed_at;   // 0 = never renewed
    uint64_t  bytes_used;   // allocated bytes, refreshed on create/renew
} workspace_meta_t;

// Root of the session store; `SANDBOX_WORKSPACE_ROOT` overrides it (tests).
const char* workspace_root(void);

// Platform maximum lifetime; `SANDBOX_WORKSPACE_MAX_TTL` overrides it.
uint32_t workspace_max_ttl_seconds(void);

// Resolve a session key to its directory and image paths. Never fails for a
// non-empty key, and never escapes `workspace_root()`.
void workspace_paths(const char* session_key, char* dir, size_t dir_n,
                     char* image, size_t image_n);

// Copy `src` to a fresh `dst`, preferring reflink (FICLONE: btrfs/xfs), then a
// sparse-aware SEEK_DATA/SEEK_HOLE copy, then a plain copy. Returns 0 or -1
// with errno set; on failure `dst` is unlinked.
int workspace_clone(const char* src, const char* dst);

// Create the session's volume if absent, else return the existing one. `out`
// receives the (possibly pre-existing) registry row. `ttl_seconds == 0` means
// the default. Never extends an existing expiry: re-creating a sandbox must not
// silently buy more lifetime.
int workspace_ensure(const char* session_key, uid_t owner_uid, uint32_t size_mb,
                     uint32_t ttl_seconds, const char* base_image,
                     workspace_meta_t* out);

// Read the registry row for a session. Returns 0, or -1/ENOENT if unknown.
int workspace_load_meta(const char* session_key, workspace_meta_t* out);

// Make the session image usable by the jailed VMM: Firecracker opens the
// workspace read-write as the jailer uid, so the image must be owned by it.
// Session directories are 0700, which is what keeps other local users out.
int workspace_chown(const char* session_key, uid_t uid, gid_t gid);

// Extend a session's TTL by `extra_seconds`, capped at `created_at + max`. Never
// shortens an existing expiry; returns -1/ERANGE once the session is past the
// platform maximum.
int workspace_renew(const char* session_key, uint32_t extra_seconds, int64_t now,
                    workspace_meta_t* out);

// Delete the image and its registry row (idempotent).
int workspace_destroy(const char* session_key);

// Reap every session whose expiry is <= `now`, plus abandoned staging dirs.
// Idempotent and crash-safe: a partial create lives in a staging directory and
// is never visible as a session. Returns the number reaped in *expired_out.
int workspace_reap(int64_t now, int* expired_out);

// Accounted usage for one owner: allocated bytes and volume count.
int workspace_usage(uid_t owner, uint64_t* bytes, uint32_t* count);

// Path of the base image a template stores next to its snapshot files.
void workspace_base_path(const char* template, char* out, size_t n);

#endif // WORKSPACE_H
