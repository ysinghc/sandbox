// SPDX-License-Identifier: GPL-2.0-only
#ifndef TEMPLATE_STORE_H
#define TEMPLATE_STORE_H

// #25: content-addressed, immutable template store.
//
//   <root>/.store/<digest>/   the template (memory.snap, vmstate, rootfs.ext4,
//                             base_workspace.ext4, manifest.bin, template.json)
//   <root>/<name>             symlink -> .store/<digest>  (what the daemon opens)
//   <root>/.store/history/<name>   append-only "unix_ts digest action" log
//
// The digest is SHA-256 over the hashes and sizes of the payload files the
// manifest already binds (memory, vmstate, rootfs, workspace base), so two
// templates are the same template exactly when their payloads are. A published
// store directory is never modified; "publish" and "rollback" only repoint the
// name symlink (one rename(2), so a concurrent restore sees the old or the new
// template, never neither). template.json is metadata and is not part of the
// identity.

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define TSTORE_DIGEST_LEN 64

typedef struct {
    // All optional, hex or NULL. Recorded in template.json so a template can be
    // traced to the spec and inputs it was built from.
    const char* spec_sha256;
    const char* kernel_sha256;
    const char* spec_name;
} tstore_meta_t;

// [A-Za-z0-9][A-Za-z0-9._-]{0,63}. Never starts with '.', so it cannot collide
// with the store's own entries or escape the root.
int tstore_name_valid(const char* name);
int tstore_digest_valid(const char* s);

// Digest of the template at <root>/<ref> (a name, or ".store/<digest>"). Reads
// the manifest only; use tstore_verify to re-hash the payloads.
int tstore_digest(const char* ref, char out[TSTORE_DIGEST_LEN + 1]);

// Publish the staged template <root>/<staged> as <name>: move it into the store
// (dropped as a duplicate if that digest is already stored), make it read-only,
// and atomically point <name> at it. A legacy real directory already at <name>
// is adopted into the store first. 0 ok, -1 error (errno / stderr).
int tstore_publish(const char* name, const char* staged, const tstore_meta_t* meta,
                   char digest_out[TSTORE_DIGEST_LEN + 1]);

// Digest <name> currently points at; -1 if it is not a store template.
int tstore_resolve(const char* name, char out[TSTORE_DIGEST_LEN + 1]);

// Point <name> at the digest it served before the current one (that is still
// stored). Calling it again returns to the newer one.
int tstore_rollback(const char* name, char digest_out[TSTORE_DIGEST_LEN + 1]);

// Withdraw <name>; its store entries become collectable once unreferenced.
int tstore_unpublish(const char* name);

// Re-hash the payloads of <name> (or of a store digest) against its manifest and
// check the directory really is the digest it is named. 0 intact, -1 not.
int tstore_verify(const char* name_or_digest);

// One JSON object per line: every name, then store entries nothing points at.
int tstore_list(FILE* out);

typedef struct {
    unsigned removed, kept_referenced, kept_young;
    uint64_t bytes_reclaimed;
} tstore_gc_result_t;

// Collect store entries that no name points at and no name's last `keep`
// histories (keep >= 1; 2 keeps the previous version for rollback) refer to,
// and that are at least min_age_s old. dry_run reports without deleting. Every
// decision is written to `report` (one line each) when it is not NULL.
int tstore_gc(unsigned keep, time_t min_age_s, int dry_run, FILE* report,
              tstore_gc_result_t* res);

#endif  // TEMPLATE_STORE_H
