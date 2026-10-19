// SPDX-License-Identifier: GPL-2.0-only
// Phase 15: the session workspace registry (#23).
//
// Needs no root and no KVM: it exercises the parts that decide whether files
// survive a session, whether a session can outlive its TTL, and whether one
// session can reach another's volume. The VM half (a real /workspace mount) is
// covered by the privileged ipc test.
//
// The base image is a stand-in regular file rather than ext4: this test is about
// the registry and the copy, and a 512 MiB sparse ext4 would only slow the
// suite down. The real format is asserted where it is created (build-template).

#define _GNU_SOURCE

#include "workspace.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static char g_root[PATH_MAX];
static char g_base[PATH_MAX];

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        if (cond) {                                                         \
            printf("[test] %-40s PASS\n", msg);                             \
        } else {                                                            \
            printf("[test] %-40s FAIL\n", msg);                             \
            fflush(stdout);                                                 \
            abort();                                                        \
        }                                                                   \
    } while (0)

static void write_file(const char* path, const char* data, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) abort();
    if (write(fd, data, len) != (ssize_t)len) abort();
    close(fd);
}

// "Write a file" at the registry level: the guest writes through its own ext4,
// the host sees allocated bytes. Simulating it by touching the image keeps the
// assertion about *containment* (bytes counted, path namespaced) honest.
static void touch_image(const char* key, const char* tag) {
    char img[PATH_MAX];
    workspace_paths(key, NULL, 0, img, sizeof(img));
    int fd = open(img, O_WRONLY | O_APPEND);
    if (fd < 0) abort();
    if (write(fd, tag, strlen(tag)) != (ssize_t)strlen(tag)) abort();
    close(fd);
}

// Search the whole image, not a window: an appended marker lands at the end of a
// multi-megabyte file, and a capped read would call that "missing".
//
// memmem, not strstr: a sparse image is mostly NUL bytes, and strstr stops at the
// first one -- which is why this check silently saw nothing the first time.
static int image_contains(const char* key, const char* tag) {
    char img[PATH_MAX];
    workspace_paths(key, NULL, 0, img, sizeof(img));
    FILE* f = fopen(img, "r");
    if (!f) return 0;
    size_t tlen = strlen(tag);
    char* buf = malloc((1 << 16) + tlen);
    if (!buf) { fclose(f); return 0; }
    size_t keep = 0;
    int found = 0;
    for (;;) {
        size_t n = fread(buf + keep, 1, 1 << 16, f);
        if (n == 0) break;
        size_t total = keep + n;
        if (memmem(buf, total, tag, tlen)) { found = 1; break; }
        // Carry the tail so a marker split across two reads is still seen.
        keep = (tlen > 1 && total >= tlen - 1) ? tlen - 1 : total;
        memmove(buf, buf + total - keep, keep);
    }
    free(buf);
    fclose(f);
    return found;
}

static int image_exists(const char* key) {
    char img[PATH_MAX];
    workspace_paths(key, NULL, 0, img, sizeof(img));
    return access(img, F_OK) == 0;
}

// --- tests -----------------------------------------------------------------

// Offset of the first differing byte, or -1 if identical, -2 if unreadable.
static long long first_diff(const char* a, const char* b) {
    int fa = open(a, O_RDONLY);
    int fb = open(b, O_RDONLY);
    if (fa < 0 || fb < 0) {
        if (fa >= 0) close(fa);
        if (fb >= 0) close(fb);
        return -2;
    }
    static char ba[1 << 16], bb[1 << 16];
    long long off = 0, diff = -1;
    for (;;) {
        ssize_t na = read(fa, ba, sizeof(ba));
        ssize_t nb = read(fb, bb, sizeof(bb));
        if (na != nb) { diff = off; break; }
        if (na <= 0) break;
        for (ssize_t i = 0; i < na; i++) {
            if (ba[i] != bb[i]) { diff = off + i; break; }
        }
        if (diff >= 0) break;
        off += na;
    }
    close(fa);
    close(fb);
    return diff;
}

// A session volume is a live ext4 filesystem that the guest mounts, so a clone
// must be byte-identical to its base -- not merely the same size with the
// extents that SEEK_DATA happened to report. The hand-made sparse file below
// covers the copy logic; this covers the real artifact, whose extents come from
// mke2fs and look nothing like a hand-written file. A clone that silently drops
// a block here is not a small bug: the guest reports "group descriptors
// corrupted!" on mount, or worse, mounts a filesystem that is quietly wrong.
static void test_clone_of_formatted_image(void) {
    printf("[test] clone (formatted image)...\n");
    char base[PATH_MAX], copy[PATH_MAX];
    snprintf(base, sizeof(base), "%s/fmt-base.ext4", g_root);
    snprintf(copy, sizeof(copy), "%s/fmt-copy.ext4", g_root);
    unlink(base);
    unlink(copy);
    CHECK(workspace_format_base(base, 16) == 0, "format a base image");
    CHECK(workspace_clone(base, copy) == 0, "clone a formatted image");
    long long d = first_diff(base, copy);
    if (d != -1) fprintf(stderr, "[test] clone differs at byte %lld\n", d);
    CHECK(d == -1, "a cloned image is byte-identical to its base");
    unlink(base);
    unlink(copy);
}

static void test_clone_fidelity(void) {
    printf("[test] clone...\n");
    // A sparse source: a hole, data, a hole, data. A clone that ignores sparseness
    // still passes a content check; one that ignores *holes* corrupts the tail,
    // which is what the marker at the end catches.
    char src[PATH_MAX], dst[PATH_MAX];
    snprintf(src, sizeof(src), "%s/src.img", g_root);
    snprintf(dst, sizeof(dst), "%s/dst.img", g_root);
    unlink(src);
    unlink(dst);
    write_file(src, "HEAD", 4);
    if (ftruncate(open(src, O_WRONLY), 1u << 20) < 0) abort();
    int fd = open(src, O_WRONLY);
    if (pwrite(fd, "TAIL", 4, (1u << 20) - 4) != 4) abort();
    close(fd);

    CHECK(workspace_clone(src, dst) == 0, "clone returns 0");
    struct stat ss, ds;
    CHECK(stat(src, &ss) == 0 && stat(dst, &ds) == 0 && ss.st_size == ds.st_size,
          "clone preserves size");
    FILE* f = fopen(dst, "r");
    CHECK(f != NULL, "clone produced a readable image");
    char head[5] = {0}, tail[5] = {0};
    if (fread(head, 1, 4, f) != 4) abort();
    if (fseek(f, (1u << 20) - 4, SEEK_SET) != 0) abort();
    if (fread(tail, 1, 4, f) != 4) abort();
    fclose(f);
    CHECK(strcmp(head, "HEAD") == 0 && strcmp(tail, "TAIL") == 0,
          "clone copies both ends of a sparse file");

    // Same-size, different-content must not be mistaken for the same volume.
    CHECK(workspace_clone(src, dst) < 0 && errno == EEXIST,
          "clone refuses to overwrite an existing image");
    unlink(src);
    unlink(dst);
}

static void test_ensure_and_persistence(void) {
    printf("[test] ensure/persist...\n");
    workspace_meta_t m;
    CHECK(workspace_ensure("sess-a", 4242, 512, 0, g_base, &m) == 0,
          "ensure creates a session volume");
    CHECK(m.owner_uid == 4242 && m.size_mb == 512, "meta records owner and size");
    CHECK(m.expires_at - m.created_at == WORKSPACE_DEFAULT_TTL_SECONDS,
          "default TTL is the 7-day default");
    CHECK(image_exists("sess-a"), "image exists at the session path");

    touch_image("sess-a", "persisted\n");
    CHECK(image_contains("sess-a", "persisted"), "a write lands in the image");

    // Recreate the same session: the volume must be reused, not replaced, and the
    // expiry must not be silently extended (D5: renewal is explicit).
    workspace_meta_t m2;
    CHECK(workspace_ensure("sess-a", 4242, 512, 0, g_base, &m2) == 0,
          "ensure on an existing session succeeds");
    CHECK(strcmp(m.id, m2.id) == 0 && m2.created_at == m.created_at,
          "ensure reuses the same volume");
    CHECK(m2.expires_at == m.expires_at, "re-create does not extend the TTL");
    CHECK(image_contains("sess-a", "persisted"),
          "files survive a re-create (the point of the feature)");
}

static void test_ttl_clamp_and_renew(void) {
    printf("[test] ttl...\n");
    workspace_meta_t m;
    // An over-long TTL is clamped to the platform maximum, not honoured.
    CHECK(workspace_ensure("sess-long", 1, 512, 90u * 24 * 3600, g_base, &m) == 0,
          "ensure clamps a too-long TTL");
    CHECK(m.expires_at - m.created_at == (int64_t)workspace_max_ttl_seconds(),
          "TTL clamped to the platform maximum");
    // A tiny TTL is raised to the floor rather than rejected.
    CHECK(workspace_ensure("sess-short", 1, 512, 1, g_base, &m) == 0,
          "ensure raises a too-short TTL");
    CHECK(m.expires_at - m.created_at == (int64_t)WORKSPACE_MIN_TTL_SECONDS,
          "TTL raised to the minimum");

    int64_t now = (int64_t)time(NULL);
    CHECK(workspace_renew("sess-short", 3600, now, &m) == 0 &&
          m.expires_at > now + 3000 && m.renewed_at == now,
          "renew extends the expiry");
    int64_t before = m.expires_at;
    CHECK(workspace_renew("sess-short", 60, now, &m) == 0 && m.expires_at == before,
          "renew never shortens an expiry");

    // A renewal cannot push a session past created_at + max, however large the
    // request.
    int64_t capped = m.created_at + (int64_t)workspace_max_ttl_seconds();
    CHECK(workspace_renew("sess-short", 60u * 24 * 3600, now, &m) == 0 &&
          m.expires_at == capped, "renew is capped at created_at + max");

    // If the operator *tightens* the platform maximum under a live session, a
    // renewal must refuse rather than quietly grant time the policy no longer
    // allows. (expires_at > now, but created_at + max <= now.)
    setenv("SANDBOX_WORKSPACE_MAX_TTL", "60", 1);
    CHECK(workspace_renew("sess-short", 3600, m.created_at + 120, &m) < 0 &&
          errno == ERANGE, "renew refuses past the platform maximum");
    unsetenv("SANDBOX_WORKSPACE_MAX_TTL");
    CHECK(workspace_renew("sess-short", 60, now, &m) == 0 && m.expires_at == capped,
          "a later maximum does not shorten a session");
    CHECK(workspace_renew("nope", 60, now, &m) < 0 && errno == ENOENT,
          "renew of an unknown session fails");
}

static void test_reap(void) {
    printf("[test] reap...\n");
    workspace_meta_t m;
    CHECK(workspace_ensure("sess-expired", 7, 512, 60, g_base, &m) == 0,
          "create a session to expire");
    touch_image("sess-expired", "gone soon\n");
    CHECK(workspace_ensure("sess-live", 7, 512, WORKSPACE_DEFAULT_TTL_SECONDS,
                           g_base, &m) == 0,
          "create a session that must survive");

    int n = -1;
    int64_t now = (int64_t)time(NULL);
    CHECK(workspace_reap(now, &n) == 0 && n == 0,
          "reap before expiry removes nothing");
    CHECK(image_exists("sess-expired"), "not-yet-expired image is intact");

    CHECK(workspace_reap(now + 61, &n) == 0 && n == 1,
          "reap after expiry removes the volume");
    CHECK(!image_exists("sess-expired"), "expired image is gone");
    CHECK(image_exists("sess-live"), "an unexpired session is untouched");

    // Idempotent and crash-safe: a second pass is a no-op, and a half-built
    // staging directory is cleared once it is stale.
    CHECK(workspace_reap(now + 61, &n) == 0 && n == 0, "reap is idempotent");
    char staging[PATH_MAX], file[PATH_MAX];
    snprintf(staging, sizeof(staging), "%s/%s%d-halfbuilt", g_root, ".tmp-",
             (int)getpid());
    if (mkdir(staging, 0700) < 0) abort();
    snprintf(file, sizeof(file), "%s/workspace.ext4", staging);
    write_file(file, "partial", 7);
    CHECK(workspace_reap(now, &n) == 0 && access(staging, F_OK) == 0,
          "fresh staging dir is left alone (a create may be in flight)");
    CHECK(workspace_reap(now + 3601, &n) == 0 && access(staging, F_OK) != 0,
          "stale staging dir is reaped");
}

static void test_isolation_and_accounting(void) {
    printf("[test] isolation/accounting...\n");
    workspace_meta_t m;
    CHECK(workspace_ensure("sess-x", 1000, 512, 0, g_base, &m) == 0, "create x");
    CHECK(workspace_ensure("sess-y", 1001, 512, 0, g_base, &m) == 0, "create y");
    touch_image("sess-x", "x-only\n");
    CHECK(image_contains("sess-x", "x-only") && !image_contains("sess-y", "x-only"),
          "sessions have separate images");

    // A traversal-shaped key is not refused -- a conversation id may legitimately
    // contain '/', as base64 often does -- but it cannot name another session's
    // volume, because the directory is a digest of the key.
    CHECK(workspace_ensure("", 1, 512, 0, g_base, &m) < 0, "an empty key is refused");
    char dir[PATH_MAX];
    workspace_paths("../../etc/passwd", dir, sizeof(dir), NULL, 0);
    CHECK(strncmp(dir, g_root, strlen(g_root)) == 0 && !strstr(dir, ".."),
          "a traversal-shaped key still resolves inside the root");
    CHECK(workspace_destroy("../../etc/passwd") == 0,
          "and cannot delete anything outside it");

    uint64_t bytes = 0;
    uint32_t count = 0;
    CHECK(workspace_usage(1000, &bytes, &count) == 0 && count == 1 && bytes > 0,
          "accounting reports the owner's volume");
    CHECK(workspace_usage(1001, &bytes, &count) == 0 && count == 1,
          "accounting is per owner");
    CHECK(workspace_usage(9999, &bytes, &count) == 0 && count == 0 && bytes == 0,
          "an owner with no volumes accounts zero");

    // Destroy is explicit and idempotent.
    CHECK(workspace_destroy("sess-x") == 0 && !image_exists("sess-x"),
          "destroy removes the volume");
    CHECK(workspace_destroy("sess-x") == 0, "destroy is idempotent");
    CHECK(!image_contains("sess-y", "x-only"), "destroy does not touch other sessions");
}

static void test_lease(void) {
    printf("[test] lease...\n");
    // Two VMs on one image would write the same blocks through separate page
    // caches and destroy each other's files, so a session volume is exclusive.
    CHECK(workspace_lease_count() == 0, "no leases at rest");
    CHECK(workspace_lease("locked") == 0, "lease acquired");
    CHECK(workspace_lease_count() == 1, "lease counted");
    CHECK(workspace_lease("locked") < 0 && errno == EBUSY,
          "a second lease on the same session is refused");
    CHECK(workspace_lease("other") == 0 && workspace_lease_count() == 2,
          "an unrelated session can still be leased");
    CHECK(workspace_lease("") < 0, "an empty key is refused");
    workspace_release("locked");
    CHECK(workspace_lease_count() == 1, "release frees the lease");
    CHECK(workspace_lease("locked") == 0, "the session can be leased again");
    workspace_release("locked");
    workspace_release("other");
    workspace_release("never-held");  // must not corrupt the table
    CHECK(workspace_lease_count() == 0, "releasing an unheld lease is a no-op");
}

int main(void) {
    snprintf(g_root, sizeof(g_root), "/tmp/sbtest-ws-%d", (int)getpid());
    setenv("SANDBOX_WORKSPACE_ROOT", g_root, 1);
    if (mkdir(g_root, 0700) < 0) { perror("mkdir"); return 1; }
    snprintf(g_base, sizeof(g_base), "%s/base.img", g_root);
    // A 4 MiB base with real content: big enough for the sparse path to be
    // exercised, small enough to keep the suite fast.
    write_file(g_base, "BASE", 4);
    int fd = open(g_base, O_WRONLY);
    if (ftruncate(fd, 4u << 20) < 0) abort();
    if (pwrite(fd, "END", 3, (4u << 20) - 3) != 3) abort();
    close(fd);

    test_clone_of_formatted_image();
    test_clone_fidelity();
    test_ensure_and_persistence();
    test_ttl_clamp_and_renew();
    test_reap();
    test_isolation_and_accounting();
    test_lease();

    // The base image must never be handed out: it is shared by every session.
    CHECK(image_exists("sess-x") == 0, "destroyed session leaves nothing behind");
    printf("ALL WORKSPACE TESTS PASSED\n");
    return 0;
}
