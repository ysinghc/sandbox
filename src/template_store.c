// SPDX-License-Identifier: GPL-2.0-only
// #25: content-addressed, immutable template store. See template_store.h.

#define _GNU_SOURCE
#include "template_store.h"

#include <ctype.h>
#include <stdarg.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "sandbox_fs.h"
#include "sha256.h"
#include "snapshot_manager.h"

#define STORE ".store"
#define HIST_MAX 4096

int tstore_name_valid(const char* name) {
    if (!name || !isalnum((unsigned char)name[0])) return 0;
    size_t n = strlen(name);
    if (n > 64) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!isalnum(c) && c != '.' && c != '_' && c != '-') return 0;
    }
    return 1;
}

int tstore_digest_valid(const char* s) {
    if (!s || strlen(s) != TSTORE_DIGEST_LEN) return 0;
    for (int i = 0; i < TSTORE_DIGEST_LEN; i++)
        if (!isxdigit((unsigned char)s[i]) || isupper((unsigned char)s[i])) return 0;
    return 1;
}

static int pfmt(char* out, size_t n, const char* fmt, ...) __attribute__((format(printf, 3, 4)));
static int pfmt(char* out, size_t n, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(out, n, fmt, ap);
    va_end(ap);
    if (r < 0 || (size_t)r >= n) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int ensure_dirs(void) {
    char p[PATH_MAX];
    if (mkdir(snapshot_root_dir(), 0755) < 0 && errno != EEXIST) {
        // The root may be several levels deep on a fresh host.
        char cmd_path[PATH_MAX];
        if (pfmt(cmd_path, sizeof(cmd_path), "%s", snapshot_root_dir()) < 0) return -1;
        for (char* q = cmd_path + 1; *q; q++) {
            if (*q != '/') continue;
            *q = '\0';
            if (mkdir(cmd_path, 0755) < 0 && errno != EEXIST) return -1;
            *q = '/';
        }
        if (mkdir(cmd_path, 0755) < 0 && errno != EEXIST) return -1;
    }
    if (pfmt(p, sizeof(p), "%s/" STORE, snapshot_root_dir()) < 0) return -1;
    if (mkdir(p, 0755) < 0 && errno != EEXIST) return -1;
    if (pfmt(p, sizeof(p), "%s/" STORE "/history", snapshot_root_dir()) < 0) return -1;
    if (mkdir(p, 0755) < 0 && errno != EEXIST) return -1;
    return 0;
}

static int lock_store(void) {
    if (ensure_dirs() < 0) return -1;
    char p[PATH_MAX];
    if (pfmt(p, sizeof(p), "%s/" STORE "/lock", snapshot_root_dir()) < 0) return -1;
    int fd = open(p, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void unlock_store(int fd) {
    if (fd >= 0) close(fd);  // closing drops the flock
}

static void fsync_dir(const char* path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }
}

int tstore_digest(const char* ref, char out[TSTORE_DIGEST_LEN + 1]) {
    snap_manifest_t* m = NULL;
    if (read_manifest(ref, &m) < 0) return -1;
    char mem[65], vms[65], rfs[65], wks[65], krn[65] = "none";
    // The kernel is bundled beside the snapshot but not bound by the manifest.
    // It decides what the guest runs on, so it is part of the identity.
    char kp[PATH_MAX];
    uint8_t kd[32];
    if (pfmt(kp, sizeof(kp), "%s/%s/vmlinux", snapshot_root_dir(), ref) == 0 &&
        access(kp, F_OK) == 0) {
        if (sha256_file(kp, kd) < 0) {
            free(m);
            return -1;
        }
        sha256_hex(kd, krn);
    }
    sha256_hex(m->memory_sha256, mem);
    sha256_hex(m->vmstate_sha256, vms);
    sha256_hex(m->rootfs_sha256, rfs);
    sha256_hex(m->workspace_sha256, wks);
    char buf[640];
    int n = snprintf(buf, sizeof(buf),
                     "sandbox-template/v1\nmemory %s\nvmstate %s\nrootfs %s\n"
                     "workspace %s\nkernel %s\nmem_size %llu\nrootfs_size %llu\n"
                     "workspace_size %llu\n",
                     mem, vms, rfs, wks, krn, (unsigned long long)m->guest_mem_size,
                     (unsigned long long)m->rootfs_size,
                     (unsigned long long)m->workspace_size);
    free(m);
    uint8_t d[32];
    sha256(buf, (size_t)n, d);
    sha256_hex(d, out);
    return 0;
}

// ---- history ----------------------------------------------------------------

typedef struct {
    time_t ts;
    char digest[65];
} hist_t;

static int hist_path(const char* name, char* out, size_t n) {
    return pfmt(out, n, "%s/" STORE "/history/%s", snapshot_root_dir(), name);
}

static void hist_append(const char* name, const char* digest, const char* action) {
    char p[PATH_MAX];
    if (hist_path(name, p, sizeof(p)) < 0) return;
    FILE* f = fopen(p, "a");
    if (!f) return;
    fprintf(f, "%lld %s %s\n", (long long)time(NULL), digest, action);
    fflush(f);
    fsync(fileno(f));
    fclose(f);
}

// Newest last. Returns the count.
static size_t hist_read(const char* name, hist_t* out, size_t max) {
    char p[PATH_MAX];
    if (hist_path(name, p, sizeof(p)) < 0) return 0;
    FILE* f = fopen(p, "r");
    if (!f) return 0;
    size_t n = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        long long ts;
        char dg[80];
        if (sscanf(line, "%lld %79s", &ts, dg) != 2 || !tstore_digest_valid(dg)) continue;
        if (n == max) {  // keep the newest max entries
            memmove(out, out + 1, (max - 1) * sizeof(*out));
            n--;
        }
        out[n].ts = (time_t)ts;
        memcpy(out[n].digest, dg, 65);
        n++;
    }
    fclose(f);
    return n;
}

// ---- store entries ----------------------------------------------------------

static int store_dir(const char* digest, char* out, size_t n) {
    return pfmt(out, n, "%s/" STORE "/%s", snapshot_root_dir(), digest);
}

static int store_has(const char* digest) {
    char p[PATH_MAX];
    struct stat st;
    return store_dir(digest, p, sizeof(p)) == 0 && lstat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

// Read-only on disk: the daemon runs as root and ignores modes, but a stray
// non-root tool (or an unprivileged `rm`) must not be able to edit a template.
// The directory itself is locked last, after the move into the store: rename(2)
// needs write permission on a directory it moves (it rewrites its "..").
static void freeze_files(const char* dir) {
    DIR* d = opendir(dir);
    if (d) {
        struct dirent* e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            char p[PATH_MAX];
            if (pfmt(p, sizeof(p), "%s/%s", dir, e->d_name) == 0) {
                struct stat st;
                if (lstat(p, &st) == 0 && S_ISREG(st.st_mode)) chmod(p, 0444);
            }
        }
        closedir(d);
    }
}

static void remove_entry(const char* dir) {
    chmod(dir, 0755);  // a frozen directory refuses unlink for non-root
    sandbox_rm_rf(dir);
}

static uint64_t dir_bytes(const char* dir) {
    uint64_t total = 0;
    DIR* d = opendir(dir);
    if (!d) return 0;
    struct dirent* e;
    while ((e = readdir(d))) {
        char p[PATH_MAX];
        struct stat st;
        if (pfmt(p, sizeof(p), "%s/%s", dir, e->d_name) == 0 && lstat(p, &st) == 0 &&
            S_ISREG(st.st_mode))
            total += (uint64_t)st.st_blocks * 512u;  // sparse images count as allocated
    }
    closedir(d);
    return total;
}

static int write_meta(const char* dir, const char* name, const char* digest,
                      const tstore_meta_t* meta) {
    char p[PATH_MAX], tmp[PATH_MAX];
    if (pfmt(p, sizeof(p), "%s/template.json", dir) < 0) return -1;
    struct stat st;
    if (lstat(p, &st) == 0) return 0;  // adopted: keep what it was built with
    if (pfmt(tmp, sizeof(tmp), "%s/.template.json.tmp", dir) < 0) return -1;

    snap_manifest_t* m = NULL;
    char dref[PATH_MAX];
    // `dir` is under the root; read_manifest wants the path relative to it.
    size_t rl = strlen(snapshot_root_dir());
    if (strncmp(dir, snapshot_root_dir(), rl) != 0 || dir[rl] != '/') {
        errno = EINVAL;
        return -1;
    }
    if (pfmt(dref, sizeof(dref), "%s", dir + rl + 1) < 0) return -1;
    if (read_manifest(dref, &m) < 0) return -1;
    struct utsname u;
    uname(&u);
    char mem[65], rfs[65];
    sha256_hex(m->memory_sha256, mem);
    sha256_hex(m->rootfs_sha256, rfs);

    FILE* f = fopen(tmp, "w");
    if (!f) {
        free(m);
        return -1;
    }
    fprintf(f,
            "{\n  \"name\": \"%s\",\n  \"digest\": \"%s\",\n  \"created_at\": %lld,\n"
            "  \"arch\": \"%s\",\n  \"manifest_version\": %u,\n"
            "  \"guest_memory_mib\": %llu,\n  \"rootfs_size\": %llu,\n"
            "  \"workspace_size\": %llu,\n  \"memory_sha256\": \"%s\",\n"
            "  \"rootfs_sha256\": \"%s\"",
            name, digest, (long long)time(NULL), u.machine, m->version,
            (unsigned long long)(m->guest_mem_size >> 20),
            (unsigned long long)m->rootfs_size, (unsigned long long)m->workspace_size,
            mem, rfs);
    if (meta && meta->spec_name && tstore_name_valid(meta->spec_name))
        fprintf(f, ",\n  \"spec\": \"%s\"", meta->spec_name);
    if (meta && meta->spec_sha256 && tstore_digest_valid(meta->spec_sha256))
        fprintf(f, ",\n  \"spec_sha256\": \"%s\"", meta->spec_sha256);
    if (meta && meta->kernel_sha256 && tstore_digest_valid(meta->kernel_sha256))
        fprintf(f, ",\n  \"kernel_sha256\": \"%s\"", meta->kernel_sha256);
    fputs("\n}\n", f);
    free(m);
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        unlink(tmp);
        return -1;
    }
    fclose(f);
    return rename(tmp, p);
}

// Verify the template at <root>/<ref>, then move it into the store as its
// digest. If that digest is already stored the new copy is a duplicate and is
// dropped (and the stored one's age refreshed).
// The manifest's version is how the daemon notices a changed template (it drains
// its warm pool when the number differs). A staged build cannot count rebuilds --
// it is built under a staging name -- so the version is derived from the content:
// the same template always has the same version, a different one a different
// version (to within a 32-bit collision), and a rollback restores the old one.
static int stamp_version(const char* ref, const char* digest) {
    snap_manifest_t* m = NULL;
    if (read_manifest(ref, &m) < 0) return -1;
    char hex[9];
    memcpy(hex, digest, 8);
    hex[8] = '\0';
    uint32_t v = (uint32_t)strtoul(hex, NULL, 16);
    if (v == 0) v = 1;
    int rc = 0;
    if (m->version != v) {
        char p[PATH_MAX];
        m->version = v;
        rc = pfmt(p, sizeof(p), "%s/%s/manifest.bin", snapshot_root_dir(), ref);
        if (rc == 0) rc = write_manifest(p, m);
    }
    free(m);
    return rc;
}

static int ingest(const char* ref, const char* name, const tstore_meta_t* meta,
                  char digest[TSTORE_DIGEST_LEN + 1], int stamp) {
    if (snapshot_verify(ref) < 0) {
        errno = EBADMSG;
        return -1;
    }
    if (tstore_digest(ref, digest) < 0) return -1;
    char src[PATH_MAX], dst[PATH_MAX];
    if (pfmt(src, sizeof(src), "%s/%s", snapshot_root_dir(), ref) < 0) return -1;
    if (store_dir(digest, dst, sizeof(dst)) < 0) return -1;
    if (store_has(digest)) {
        utimensat(AT_FDCWD, dst, NULL, 0);
        remove_entry(src);
        return 0;
    }
    if (stamp && stamp_version(ref, digest) < 0) return -1;
    if (write_meta(src, name, digest, meta) < 0) return -1;
    freeze_files(src);
    if (rename(src, dst) < 0) return -1;
    chmod(dst, 0555);
    fsync_dir(snapshot_root_dir());
    return 0;
}

static int point_name_at(const char* name, const char* digest) {
    char tmp[PATH_MAX], final[PATH_MAX], target[PATH_MAX];
    if (pfmt(tmp, sizeof(tmp), "%s/.link-%s-%d", snapshot_root_dir(), name, (int)getpid()) < 0 ||
        pfmt(final, sizeof(final), "%s/%s", snapshot_root_dir(), name) < 0 ||
        pfmt(target, sizeof(target), STORE "/%s", digest) < 0)
        return -1;
    unlink(tmp);
    if (symlink(target, tmp) < 0) return -1;
    if (rename(tmp, final) < 0) {
        int e = errno;
        unlink(tmp);
        errno = e;
        return -1;
    }
    fsync_dir(snapshot_root_dir());
    return 0;
}

int tstore_resolve(const char* name, char out[TSTORE_DIGEST_LEN + 1]) {
    if (!tstore_name_valid(name)) {
        errno = EINVAL;
        return -1;
    }
    char p[PATH_MAX], tgt[PATH_MAX];
    if (pfmt(p, sizeof(p), "%s/%s", snapshot_root_dir(), name) < 0) return -1;
    ssize_t n = readlink(p, tgt, sizeof(tgt) - 1);
    if (n < 0) return -1;
    tgt[n] = '\0';
    if (strncmp(tgt, STORE "/", sizeof(STORE)) != 0 || !tstore_digest_valid(tgt + sizeof(STORE))) {
        errno = EINVAL;
        return -1;
    }
    memcpy(out, tgt + sizeof(STORE), TSTORE_DIGEST_LEN + 1);
    return 0;
}

int tstore_publish(const char* name, const char* staged, const tstore_meta_t* meta,
                   char digest_out[TSTORE_DIGEST_LEN + 1]) {
    if (!tstore_name_valid(name) || !staged || !*staged || strchr(staged, '/') ||
        !digest_out) {
        errno = EINVAL;
        return -1;
    }
    int lk = lock_store();
    if (lk < 0) return -1;
    int rc = -1, saved = 0, adopted = 0;
    char dg[65], np[PATH_MAX], sp[PATH_MAX];
    struct stat st;

    // A real directory already at <name> is a pre-store template: adopt it, so
    // what was being served stays reachable (and rollback-able).
    if (pfmt(np, sizeof(np), "%s/%s", snapshot_root_dir(), name) < 0) goto out;
    if (lstat(np, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (ingest(name, name, meta, dg, 0) < 0) goto out;
        hist_append(name, dg, "adopt");
        adopted = 1;
    }
    if (strcmp(staged, name) != 0) {
        if (pfmt(sp, sizeof(sp), "%s/%s", snapshot_root_dir(), staged) < 0) goto out;
        if (lstat(sp, &st) < 0) goto out;
        if (!S_ISDIR(st.st_mode)) {
            errno = ENOTDIR;
            goto out;
        }
        if (ingest(staged, name, meta, dg, 1) < 0) goto out;
    } else if (!adopted) {
        // Nothing staged and nothing legacy to adopt: there is nothing to publish.
        errno = ENOENT;
        goto out;
    }
    if (point_name_at(name, dg) < 0) goto out;
    hist_append(name, dg, "publish");
    memcpy(digest_out, dg, 65);
    rc = 0;
out:
    saved = errno;
    unlock_store(lk);
    errno = saved;
    return rc;
}

int tstore_rollback(const char* name, char digest_out[TSTORE_DIGEST_LEN + 1]) {
    if (!tstore_name_valid(name) || !digest_out) {
        errno = EINVAL;
        return -1;
    }
    int lk = lock_store();
    if (lk < 0) return -1;
    int rc = -1, saved;
    char cur[65];
    hist_t* h = malloc(HIST_MAX * sizeof(*h));
    if (!h) goto out;
    if (tstore_resolve(name, cur) < 0) goto out_free;
    size_t n = hist_read(name, h, HIST_MAX);
    for (size_t i = n; i-- > 0;) {
        if (strcmp(h[i].digest, cur) == 0 || !store_has(h[i].digest)) continue;
        if (point_name_at(name, h[i].digest) < 0) goto out_free;
        hist_append(name, h[i].digest, "rollback");
        memcpy(digest_out, h[i].digest, 65);
        rc = 0;
        goto out_free;
    }
    errno = ENOENT;  // nothing earlier to return to
out_free:
    saved = errno;
    free(h);
    errno = saved;
out:
    saved = errno;
    unlock_store(lk);
    errno = saved;
    return rc;
}

int tstore_unpublish(const char* name) {
    if (!tstore_name_valid(name)) {
        errno = EINVAL;
        return -1;
    }
    int lk = lock_store();
    if (lk < 0) return -1;
    int rc = -1, saved;
    char p[PATH_MAX], cur[65];
    if (pfmt(p, sizeof(p), "%s/%s", snapshot_root_dir(), name) < 0) goto out;
    if (tstore_resolve(name, cur) < 0) {  // refuse to delete a legacy directory
        if (errno == EINVAL) errno = EISDIR;
        goto out;
    }
    if (unlink(p) < 0) goto out;
    char hp[PATH_MAX];
    if (hist_path(name, hp, sizeof(hp)) == 0) unlink(hp);
    fsync_dir(snapshot_root_dir());
    rc = 0;
out:
    saved = errno;
    unlock_store(lk);
    errno = saved;
    return rc;
}

int tstore_verify(const char* ref) {
    char want[65], have[65], dref[PATH_MAX];
    if (tstore_digest_valid(ref)) {
        memcpy(want, ref, 65);
        if (pfmt(dref, sizeof(dref), STORE "/%s", ref) < 0) return -1;
    } else if (tstore_name_valid(ref)) {
        if (pfmt(dref, sizeof(dref), "%s", ref) < 0) return -1;
        if (tstore_resolve(ref, want) < 0) want[0] = '\0';  // legacy: hashes only
    } else {
        errno = EINVAL;
        return -1;
    }
    if (snapshot_verify(dref) < 0) return -1;
    if (tstore_digest(dref, have) < 0) return -1;
    if (want[0] && strcmp(want, have) != 0) {
        fprintf(stderr, "[template] %s: contents are %s, not the %s it is filed as\n", ref,
                have, want);
        return -1;
    }
    return 0;
}

// ---- listing and collection -------------------------------------------------

static int cmp_str(const void* a, const void* b) {
    return strcmp(*(char* const*)a, *(char* const*)b);
}

// Sorted names of the entries in dir that satisfy keep(). Caller frees.
static char** list_dir(const char* dir, int (*keep)(const char*), size_t* count) {
    *count = 0;
    DIR* d = opendir(dir);
    if (!d) return NULL;
    size_t cap = 16;
    char** v = malloc(cap * sizeof(*v));
    struct dirent* e;
    while (v && (e = readdir(d))) {
        if (!keep(e->d_name)) continue;
        if (*count == cap) {
            char** nv = realloc(v, cap * 2 * sizeof(*v));
            if (!nv) break;
            v = nv;
            cap *= 2;
        }
        v[*count] = strdup(e->d_name);
        if (v[*count]) (*count)++;
    }
    closedir(d);
    if (v && *count) qsort(v, *count, sizeof(*v), cmp_str);
    return v;
}

static void free_list(char** v, size_t n) {
    for (size_t i = 0; i < n; i++) free(v[i]);
    free(v);
}

static int keep_name(const char* s) { return tstore_name_valid(s); }
static int keep_digest(const char* s) { return tstore_digest_valid(s); }

int tstore_list(FILE* out) {
    char root_store[PATH_MAX];
    if (pfmt(root_store, sizeof(root_store), "%s/" STORE, snapshot_root_dir()) < 0) return -1;
    size_t nn, nd, i;
    char** names = list_dir(snapshot_root_dir(), keep_name, &nn);
    if (!names && access(snapshot_root_dir(), F_OK) != 0) return -1;
    char** seen = calloc(nn + 1, sizeof(*seen));  // digests that a name points at
    size_t nseen = 0;
    for (i = 0; i < nn; i++) {
        char p[PATH_MAX], dg[65];
        struct stat st;
        if (pfmt(p, sizeof(p), "%s/%s", snapshot_root_dir(), names[i]) < 0 ||
            lstat(p, &st) < 0)
            continue;
        if (S_ISLNK(st.st_mode)) {
            if (tstore_resolve(names[i], dg) < 0) continue;
            fprintf(out, "{\"name\":\"%s\",\"digest\":\"%s\",\"legacy\":false}\n", names[i], dg);
            if (seen) seen[nseen++] = strdup(dg);
        } else if (S_ISDIR(st.st_mode) && tstore_digest(names[i], dg) == 0) {
            fprintf(out, "{\"name\":\"%s\",\"digest\":\"%s\",\"legacy\":true}\n", names[i], dg);
        }
    }
    free_list(names, nn);
    char** digests = list_dir(root_store, keep_digest, &nd);
    for (i = 0; i < nd; i++) {
        int ref = 0;
        for (size_t j = 0; j < nseen; j++)
            if (seen[j] && strcmp(seen[j], digests[i]) == 0) ref = 1;
        if (ref) continue;
        char p[PATH_MAX];
        struct stat st;
        long long age = 0;
        if (pfmt(p, sizeof(p), "%s/%s", root_store, digests[i]) == 0 && lstat(p, &st) == 0)
            age = (long long)(time(NULL) - st.st_mtime);
        fprintf(out, "{\"digest\":\"%s\",\"referenced\":false,\"age_s\":%lld}\n", digests[i], age);
    }
    free_list(digests, nd);
    if (seen) free_list(seen, nseen);
    return 0;
}

typedef struct {
    char digest[65];
    char by[65];
    int current;
} ref_t;

static int add_ref(ref_t** v, size_t* n, size_t* cap, const char* dg, const char* by, int cur) {
    for (size_t i = 0; i < *n; i++) {
        if (strcmp((*v)[i].digest, dg) == 0) {
            if (cur && !(*v)[i].current) {
                (*v)[i].current = 1;
                memcpy((*v)[i].by, by, strlen(by) + 1);
            }
            return 0;
        }
    }
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 16;
        ref_t* nv = realloc(*v, nc * sizeof(**v));
        if (!nv) return -1;
        *v = nv;
        *cap = nc;
    }
    memcpy((*v)[*n].digest, dg, 65);
    snprintf((*v)[*n].by, sizeof((*v)[*n].by), "%s", by);
    (*v)[*n].current = cur;
    (*n)++;
    return 0;
}

int tstore_gc(unsigned keep, time_t min_age_s, int dry_run, FILE* report,
              tstore_gc_result_t* res) {
    tstore_gc_result_t local = {0};
    if (!res) res = &local;
    memset(res, 0, sizeof(*res));
    if (keep < 1) keep = 1;
    int lk = lock_store();
    if (lk < 0) return -1;
    int rc = -1, saved;
    ref_t* refs = NULL;
    size_t nref = 0, cap = 0, i, nnames = 0, ndig = 0;
    char **names = NULL, **digs = NULL;
    hist_t* h = malloc(HIST_MAX * sizeof(*h));
    if (!h) goto out;

    char root_store[PATH_MAX];
    if (pfmt(root_store, sizeof(root_store), "%s/" STORE, snapshot_root_dir()) < 0) goto out;
    names = list_dir(snapshot_root_dir(), keep_name, &nnames);
    for (i = 0; i < nnames; i++) {
        char cur[65];
        if (tstore_resolve(names[i], cur) == 0 &&
            add_ref(&refs, &nref, &cap, cur, names[i], 1) < 0)
            goto out;
    }
    char** hnames = NULL;
    size_t nh = 0;
    {
        char hdir[PATH_MAX];
        if (pfmt(hdir, sizeof(hdir), "%s/history", root_store) < 0) goto out;
        hnames = list_dir(hdir, keep_name, &nh);
    }
    for (i = 0; i < nh; i++) {
        size_t n = hist_read(hnames[i], h, HIST_MAX), kept = 0;
        char seen[8][65];  // distinct digests, newest first, at most `keep`
        for (size_t j = n; j-- > 0 && kept < keep && kept < 8;) {
            int dup = 0;
            for (size_t k = 0; k < kept; k++)
                if (strcmp(seen[k], h[j].digest) == 0) dup = 1;
            if (dup) continue;
            memcpy(seen[kept++], h[j].digest, 65);
            if (add_ref(&refs, &nref, &cap, h[j].digest, hnames[i], 0) < 0) {
                free_list(hnames, nh);
                goto out;
            }
        }
    }
    if (hnames) free_list(hnames, nh);

    digs = list_dir(root_store, keep_digest, &ndig);
    time_t now = time(NULL);
    for (i = 0; i < ndig; i++) {
        char p[PATH_MAX];
        struct stat st;
        if (pfmt(p, sizeof(p), "%s/%s", root_store, digs[i]) < 0 || lstat(p, &st) < 0) continue;
        const ref_t* r = NULL;
        for (size_t j = 0; j < nref; j++)
            if (strcmp(refs[j].digest, digs[i]) == 0) r = &refs[j];
        if (r) {
            res->kept_referenced++;
            if (report)
                fprintf(report, "keep   %s  %s of %s\n", digs[i],
                        r->current ? "current" : "previous", r->by);
            continue;
        }
        time_t age = now - st.st_mtime;
        if (age < min_age_s) {
            res->kept_young++;
            if (report)
                fprintf(report, "keep   %s  unreferenced, %llds old (grace %llds)\n", digs[i],
                        (long long)age, (long long)min_age_s);
            continue;
        }
        uint64_t bytes = dir_bytes(p);
        if (report)
            fprintf(report, "%s %s  unreferenced, %llds old, %llu bytes\n",
                    dry_run ? "would remove" : "remove", digs[i], (long long)age,
                    (unsigned long long)bytes);
        if (!dry_run) remove_entry(p);
        res->removed++;
        res->bytes_reclaimed += bytes;
    }
    if (!dry_run && res->removed) fsync_dir(root_store);
    rc = 0;
out:
    saved = errno;
    free(h);
    free(refs);
    if (names) free_list(names, nnames);
    if (digs) free_list(digs, ndig);
    unlock_store(lk);
    errno = saved;
    return rc;
}
