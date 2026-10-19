// SPDX-License-Identifier: GPL-2.0-only
//
// workspace — see include/workspace.h for the design notes.

#define _GNU_SOURCE

#include "workspace.h"

#include "jailer.h"        // mkdir_recursive
#include "sandbox_fs.h"    // sandbox_rm_rf
#include "sha256.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

// Keep in step with snapshot_manager.c; a workspace base image lives beside the
// template's snapshot files so one store holds everything a restore needs.
#define SNAPSHOT_DEFAULT_ROOT "/var/lib/sandbox-engine/snapshots"

#define WS_STAGING_PREFIX ".tmp-"
#define WS_STAGING_GRACE_SECONDS 3600   // abandoned staging dirs
#define WS_ORPHAN_GRACE_SECONDS 86400   // dirs with no registry row at all
#define WS_KEY_MAX 127

const char* workspace_root(void) {
    const char* e = getenv("SANDBOX_WORKSPACE_ROOT");
    return (e && *e) ? e : WORKSPACE_DEFAULT_ROOT;
}

uint32_t workspace_max_ttl_seconds(void) {
    const char* e = getenv("SANDBOX_WORKSPACE_MAX_TTL");
    if (e && *e) {
        unsigned long v = strtoul(e, NULL, 10);
        if (v >= WORKSPACE_MIN_TTL_SECONDS) return (uint32_t)v;
    }
    return WORKSPACE_DEFAULT_MAX_TTL_SECONDS;
}

// A session key becomes a directory name, so refuse anything that could be
// ambiguous in a path or in the JSON registry. The digest is the actual
// directory name, which is what makes traversal impossible; this check exists so
// that the *key* stays round-trippable and human-readable in meta.json.
static int key_valid(const char* key) {
    if (!key || !*key) return 0;
    size_t n = strlen(key);
    if (n > WS_KEY_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)key[i];
        if (c < 0x20 || c == 0x7f || c == '"' || c == '\\') return 0;
    }
    return 1;
}

static void session_id(const char* key, char out[65]) {
    uint8_t d[32];
    sha256(key, strlen(key), d);
    sha256_hex(d, out);
}

void workspace_paths(const char* session_key, char* dir, size_t dir_n,
                     char* image, size_t image_n) {
    char id[65];
    session_id(session_key, id);
    if (dir && dir_n) snprintf(dir, dir_n, "%s/%s", workspace_root(), id);
    if (image && image_n) snprintf(image, image_n, "%s/%s/" WORKSPACE_IMAGE_NAME,
                                   workspace_root(), id);
}

void workspace_base_path(const char* template, char* out, size_t n) {
    const char* root = getenv("SANDBOX_SNAPSHOT_ROOT");
    if (!root || !*root) root = SNAPSHOT_DEFAULT_ROOT;
    snprintf(out, n, "%s/%s/base_" WORKSPACE_IMAGE_NAME, root, template);
}

// --- base image ------------------------------------------------------------

int workspace_format_base(const char* path, uint32_t size_mb) {
    if (!path || !*path || size_mb == 0) { errno = EINVAL; return -1; }

    // Sparse: only the ext4 metadata occupies blocks, so a 512 MiB volume costs
    // a few MiB on disk and clones in milliseconds.
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)size_mb * 1024 * 1024) < 0) {
        int e = errno;
        close(fd);
        unlink(path);
        errno = e;
        return -1;
    }
    close(fd);

    // exec, never system(): this runs at template-build time on a path the
    // caller chose, and a shell would interpret it. This is the *only* mkfs in
    // the session path's lifetime (D7) -- format once, clone per session.
    const char* mkfs = NULL;
    const char* candidates[] = {"/sbin/mkfs.ext4", "/usr/sbin/mkfs.ext4",
                                "/usr/bin/mkfs.ext4", "/bin/mkfs.ext4"};
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (access(candidates[i], X_OK) == 0) { mkfs = candidates[i]; break; }
    }
    if (!mkfs) {
        fprintf(stderr, "[workspace] cannot format %s: no mkfs.ext4 found "
                        "(install e2fsprogs)\n", path);
        unlink(path);
        errno = ENOENT;
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        int e = errno;
        unlink(path);
        errno = e;
        return -1;
    }
    if (pid == 0) {
        // -F: it is a plain file, not a block device. -q: no chatter.
        // -m 0: no root reserve; the volume is entirely the tenant's.
        // -E lazy_itable_init: do not zero the inode tables up front.
        execl(mkfs, mkfs, "-F", "-q", "-m", "0", "-E", "lazy_itable_init", path,
              (char*)NULL);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        int e = errno;
        unlink(path);
        errno = e;
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[workspace] %s failed on %s (status %d)\n", mkfs, path,
                status);
        unlink(path);
        errno = EIO;
        return -1;
    }
    fprintf(stderr,
            "[workspace] formatted base image %s (%u MiB, sparse)\n", path,
            size_mb);
    return 0;
}

// --- image copy ------------------------------------------------------------
int workspace_clone(const char* src, const char* dst) {
    if (!src || !dst) { errno = EINVAL; return -1; }

    int sfd = open(src, O_RDONLY | O_CLOEXEC);
    if (sfd < 0) return -1;
    int dfd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (dfd < 0) { int e = errno; close(sfd); errno = e; return -1; }

    // 1. Reflink (btrfs/xfs): copy-on-write, no data movement.
    if (ioctl(dfd, FICLONE, sfd) == 0) {
        close(sfd);
        close(dfd);
        return 0;
    }
    int reflink_errno = errno;  // EOPNOTSUPP/EXDEV/EINVAL on ext4
    if (reflink_errno != EOPNOTSUPP && reflink_errno != EXDEV &&
        reflink_errno != EINVAL && reflink_errno != ENOTTY) {
        goto fail;
    }

    // 2. Sparse-aware copy: transfer only the allocated extents.
    {
        struct stat st;
        if (fstat(sfd, &st) < 0) goto fail;
        if (ftruncate(dfd, st.st_size) < 0) goto fail;
        bool sparse_ok = true;
        for (off_t pos = 0; pos < st.st_size;) {
            off_t data = lseek(sfd, pos, SEEK_DATA);
            if (data < 0) {
                if (errno == ENXIO) break;  // no data left
                sparse_ok = false;
                break;
            }
            off_t hole = lseek(sfd, data, SEEK_HOLE);
            if (hole < 0) hole = st.st_size;
            if (lseek(dfd, data, SEEK_SET) < 0 || lseek(sfd, data, SEEK_SET) < 0) {
                sparse_ok = false;
                break;
            }
            off_t left = hole - data;
            while (left > 0) {
                size_t chunk = (size_t)(left > (1 << 20) ? (1 << 20) : left);
                ssize_t sent = sendfile(dfd, sfd, NULL, chunk);
                if (sent <= 0) { sparse_ok = false; break; }
                left -= sent;
            }
            if (!sparse_ok) break;
            pos = hole;
        }
        if (sparse_ok) {
            close(sfd);
            close(dfd);
            return 0;
        }
        // Fall through to the plain copy; the file is already sized.
        if (lseek(sfd, 0, SEEK_SET) < 0 || lseek(dfd, 0, SEEK_SET) < 0) goto fail;
    }

    // 3. Plain copy. Correct on any filesystem, and worth a warning: the design
    //    assumed reflink or a sparse copy, so this path means an unexpected
    //    filesystem (and a much slower create).
    fprintf(stderr, "[workspace] WARNING: plain copy fallback for %s "
                    "(no reflink, no sparse extents)\n", dst);
    {
        char buf[1 << 16];
        ssize_t n;
        while ((n = read(sfd, buf, sizeof(buf))) > 0) {
            ssize_t off = 0;
            while (off < n) {
                ssize_t w = write(dfd, buf + off, (size_t)(n - off));
                if (w < 0) goto fail;
                off += w;
            }
        }
        if (n < 0) goto fail;
    }
    close(sfd);
    close(dfd);
    return 0;

fail:
    {
        int e = errno;
        close(sfd);
        close(dfd);
        unlink(dst);
        errno = e;
        return -1;
    }
}

// --- registry --------------------------------------------------------------

static int meta_path(const char* session_key, char* out, size_t n) {
    char dir[PATH_MAX];
    workspace_paths(session_key, dir, sizeof(dir), NULL, 0);
    snprintf(out, n, "%s/meta.json", dir);
    return 0;
}

static uint64_t allocated_bytes(const char* path) {
    struct stat st;
    if (stat(path, &st) < 0) return 0;
    return (uint64_t)st.st_blocks * 512u;
}

static int write_meta(const workspace_meta_t* m) {
    char path[PATH_MAX];
    meta_path(m->session_key, path, sizeof(path));

    // Write to a sibling and rename: a torn meta.json would be a session with a
    // volume and no expiry, which is the one state the reaper cannot fix.
    char tmp[PATH_MAX + 32];
    snprintf(tmp, sizeof(tmp), "%s.tmp-%d", path, (int)getpid());
    FILE* f = fopen(tmp, "w");
    if (!f) return -1;
    int rc = fprintf(f,
                     "{\n"
                     "  \"id\": \"%s\",\n"
                     "  \"session_key\": \"%s\",\n"
                     "  \"owner_uid\": %u,\n"
                     "  \"size_mb\": %u,\n"
                     "  \"created_at\": %lld,\n"
                     "  \"expires_at\": %lld,\n"
                     "  \"renewed_at\": %lld,\n"
                     "  \"bytes_used\": %llu\n"
                     "}\n",
                     m->id, m->session_key, (unsigned)m->owner_uid, m->size_mb,
                     (long long)m->created_at, (long long)m->expires_at,
                     (long long)m->renewed_at, (unsigned long long)m->bytes_used);
    if (fclose(f) != 0 || rc < 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) < 0) {
        int e = errno;
        unlink(tmp);
        errno = e;
        return -1;
    }
    return 0;
}

static long long json_ll(const char* s, const char* field, int* ok) {
    const char* p = strstr(s, field);
    if (!p) { *ok = 0; return 0; }
    p += strlen(field);
    return strtoll(p, NULL, 10);
}

static int read_meta_at(const char* path, const char* expect_key,
                        workspace_meta_t* out) {
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    memset(out, 0, sizeof(*out));
    int ok = 1;
    const char* p = strstr(buf, "\"session_key\": \"");
    if (!p) { errno = EINVAL; return -1; }
    p += strlen("\"session_key\": \"");
    const char* q = strchr(p, '"');
    if (!q || (size_t)(q - p) >= sizeof(out->session_key)) { errno = EINVAL; return -1; }
    memcpy(out->session_key, p, (size_t)(q - p));
    out->session_key[q - p] = '\0';
    if (expect_key && strcmp(expect_key, out->session_key) != 0) {
        errno = EINVAL;
        return -1;
    }
    session_id(out->session_key, out->id);
    p = strstr(buf, "\"owner_uid\": ");
    if (!p) { errno = EINVAL; return -1; }
    out->owner_uid = (uid_t)strtoul(p + strlen("\"owner_uid\": "), NULL, 10);
    out->size_mb = (uint32_t)json_ll(buf, "\"size_mb\": ", &ok);
    out->created_at = json_ll(buf, "\"created_at\": ", &ok);
    out->expires_at = json_ll(buf, "\"expires_at\": ", &ok);
    out->renewed_at = json_ll(buf, "\"renewed_at\": ", &ok);
    out->bytes_used = (uint64_t)json_ll(buf, "\"bytes_used\": ", &ok);
    (void)ok;
    return 0;
}

int workspace_load_meta(const char* session_key, workspace_meta_t* out) {
    if (!out || !key_valid(session_key)) { errno = EINVAL; return -1; }
    char path[PATH_MAX];
    meta_path(session_key, path, sizeof(path));
    return read_meta_at(path, session_key, out);
}

int workspace_ensure(const char* session_key, uid_t owner_uid, uint32_t size_mb,
                     uint32_t ttl_seconds, const char* base_image,
                     workspace_meta_t* out) {
    if (!key_valid(session_key) || !base_image) { errno = EINVAL; return -1; }

    // Existing session: the whole point of the feature. Reuse it untouched.
    if (workspace_load_meta(session_key, out) == 0) return 0;
    if (errno != ENOENT && errno != EINVAL) return -1;

    if (size_mb == 0) size_mb = WORKSPACE_DEFAULT_SIZE_MB;
    uint32_t max_ttl = workspace_max_ttl_seconds();
    if (ttl_seconds == 0) ttl_seconds = WORKSPACE_DEFAULT_TTL_SECONDS;
    if (ttl_seconds < WORKSPACE_MIN_TTL_SECONDS) ttl_seconds = WORKSPACE_MIN_TTL_SECONDS;
    if (ttl_seconds > max_ttl) ttl_seconds = max_ttl;

    const char* root = workspace_root();
    if (mkdir_recursive(root, 0700) < 0) return -1;

    // Stage, then rename. A crash mid-create therefore leaves a .tmp-* directory
    // that the reaper removes, never a half-built session that a restore would
    // attach to. meta.json is written *after* the rename (write_meta derives its
    // path from the key), which is why an orphan directory is possible at all --
    // and why the reaper has a grace period before touching one.
    char id[65];
    session_id(session_key, id);
    char staging[PATH_MAX], final[PATH_MAX];
    snprintf(staging, sizeof(staging), "%s/%s%d-%s", root, WS_STAGING_PREFIX,
             (int)getpid(), id);
    snprintf(final, sizeof(final), "%s/%s", root, id);
    sandbox_rm_rf(staging);
    if (mkdir(staging, 0700) < 0) return -1;

    char img[PATH_MAX];
    snprintf(img, sizeof(img), "%s/" WORKSPACE_IMAGE_NAME, staging);
    if (workspace_clone(base_image, img) < 0) {
        int e = errno;
        sandbox_rm_rf(staging);
        errno = e;
        return -1;
    }

    workspace_meta_t m;
    memset(&m, 0, sizeof(m));
    snprintf(m.id, sizeof(m.id), "%s", id);
    snprintf(m.session_key, sizeof(m.session_key), "%s", session_key);
    m.owner_uid = owner_uid;
    m.size_mb = size_mb;
    m.created_at = (int64_t)time(NULL);
    m.expires_at = m.created_at + (int64_t)ttl_seconds;
    m.renewed_at = 0;
    m.bytes_used = allocated_bytes(img);

    if (rename(staging, final) < 0) {
        int e = errno;
        sandbox_rm_rf(staging);
        errno = e;
        return -1;
    }
    if (write_meta(&m) < 0) {
        int e = errno;
        sandbox_rm_rf(final);
        errno = e;
        return -1;
    }
    if (out) *out = m;
    return 0;
}

int workspace_renew(const char* session_key, uint32_t extra_seconds, int64_t now,
                    workspace_meta_t* out) {
    workspace_meta_t m;
    if (workspace_load_meta(session_key, &m) < 0) return -1;
    if (m.expires_at <= now) { errno = ESTALE; return -1; }

    int64_t capped = m.created_at + (int64_t)workspace_max_ttl_seconds();
    if (capped <= now) {
        // Past the platform maximum: the session has had its full life.
        errno = ERANGE;
        return -1;
    }
    int64_t target = now + (int64_t)(extra_seconds ? extra_seconds
                                                  : WORKSPACE_DEFAULT_TTL_SECONDS);
    if (target > capped) target = capped;
    if (target > m.expires_at) {
        m.expires_at = target;
        m.renewed_at = now;
        if (write_meta(&m) < 0) return -1;
    }
    if (out) *out = m;
    return 0;
}

int workspace_destroy(const char* session_key) {
    if (!key_valid(session_key)) { errno = EINVAL; return -1; }
    char dir[PATH_MAX];
    workspace_paths(session_key, dir, sizeof(dir), NULL, 0);
    return sandbox_rm_rf(dir);
}

// Remove the image before the registry row, so a crash in between leaves a row
// whose image is missing (re-attachable? no: recreated empty) rather than an
// image with no expiry that the reaper would keep forever.
static int reap_one(const char* dir, uint64_t* freed) {
    char img[PATH_MAX];
    snprintf(img, sizeof(img), "%s/" WORKSPACE_IMAGE_NAME, dir);
    *freed += allocated_bytes(img);
    return sandbox_rm_rf(dir);
}

// --- exclusive-use leases (#23) --------------------------------------------
//
// Two VMs bound to one image would corrupt it: both would write the same blocks
// through their own page caches, and neither would see the other's writes. The
// engine is the only thing that binds a volume, so an in-process lease is
// sufficient -- and it is the difference between "a second create is refused"
// and "a second create silently destroys the session".
#define WS_LEASE_MAX 256
static char g_leases[WS_LEASE_MAX][65];
static size_t g_lease_count;
static pthread_mutex_t g_lease_lock = PTHREAD_MUTEX_INITIALIZER;

int workspace_lease(const char* session_key) {
    if (!key_valid(session_key)) { errno = EINVAL; return -1; }
    char id[65];
    session_id(session_key, id);
    pthread_mutex_lock(&g_lease_lock);
    for (size_t i = 0; i < g_lease_count; i++) {
        if (strcmp(g_leases[i], id) == 0) {
            pthread_mutex_unlock(&g_lease_lock);
            errno = EBUSY;
            return -1;
        }
    }
    if (g_lease_count >= WS_LEASE_MAX) {
        pthread_mutex_unlock(&g_lease_lock);
        errno = ENOSPC;
        return -1;
    }
    memcpy(g_leases[g_lease_count], id, sizeof(id));
    g_lease_count++;
    pthread_mutex_unlock(&g_lease_lock);
    return 0;
}

void workspace_release(const char* session_key) {    if (!key_valid(session_key)) return;
    char id[65];
    session_id(session_key, id);
    pthread_mutex_lock(&g_lease_lock);
    for (size_t i = 0; i < g_lease_count; i++) {
        if (strcmp(g_leases[i], id) == 0) {
            g_leases[i][0] = '\0';  // tombstone; compact on the next free slot
            if (i + 1 == g_lease_count) {
                while (g_lease_count && g_leases[g_lease_count - 1][0] == '\0') {
                    g_lease_count--;
                }
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_lease_lock);
}


int workspace_reap(int64_t now, int* expired_out) {    int expired = 0;
    DIR* d = opendir(workspace_root());
    if (!d) {
        if (errno == ENOENT) { if (expired_out) *expired_out = 0; return 0; }
        return -1;
    }
    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0 ||
            strcmp(de->d_name, "lost+found") == 0) {
            continue;
        }
        char dir[PATH_MAX];
        snprintf(dir, sizeof(dir), "%s/%s", workspace_root(), de->d_name);
        struct stat st;
        if (lstat(dir, &st) < 0) continue;
        if (!S_ISDIR(st.st_mode)) continue;

        if (strncmp(de->d_name, WS_STAGING_PREFIX, strlen(WS_STAGING_PREFIX)) == 0) {
            if (now - (int64_t)st.st_mtime > WS_STAGING_GRACE_SECONDS) {
                uint64_t freed = 0;
                if (reap_one(dir, &freed) == 0) {
                    fprintf(stderr, "[workspace] reaped abandoned staging dir %s\n",
                            de->d_name);
                }
            }
            continue;
        }

        char meta[PATH_MAX];
        snprintf(meta, sizeof(meta), "%s/meta.json", dir);
        workspace_meta_t m;
        if (read_meta_at(meta, NULL, &m) < 0) {
            // No readable registry row: either a crash between rename and
            // meta.json (unlikely now) or foreign data. Only clear it out once
            // it is old enough not to race a create in flight.
            if (now - (int64_t)st.st_mtime > WS_ORPHAN_GRACE_SECONDS) {
                uint64_t freed = 0;
                if (reap_one(dir, &freed) == 0) {
                    fprintf(stderr, "[workspace] reaped orphan dir %s (no meta.json)\n",
                            de->d_name);
                }
            }
            continue;
        }
        if (m.expires_at <= now) {
            uint64_t freed = 0;
            if (reap_one(dir, &freed) == 0) {
                expired++;
                fprintf(stderr,
                        "[workspace] expired session %s (owner %u, %llu bytes, "
                        "expired %llds ago)\n",
                        m.session_key, (unsigned)m.owner_uid,
                        (unsigned long long)freed, (long long)(now - m.expires_at));
            } else {
                fprintf(stderr, "[workspace] FAILED to expire session %s: %s\n",
                        m.session_key, strerror(errno));
            }
        }
    }
    closedir(d);
    if (expired_out) *expired_out = expired;
    return 0;
}

int workspace_lease_count(void) {
    int n = 0;
    pthread_mutex_lock(&g_lease_lock);
    for (size_t i = 0; i < g_lease_count; i++) {
        if (g_leases[i][0]) n++;
    }
    pthread_mutex_unlock(&g_lease_lock);
    return n;
}

int workspace_usage(uid_t owner, uint64_t* bytes, uint32_t* count) {
    uint64_t total = 0;
    uint32_t n = 0;
    DIR* d = opendir(workspace_root());
    if (!d) {
        if (errno == ENOENT) {
            if (bytes) *bytes = 0;
            if (count) *count = 0;
            return 0;
        }
        return -1;
    }
    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char meta[PATH_MAX];
        snprintf(meta, sizeof(meta), "%s/%s/meta.json", workspace_root(), de->d_name);
        workspace_meta_t m;
        if (read_meta_at(meta, NULL, &m) < 0) continue;
        if (owner != (uid_t)-1 && m.owner_uid != owner) continue;
        total += m.bytes_used;
        n++;
    }
    closedir(d);
    if (bytes) *bytes = total;
    if (count) *count = n;
    return 0;
}
