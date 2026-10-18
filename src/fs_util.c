// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include "sandbox_fs.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// nftw(3) callback. FTW_DEPTH reports children before their parent, so one
// post-order pass removes a whole tree. FTW_PHYS never follows symlinks, so a
// symlink pointing outside the tree is unlinked rather than walked into.
static int rm_cb(const char* path, const struct stat* sb, int typeflag,
                 struct FTW* ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    if (typeflag == FTW_DP) {  // directory, visited post-order
        if (rmdir(path) != 0 && errno != ENOENT) return -1;
    } else {  // FTW_F, FTW_SL, FTW_SLN
        if (unlink(path) != 0 && errno != ENOENT) return -1;
    }
    return 0;
}

int sandbox_rm_rf(const char* path) {
    if (!path || !*path) {
        errno = EINVAL;
        return -1;
    }
    // 32 open descriptors is enough for jail trees and bounds fd use.
    if (nftw(path, rm_cb, 32, FTW_DEPTH | FTW_PHYS) == 0) return 0;
    return (errno == ENOENT) ? 0 : -1;  // missing == already gone
}

int sandbox_copy_file(const char* src, const char* dst) {
    if (!src || !dst) {
        errno = EINVAL;
        return -1;
    }

    int in = open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0) return -1;

    struct stat st;
    if (fstat(in, &st) < 0) {
        int e = errno;
        close(in);
        errno = e;
        return -1;
    }

    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                   st.st_mode & 0777);
    if (out < 0) {
        int e = errno;
        close(in);
        errno = e;
        return -1;
    }

    for (;;) {
        char buf[1 << 16];
        ssize_t n = read(in, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            goto fail;
        }
        if (n == 0) break;
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w < 0) {
                if (errno == EINTR) continue;
                goto fail;
            }
            off += w;
        }
    }

    close(in);
    close(out);
    return 0;

fail: {
    int e = errno;
    close(in);
    close(out);
    errno = e;
    return -1;
}
}
