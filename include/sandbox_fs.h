// SPDX-License-Identifier: GPL-2.0-only
//
// sandbox_fs — filesystem helpers that never invoke a shell.
//
// The daemon previously removed trees with system("rm -rf …") and copied files
// with system("cp …"). Both interpreted shell metacharacters in caller-supplied
// paths (template names, jail roots) — a command-injection vector flagged by
// the §12.2 audit. These helpers do the work in-process.

#ifndef SANDBOX_FS_H
#define SANDBOX_FS_H

// Recursively remove `path`, like `rm -rf`: a file, directory or symlink.
// Symlinks are never followed (a symlink is unlinked, not traversed). A path
// that does not exist is not an error. Returns 0 on success, -1 with errno set.
int sandbox_rm_rf(const char* path);

// Copy the regular file `src` to `dst`, creating or truncating `dst` with the
// source's permission bits. Returns 0 on success, -1 with errno set.
int sandbox_copy_file(const char* src, const char* dst);

#endif  // SANDBOX_FS_H
