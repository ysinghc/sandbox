# Workspace Disk Architecture

<!-- SPDX-License-Identifier: GPL-2.0-only -->

> **Decision D7 (confirmed 2026-10-18):** workspace images are pre-formatted at
> template-build time. Session-create clones the base image (btrfs/xfs reflink
> for near-instant copy; sparse fallback on other filesystems). `mkfs.ext4` is
> **never** run at session-create time.

---

## 0. Status: what exists, and where it deviates from this design

**Implemented in 0.14.0 (#23).** This section is the ground truth; the sections
below it are the design as first written, and where they disagree with the code
they are marked. A design that drifts from the implementation is worse than no
design, so the deviations and their reasons are recorded here rather than quietly
edited away.

Where the implementation deviates, and why:

1. **The base image is never mounted or pre-populated (§2.1, §2.3).** The design
   mounted the base at build time to pre-install content. The code calls
   `workspace_format_base()` (`src/workspace.c`), which runs `mkfs.ext4` via
   `exec` (never `system()`) and stops there. Pre-population is a template-recipe
   feature nobody has needed yet; adding a loop mount to the build path would add
   a root-and-loop-device requirement for no current benefit. `lazy_itable_init`
   is left at mke2fs' default.

2. **The guest mounts `/workspace` *after* each restore, not before capture
   (§4).** This is the single most important deviation, and it was found by a
   failing test rather than by review. Mounting before the capture bakes the base
   image's ext4 state and page cache into the snapshot, and every restore then
   serves a *different* file behind the same device — the guest reads metadata
   from RAM that does not match the volume, and reports
   `EXT4-fs error (device vdb): checksumming directory block 0`. The guest agent
   calls `mount("/dev/vdb", "/workspace", "ext4", 0, NULL)` on first use after a
   restore (`scripts/sandbox-agent.c`, `ws_ensure_mount()`). Two things follow:
   "a clone is byte-identical to its base" becomes true by construction rather
   than by discipline, and ext4 replays the journal of a session whose VM was
   killed mid-write, so a volume cannot come back torn.

3. **Writes are flushed before the VM is killed (§4).** A page written by the
   workload belongs to the *guest* until the guest writes it back, and
   `vmm_destroy()` SIGKILLs the VMM. Without a flush, "the session remembers
   things" was false for anything the workload had not itself flushed: the e2e
   test re-created a session and found only its own new line. The engine now asks
   the guest to `sync()` (a reserved control payload on the existing vsock env
   channel, answered with `SANDBOX-FLUSH-OK`) and waits for the acknowledgement,
   bounded by `SANDBOX_FLUSH_MS`. Best effort: a wedged guest is still destroyed,
   and the missing flush is reported.

4. **The jail-view constant name changed.** `WORKSPACE_JAILVIEW` no longer exists;
   the jail path is `JAIL_WORKSPACE_PATH` in `include/jailer.h`, and
   `include/workspace.h` deals only in host paths. The jailer chowns the volume at
   bind time, so `workspace_chown()` was deleted.

5. **Session identity and layout.** The registry keys a session by
   `sha256_hex(session_key)` (`session_key` is 1–127 printable bytes without `"`
   or `\`), stores `<root>/<sha256>/{workspace.ext4,meta.json}`, creates it in a
   `.tmp-<pid>-<sha256>` directory and `rename()`s it into place. The design
   predates the key/registry split and stored `.meta` inside the session
   directory under a session id.

6. **TTL is enforced by the registry reaper, not by unmounting a jail (§5).**
   `workspace_reap()` runs on a timer in the daemon
   (`SANDBOX_REAP_INTERVAL_SECONDS`, default 60 s), removes expired sessions and
   abandoned staging directories, and never touches a session that is in use.
   `expires_at = created_at + clamp(ttl, 60, platform_max)`: an absolute deadline
   from creation, never extended automatically. Re-creating a session never
   extends it; renewal (`workspace_renew()`) never shortens it.

7. **A warm-pool VM cannot use a session volume, and does not (§3.2).** A pool
   member is restored at provisioning time, before any request exists, so it binds
   a per-VM *scratch* clone of the base as its volume. A request that names a
   session key bypasses the pool and restores on purpose
   (`restore_vm_with_workspace()`); an exclusive-use lease
   (`workspace_lease()`/`workspace_release()`) prevents two VMs writing one image.

8. **ext4 is supported first-class, not just as a fallback (§6).** The FUSE-free
   plain-ext4 path must work, so `workspace_clone()` proves it: a real formatted
   image is cloned and compared byte-for-byte in `tests/test_workspace.c`. The
   btrfs/xfs reflink path remains the fast path.


---

## 1. Overview

Every sandbox session gets a private, writable ext4 volume mounted at `/workspace`
inside the guest. The session persists across pauses and survives until the session
TTL expires (default 7 days, configurable).

The volume lifecycle has two distinct phases:

```
Template-build time                    Session-create time
─────────────────────────────          ──────────────────────────────────────────
scripts/build-template.sh              src/vmm_manager.c  (vmm_restore)
  │                                      │
  ├─ mkfs.ext4 -q                        ├─ workspace_clone(base, session path)
  │    base_workspace.ext4               │    reflink (btrfs/xfs) OR sparse copy
  │    (sparse, default 512 MiB)         │
  │                                      ├─ bind-mount session image
  ├─ mount + pre-populate /workspace     │    over <jail_root>/workspace.ext4
  │    (e.g. /workspace/bin, venvs)      │
  │                                      └─ boot/restore FC with the drive
  ├─ umount
  │
  └─ store as snapshots/<name>/
         base_workspace.ext4   ← the only ext4 image ever formatted
         workspace_size_mb     ← recorded in template.json
```

---

## 2. Base image creation (template-build time)

### 2.1 Creating the sparse image

The `scripts/build-template.sh` script creates the base workspace image as part
of every template build. It runs once and the result is stored in the snapshot store.

```bash
#!/usr/bin/env bash
# Called by scripts/build-template.sh after rootfs build is complete.
# Requires: mkfs.ext4, e2fsck, resize2fs (e2fsprogs), loop device support.
# Must run as root (mkfs, mount).

TEMPLATE_NAME="$1"
WORKSPACE_MB="${2:-512}"
SNAPSHOT_ROOT="${SANDBOX_SNAPSHOT_ROOT:-/var/lib/sandbox-engine/snapshots}"
STAGING="${SNAPSHOT_ROOT}/.staging/${TEMPLATE_NAME}"

echo "[workspace] Creating ${WORKSPACE_MB} MiB sparse ext4 base image..."

# 1. Allocate a sparse file (no actual disk blocks consumed yet)
truncate -s "${WORKSPACE_MB}M" "${STAGING}/base_workspace.ext4"

# 2. Format — runs ONLY here, never at session-create time.
#    -q: quiet  -m 1: 1% reserved (agent doesn't need headroom)
#    -E lazy_itable_init=0: fully init inode table now (deterministic, clone-safe)
#    -L workspace: volume label
mkfs.ext4 -q -m 1 -E lazy_itable_init=0 -L workspace \
  "${STAGING}/base_workspace.ext4"

# 3. Pre-populate if the template recipe includes workspace content
MNTPOINT=$(mktemp -d)
mount -o loop "${STAGING}/base_workspace.ext4" "${MNTPOINT}"

mkdir -p "${MNTPOINT}/bin"
mkdir -p "${MNTPOINT}/lib"
mkdir -p "${MNTPOINT}/tmp"
# Example: pre-install a Python venv into /workspace/venv
# cp -a /opt/python-venv "${MNTPOINT}/venv"
# chown -R 1000:1000 "${MNTPOINT}"

umount "${MNTPOINT}"
rmdir "${MNTPOINT}"

# 4. Shrink the sparse representation so the base image only
#    occupies space proportional to its actual content.
e2fsck -fp "${STAGING}/base_workspace.ext4" >/dev/null
resize2fs -M "${STAGING}/base_workspace.ext4" >/dev/null
# Grow back to the full declared size — extra space is sparse (zero cost on disk)
resize2fs "${STAGING}/base_workspace.ext4" "${WORKSPACE_MB}M" >/dev/null

echo "[workspace] Base image ready: $(du -sh "${STAGING}/base_workspace.ext4" | cut -f1) on disk"
```

> **Why `lazy_itable_init=0`?** With lazy init, the inode table is zeroed
> incrementally by a background kernel thread. In a cloned image this thread
> restarts on every new session and wastes I/O. Fully initialising at build time
> makes the image deterministic and clone-safe.

### 2.2 Recorded metadata (`template.json`)

```json
{
  "name": "python-agent",
  "version": "1.2.3",
  "built_at": "2026-10-18T08:00:00Z",
  "arch": "x86_64",
  "workspace_size_mb": 512,
  "workspace_image": "base_workspace.ext4",
  "workspace_sha256": "<sha256 of base_workspace.ext4>"
}
```

`workspace_sha256` is verified by `snapshot_verify_manifest()` on the same
`(dev, ino, size, mtime)` cache path used for `memory.snap`.

---

## 3. Session-create time: cloning the base image

### 3.1 The `workspace_clone()` function

Add to `src/vmm_manager.c` (or a new `src/workspace.c`):

```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <linux/fs.h>   /* FICLONE */

/**
 * workspace_clone — create a per-session workspace image from the template base.
 *
 * Strategy (in order of preference):
 *  1. ioctl FICLONE (btrfs/xfs reflink): copy-on-write, O(1), no data copied.
 *  2. sendfile with SEEK_DATA/SEEK_HOLE: copies only allocated extents (sparse-aware).
 *  3. plain read/write fallback (correct but slow; logs a warning).
 *
 * Returns 0 on success, -1 with errno set on failure.
 */
int workspace_clone(const char *src_path, const char *dst_path)
{
    int src_fd = open(src_path, O_RDONLY | O_CLOEXEC);
    if (src_fd < 0) return -1;

    int dst_fd = open(dst_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (dst_fd < 0) { close(src_fd); return -1; }

    /* Attempt 1: reflink (btrfs/xfs) — near-instant, zero data movement */
    if (ioctl(dst_fd, FICLONE, src_fd) == 0) {
        close(src_fd); close(dst_fd);
        return 0;
    }
    /* EOPNOTSUPP or EXDEV: filesystem does not support it; fall through */

    /* Attempt 2: sparse-aware copy via SEEK_DATA/SEEK_HOLE + sendfile */
    struct stat st;
    if (fstat(src_fd, &st) < 0) goto fail;
    if (ftruncate(dst_fd, st.st_size) < 0) goto fail;  /* pre-allocate sparse */

    off_t pos = 0;
    while (pos < st.st_size) {
        off_t data_start = lseek(src_fd, pos, SEEK_DATA);
        if (data_start < 0) {
            if (errno == ENXIO) break;  /* no more data extents */
            goto fallback;
        }
        off_t hole_start = lseek(src_fd, data_start, SEEK_HOLE);
        if (hole_start < 0) hole_start = st.st_size;

        if (lseek(dst_fd, data_start, SEEK_SET) < 0) goto fail;
        if (lseek(src_fd, data_start, SEEK_SET) < 0) goto fail;
        off_t remaining = hole_start - data_start;
        while (remaining > 0) {
            size_t chunk = (size_t)(remaining > (1 << 20) ? (1 << 20) : remaining);
            ssize_t sent = sendfile(dst_fd, src_fd, NULL, chunk);
            if (sent <= 0) goto fallback;
            remaining -= sent;
        }
        pos = hole_start;
    }
    close(src_fd); close(dst_fd);
    return 0;

fallback:
    fprintf(stderr, "[workspace] WARNING: falling back to plain copy for %s\n", dst_path);
    if (lseek(src_fd, 0, SEEK_SET) < 0 || lseek(dst_fd, 0, SEEK_SET) < 0) goto fail;
    char buf[1 << 16];
    ssize_t n;
    while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(dst_fd, buf + off, (size_t)(n - off));
            if (w < 0) goto fail;
            off += w;
        }
    }
    if (n < 0) goto fail;
    close(src_fd); close(dst_fd);
    return 0;

fail:
    { int e = errno; close(src_fd); close(dst_fd); unlink(dst_path); errno = e; }
    return -1;
}
```

### 3.2 Where it is called

In `vmm_restore()` (`src/vmm_manager.c`), before the jail is populated:

```c
/* Derive paths */
char base_ws[PATH_MAX], session_ws[PATH_MAX];
snprintf(base_ws, sizeof(base_ws),
         "%s/%s/base_workspace.ext4", snapshot_root(), spec->template_name);
snprintf(session_ws, sizeof(session_ws),
         WORKSPACE_ROOT "/%s/workspace.ext4", spec->session_id);

if (access(session_ws, F_OK) != 0) {
    /* New session: clone base image */
    if (workspace_clone(base_ws, session_ws) < 0) {
        LOG_ERR("workspace_clone failed: %s", strerror(errno));
        return NULL;
    }
    workspace_write_meta(session_ws_dir, spec);   /* writes .meta JSON */
}
/* Existing session (resume after pause): image already present, skip clone */

/* Bind-mount into the jail */
char jail_ws[PATH_MAX];
snprintf(jail_ws, sizeof(jail_ws), "%s/workspace.ext4", jail_root);
if (bind_file(session_ws, jail_ws) < 0) {
    LOG_ERR("bind workspace into jail: %s", strerror(errno));
    return NULL;
}
```

### 3.3 Performance characteristics

| Filesystem | Clone strategy | Typical time (512 MiB base, ~5 MiB allocated) | Notes |
|---|---|---|---|
| btrfs | `FICLONE` reflink | **< 1 ms** | COW; zero data copied |
| xfs (`reflink=1`) | `FICLONE` reflink | **< 1 ms** | Same |
| ext4, tmpfs, NFS | Sparse copy (sendfile) | **2–8 ms** for 5 MiB allocated | Proportional to allocated bytes |
| any (fallback) | Plain read/write | **~200–800 ms** | Should never occur; triggers log warning |

The base image after `resize2fs -M` for a minimal Python rootfs is typically
**3–8 MiB allocated** in a 512 MiB sparse file. On ext4 the sparse sendfile path
takes **< 5 ms**, which keeps the provisioned-latency budget intact (46 ms avg
today; < 250 ms target).

> **Production recommendation:** use btrfs for `/var/lib/sandbox-engine/`. On a
> standard ext4 root, create a dedicated btrfs loopback or partition. See §6 for
> setup instructions.

---

## 4. Guest-side configuration

**As built (see §0.2 and §0.3 — the text under "as designed" below was wrong).**

The guest does *not* mount the volume before the template is captured. The init
script only reports that the device was attached:

```sh
# scripts/build-custom-rootfs.sh: /workspace exists in the rootfs image (the
# guest root is read-only, so the mount point is created at build time). The
# volume is deliberately left unmounted here.
if [ -b /dev/vdb ]; then echo "SANDBOX-WORKSPACE-DEVICE present"; fi
```

The guest agent mounts it on first use after a restore, and the engine flushes it
before the VM is killed:

```c
/* scripts/sandbox-agent.c */
if (mount("/dev/vdb", "/workspace", "ext4", 0, NULL) == 0 || errno == EBUSY)
    g_ws_mounted = 1;   /* once per restore; ext4 replays any journal here */
```

<details>
<summary>As designed (superseded — kept to show what was wrong)</summary>

```sh
# Mount the second drive as /workspace
mkdir -p /workspace
mount -t ext4 -o rw,relatime /dev/vdb /workspace
chown 1000:1000 /workspace
```

The template snapshot is captured **after** this mount is set up, so the Firecracker
config has the drive registered and the mount point exists in guest memory. On
restore, the per-session image is bind-mounted over `workspace.ext4` in the jail
*before* FC starts, so the guest kernel sees the new contents without any guest-side
remount.

Capturing the mount is what broke: a restored guest resumes a *mounted* ext4 whose
backing content has been replaced, so its in-memory metadata is for the base image
while its I/O goes to the session's. It cannot work by construction.
</details>

---

## 5. TTL-driven cleanup

The TTL manager thread (added in issue #23) scans session meta files every 60 s
and calls `workspace_expire()` for sessions past their `expires_at`:

```c
void workspace_expire(const char *session_id)
{
    /* 1. Destroy the sandbox if it is still running */
    sandbox_handle_t *h = session_lookup(session_id);
    if (h) sandbox_destroy(h);

    /* 2. Lazy-unmount the workspace from the jail (safe if still busy) */
    char jail_ws[PATH_MAX];
    snprintf(jail_ws, sizeof(jail_ws), JAIL_ROOT "/%s/workspace.ext4", session_id);
    umount2(jail_ws, MNT_DETACH);

    /* 3. Delete the session workspace image */
    char ws_path[PATH_MAX];
    snprintf(ws_path, sizeof(ws_path),
             WORKSPACE_ROOT "/%s/workspace.ext4", session_id);
    unlink(ws_path);

    /* 4. Remove meta file and session directory */
    char meta[PATH_MAX];
    snprintf(meta, sizeof(meta), WORKSPACE_ROOT "/%s/.meta", session_id);
    unlink(meta);
    rmdir(/* session dir */);
}
```

**`.meta` JSON format** (written by `workspace_write_meta()` at session-create):

```json
{
  "session_id":          "ses_01jdf3xp",
  "template":            "python-agent",
  "created_at":          1729000000,
  "expires_at":          1729604800,
  "workspace_mb":        512,
  "ttl_renewed_count":   0
}
```

`expires_at` is updated (up to `workspace_max_ttl_seconds`) by `sandbox_renew()`.

---

## 6. Host filesystem requirements & setup

| Path | Required | Recommended | Why |
|---|---|---|---|
| `/var/lib/sandbox-engine/snapshots/` | rw, bind-mount capable | btrfs | Template store; base images live here |
| `/var/lib/sandbox-engine/workspaces/` | rw, bind-mount capable | btrfs/xfs with reflink | Session workspace images; reflink = instant clone |
| `/var/lib/sandbox-engine/jail/` | rw, bind-mount, dev-node capable | any | Jail roots; needs `MS_BIND`, `/dev/kvm`, `/dev/net/tun` |

**Setup (operator runs once, as root):**

```bash
# Option A: dedicated btrfs volume (recommended for production)
mkfs.btrfs /dev/sdXY
mount /dev/sdXY /var/lib/sandbox-engine
btrfs subvolume create /var/lib/sandbox-engine/snapshots
btrfs subvolume create /var/lib/sandbox-engine/workspaces
btrfs subvolume create /var/lib/sandbox-engine/jail

# Option B: loopback btrfs on an ext4 host (dev / single-host)
truncate -s 50G /var/lib/sandbox-engine.btrfs
mkfs.btrfs /var/lib/sandbox-engine.btrfs
mount -o loop /var/lib/sandbox-engine.btrfs /var/lib/sandbox-engine
# Add to /etc/fstab:
# /var/lib/sandbox-engine.btrfs /var/lib/sandbox-engine btrfs loop 0 0

# Verify reflink support (should print "reflink OK"):
touch /var/lib/sandbox-engine/reflink_test_src
cp --reflink=always /var/lib/sandbox-engine/reflink_test_src \
                    /var/lib/sandbox-engine/reflink_test_dst \
  && echo "reflink OK" || echo "reflink NOT supported — using sparse fallback"
rm -f /var/lib/sandbox-engine/reflink_test_{src,dst}
```

Add to `config/engine.conf`:

```ini
# Workspace storage
workspace_root          = /var/lib/sandbox-engine/workspaces
workspace_default_ttl_seconds = 604800    # 7 days
workspace_max_ttl_seconds     = 2592000   # 30 days
workspace_default_size_mb     = 512
```

---

## 7. Worked example: full session lifecycle

```
$ sandbox-cli session create --template python-agent --ttl 7d
[workspace] reflink clone: snapshots/python-agent/base_workspace.ext4
            → workspaces/ses_01jdf3xp/workspace.ext4  (0.3 ms, btrfs FICLONE)
[vmm_restore] bind: workspaces/ses_01jdf3xp/workspace.ext4
              → jail/ses_01jdf3xp/workspace.ext4
[vmm_restore] /snapshot/load ok
[vmm_restore] time total=48ms prep=3ms listen=1ms spawn=8ms sock=18ms load=13ms resume=5ms
Session: ses_01jdf3xp  expires: 2026-10-25T14:45:00+05:30

$ sandbox-cli exec ses_01jdf3xp -- python3 -c \
    "open('/workspace/hello.txt','w').write('hello persistent world')"
exit_code=0

$ sandbox-cli exec ses_01jdf3xp -- cat /workspace/hello.txt
hello persistent world

$ sandbox-cli session renew ses_01jdf3xp --extra 7d
Session ses_01jdf3xp  new expiry: 2026-11-01T14:45:00+05:30

$ sandbox-cli session destroy ses_01jdf3xp
[ttl] expiring ses_01jdf3xp
[workspace] umount2 jail/ses_01jdf3xp/workspace.ext4 (MNT_DETACH)
[workspace] unlink workspaces/ses_01jdf3xp/workspace.ext4
[workspace] cleaned up session ses_01jdf3xp
```

---

## 8. Open items / future work

| Item | Phase | Notes |
|---|---|---|
| Delta snapshot of workspace (dirty pages only) | M5 #15 | Combine with content-addressed store for deduplication |
| Per-tenant quota enforcement (`df` or btrfs project quotas) | M4 #11 | Block writes when quota exceeded; surface via API |
| Encrypted workspaces (dm-crypt per session) | M4+ | Key derived from session token; requires privilege-sep daemon (#9) |
| Workspace pre-warming (pre-clone N images into a pool) | M5 | Amortises sparse-copy cost on non-reflink hosts |

