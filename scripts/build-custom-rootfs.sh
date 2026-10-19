#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# build-custom-rootfs.sh
# Creates a minimal ext4 rootfs for sandbox template tests.
# The rootfs has a custom /init that:
#   - Mounts proc/sys/dev
#   - Prints "SANDBOX-READY" to serial (ttyS0)
#   - Sleeps forever (snapshot taken by host while running)
#
# Usage: sudo bash build-custom-rootfs.sh
set -euo pipefail

# SANDBOX_ROOTFS_OUT lets CI build into a scratch path instead of overwriting
# the operator's asset (the engine reads the result via SANDBOX_ROOTFS, the same
# variable scripts/benchmark.sh and tests/make_template.c honour).
ROOTFS_OUT="${SANDBOX_ROOTFS_OUT:-/opt/sandbox-assets/rootfs.ext4}"
ROOTFS_SIZE_MB=128
MNTDIR=$(mktemp -d /tmp/rootfs-mnt.XXXXXX)

log() { echo "[rootfs] $*"; }

# ── 0. Sanity ─────────────────────────────────────────────────────────────────
if [ "$(id -u)" != 0 ]; then
    echo "error: must run as root (loop mount + mkfs)" >&2
    exit 1
fi
mkdir -p "$(dirname "$ROOTFS_OUT")"

# ── 1. Install busybox-static ─────────────────────────────────────────────────
# Best effort: without network we fall back to whatever busybox is installed,
# which must be statically linked (the rootfs ships no libc) -- verified below.
log "Installing busybox-static..."
apt-get install -y --no-install-recommends busybox-static 2>/dev/null | tail -3
BUSYBOX=$(which busybox-static 2>/dev/null || which busybox)
log "  busybox: $BUSYBOX ($($BUSYBOX --help 2>&1 | head -1))"
if ldd "$BUSYBOX" >/dev/null 2>&1; then
    echo "error: $BUSYBOX is dynamically linked; the rootfs has no libc." >&2
    echo "       install busybox-static (apt-get install busybox-static)." >&2
    exit 1
fi

# ── 2. Create ext4 image ──────────────────────────────────────────────────────
log "Creating ${ROOTFS_SIZE_MB}MB ext4 image at $ROOTFS_OUT..."
dd if=/dev/zero of="$ROOTFS_OUT" bs=1M count="$ROOTFS_SIZE_MB" status=none
mkfs.ext4 -q -L "sandbox-root" "$ROOTFS_OUT"
log "  Image created: $(stat -c '%s bytes' $ROOTFS_OUT)"

# ── 3. Mount and populate ─────────────────────────────────────────────────────
log "Mounting and populating rootfs..."
mount -o loop "$ROOTFS_OUT" "$MNTDIR"

# Directory skeleton
mkdir -p "$MNTDIR"/{bin,sbin,usr/bin,usr/sbin,dev,proc,sys,tmp,run,etc,var/log}
chmod 1777 "$MNTDIR/tmp"

# Busybox installation
cp "$BUSYBOX" "$MNTDIR/bin/busybox"
chmod +x "$MNTDIR/bin/busybox"

# Busybox symlinks (sh, mount, sleep, etc.)
for cmd in sh ash mount umount echo cat ls mkdir touch sleep ps; do
    ln -sf /bin/busybox "$MNTDIR/bin/$cmd" 2>/dev/null || true
done

# ── 3a. Workspace mountpoint (#23) ────────────────────────────────────────────
# The guest root is mounted read-only, so /init cannot create this at boot; it
# has to exist in the image. The session workspace is mounted here.
mkdir -p "$MNTDIR/workspace"

# ── 3b. Guest env agent (Phase 9b) ────────────────────────────────────────────
# Static binary; started by /init before capture, resumes blocked in accept()
# after a snapshot restore to receive the host's per-VM env over vsock.
# The peer classifier (#10) lives in the repo so the host unit test can link the
# same file; it is freestanding (libc + linux/vm_sockets.h only).
log "Building guest env agent..."
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_SRC="$REPO_ROOT/scripts/sandbox-agent.c"
gcc -static -O2 -Wall -Wextra -I"$REPO_ROOT/include" \
    -o "$MNTDIR/bin/sandbox-agent" \
    "$AGENT_SRC" "$REPO_ROOT/src/vsock_peer.c"
chmod +x "$MNTDIR/bin/sandbox-agent"
log "  agent: $(file -b "$MNTDIR/bin/sandbox-agent")"

# ── 4. Custom /init ───────────────────────────────────────────────────────────
log "Writing /init script..."
cat > "$MNTDIR/init" << 'INIT_SCRIPT'
#!/bin/sh
# Sandbox guest init — minimal environment for template snapshot creation.
# The host snapshots this VM after "SANDBOX-READY" appears on serial.

# Mount essential pseudo-filesystems
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true

# Session workspace (Phase 15, #23). The host attaches this template's workspace
# drive second, so it enumerates as /dev/vdb; the mount is made *here*, before
# capture, so the snapshot records the mounted filesystem. Every restore then
# binds a different host file behind the same device: the guest keeps this mount
# across a destroy + recreate, which is what makes a session's files persist.
# Clones are byte-identical to the base image, so the page cache captured with
# the template stays valid for the session's own copy.
mkdir -p /workspace 2>/dev/null || true
if mount -t ext4 /dev/vdb /workspace 2>/dev/null; then
    echo "SANDBOX-WORKSPACE-MOUNTED"
else
    echo "SANDBOX-WORKSPACE-NODEVICE"
fi

# Configure lo
ip link set lo up 2>/dev/null || true

# Per-VM env agent (vsock) is the foreground process. It binds the listener,
# prints "SANDBOX-READY" (the host's snapshot trigger), then busy-loops serving
# the host's per-VM env injection while emitting "SANDBOX-TICK".
#
# The agent (not this shell) owns the CPU loop on purpose: after a UFFD restore
# the aarch64 arch timer does not re-arm on this host, so the scheduler tick
# stops and a CPU-hogging shell loop would starve every other guest process.
# One process that both polls the vsock socket and emits the heartbeat keeps
# working without timer interrupts. `exec` replaces the shell so the captured
# snapshot has the agent as the only CPU consumer.
echo "SANDBOX-AGENT-LAUNCH"
exec /bin/sandbox-agent
INIT_SCRIPT
chmod +x "$MNTDIR/init"

# ── 5. Minimal /etc/passwd (avoids some kernel warnings) ─────────────────────
cat > "$MNTDIR/etc/passwd" << 'PASSWD'
root:x:0:0:root:/root:/bin/sh
PASSWD
cat > "$MNTDIR/etc/group" << 'GROUP'
root:x:0:
GROUP

log "  Rootfs contents:"
ls -la "$MNTDIR/"

# ── 6. Unmount ────────────────────────────────────────────────────────────────
log "Unmounting..."
umount "$MNTDIR"
rmdir "$MNTDIR"

# ── 7. Verify ────────────────────────────────────────────────────────────────
log ""
log "=== Rootfs complete ==="
log "Path:  $ROOTFS_OUT"
log "Size:  $(du -sh $ROOTFS_OUT | cut -f1)"
log "Type:  $(file $ROOTFS_OUT | cut -d: -f2)"
log ""
log "Verify /init exists in image:"
debugfs -R "ls -l /" "$ROOTFS_OUT" 2>/dev/null | grep "init" || \
    (mount -o loop,ro "$ROOTFS_OUT" "$MNTDIR" && ls -la "$MNTDIR/init" && umount "$MNTDIR" && rmdir "$MNTDIR")
