#!/usr/bin/env bash
# build-custom-rootfs.sh
# Creates a minimal ext4 rootfs for sandbox template tests.
# The rootfs has a custom /init that:
#   - Mounts proc/sys/dev
#   - Prints "SANDBOX-READY" to serial (ttyS0)
#   - Sleeps forever (snapshot taken by host while running)
#
# Usage: sudo bash build-custom-rootfs.sh
set -euo pipefail

ROOTFS_OUT="/opt/sandbox-assets/rootfs.ext4"
ROOTFS_SIZE_MB=128
MNTDIR=$(mktemp -d /tmp/rootfs-mnt.XXXXXX)

log() { echo "[rootfs] $*"; }

# ── 1. Install busybox-static ─────────────────────────────────────────────────
log "Installing busybox-static..."
apt-get install -y --no-install-recommends busybox-static 2>/dev/null | tail -3
BUSYBOX=$(which busybox-static 2>/dev/null || which busybox)
log "  busybox: $BUSYBOX ($($BUSYBOX --help 2>&1 | head -1))"

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

# Configure lo
ip link set lo up 2>/dev/null || true

# Signal the host that the guest is ready for snapshotting
echo "SANDBOX-READY"

# Heartbeat: after a snapshot restore the guest resumes *mid-loop* (it does not
# re-run this script), so a fresh line here is executable proof that the
# restored vCPU is running and its pages are being served. The loop deliberately
# does NOT sleep (busy spin): on this aarch64 host the guest's arch timer does
# not fire reliably after restore, so a sleeping guest would hang in WFI.
while true; do
    echo "SANDBOX-TICK"
    i=0
    while [ "$i" -lt 200000 ]; do i=$((i + 1)); done
done
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
