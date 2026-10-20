#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# /init for the sandbox guest. Installed verbatim into every guest image
# (busybox and Debian alike) so the two cannot drift; see
# scripts/build-custom-rootfs.sh and scripts/build-debian-rootfs.sh.
#
# The host snapshots this VM after "SANDBOX-READY" appears on serial.

# Mount essential pseudo-filesystems
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true
# Debian expects a writable /run even when / is read-only (apt, dpkg and most
# daemons create lock files there). The busybox image has no /run; the guard
# keeps this a no-op for it.
[ -d /run ] && mount -t tmpfs tmpfs /run 2>/dev/null

# Session workspace (Phase 15, #23). The host attaches this template's workspace
# drive second, so it enumerates as /dev/vdb.
#
# It is deliberately NOT mounted here. The template is snapshotted with this
# process's memory, so mounting before the capture would bake the *base* image's
# ext4 superblock, inode tables and page cache into the snapshot -- and every
# restore serves a different file (the session's own copy) behind the same
# device. The guest would then read stale metadata from RAM and report
# "EXT4-fs error: checksumming directory block 0" as soon as it touched
# /workspace. Instead the agent mounts the volume after each restore (see
# scripts/sandbox-agent.c), which also means ext4 replays the journal of a
# session that was killed mid-write, so a volume cannot come back inconsistent.
if [ -b /dev/vdb ]; then
    echo "SANDBOX-WORKSPACE-DEVICE present"
else
    echo "SANDBOX-WORKSPACE-DEVICE absent"
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
#
# Do not "simplify" this back to a shell `sleep 1` heartbeat. On aarch64 the
# guest's timer interrupt is never delivered after a restore (SYSTEM DESIGN.md
# §15.7 has a minimal, engine-free reproduction: a guest snapshotted mid-sleep
# never wakes, and a 6.1 guest behaves identically -- it is upstream
# firecracker#6313). x86_64 is unaffected, but the heartbeat stays portable.
echo "SANDBOX-AGENT-LAUNCH"
exec /bin/sandbox-agent
