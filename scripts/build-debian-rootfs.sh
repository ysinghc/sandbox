#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# build-debian-rootfs.sh
#
# Builds the Debian guest image (#32): a real userland with dpkg/apt, bash,
# coreutils and python3, the engine's static agent, and the same /init the
# busybox image uses, packed into a sparse ext4 image.
#
# Why this and not a distro ISO: the guest boots with `init=/init root=/dev/vda ro`
# and no initramfs, and `/` stays read-only. Package installs are not how a
# sandbox is customised (they would be lost, and they break determinism); the
# template is. /workspace is the writable, persistent part.
#
# Usage:
#   sudo bash scripts/build-debian-rootfs.sh [--suite bookworm] [--out PATH]
#
# Environment:
#   SANDBOX_ROOTFS_OUT        output image (default /opt/sandbox-assets/rootfs-debian.ext4)
#   SANDBOX_DEBIAN_SUITE      suite (default bookworm)
#   SANDBOX_DEBIAN_MIRROR     mirror (default http://deb.debian.org/debian)
#   SANDBOX_DEBIAN_ARCH       amd64/arm64 (default: host arch; must match host)
#   SANDBOX_DEBIAN_PACKAGES   extra comma-separated packages
#   SANDBOX_DEBIAN_SIZE_MB    fixed image size (default: derived from content)
#   SANDBOX_DEBIAN_CACHE_DIR  package cache; reuse it so a rebuild installs the same .debs
#   SANDBOX_DEBIAN_PROVISION  script run as root inside the new root after the packages
#                             are installed (the "build steps" of a template, #25)
#   SOURCE_DATE_EPOCH         timestamp every file is clamped to and the filesystem is
#                             stamped with; default: the commit time of this checkout.
#                             With the same inputs (revision, suite, mirror, packages,
#                             provision script, cached packages) the image is
#                             byte-identical, which is what makes a template's digest
#                             attributable to its spec rather than to the build.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
while [ $# -gt 0 ]; do
    case "$1" in
        --suite) SANDBOX_DEBIAN_SUITE="${2:?--suite needs a value}"; shift 2 ;;
        --out) SANDBOX_ROOTFS_OUT="${2:?--out needs a value}"; shift 2 ;;
        *) echo "[debian] error: unknown argument $1" >&2; exit 2 ;;
    esac
done
SUITE="${SANDBOX_DEBIAN_SUITE:-bookworm}"
MIRROR="${SANDBOX_DEBIAN_MIRROR:-http://deb.debian.org/debian}"
ARCH="${SANDBOX_DEBIAN_ARCH:-$(dpkg --print-architecture)}"
OUT="${SANDBOX_ROOTFS_OUT:-/opt/sandbox-assets/rootfs-debian.ext4}"
SIZE_MB="${SANDBOX_DEBIAN_SIZE_MB:-0}"
PROVISION="${SANDBOX_DEBIAN_PROVISION:-}"
SDE="${SOURCE_DATE_EPOCH:-$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null || true)}"
SDE="${SDE:-1700000000}"

# The set an agent sandbox needs to be useful out of the box. Deliberately small:
# python3 (not the -dev tree), curl for API calls, iproute2 because /init brings
# up lo, procps for ps. Anything else belongs in a template (#25).
PACKAGES="ca-certificates,curl,procps,iproute2,python3-minimal,less,file,xz-utils"
PACKAGES="${PACKAGES}${SANDBOX_DEBIAN_PACKAGES:+,${SANDBOX_DEBIAN_PACKAGES}}"

log() { echo "[debian] $*"; }
die() { echo "[debian] error: $*" >&2; exit 1; }

# ── 0. Sanity ────────────────────────────────────────────────────────────────
[ "$(id -u)" = "0" ] || die "must run as root (debootstrap + file ownership in the image)"
command -v debootstrap >/dev/null || die "debootstrap not installed (apt-get install debootstrap)"
command -v mke2fs >/dev/null || die "e2fsprogs not installed"

HOST_ARCH="$(dpkg --print-architecture)"
[ "$ARCH" = "$HOST_ARCH" ] || die "cross-arch builds are not supported yet: target $ARCH, host $HOST_ARCH
  The guest agent is compiled by this script and must match the guest. Build the
  image on a host of the target architecture (that is what CI does per leg)."

mkdir -p "$(dirname "$OUT")"
WORK="$(mktemp -d /var/tmp/debian-rootfs.XXXXXX)"
ROOTDIR="$WORK/root"
cleanup() {
    for m in dev/pts dev proc; do umount "$ROOTDIR/$m" 2>/dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── 1. Base system ───────────────────────────────────────────────────────────
log "debootstrap $SUITE ($ARCH) from $MIRROR"
# A mirror that drops a few downloads (an index naming a package version it has
# just replaced, a stalled connection) fails the whole run with "Couldn't download
# packages". That is routine for a public mirror and says nothing about the image,
# so retry; the cache keeps everything already fetched, so a retry only asks for
# what was missing.
#
# A stalled connection is worse than a failed one: debootstrap's wget has no
# overall timeout, and one dead socket hung a CI job for 40+ minutes. So give wget
# its own read timeout and bound every attempt, which turns a stall into a failure
# the retry can handle.
CACHE="${SANDBOX_DEBIAN_CACHE_DIR:-$WORK/cache}"
mkdir -p "$CACHE"
printf 'timeout = 30\ntries = 3\nwaitretry = 2\n' >"$WORK/wgetrc"
export WGETRC="$WORK/wgetrc"
attempt=1
until timeout --kill-after=30 "${DEBOOTSTRAP_TIMEOUT:-900}" debootstrap --arch="$ARCH" --variant=minbase --include="$PACKAGES" \
        --cache-dir="$CACHE" "$SUITE" "$ROOTDIR" "$MIRROR" >"$WORK/debootstrap.log" 2>&1; do
    tail -5 "$WORK/debootstrap.log" >&2
    if [ "$attempt" -ge "${DEBOOTSTRAP_ATTEMPTS:-3}" ]; then
        tail -40 "$WORK/debootstrap.log" >&2
        die "debootstrap failed after $attempt attempts (full log above)"
    fi
    log "debootstrap attempt $attempt failed; retrying in 20s"
    attempt=$((attempt + 1))
    sleep 20
    rm -rf "$ROOTDIR"
done
log "  base: $(cat "$ROOTDIR/etc/debian_version" 2>/dev/null || echo unknown) ($(du -sh "$ROOTDIR" | cut -f1))"

# ── 2. Guest pieces the engine requires ──────────────────────────────────────
# /init and the agent are the contract with the host: SANDBOX-READY on serial,
# env injection over vsock, /workspace mounted after every restore.
log "Building the guest agent (static, $ARCH)"
gcc -static -O2 -Wall -Wextra -I"$REPO_ROOT/include" \
    -ffile-prefix-map="$REPO_ROOT"=. -o "$ROOTDIR/bin/sandbox-agent" \
    "$REPO_ROOT/scripts/sandbox-agent.c" "$REPO_ROOT/src/vsock_peer.c" \
    "$REPO_ROOT/src/guest_rpc_server.c" "$REPO_ROOT/src/guest_rpc_wire.c"
chmod 0755 "$ROOTDIR/bin/sandbox-agent"

log "Installing /init (shared with the busybox image)"
install -m 0755 "$REPO_ROOT/scripts/guest-init.sh" "$ROOTDIR/init"

# ── 2b. Template build steps ─────────────────────────────────────────────────
# What a template adds to the base image beyond the package list. It runs with
# the host's network (it is a build, not a sandbox) so it can fetch pinned
# artifacts; for the image to stay reproducible it must not depend on anything
# that changes between runs (unpinned downloads, the date, random values).
if [ -n "$PROVISION" ]; then
    [ -f "$PROVISION" ] || die "provision script not found: $PROVISION"
    log "Running the provision script: $PROVISION"
    install -m 0755 "$PROVISION" "$ROOTDIR/tmp/provision.sh"
    cp /etc/resolv.conf "$ROOTDIR/etc/resolv.conf"
    mount -t proc proc "$ROOTDIR/proc"
    mount --bind /dev "$ROOTDIR/dev"
    mount -t devpts devpts "$ROOTDIR/dev/pts"
    if ! chroot "$ROOTDIR" /usr/bin/env -i HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
            SOURCE_DATE_EPOCH="$SDE" DEBIAN_FRONTEND=noninteractive /bin/bash /tmp/provision.sh; then
        die "the provision script failed"
    fi
    umount "$ROOTDIR/dev/pts" "$ROOTDIR/dev" "$ROOTDIR/proc"
fi

# The root fs is mounted read-only, so the mountpoint must exist in the image.
mkdir -p "$ROOTDIR/workspace" "$ROOTDIR/run" "$ROOTDIR/tmp"
chmod 1777 "$ROOTDIR/tmp"

# ── 3. Trim the image ────────────────────────────────────────────────────────
# Package metadata is the difference between a 300 MB image and a 450 MB one,
# and `apt-get update` in a sandbox is a network operation with no cache to
# reuse anyway (egress is policy-controlled, #26).
rm -rf "$ROOTDIR"/var/lib/apt/lists/* \
       "$ROOTDIR"/var/cache/apt/archives/*.deb \
       "$ROOTDIR"/var/log/* \
       "$ROOTDIR"/tmp/*
log "  trimmed: $(du -sh "$ROOTDIR" | cut -f1)"

cat > "$ROOTDIR/etc/hostname" <<'HOSTNAME'
sandbox
HOSTNAME
cat > "$ROOTDIR/etc/hosts" <<'HOSTS'
127.0.0.1 localhost sandbox
::1       localhost
HOSTS
# Placeholder, not a promise: egress is default-deny until #26 installs a
# per-session policy, so a guest cannot resolve anything today regardless of
# what this file says. Writing the file keeps tools that insist on reading it
# from failing for the wrong reason.
cat > "$ROOTDIR/etc/resolv.conf" <<'RESOLV'
nameserver 1.1.1.1
RESOLV
ln -sf /usr/share/zoneinfo/Etc/UTC "$ROOTDIR/etc/localtime"

# ── 3b. Make the image a function of its inputs ──────────────────────────────
# Everything below removes or pins something that would otherwise differ between
# two builds of the same spec: the install date, caches keyed on inode numbers
# and mtimes, and files newer than the epoch.
rm -f "$ROOTDIR"/var/cache/ldconfig/aux-cache "$ROOTDIR"/var/cache/apt/*.bin \
      "$ROOTDIR"/var/cache/debconf/*-old "$ROOTDIR"/var/lib/dpkg/*-old \
      "$ROOTDIR"/etc/resolv.conf.dpkg-* "$ROOTDIR"/run/* 2>/dev/null || true
: > "$ROOTDIR/etc/machine-id"
for f in "$ROOTDIR/etc/shadow" "$ROOTDIR/etc/shadow-"; do
    # field 3 of shadow is "days since epoch of the last password change"
    [ -f "$f" ] && sed -i -E "s/^([^:]*:[^:]*:)[0-9]+:/\1$((SDE / 86400)):/" "$f"
done
find "$ROOTDIR" -xdev -newermt "@$SDE" -print0 | xargs -0 -r touch -h -d "@$SDE"

# ── 4. ext4 image ────────────────────────────────────────────────────────────
# mke2fs -d populates the filesystem from the directory in one pass: no loop
# mount, no mount namespace, and the result is a sparse file (the image's
# apparent size is the filesystem size, its disk usage is the content size).
USED_MB=$(du -sm "$ROOTDIR" | cut -f1)
if [ "$SIZE_MB" = "0" ]; then
    SIZE_MB=$(( USED_MB * 135 / 100 + 64 ))
    [ "$SIZE_MB" -lt 256 ] && SIZE_MB=256
fi
log "creating ${SIZE_MB}MiB sparse ext4 at $OUT (content ${USED_MB}MiB)"
rm -f "$OUT"
truncate -s "${SIZE_MB}M" "$OUT"
# A fixed UUID and hash seed, and every timestamp the tool would take from the
# clock taken from SOURCE_DATE_EPOCH instead: mke2fs would otherwise stamp each
# image with a fresh random identity and "now".
FS_UUID="5b0e5a1d-7c0f-4f6e-9d2a-0c1f5a6d7e80"
E2FSPROGS_FAKE_TIME="$SDE" mke2fs -q -t ext4 -F -L sandbox-root -U "$FS_UUID" \
    -E "hash_seed=$FS_UUID,root_owner=0:0,nodiscard" -d "$ROOTDIR" "$OUT"

# ── 5. Verify the image itself, not the directory it came from ──────────────
# Both checks read the finished filesystem, so a bad copy (lost mode, missing
# file) cannot pass on the strength of the source tree.
debugfs -R "cat /etc/debian_version" "$OUT" 2>/dev/null | tr -d '\n' >"$WORK/ver"
[ -s "$WORK/ver" ] || die "/etc/debian_version is missing from the image"
log "  guest Debian version: $(cat "$WORK/ver")"
debugfs -R "stat /init" "$OUT" 2>/dev/null | grep -q "Mode:  0755" \
    || die "/init is missing or not executable in the image"
debugfs -R "stat /workspace" "$OUT" 2>/dev/null | grep -q "Type: directory" \
    || die "/workspace mountpoint is missing from the image"
debugfs -R "stat /bin/sandbox-agent" "$OUT" 2>/dev/null | grep -q "Mode:  0755" \
    || die "the guest agent is missing from the image"

# ── 6. Hand the file back to the invoking user ──────────────────────────────
# CI runs this under sudo from a non-root runner; a root-owned image in the
# runner's work tree makes the next checkout fail (EACCES) before its first step.
if [ "${SUDO_UID:-0}" != "0" ] && [ -n "${SUDO_UID:-}" ]; then
    log "chown $OUT to $SUDO_UID:${SUDO_GID:-$SUDO_UID}"
    chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT" "$(dirname "$OUT")"
fi

log ""
log "=== Debian guest image complete ==="
log "path:      $OUT"
log "suite:     $SUITE ($(cat "$WORK/ver"))"
log "arch:      $ARCH"
log "filesystem: ${SIZE_MB} MiB apparent, $(du -h --apparent-size "$OUT" | cut -f1) / $(du -h "$OUT" | cut -f1) on disk"
log "sha256:    $(sha256sum "$OUT" | cut -d' ' -f1)"
