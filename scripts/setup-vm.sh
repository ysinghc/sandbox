#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# setup-vm.sh — Bootstrap sandbox-dev Multipass VM for Phase 6 testing
# Run as: sudo bash setup-vm.sh (inside the VM)
set -euo pipefail

FC_VERSION="v1.17.0"
ARCH="x86_64"

log() { echo "[setup] $*"; }

# ── 1. System packages ────────────────────────────────────────────────────────
log "Installing build dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config git \
    libseccomp-dev libprotobuf-dev protobuf-compiler \
    linux-tools-generic \
    curl wget ca-certificates \
    cpu-checker util-linux \
    attr xattr \
    2>/dev/null

# ── 2. KVM check ─────────────────────────────────────────────────────────────
log "Checking KVM..."
if [ -c /dev/kvm ]; then
    chmod 666 /dev/kvm
    log "  /dev/kvm OK"
else
    log "  WARNING: /dev/kvm not present — make_template will SKIP (needs KVM)"
fi

# ── 3. Firecracker binary ─────────────────────────────────────────────────────
log "Downloading Firecracker ${FC_VERSION}..."
TMP_FC=$(mktemp -d)
curl -sSL \
    "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-${ARCH}.tgz" \
    -o "${TMP_FC}/fc.tgz"
tar -xz -C "${TMP_FC}" -f "${TMP_FC}/fc.tgz"
# The tarball contains release-<version>-<arch>/firecracker-<version>-<arch>
FC_BIN=$(find "${TMP_FC}" -name "firecracker-${FC_VERSION}-${ARCH}" -type f | head -1)
if [ -z "${FC_BIN}" ]; then
    log "ERROR: could not find firecracker binary in tarball"
    ls -la "${TMP_FC}"/*/
    exit 1
fi
install -m 755 "${FC_BIN}" /usr/local/bin/firecracker
log "  Firecracker installed: $(/usr/local/bin/firecracker --version 2>&1 | head -1)"
rm -rf "${TMP_FC}"

# ── 4. Guest assets ───────────────────────────────────────────────────────────
log "Downloading Firecracker guest assets (vmlinux + rootfs)..."
mkdir -p /opt/sandbox-assets

# Use the official Firecracker getting-started assets (these are the same ones
# used in their CI and quick-start guide).
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin"
ROOTFS_URL="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/rootfs/bionic.rootfs.ext4"

log "  Downloading vmlinux (~24MB)..."
curl -sSL "${KERNEL_URL}" -o /opt/sandbox-assets/vmlinux
log "  vmlinux: $(stat -c '%s bytes' /opt/sandbox-assets/vmlinux)"

log "  Downloading rootfs (~83MB)..."
curl -sSL "${ROOTFS_URL}" -o /opt/sandbox-assets/rootfs.ext4
log "  rootfs: $(stat -c '%s bytes' /opt/sandbox-assets/rootfs.ext4)"

# ── 5. nobody user/group (uid 65534) ─────────────────────────────────────────
log "Ensuring uid/gid 65534 (nobody/nogroup) exists..."
id 65534 &>/dev/null || useradd -u 65534 -M -s /usr/sbin/nologin nobody-jail
getent group 65534 &>/dev/null || groupadd -g 65534 nogroup-jail
log "  uid 65534: OK"

# ── 6. Summary ────────────────────────────────────────────────────────────────
log ""
log "=== Setup complete ==="
log "Firecracker: $(/usr/local/bin/firecracker --version 2>&1 | head -1)"
log "vmlinux:     $(ls -lh /opt/sandbox-assets/vmlinux | awk '{print $5, $9}')"
log "rootfs:      $(ls -lh /opt/sandbox-assets/rootfs.ext4 | awk '{print $5, $9}')"
log "KVM:         $([ -c /dev/kvm ] && echo 'present' || echo 'MISSING')"
log ""
log "Next: build the project inside the VM and run CTest."
