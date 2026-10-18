#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# build-and-test.sh — Build sandbox-engine in the VM and run Phase 6 fixture
# Run from: multipass exec sandbox-dev -- bash /home/ubuntu/sandbox/scripts/build-and-test.sh
set -euo pipefail

BUILD_DIR="/tmp/sandbox-build"
SANDBOX_DIR="/home/ubuntu/sandbox"

log() { echo "[build] $*"; }

# ── Build ─────────────────────────────────────────────────────────────────────
log "Configuring CMake build (Release, no TSAN)..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cmake -S "${SANDBOX_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -G Ninja \
    2>&1

log "Building sandbox library and test binaries..."
cmake --build "${BUILD_DIR}" -j4 2>&1

log "Build complete. Binaries:"
ls -lh "${BUILD_DIR}/libsandbox.so" "${BUILD_DIR}/tests/make_template"

# ── Preflight checks ─────────────────────────────────────────────────────────
log ""
log "=== Preflight ==="
log "Firecracker:  $(/usr/local/bin/firecracker --version 2>&1 | head -1)"
log "vmlinux:      $(stat -c '%s bytes' /opt/sandbox-assets/vmlinux 2>/dev/null || echo MISSING)"
log "rootfs.ext4:  $(stat -c '%s bytes' /opt/sandbox-assets/rootfs.ext4 2>/dev/null || echo MISSING)"
log "KVM:          $([ -c /dev/kvm ] && echo 'present' || echo 'MISSING')"
log "uid 65534:    $(id 65534 2>/dev/null || echo 'MISSING')"

# ── Run make_template directly (no CTest, easier stderr capture) ─────────────
SNAPROOT="/tmp/sbtest-phase6/snapshots"
JAILROOT="/tmp/sbtest-phase6/jails"
rm -rf /tmp/sbtest-phase6
mkdir -p "${SNAPROOT}" "${JAILROOT}"

log ""
log "=== Running make_template ==="
log "SANDBOX_SNAPSHOT_ROOT=${SNAPROOT}"
log "SANDBOX_JAIL_ROOT=${JAILROOT}"
log "FIRECRACKER_BIN=/usr/local/bin/firecracker"

# Run with SANDBOX_FC_SECCOMP=0 first to isolate permission issues from seccomp.
sudo -E \
    SANDBOX_SNAPSHOT_ROOT="${SNAPROOT}" \
    SANDBOX_JAIL_ROOT="${JAILROOT}" \
    FIRECRACKER_BIN=/usr/local/bin/firecracker \
    SANDBOX_FC_SECCOMP=0 \
    LD_LIBRARY_PATH="${BUILD_DIR}" \
    "${BUILD_DIR}/tests/make_template" 2>&1
RC=$?

log ""
log "=== make_template exit code: ${RC} ==="
if [ "${RC}" -eq 0 ]; then
    log "SUCCESS — checking snapshot files..."
    ls -lh "${SNAPROOT}/e2e/" 2>/dev/null || log "  (published to final path)"
    ls -lh "${SNAPROOT}/" 2>/dev/null
else
    log "FAILED — jail contents for post-mortem:"
    find "${JAILROOT}" -ls 2>/dev/null | head -30 || true
    log "Last serial log lines:"
    find "${JAILROOT}" -name 'serial.log' -exec tail -30 {} \; 2>/dev/null || true
fi
exit "${RC}"
