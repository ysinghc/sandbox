#!/usr/bin/env bash
# run-template-test.sh — Run make_template with proper library path, must be run as root
# Usage: sudo bash run-template-test.sh
set -euo pipefail

BUILD=/tmp/sandbox-build
SNAP=/tmp/sbtest-final/snapshots
JAIL=/tmp/sbtest-final/jails

echo "[run] Verifying binary has diagnostic strings..."
if strings "${BUILD}/libsandbox.so" | grep -q "jailer steps"; then
    echo "  OK: diagnostic strings found in libsandbox.so"
else
    echo "  ERROR: diagnostic strings NOT in libsandbox.so - wrong binary!"
    exit 1
fi

echo ""
echo "[run] Checking library load path..."
# Use patchelf or chrpath to bake in the RPATH, or set via ldconfig
ldconfig -n "${BUILD}"

echo ""
echo "[run] Creating test dirs..."
rm -rf /tmp/sbtest-final
mkdir -p "${SNAP}" "${JAIL}"

echo ""
echo "[run] Starting make_template with all env vars..."
echo "  BUILD=${BUILD}"
echo "  SNAP=${SNAP}"
echo "  JAIL=${JAIL}"
echo "  FC=$(/usr/local/bin/firecracker --version 2>&1 | head -1)"
echo ""

# Bypass potential sudo LD_LIBRARY_PATH stripping by using the wrapper directly
exec env \
    SANDBOX_SNAPSHOT_ROOT="${SNAP}" \
    SANDBOX_JAIL_ROOT="${JAIL}" \
    FIRECRACKER_BIN=/usr/local/bin/firecracker \
    SANDBOX_FC_SECCOMP=0 \
    LD_LIBRARY_PATH="${BUILD}" \
    "${BUILD}/tests/make_template"
