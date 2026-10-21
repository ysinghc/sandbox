#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# fetch-guest-kernel.sh -- install the pinned guest kernel from Firecracker's
# public CI bucket, verifying it against a digest recorded in this file.
#
# Why pin instead of "latest": the guest kernel is part of the template, so a
# silent kernel change would silently invalidate every measured boot/restore
# number and every guest-side assertion. The version, snapshot and digests live
# here, under review, and the script refuses anything else.
#
# Why not the 4.14 quickstart kernel: 4.14 is EOL (no fixes since 2024), its
# ext4 lacks modern metadata features, and it is older than the vsock local
# transport (Linux 5.6). A sandbox product should not ship an unmaintained
# kernel inside the isolation boundary. 6.18 is what Firecracker's own CI tests
# with this release line; see docs/BUILDING.md "Guest kernels".
#
# Usage:
#   scripts/fetch-guest-kernel.sh [--arch native|x86_64|aarch64] [--out PATH]
#
# --out defaults to "vmlinux" in the current directory. The config is written
# next to it as "<out>.config" so the provenance of a booted kernel is
# answerable from the tree it was installed into.
set -euo pipefail

PINNED_VERSION="6.18.54"
PINNED_SNAPSHOT="20261021-1e5fcc27b59f-0"
BASE_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/${PINNED_SNAPSHOT}"

# sha256 of vmlinux-6.18.54 / vmlinux-6.18.54.config, per architecture.
SHA_X86_64_VMLINUX="f697969a2f005d296e8c5e2fcd0f6a4f305eb3a06b085d3930d10f1eab3a0883"
SHA_X86_64_CONFIG="7dbdc7445d01d3dd049b1e653534bde71266d59afaf9c1de50a8a6b8a8c138d0"
SHA_AARCH64_VMLINUX="92f2569ccb456f62c2c7618b9d9ce40020effbd173783633da051d1d9816b9ba"
SHA_AARCH64_CONFIG="7dc3f6139862e6411ab2f9012ca60b321742a7b82fd731fcd1fe8510a788c5e0"

arch="native"
out="vmlinux"

while [ $# -gt 0 ]; do
    case "$1" in
        --arch) arch="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ "$arch" = "native" ]; then
    case "$(uname -m)" in
        x86_64|aarch64) arch="$(uname -m)" ;;
        *) echo "error: unsupported host arch $(uname -m); pass --arch" >&2; exit 2 ;;
    esac
fi

case "$arch" in
    x86_64)
        sha_vmlinux="$SHA_X86_64_VMLINUX"
        sha_config="$SHA_X86_64_CONFIG" ;;
    aarch64)
        sha_vmlinux="$SHA_AARCH64_VMLINUX"
        sha_config="$SHA_AARCH64_CONFIG" ;;
    *) echo "error: arch must be x86_64 or aarch64 (got '$arch')" >&2; exit 2 ;;
esac

vmlinux_url="$BASE_URL/$arch/vmlinux-$PINNED_VERSION"
config_url="$BASE_URL/$arch/vmlinux-$PINNED_VERSION.config"

log() { echo "[kernel] $*"; }

out_dir="$(dirname "$out")"
mkdir -p "$out_dir"
tmp_vmlinux="$(mktemp "$out.XXXXXX")"
tmp_config="$(mktemp "$out.config.XXXXXX")"
trap 'rm -f "$tmp_vmlinux" "$tmp_config"' EXIT

fetch() {
    local url="$1" dst="$2" want="$3" what="$4"
    log "fetching $what: $url"
    curl -fsSL "$url" -o "$dst"
    local got
    got="$(sha256sum "$dst" | cut -d' ' -f1)"
    if [ "$got" != "$want" ]; then
        echo "error: $what digest mismatch" >&2
        echo "  want $want" >&2
        echo "  got  $got" >&2
        exit 1
    fi
}

fetch "$vmlinux_url" "$tmp_vmlinux" "$sha_vmlinux" "vmlinux-$PINNED_VERSION ($arch)"
fetch "$config_url" "$tmp_config" "$sha_config" "vmlinux-$PINNED_VERSION.config ($arch)"

chmod 0644 "$tmp_vmlinux" "$tmp_config"
mv -f "$tmp_vmlinux" "$out"
mv -f "$tmp_config" "$out.config"

log "installed: $out ($(stat -c '%s bytes' "$out"), sha256 ${sha_vmlinux:0:16}...)"
log "config:    $out.config"
log "provenance: firecracker-ci/$PINNED_SNAPSHOT/$arch/vmlinux-$PINNED_VERSION"
log "use it:    SANDBOX_KERNEL=$out"
