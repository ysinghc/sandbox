#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# build-template.sh — build a template from a checked-in spec (#25).
#
#   base image (debootstrap) -> provision -> ext4 -> cold boot -> snapshot
#   -> content-addressed store -> published under the spec's name
#
# Usage:
#   sudo bash scripts/build-template.sh templates/python-agent [options]
#
# Options:
#   --kernel PATH      guest kernel (default $SANDBOX_KERNEL, else /opt/sandbox-assets/vmlinux)
#   --cli PATH         sandbox-cli to publish with (default: sandbox-cli on PATH, else ./build)
#   --check            validate the spec and print its sha256; build nothing (no root)
#   --rootfs-only      stop after the image and print its sha256 (no KVM needed)
#   --keep-rootfs PATH write the image here (default: a temp file, removed on exit)
#   --cache-dir DIR    debootstrap package cache (reuse it to rebuild the same image)
#   --name NAME        publish under NAME instead of the spec directory's name
#
# The snapshot root is SANDBOX_SNAPSHOT_ROOT (default /var/lib/sandbox-engine/snapshots).
# The spec format and the add-a-library workflows are in docs/TEMPLATES.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
log() { echo "[template] $*"; }
die() { echo "[template] error: $*" >&2; exit 1; }

SPEC_DIR=""; KERNEL="${SANDBOX_KERNEL:-/opt/sandbox-assets/vmlinux}"; CLI=""
CHECK=0; ROOTFS_ONLY=0; KEEP_ROOTFS=""; CACHE_DIR=""; NAME=""
while [ $# -gt 0 ]; do
    case "$1" in
        --kernel) KERNEL="${2:?}"; shift 2 ;;
        --cli) CLI="${2:?}"; shift 2 ;;
        --check) CHECK=1; shift ;;
        --rootfs-only) ROOTFS_ONLY=1; shift ;;
        --keep-rootfs) KEEP_ROOTFS="${2:?}"; shift 2 ;;
        --cache-dir) CACHE_DIR="${2:?}"; shift 2 ;;
        --name) NAME="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) die "unknown option $1" ;;
        *) [ -z "$SPEC_DIR" ] || die "one spec directory at a time"; SPEC_DIR="$1"; shift ;;
    esac
done
[ -n "$SPEC_DIR" ] || die "usage: build-template.sh SPEC_DIR [options]"
SPEC_DIR="${SPEC_DIR%/}"
CONF="$SPEC_DIR/template.conf"
[ -f "$CONF" ] || die "no $CONF"
NAME="${NAME:-$(basename "$SPEC_DIR")}"
[[ "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "invalid template name: $NAME"

# ── Parse the spec as data ───────────────────────────────────────────────────
declare -A S=( [base]=debian [suite]=bookworm [packages]= [snapshot]= [provision]=
               [memory_mib]=256 [vcpus]=1 [workspace_size_mb]=512 [description]= )
ln=0
while IFS= read -r line || [ -n "$line" ]; do
    ln=$((ln + 1))
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
    [ -n "$line" ] || continue
    [[ "$line" =~ ^([a-z_]+)=(.*)$ ]] || die "$CONF:$ln: expected key=value"
    k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
    [[ -v "S[$k]" ]] || die "$CONF:$ln: unknown key '$k'"
    S[$k]="$v"
done < "$CONF"

[ "${S[base]}" = debian ] || die "$CONF: base=${S[base]} is not supported (only 'debian')"
[[ "${S[suite]}" =~ ^[a-z][a-z0-9-]*$ ]] || die "$CONF: bad suite '${S[suite]}'"
[[ -z "${S[packages]}" || "${S[packages]}" =~ ^[a-z0-9][a-z0-9+.,:-]*$ ]] || die "$CONF: bad packages list"
[[ -z "${S[snapshot]}" || "${S[snapshot]}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "$CONF: snapshot must look like 20261001T000000Z"
for k in memory_mib vcpus workspace_size_mb; do
    [[ "${S[$k]}" =~ ^[1-9][0-9]*$ ]] || die "$CONF: $k must be a positive integer"
done
PROVISION=""
if [ -n "${S[provision]}" ]; then
    [[ "${S[provision]}" =~ ^[A-Za-z0-9._-]+$ ]] || die "$CONF: provision must be a file name in the spec directory"
    PROVISION="$SPEC_DIR/${S[provision]}"
    [ -f "$PROVISION" ] || die "$CONF: provision script $PROVISION not found"
fi

# The spec's identity: its text and the script it runs. Recorded in template.json
# so a published template can be traced to what built it.
SPEC_SHA="$( { cat "$CONF"; [ -z "$PROVISION" ] || cat "$PROVISION"; } | sha256sum | cut -d' ' -f1)"
log "spec $NAME  sha256 $SPEC_SHA"
if [ "$CHECK" = 1 ]; then
    echo "spec_sha256=$SPEC_SHA"
    exit 0
fi
[ "$(id -u)" = 0 ] || die "must run as root (debootstrap, and the cold boot needs /dev/kvm)"

# ── 1. The image ─────────────────────────────────────────────────────────────
WORK="$(mktemp -d /var/tmp/build-template.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
ROOTFS="${KEEP_ROOTFS:-$WORK/rootfs.ext4}"
export SANDBOX_DEBIAN_SUITE="${S[suite]}"
export SANDBOX_DEBIAN_PACKAGES="${S[packages]}"
export SANDBOX_ROOTFS_OUT="$ROOTFS"
[ -z "${S[snapshot]}" ] || export SANDBOX_DEBIAN_MIRROR="http://snapshot.debian.org/archive/debian/${S[snapshot]}/"
[ -z "$PROVISION" ] || export SANDBOX_DEBIAN_PROVISION="$(cd "$(dirname "$PROVISION")" && pwd)/$(basename "$PROVISION")"
[ -z "$CACHE_DIR" ] || export SANDBOX_DEBIAN_CACHE_DIR="$CACHE_DIR"
bash "$REPO_ROOT/scripts/build-debian-rootfs.sh" --suite "${S[suite]}" --out "$ROOTFS" >"$WORK/rootfs.log" 2>&1 \
    || { tail -40 "$WORK/rootfs.log" >&2; die "the image build failed (log above)"; }
ROOTFS_SHA="$(sha256sum "$ROOTFS" | cut -d' ' -f1)"
log "image sha256 $ROOTFS_SHA"
if [ "$ROOTFS_ONLY" = 1 ]; then
    echo "rootfs_sha256=$ROOTFS_SHA"
    echo "spec_sha256=$SPEC_SHA"
    exit 0
fi

# ── 2. Capture and publish ───────────────────────────────────────────────────
[ -f "$KERNEL" ] || die "kernel not found: $KERNEL (--kernel or SANDBOX_KERNEL)"
if [ -z "$CLI" ]; then
    CLI="$(command -v sandbox-cli || true)"
    [ -n "$CLI" ] || for c in "$REPO_ROOT"/build/sandbox-cli /usr/local/bin/sandbox-cli; do [ -x "$c" ] && CLI="$c" && break; done
fi
[ -n "$CLI" ] && [ -x "$CLI" ] || die "sandbox-cli not found (--cli PATH)"
log "capturing ${S[memory_mib]} MiB / ${S[vcpus]} vCPU with a ${S[workspace_size_mb]} MiB workspace"
"$CLI" template build --name "$NAME" --kernel "$KERNEL" --rootfs "$ROOTFS" \
    --memory "${S[memory_mib]}" --vcpus "${S[vcpus]}" --workspace-mb "${S[workspace_size_mb]}" \
    --spec "$(basename "$SPEC_DIR")" --spec-sha256 "$SPEC_SHA"
