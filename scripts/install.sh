#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# install.sh — install a Sandbox Engine release for this machine's architecture.
#
# Downloads the release's staged install tree (the same asset that has been
# published since v0.12.0, so this works for old and new releases alike),
# verifies its SHA-256, and installs the binaries and libraries.
#
#   sudo scripts/install.sh                      # latest, into /usr/local
#   sudo scripts/install.sh --version v0.12.0
#   sudo scripts/install.sh --prefix /opt/sandbox
#   sudo scripts/install.sh --full               # whole tree over / (units, config, state dirs)
#   scripts/install.sh --dry-run                 # print the plan, download nothing
#
# x86_64 and aarch64 are both first-class (arm64 releases are built natively on
# ubuntu-24.04-arm). The asset for this machine is selected automatically.

set -uo pipefail

REPO="${SANDBOX_REPO:-ysinghc/sandbox}"
VERSION="latest"
PREFIX="/usr/local"
FULL=0
DRY_RUN=0

die() { printf 'install.sh: %s\n' "$1" >&2; exit 1; }

usage() {
    cat <<'EOF'
usage: install.sh [options]

  --version <tag|latest>   release to install                (default: latest)
  --prefix <dir>           where binaries/libraries go       (default: /usr/local)
  --full                   extract the whole staged tree over / (root, and
                           installs systemd units, config and state dirs)
  --dry-run                print the plan; download nothing
  -h, --help               this help

Environment:
  SANDBOX_REPO             owner/repo to pull from  (default: ysinghc/sandbox)
  SANDBOX_BASE_URL         override the release download base (mirrors/air-gap)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || die "--version needs an argument"; VERSION="$2"; shift 2 ;;
        --prefix)  [ $# -ge 2 ] || die "--prefix needs an argument";  PREFIX="$2";  shift 2 ;;
        --full)    FULL=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

case "$(uname -m)" in
    x86_64|amd64)  ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) die "unsupported architecture: $(uname -m) (need x86_64 or aarch64)" ;;
esac

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar  >/dev/null 2>&1 || die "tar is required"

if [ "$VERSION" = latest ]; then
    VERSION="$(curl -fsSL --retry 3 --retry-delay 2 "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -m1 '"tag_name"' \
        | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
    [ -n "$VERSION" ] || die "could not resolve the latest release of ${REPO}"
fi

BASE="sandbox-engine-${VERSION#v}-linux-${ARCH}"
ASSET="${BASE}.tar.gz"
BASE_URL="${SANDBOX_BASE_URL:-https://github.com/${REPO}/releases/download}"
URL="${BASE_URL%/}/${VERSION}"

printf 'Sandbox Engine %s (%s)\n' "$VERSION" "$ARCH"
printf '  asset:  %s\n' "$ASSET"
if [ "$FULL" -eq 1 ]; then
    printf '  action: extract the staged tree over /\n'
    [ "$(id -u)" -eq 0 ] || die "--full extracts over / and must run as root"
else
    printf '  action: install binaries to %s/bin, libraries to %s/lib\n' \
        "$PREFIX" "$PREFIX"
fi

if [ "$DRY_RUN" -eq 1 ]; then
    printf '  (dry run — nothing downloaded)\n'
    exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

printf '  downloading %s ...\n' "$URL/$ASSET"
curl -fsSL --retry 3 --retry-delay 2 -o "$TMP/$ASSET" "$URL/$ASSET" \
    || die "download failed: $URL/$ASSET"

if command -v sha256sum >/dev/null 2>&1 \
   && curl -fsSL --retry 3 --retry-delay 2 -o "$TMP/$ASSET.sha256" "$URL/$ASSET.sha256" 2>/dev/null; then
    ( cd "$TMP" && sha256sum -c "$ASSET.sha256" >/dev/null ) \
        || die "checksum verification failed for $ASSET"
    printf '  checksum: ok\n'
else
    printf '  warning: no SHA-256 available for %s; skipped verification\n' \
        "$ASSET" >&2
fi

if [ "$FULL" -eq 1 ]; then
    tar -C / -xzf "$TMP/$ASSET" || die "extract failed"
    command -v ldconfig >/dev/null 2>&1 && ldconfig
    printf '  installed staged tree over /\n'
    exit 0
fi

mkdir -p "$TMP/tree"
tar -C "$TMP/tree" -xzf "$TMP/$ASSET" || die "extract failed"

# Locate installed files rather than assume a bindir/libdir layout (the tree
# has moved between releases: lib/ vs lib/<triplet>/).
find_one() {
    local f
    f="$(find "$TMP/tree" -type f -name "$1" -print -quit)"
    [ -n "$f" ] || die "release asset does not contain '$1'"
    printf '%s\n' "$f"
}

BIN_DIR="$(dirname "$(find_one sandboxd)")"
LIB_DIR="$(dirname "$(find_one libsandbox.so)")"

mkdir -p "$PREFIX/bin" "$PREFIX/lib"
for b in sandboxd sandbox-broker sandbox-cli; do
    src="$BIN_DIR/$b"
    [ -f "$src" ] || die "release asset is missing '$b'"
    install -m 0755 "$src" "$PREFIX/bin/$b"
    printf '  installed %s\n' "$PREFIX/bin/$b"
done
for l in libsandbox.so 'libsandbox++.so'; do
    src="$LIB_DIR/$l"
    [ -f "$src" ] || die "release asset is missing '$l'"
    install -m 0755 "$src" "$PREFIX/lib/$l"
    printf '  installed %s\n' "$PREFIX/lib/$l"
done

# Make libsandbox discoverable. Best effort: only touch the loader cache when
# we are root and the prefix is a real system prefix.
if command -v ldconfig >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' "$PREFIX/lib" > /etc/ld.so.conf.d/sandbox-engine.conf
    ldconfig
    printf '  registered %s/lib with the dynamic loader\n' "$PREFIX"
else
    printf '  note: add %s/lib to LD_LIBRARY_PATH (or ld.so.conf) so\n' "$PREFIX"
    printf '        clients can link against libsandbox\n'
fi

printf '  done.\n'
