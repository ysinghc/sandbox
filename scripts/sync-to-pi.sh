#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Sync local sandbox source to the test Pi and rebuild. Run from the repo root.
#
# Remote paths are deliberately tilde-free:
#   - REMOTE is relative, which rsync resolves against the remote user's home.
#   - BUILD contains a literal `$HOME` that the REMOTE shell expands.
# A literal `~` inside a `${VAR:-~...}` default is tilde-expanded LOCALLY by
# bash (the ~ follows the `:`), which silently pointed rsync/the build at the
# local home. The excludes are ANCHORED (/build/, /build-*/): a bare `build*`
# would also drop scripts/build-*.sh from the sync.
set -euo pipefail

PI=${PI:-lab@10.42.0.66}
REMOTE=${REMOTE:-sandbox}          # relative -> remote $HOME/sandbox
BUILD=${BUILD:-'$HOME/sb-build'}   # expanded by the remote shell

rsync -a \
    --exclude='/build/' --exclude='/build-*/' \
    --exclude='/Testing/' --exclude='.git/' --exclude='run/' \
    ./ "$PI:$REMOTE/"

ssh "$PI" "cmake --build $BUILD -j4 2>&1 | tail -3"
