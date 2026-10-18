#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# e2e smoke — prove the restore path runs end to end and reports per-step
# timing. Root required (the jailer chroots + setuids).
#
# It deliberately owns no harness of its own: workspace setup, template build,
# daemon start and the latency probe all come from scripts/benchmark.sh, which
# is the single source of truth for provisioning a measurement environment.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BENCH="${REPO_DIR}/scripts/benchmark.sh"

KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --keep) KEEP=1; shift ;;
        -h|--help) echo "usage: sudo tests/e2e/smoke.sh [--keep]"; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo tests/e2e/smoke.sh)" >&2; exit 1; }
[ -x "$BENCH" ] || { echo "missing benchmark harness: $BENCH" >&2; exit 1; }

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

fail() { printf '\n[smoke] FAIL: %s\n' "$1" >&2; exit 1; }

# pool 1 + count 2 => one warm hit and one cold (provisioned) restore, so the
# restore path is actually exercised.
bash "$BENCH" --pool 1 --count 2 --keep >"$OUT" 2>&1
rc=$?
cat "$OUT"
[ "$rc" -eq 0 ] || fail "benchmark harness exited $rc"

prov="$(awk '$1=="provisioned"{print $(NF-1)}' "$OUT")"
[ -n "$prov" ] || fail "no cold (provisioned) restore sample was produced"
printf '[smoke] cold restore measured: %s ms\n' "$prov"

ws="$(awk -F': ' '/^\[info\] workspace: /{print $2}' "$OUT" | tail -1)"
[ -n "$ws" ] || fail "could not determine the workspace from the harness output"

log="${ws}/daemon.log"
[ -f "$log" ] || fail "daemon log not found: $log"
grep -q '\[vmm_restore\] time total=' "$log" \
    || fail "restore path logged no per-step timing (expected '[vmm_restore] time total=')"
printf '[smoke] %s\n' "$(grep -m1 '\[vmm_restore\] time total=' "$log")"

if [ "$KEEP" -eq 1 ]; then
    printf '[smoke] workspace kept: %s\n' "$ws"
else
    rm -rf "$ws"
fi
echo "[smoke] OK"
