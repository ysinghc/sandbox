#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# e2e latency assertions. Runs scripts/benchmark.sh once and asserts both
# contractual numbers: warm pool hits and cold (provisioned) restores.
#
# This replaces the planned bench_warm.sh + bench_provisioned.sh, which would
# each have re-run the entire harness (template build + 10 creates) to read a
# single number off the same output.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BENCH="${REPO_DIR}/scripts/benchmark.sh"

POOL=5
COUNT=10
WARM_MAX_MS="${SANDBOX_WARM_MAX_MS:-5}"
PROV_MAX_MS="${SANDBOX_PROV_MAX_MS:-250}"

usage() {
    cat <<'EOF'
usage: sudo tests/e2e/latency.sh [options]

  --pool N                 warm pool size            (default 5)
  --count N                sandboxes to start        (default 10)
  --warm-max-ms MS         warm-hit ceiling          (default 5)
  --provisioned-max-ms MS  cold-restore ceiling      (default 250)
  -h, --help               this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --pool) POOL="$2"; shift 2 ;;
        --count) COUNT="$2"; shift 2 ;;
        --warm-max-ms) WARM_MAX_MS="$2"; shift 2 ;;
        --provisioned-max-ms) PROV_MAX_MS="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo tests/e2e/latency.sh)" >&2; exit 1; }
[ -x "$BENCH" ] || { echo "missing benchmark harness: $BENCH" >&2; exit 1; }

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

bash "$BENCH" --pool "$POOL" --count "$COUNT" >"$OUT" 2>&1
rc=$?
cat "$OUT"
[ "$rc" -eq 0 ] || { echo "[latency] FAIL: harness exited $rc" >&2; exit 1; }

warm="$(awk '$1=="warm"{print $(NF-1)}' "$OUT")"
prov="$(awk '$1=="provisioned"{print $(NF-1)}' "$OUT")"

fail=0
check() {  # label value max_ms
    local label="$1" value="$2" max="$3"
    if [ -z "$value" ]; then
        printf '[latency] FAIL: no %s samples\n' "$label"
        fail=1
    elif awk -v v="$value" -v m="$max" 'BEGIN{exit !(v<=m)}'; then
        printf '[latency] %-11s %8s ms  (<= %s ms)  OK\n' "$label" "$value" "$max"
    else
        printf '[latency] %-11s %8s ms  (>  %s ms)  FAIL\n' "$label" "$value" "$max"
        fail=1
    fi
}

check warm "$warm" "$WARM_MAX_MS"
check provisioned "$prov" "$PROV_MAX_MS"

exit "$fail"
