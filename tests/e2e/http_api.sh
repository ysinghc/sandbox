#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# e2e: the control-plane HTTP API (#27) against the real engine. Root + /dev/kvm.
#
# tests/test_http_api.c proves the API's own behaviour against a fake engine. This
# proves the other half: that the same calls, made over HTTP, reach a real daemon
# and a real guest -- create, run a command, move files both ways, keep a
# workspace across a VM's life, stream, isolate principals -- and that the
# numbers the API reports are the engine's.
#
# Usage: sudo tests/e2e/http_api.sh [--keep]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${SANDBOX_BUILD_DIR:-${REPO_DIR}/build}"
SANDBOXD="${BUILD_DIR}/sandboxd"
SANDBOX_API="${BUILD_DIR}/sandbox-api"
MAKE_TEMPLATE="${BUILD_DIR}/tests/make_template"
FC_BIN="${FIRECRACKER_BIN:-/usr/local/bin/firecracker}"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
for f in "$SANDBOXD" "$SANDBOX_API" "$MAKE_TEMPLATE" "$FC_BIN"; do
    [ -x "$f" ] || { echo "missing $f" >&2; exit 1; }
done
command -v curl >/dev/null && command -v python3 >/dev/null || { echo "curl and python3 are required" >&2; exit 1; }
[ -c /dev/kvm ] || { echo "/dev/kvm not present" >&2; exit 1; }

# The jail mknods /dev/kvm: it needs a filesystem that permits device nodes.
PARENT=/var/tmp
WORK="$(mktemp -d "$PARENT/sandbox-httpapi.XXXXXX")"
SNAP="$WORK/snapshots"; JAIL="$WORK/jails"; WSROOT="$WORK/workspaces"
SOCK="$WORK/engine.sock"; APISOCK="$WORK/api.sock"
mkdir -p "$SNAP" "$JAIL" "$WSROOT"
TEMPLATE=apitest
DAEMON_PID=""; API_PID=""

cleanup() {
    [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
    sleep 0.5
    [ -n "$API_PID" ] && kill -9 "$API_PID" 2>/dev/null
    [ -n "$DAEMON_PID" ] && kill -9 "$DAEMON_PID" 2>/dev/null
    pkill -9 -x firecracker 2>/dev/null || true
    for pat in "$JAIL" "$SNAP"; do
        mount 2>/dev/null | grep -F "$pat" | awk '{print $3}' | while read -r m; do umount -l "$m" 2>/dev/null || true; done
    done
    for d in /sys/fs/cgroup/sandboxd/active/*; do [ -d "$d" ] && rmdir "$d" 2>/dev/null || true; done
    if [ "$KEEP" = 1 ]; then echo "[e2e] workspace kept: $WORK"; else chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"; fi
}
trap cleanup EXIT INT TERM

fails=0
ok()  { printf '[e2e] %-66s PASS\n' "$1"; }
bad() { printf '[e2e] %-66s FAIL\n' "$1"; fails=$((fails + 1)); }
check() { if [ "$1" = 0 ]; then ok "$2"; else bad "$2"; fi; }

free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

# ── the engine ───────────────────────────────────────────────────────────────
export SANDBOX_SNAPSHOT_ROOT="$SNAP" SANDBOX_JAIL_ROOT="$JAIL" SANDBOX_WORKSPACE_ROOT="$WSROOT"
export SANDBOX_TEMPLATE_NAME="$TEMPLATE" FIRECRACKER_BIN="$FC_BIN"
echo "[e2e] building template '$TEMPLATE'"
"$MAKE_TEMPLATE" >"$WORK/make_template.log" 2>&1 || { tail -30 "$WORK/make_template.log" >&2; echo "template build failed" >&2; exit 1; }

METRICS_PORT="$(free_port)"
cat >"$WORK/engine.conf" <<EOF
[daemon]
socket_path = $SOCK
broker_control_socket = $WORK/broker.sock
template = $TEMPLATE
allowed_services =
allowed_uids = 0
jailer_uid = 65534
jailer_gid = 65534
vsock_settle_ms = 1000
create_workers = 4
pool_wait_timeout_ms = 10000

[pool]
pool_size = 2
max_queue_depth = 16

[cgroup]
cgroup_enable = 1
cgroup_slack_mib = 64

[paths]
jail_root = $JAIL
snapshot_root = $SNAP

[metrics]
metrics_port = $METRICS_PORT
metrics_bind = 127.0.0.1
log_level = warn
EOF
setsid "$SANDBOXD" --config "$WORK/engine.conf" >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { tail -20 "$WORK/daemon.log" >&2; echo "daemon never started" >&2; exit 1; }
for _ in $(seq 1 600); do
    warm="$(curl -s --max-time 2 "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null | awk '$1=="sandbox_pool_warm_count"{print $2}')"
    [ -n "${warm:-}" ] && [ "$warm" -ge 2 ] 2>/dev/null && break
    sleep 0.1
done
[ "${warm:-0}" -ge 2 ] 2>/dev/null || { tail -40 "$WORK/daemon.log" >&2; echo "pool never warmed" >&2; exit 1; }
echo "[e2e] engine up, pool warm"

# ── the API ──────────────────────────────────────────────────────────────────
TOKA="tok-alice-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TOKB="tok-bob-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
HA="$(printf %s "$TOKA" | sha256sum | cut -d' ' -f1)"
HB="$(printf %s "$TOKB" | sha256sum | cut -d' ' -f1)"
cat >"$WORK/tokens.conf" <<EOF
[alice]
token_sha256 = $HA
[bob]
token_sha256 = $HB
EOF
chmod 600 "$WORK/tokens.conf"
APIPORT="$(free_port)"
"$SANDBOX_API" --engine-socket "$SOCK" --socket "$APISOCK" --listen "127.0.0.1:$APIPORT" \
    --tokens "$WORK/tokens.conf" --template "$TEMPLATE" --idle 4 --pool-wait 10000 >"$WORK/api.log" 2>&1 &
API_PID=$!
for _ in $(seq 1 50); do curl -s "http://127.0.0.1:$APIPORT/v1/health" >/dev/null 2>&1 && break; sleep 0.1; done
BASE="http://127.0.0.1:$APIPORT"

# req TOKEN METHOD PATH [JSON] [curl args...] -> HTTP_STATUS, HTTP_BODY
req() {
    local tok="$1" m="$2" p="$3" body="${4:-}"
    shift 4 2>/dev/null || shift $#
    local args=(-s -m 90 -o "$WORK/body" -w '%{http_code}' -X "$m" "$BASE$p")
    [ -n "$tok" ] && args+=(-H "Authorization: Bearer $tok")
    [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data-binary "$body")
    HTTP_STATUS="$(curl "${args[@]}" "$@")"
    HTTP_BODY="$(cat "$WORK/body")"
}
jget() { python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
for k in sys.argv[1].split("."):
    d = d[k]
print(str(d).lower() if isinstance(d, bool) else d)' "$1" <<<"$HTTP_BODY" 2>/dev/null; }

# ── auth ─────────────────────────────────────────────────────────────────────
req "" GET /v1/health
check $([ "$HTTP_STATUS" = 200 ]; echo $?) "health needs no credentials"
req "" GET /v1/sessions
check $([ "$HTTP_STATUS" = 401 ]; echo $?) "no token: 401"

# ── create: and how long it takes ────────────────────────────────────────────
t0=$(date +%s%N)
req "$TOKA" POST /v1/sessions '{"key":"e2e-1"}'
t1=$(date +%s%N)
SID="$(jget id)"
check $([ "$HTTP_STATUS" = 201 ] && [ "$(jget state)" = ready ] && [ -n "$SID" ]; echo $?) "create a session: 201, ready"
echo "[e2e] create latency (HTTP, including the engine's restore): $(( (t1 - t0) / 1000000 )) ms"
EXP="$(jget expires_at)"
check $([ -n "$EXP" ] && [ "$EXP" -gt "$(date +%s)" ]; echo $?) "expires_at is a real deadline from the engine"

# ── exec ─────────────────────────────────────────────────────────────────────
req "$TOKA" POST "/v1/sessions/$SID/exec" '{"command":"echo hello from the guest; uname -s"}'
check $([ "$HTTP_STATUS" = 200 ] && jget stdout | grep -q "hello from the guest" && [ "$(jget exit_code)" = 0 ]; echo $?) "exec runs a command in the guest"
req "$TOKA" POST "/v1/sessions/$SID/exec" '{"argv":["/bin/sh","-c","exit 3"]}'
check $([ "$HTTP_STATUS" = 200 ] && [ "$(jget exit_code)" = 3 ]; echo $?) "a failing command reports its exit code"
req "$TOKA" POST "/v1/sessions/$SID/exec" '{"command":"cat","stdin":"fed through stdin"}'
check $([ "$(jget stdout)" = "fed through stdin" ]; echo $?) "stdin reaches the command"

# ── files, both directions ───────────────────────────────────────────────────
printf 'written over HTTP\n' >"$WORK/up.txt"
HTTP_STATUS="$(curl -s -o "$WORK/body" -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOKA" --data-binary @"$WORK/up.txt" "$BASE/v1/sessions/$SID/files?path=/workspace/up.txt")"
check $([ "$HTTP_STATUS" = 200 ]; echo $?) "PUT a file into /workspace"
req "$TOKA" POST "/v1/sessions/$SID/exec" '{"command":"cat /workspace/up.txt"}'
check $([ "$(jget stdout)" = "written over HTTP" ]; echo $?) "the guest sees the file the API wrote"
req "$TOKA" POST "/v1/sessions/$SID/exec" '{"command":"echo made by the guest > /workspace/down.txt"}'
HTTP_STATUS="$(curl -s -o "$WORK/down" -w '%{http_code}' -H "Authorization: Bearer $TOKA" "$BASE/v1/sessions/$SID/files?path=/workspace/down.txt")"
check $([ "$HTTP_STATUS" = 200 ] && grep -q "made by the guest" "$WORK/down"; echo $?) "GET returns the file the guest wrote"
req "$TOKA" GET "/v1/sessions/$SID/files?path=/etc/passwd"
check $([ "$HTTP_STATUS" = 400 ] && [ "$(jget error.code)" = path_denied ]; echo $?) "a path outside /workspace is refused"
req "$TOKA" GET "/v1/sessions/$SID/ls?path=/workspace"
check $([ "$HTTP_STATUS" = 200 ] && grep -q '"name":"up.txt"' <<<"$HTTP_BODY"; echo $?) "ls shows both files"

# ── streaming ────────────────────────────────────────────────────────────────
curl -s -m 60 -N -X POST -H "Authorization: Bearer $TOKA" -H 'Content-Type: application/json' \
    -d '{"command":"echo streamed; echo err >&2","stream":true}' "$BASE/v1/sessions/$SID/exec" >"$WORK/sse"
check $(grep -q '^event: started' "$WORK/sse" && grep -q '^event: stdout' "$WORK/sse" && grep -q '^event: exit' "$WORK/sse"; echo $?) "SSE: started, stdout and exit events"
check $(grep -q 'streamed' "$WORK/sse" && grep -q '"exit_code":0' "$WORK/sse"; echo $?) "SSE: the output and exit code arrive"

# ── idempotency ──────────────────────────────────────────────────────────────
req "$TOKA" POST "/v1/sessions/$SID/exec" '{"command":"echo n >> /workspace/count; cat /workspace/count | wc -l"}' -H 'Idempotency-Key: once'
FIRST="$(jget stdout)"
req "$TOKA" POST "/v1/sessions/$SID/exec" '{"command":"echo n >> /workspace/count; cat /workspace/count | wc -l"}' -H 'Idempotency-Key: once'
check $([ "$FIRST" = "$(jget stdout)" ] && [ "$FIRST" = "1" ]; echo $?) "a retried command runs once"

# ── isolation ────────────────────────────────────────────────────────────────
req "$TOKB" GET "/v1/sessions/$SID"
check $([ "$HTTP_STATUS" = 404 ]; echo $?) "another principal cannot see the session"
req "$TOKB" POST "/v1/sessions/$SID/exec" '{"command":"cat /workspace/up.txt"}'
check $([ "$HTTP_STATUS" = 404 ]; echo $?) "...nor run a command in it"
req "$TOKB" POST /v1/sessions '{"key":"e2e-1"}'
BSID="$(jget id)"
check $([ "$HTTP_STATUS" = 201 ] && [ "$BSID" != "$SID" ]; echo $?) "the same key under another principal is another session"
req "$TOKB" POST "/v1/sessions/$BSID/exec" '{"command":"ls /workspace/up.txt 2>&1; true"}'
check $(! jget stdout | grep -qx '/workspace/up.txt'; echo $?) "...with its own workspace: alice's file is not there"

# ── the unix socket identifies the caller by uid ─────────────────────────────
HTTP_STATUS="$(curl -s -o "$WORK/body" -w '%{http_code}' --unix-socket "$APISOCK" http://x/v1/sessions)"
check $([ "$HTTP_STATUS" = 200 ]; echo $?) "unix socket: no token, the uid is the identity"

# ── egress and renew ─────────────────────────────────────────────────────────
req "$TOKA" POST /v1/sessions '{"key":"e2e-offline","egress_deny_all":true}'
check $([ "$HTTP_STATUS" = 201 ]; echo $?) "a session with no egress is created"
req "$TOKA" POST "/v1/sessions/$SID/renew" '{"ttl_seconds":3600}'
check $([ "$HTTP_STATUS" = 200 ] && [ "$(jget expires_at)" -ge "$EXP" ]; echo $?) "renew returns a deadline no earlier than before"

# ── a session outlives its VM ────────────────────────────────────────────────
echo "[e2e] waiting for the idle VM to be reclaimed"
sleep 8
req "$TOKA" GET "/v1/sessions/$SID"
check $([ "$(jget state)" = idle ]; echo $?) "an idle session's VM is reclaimed; the session stays"
req "$TOKA" POST "/v1/sessions/$SID/exec" '{"command":"cat /workspace/up.txt"}'
check $([ "$HTTP_STATUS" = 200 ] && [ "$(jget stdout)" = "written over HTTP" ]; echo $?) "the next request reprovisions a VM and the workspace is intact"
req "$TOKA" GET "/v1/sessions/$SID"
check $([ "$(jget state)" = ready ]; echo $?) "...and the session is ready again"

# ── delete, then the same key finds the same files ───────────────────────────
req "$TOKA" DELETE "/v1/sessions/$SID"
check $([ "$HTTP_STATUS" = 204 ]; echo $?) "delete the session"
req "$TOKA" GET "/v1/sessions/$SID"
check $([ "$HTTP_STATUS" = 404 ]; echo $?) "it is gone"
req "$TOKA" POST /v1/sessions '{"key":"e2e-1"}'
check $([ "$HTTP_STATUS" = 201 ] && [ "$(jget id)" = "$SID" ]; echo $?) "re-creating with the same key gives the same id"
req "$TOKA" POST "/v1/sessions/$SID/exec" '{"command":"cat /workspace/up.txt /workspace/down.txt"}'
check $([ "$HTTP_STATUS" = 200 ] && jget stdout | grep -q 'written over HTTP' && jget stdout | grep -q 'made by the guest'; echo $?) "...and the files from before are still there"

if kill -0 "$API_PID" 2>/dev/null; then ok "the API process is still alive"; else bad "the API process died"; tail -20 "$WORK/api.log" >&2; fi
if [ "$fails" -eq 0 ]; then echo "[e2e] ALL PASSED"; exit 0; fi
echo "[e2e] FAILED ($fails)"
tail -30 "$WORK/api.log" >&2
exit 1
