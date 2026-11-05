#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# e2e: the remote MCP gateway (#28) against the real engine. Root + /dev/kvm.
#
# tests/test_*.go in src/mcp_gateway/ prove the gateway's own behavior against a
# fake #27 API. This proves the other half: OAuth (DCR, consent, PKCE, refresh)
# and all twelve tools, driven over Streamable HTTP, reach a real daemon and a
# real guest -- and that the numbers and bytes the tools report are the engine's.
#
# Usage: sudo tests/e2e/mcp_gateway.sh [--keep]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${SANDBOX_BUILD_DIR:-${REPO_DIR}/build}"
SANDBOXD="${BUILD_DIR}/sandboxd"
SANDBOX_API="${BUILD_DIR}/sandbox-api"
MCP_GATEWAY="${BUILD_DIR}/mcp-gateway"
MAKE_TEMPLATE="${BUILD_DIR}/tests/make_template"
FC_BIN="${FIRECRACKER_BIN:-/usr/local/bin/firecracker}"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
for f in "$SANDBOXD" "$SANDBOX_API" "$MCP_GATEWAY" "$MAKE_TEMPLATE" "$FC_BIN"; do
    [ -x "$f" ] || { echo "missing $f" >&2; exit 1; }
done
command -v curl >/dev/null && command -v python3 >/dev/null || { echo "curl and python3 are required" >&2; exit 1; }
[ -c /dev/kvm ] || { echo "/dev/kvm not present" >&2; exit 1; }

# The jail mknods /dev/kvm: it needs a filesystem that permits device nodes.
PARENT=/var/tmp
WORK="$(mktemp -d "$PARENT/sandbox-mcp.XXXXXX")"
SNAP="$WORK/snapshots"; JAIL="$WORK/jails"; WSROOT="$WORK/workspaces"
SOCK="$WORK/engine.sock"; APISOCK="$WORK/api.sock"
mkdir -p "$SNAP" "$JAIL" "$WSROOT"
TEMPLATE=mcptest
DAEMON_PID=""; API_PID=""; MCP_PID=""

cleanup() {
    [ -n "$MCP_PID" ] && kill "$MCP_PID" 2>/dev/null
    [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
    sleep 0.5
    [ -n "$MCP_PID" ] && kill -9 "$MCP_PID" 2>/dev/null
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
TOKA="tok-op-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
HA="$(printf %s "$TOKA" | sha256sum | cut -d' ' -f1)"
cat >"$WORK/tokens.conf" <<EOF
[operator]
token_sha256 = $HA
EOF
chmod 600 "$WORK/tokens.conf"
APIPORT="$(free_port)"
setsid "$SANDBOX_API" --engine-socket "$SOCK" --socket "$APISOCK" --listen "127.0.0.1:$APIPORT" \
    --tokens "$WORK/tokens.conf" --template "$TEMPLATE" --idle 600 --pool-wait 10000 >"$WORK/api.log" 2>&1 &
API_PID=$!
for _ in $(seq 1 50); do curl -s "http://127.0.0.1:$APIPORT/v1/health" >/dev/null 2>&1 && break; sleep 0.1; done
curl -s "http://127.0.0.1:$APIPORT/v1/health" >/dev/null 2>&1 || { tail -20 "$WORK/api.log" >&2; echo "api never started" >&2; exit 1; }
echo "[e2e] api up"

# ── the gateway ──────────────────────────────────────────────────────────────
printf '%s\n' "$TOKA" >"$WORK/api-token"
chmod 600 "$WORK/api-token"
MCPPORT="$(free_port)"
PUBLIC="http://127.0.0.1:$MCPPORT"
setsid "$MCP_GATEWAY" --listen "127.0.0.1:$MCPPORT" --public-url "$PUBLIC" --store "$WORK/mcp-store.json" \
    --api "http://127.0.0.1:$APIPORT" --api-token-file "$WORK/api-token" >"$WORK/gateway.log" 2>&1 &
MCP_PID=$!
for _ in $(seq 1 50); do curl -s "$PUBLIC/health" >/dev/null 2>&1 && break; sleep 0.1; done
curl -s "$PUBLIC/health" >/dev/null 2>&1 || { tail -20 "$WORK/gateway.log" >&2; echo "gateway never started" >&2; exit 1; }
echo "[e2e] gateway up at $PUBLIC"

# greq TOKEN METHOD PATH [JSON] -> HTTP_STATUS, HTTP_BODY (plain gateway routes)
greq() {
    local tok="$1" m="$2" p="$3" body="${4:-}"
    local args=(-s -m 90 -o "$WORK/body" -w '%{http_code}' -X "$m" "$PUBLIC$p")
    [ -n "$tok" ] && args+=(-H "Authorization: Bearer $tok")
    [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data-binary "$body")
    HTTP_STATUS="$(curl "${args[@]}")"
    HTTP_BODY="$(cat "$WORK/body")"
}
# mcp TOKEN JSON-RPC [ACCEPT] -> HTTP_STATUS, HTTP_BODY
mcp() {
    local tok="$1" payload="$2" accept="${3:-application/json}"
    HTTP_STATUS="$(curl -s -m 90 -o "$WORK/body" -w '%{http_code}' -X POST -H "Authorization: Bearer $tok" \
        -H 'Content-Type: application/json' -H "Accept: $accept" --data-binary "$payload" "$PUBLIC/mcp")"
    HTTP_BODY="$(cat "$WORK/body")"
}
jget() { python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
for k in sys.argv[1].split("."):
    d = d[k]
print(str(d).lower() if isinstance(d, bool) else d)' "$1" <<<"$HTTP_BODY" 2>/dev/null; }
mcp_text() { python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["content"][0]["text"])' <<<"$HTTP_BODY" 2>/dev/null; }
mcp_err() { python3 -c 'import sys,json; print(json.load(sys.stdin)["error"]["code"])' <<<"$HTTP_BODY" 2>/dev/null; }

# ── auth is required, and failures teach discovery ───────────────────────────
greq "" GET /health
check $([ "$HTTP_STATUS" = 200 ]; echo $?) "gateway health needs no credentials"
HTTP_STATUS="$(curl -s -o "$WORK/body" -w '%{http_code}' -D "$WORK/hdrs" -X POST "$PUBLIC/mcp" \
    -H 'Content-Type: application/json' --data-binary '{"jsonrpc":"2.0","id":1,"method":"ping"}')"
check $([ "$HTTP_STATUS" = 401 ] && grep -q 'oauth-protected-resource' "$WORK/hdrs"; echo $?) "MCP without a token: 401 with discovery"

# ── OAuth metadata ───────────────────────────────────────────────────────────
greq "" GET /.well-known/oauth-protected-resource
check $([ "$HTTP_STATUS" = 200 ] && [ "$(jget resource)" = "$PUBLIC/mcp" ]; echo $?) "resource metadata names this server"
greq "" GET /.well-known/oauth-authorization-server
check $([ "$HTTP_STATUS" = 200 ] && [ "$(jget issuer)" = "$PUBLIC" ] && [ -n "$(jget registration_endpoint)" ] \
    && [ "$(jget client_id_metadata_document_supported)" = true ]; echo $?) "server metadata advertises DCR and CIMD"

# ── dynamic client registration ──────────────────────────────────────────────
greq "" POST /oauth/register '{"redirect_uris":["https://client.example/cb"],"client_name":"e2e"}'
CID="$(jget client_id)"
check $([ "$HTTP_STATUS" = 201 ] && [ -n "$CID" ]; echo $?) "DCR mints a client id"

# authorize minute: PKCE pair, consent page, approval, code. No browser: the
# script plays the user agent and parses the 302 itself.
pkce() { python3 -c '
import hashlib, base64, secrets
v = secrets.token_urlsafe(48)
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
print(v); print(c)'; }
read -r VERIFIER CHALLENGE < <(pkce | tr '\n' ' '; echo)
auth_url() { python3 -c '
import sys, urllib.parse
base, cid, scope = sys.argv[1], sys.argv[2], sys.argv[3]
print(base + "/oauth/authorize?" + urllib.parse.urlencode({
    "response_type": "code", "client_id": cid, "redirect_uri": "https://client.example/cb",
    "scope": scope, "state": "e2e-state", "code_challenge": sys.argv[4],
    "code_challenge_method": "S256", "resource": base + "/mcp"}))' "$PUBLIC" "$CID" "$1" "$CHALLENGE"; }
approve() { # scope -> CODE (prints the code)
    local scope="$1" page reqid loc
    page="$(curl -s -m 30 "$(auth_url "$scope")")"
    reqid="$(grep -o 'name="reqid" value="[^"]*"' <<<"$page" | cut -d'"' -f4)"
    [ -n "$reqid" ] || { echo "no reqid" >&2; return 1; }
    loc="$(curl -s -m 30 -o /dev/null -w '%{redirect_url}' -X POST "$PUBLIC/oauth/authorize" \
        --data-urlencode "reqid=$reqid" --data-urlencode "decision=approve" --data-urlencode "api_token=$TOKA")"
    python3 -c 'import sys, urllib.parse; print(dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(sys.argv[1]).query))["code"])' "$loc"
}
PAGE="$(curl -s -m 30 "$(auth_url 'sandbox:read sandbox:write')")"
check $(grep -q 'name="reqid"' <<<"$PAGE" && grep -q 'e2e' <<<"$PAGE"; echo $?) "consent page renders for the client"
CODE="$(approve 'sandbox:read sandbox:write')"
check $([ -n "$CODE" ]; echo $?) "approved consent redirects a code"

# ── code exchange ────────────────────────────────────────────────────────────
HTTP_STATUS="$(curl -s -o "$WORK/body" -w '%{http_code}' -X POST "$PUBLIC/oauth/token" \
    --data-urlencode "grant_type=authorization_code" --data-urlencode "client_id=$CID" \
    --data-urlencode "code=$CODE" --data-urlencode "code_verifier=$VERIFIER" \
    --data-urlencode "redirect_uri=https://client.example/cb" --data-urlencode "resource=$PUBLIC/mcp")"
HTTP_BODY="$(cat "$WORK/body")"
ACCESS="$(jget access_token)"; REFRESH="$(jget refresh_token)"
check $([ "$HTTP_STATUS" = 200 ] && [ -n "$ACCESS" ] && [ -n "$REFRESH" ]; echo $?) "code plus PKCE mints access and refresh"

# ── the MCP session ──────────────────────────────────────────────────────────
mcp "$ACCESS" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28"}}'
check $([ "$(jget result.protocolVersion)" = "2026-07-28" ] && [ -n "$(jget result.capabilities.tools)" ]; echo $?) "MCP initialize negotiates"
mcp "$ACCESS" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
check $([ "$(python3 -c 'import sys,json; print(len(json.load(sys.stdin)["result"]["tools"]))' <<<"$HTTP_BODY")" = 12 ]; echo $?) "tools/list shows all 12 tools"

# ── tools against the real guest ─────────────────────────────────────────────
call() { mcp "$ACCESS" "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}"; }
t0=$(date +%s%N)
call create_session '{"key":"mcp-e2e"}'
t1=$(date +%s%N)
SID="$(mcp_text | grep -o 'ses_[0-9a-f]*' | head -1)"
check $([ -n "$SID" ] && mcp_text | grep -q '(ready)'; echo $?) "MCP create_session provisions a VM"
echo "[e2e] MCP create latency (OAuth stack included): $(( (t1 - t0) / 1000000 )) ms"
call run "{\"session_id\":\"$SID\",\"command\":\"echo hello from the guest via MCP\"}"
check $(mcp_text | grep -q 'hello from the guest via MCP' && mcp_text | grep -q 'exit 0'; echo $?) "MCP run reaches the guest"
call write_file "{\"session_id\":\"$SID\",\"path\":\"/workspace/mcp-up.txt\",\"content\":\"written over MCP\"}"
check $(mcp_text | grep -q 'wrote 16 bytes'; echo $?) "MCP write_file lands bytes"
call run "{\"session_id\":\"$SID\",\"command\":\"cat /workspace/mcp-up.txt\"}"
check $([ "$(mcp_text | tail -1)" = "written over MCP" ]; echo $?) "the guest sees the file MCP wrote"
call run "{\"session_id\":\"$SID\",\"command\":\"echo made by the guest \\u003e /workspace/mcp-down.txt\"}"
call read_file "{\"session_id\":\"$SID\",\"path\":\"/workspace/mcp-down.txt\"}"
check $([ "$(mcp_text)" = "made by the guest" ]; echo $?) "MCP read_file returns guest bytes"
call get_file_stat "{\"session_id\":\"$SID\",\"path\":\"/workspace/mcp-down.txt\"}"
check $(mcp_text | grep -q 'file, 18 bytes'; echo $?) "MCP stat reports the file"
call list_files "{\"session_id\":\"$SID\",\"path\":\"/workspace\"}"
check $(mcp_text | grep -q 'mcp-up.txt' && mcp_text | grep -q 'mcp-down.txt'; echo $?) "MCP ls shows both files"
call make_directory "{\"session_id\":\"$SID\",\"path\":\"/workspace/mcp-dir\"}"
check $(mcp_text | grep -q 'created /workspace/mcp-dir'; echo $?) "MCP mkdir creates the directory"
call delete_file "{\"session_id\":\"$SID\",\"path\":\"/workspace/mcp-dir\",\"recursive\":true}"
check $(mcp_text | grep -q 'removed /workspace/mcp-dir'; echo $?) "MCP delete removes it"
call renew "{\"session_id\":\"$SID\",\"ttl_seconds\":7200}"
check $(mcp_text | grep -q 'now expires at'; echo $?) "MCP renew extends the deadline"

# ── SSE framing ──────────────────────────────────────────────────────────────
HTTP_STATUS="$(curl -s -m 60 -o "$WORK/sse" -w '%{http_code}' -X POST -H "Authorization: Bearer $ACCESS" \
    -H 'Content-Type: application/json' -H 'Accept: text/event-stream' \
    --data-binary '{"jsonrpc":"2.0","id":5,"method":"tools/list"}' "$PUBLIC/mcp")"
check $([ "$HTTP_STATUS" = 200 ] && grep -q '^event: message' "$WORK/sse" \
    && sed -n 's/^data: //p' "$WORK/sse" | grep -q '"tools"'; echo $?) "SSE framing"

# ── protocol edges ───────────────────────────────────────────────────────────
call no_such_tool '{}'
check $([ "$(mcp_err)" = "-32602" ]; echo $?) "unknown tool is -32602"
HTTP_STATUS="$(curl -s -o /dev/null -w '%{http_code}' "$PUBLIC/mcp")"
check $([ "$HTTP_STATUS" = 405 ]; echo $?) "GET /mcp is 405 (stateless)"

# ── scopes are enforced per tool ─────────────────────────────────────────────
RCODE="$(approve 'sandbox:read')"
HTTP_STATUS="$(curl -s -o "$WORK/body" -w '%{http_code}' -X POST "$PUBLIC/oauth/token" \
    --data-urlencode "grant_type=authorization_code" --data-urlencode "client_id=$CID" \
    --data-urlencode "code=$RCODE" --data-urlencode "code_verifier=$VERIFIER" \
    --data-urlencode "redirect_uri=https://client.example/cb")"
HTTP_BODY="$(cat "$WORK/body")"
RACCESS="$(jget access_token)"
mcp "$RACCESS" '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"run","arguments":{"session_id":"x","command":"id"}}}'
check $([ "$(mcp_err)" = "-32001" ]; echo $?) "read-only token cannot run"
mcp "$RACCESS" '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"list_sessions","arguments":{}}}'
check $(mcp_text | grep -q "$SID"; echo $?) "read-only token can list"

# ── destroy ────────────────────────────────────────────────────────────────
call destroy_session "{\"session_id\":\"$SID\"}"
check $(mcp_text | grep -q 'deleted'; echo $?) "MCP destroy deletes the session"
call get_status "{\"session_id\":\"$SID\"}"
check $(mcp_text | grep -q 'not_found'; echo $?) "the destroyed session is gone"

# ── refresh rotates; a replayed refresh kills the grant ──────────────────────
HTTP_STATUS="$(curl -s -o "$WORK/body" -w '%{http_code}' -X POST "$PUBLIC/oauth/token" \
    --data-urlencode "grant_type=refresh_token" --data-urlencode "client_id=$CID" \
    --data-urlencode "refresh_token=$REFRESH")"
HTTP_BODY="$(cat "$WORK/body")"
ACCESS2="$(jget access_token)"; REFRESH2="$(jget refresh_token)"
check $([ "$HTTP_STATUS" = 200 ] && [ -n "$ACCESS2" ] && [ "$ACCESS2" != "$ACCESS" ] && [ "$REFRESH2" != "$REFRESH" ]; echo $?) "refresh rotates the pair"
mcp "$ACCESS2" '{"jsonrpc":"2.0","id":8,"method":"ping"}'
check $([ "$HTTP_STATUS" = 200 ]; echo $?) "the rotated access token works"
HTTP_STATUS="$(curl -s -o "$WORK/body" -w '%{http_code}' -X POST "$PUBLIC/oauth/token" \
    --data-urlencode "grant_type=refresh_token" --data-urlencode "client_id=$CID" \
    --data-urlencode "refresh_token=$REFRESH")"
HTTP_BODY="$(cat "$WORK/body")"
check $([ "$HTTP_STATUS" = 400 ] && [ "$(jget error)" = "invalid_grant" ]; echo $?) "replaying the spent refresh fails"
mcp "$ACCESS2" '{"jsonrpc":"2.0","id":9,"method":"ping"}'
check $([ "$HTTP_STATUS" = 401 ]; echo $?) "the replay revoked the whole grant"

if kill -0 "$MCP_PID" 2>/dev/null; then ok "the gateway process is still alive"; else bad "the gateway process died"; tail -20 "$WORK/gateway.log" >&2; fi
if kill -0 "$API_PID" 2>/dev/null; then ok "the API process is still alive"; else bad "the API process died"; tail -20 "$WORK/api.log" >&2; fi
if [ "$fails" -eq 0 ]; then echo "[e2e] ALL PASSED"; exit 0; fi
echo "[e2e] FAILED ($fails)"
tail -30 "$WORK/gateway.log" >&2
exit 1
