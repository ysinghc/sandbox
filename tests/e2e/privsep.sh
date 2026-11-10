#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# e2e: the unprivileged daemon through sandbox-privileged (#9). Root + /dev/kvm
# to run (something has to start the helper), but the daemon itself runs as
# the sandboxd user and every privileged operation -- tap, nftables, jail,
# cgroup, VMM spawn/reap -- crosses the helper socket.
#
# Proves: the split actually runs (provision/exec/destroy through the helper),
# the jail/serial permissions keep the daemon's access with the world locked
# out, cgroups still meter, a session volume survives a VM's death *and* its
# ownership round-trips back to the daemon for the next attach, and nothing
# privileged leaks afterwards.
#
# Usage: sudo tests/e2e/privsep.sh [--keep]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../..}" && pwd)"
BUILD_DIR="${SANDBOX_BUILD_DIR:-${REPO_DIR}/build}"
SANDBOXD="${BUILD_DIR}/sandboxd"
HELPER="${BUILD_DIR}/sandbox-privileged"
CLI="${BUILD_DIR}/sandbox-cli"
MAKE_TEMPLATE="${BUILD_DIR}/tests/make_template"
FC_BIN="${FIRECRACKER_BIN:-/usr/local/bin/firecracker}"
DAEMON_USER="sandboxd"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
for f in "$SANDBOXD" "$HELPER" "$CLI" "$MAKE_TEMPLATE" "$FC_BIN"; do
    [ -x "$f" ] || { echo "missing $f" >&2; exit 1; }
done
command -v curl >/dev/null && command -v setpriv >/dev/null || { echo "curl and setpriv are required" >&2; exit 1; }
[ -c /dev/kvm ] || { echo "/dev/kvm not present" >&2; exit 1; }

# The jail mknods /dev/kvm: it needs a filesystem that permits device nodes.
PARENT=/var/tmp
WORK="$(mktemp -d "$PARENT/sandbox-privsep.XXXXXX")"
SNAP="$WORK/snapshots"; JAIL="$WORK/jails"; WSROOT="$WORK/workspaces"
SOCK="$WSROOT/engine.sock"; HELPER_SOCK="$WORK/helper.sock"
TEMPLATE=privseptest
HELPER_PID=""; DAEMON_PID=""

cleanup() {
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
    [ -n "$HELPER_PID" ] && kill "$HELPER_PID" 2>/dev/null
    sleep 0.5
    [ -n "$DAEMON_PID" ] && kill -9 "$DAEMON_PID" 2>/dev/null
    [ -n "$HELPER_PID" ] && kill -9 "$HELPER_PID" 2>/dev/null
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

free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

# ── users and kernel knobs ──────────────────────────────────────────────────
if ! id "$DAEMON_USER" >/dev/null 2>&1; then
    useradd -r -M -s /usr/sbin/nologin "$DAEMON_USER" || { echo "cannot create $DAEMON_USER" >&2; exit 1; }
fi
[ "$(id -u "$DAEMON_USER")" -ne 0 ] || { echo "$DAEMON_USER is uid 0?!" >&2; exit 1; }
# The daemon serves page faults in-process; unprivileged userfaultfd needs this.
sysctl -w vm.unprivileged_userfaultfd=1 >/dev/null || { echo "cannot set vm.unprivileged_userfaultfd" >&2; exit 1; }

# ── template (built as root: the store is operator-written, daemon-read) ────
export SANDBOX_SNAPSHOT_ROOT="$SNAP" SANDBOX_JAIL_ROOT="$JAIL" SANDBOX_WORKSPACE_ROOT="$WSROOT"
export SANDBOX_TEMPLATE_NAME="$TEMPLATE" FIRECRACKER_BIN="$FC_BIN"
mkdir -p "$SNAP" "$JAIL" "$WSROOT"
echo "[e2e] building template '$TEMPLATE'"
"$MAKE_TEMPLATE" >"$WORK/make_template.log" 2>&1 || { tail -30 "$WORK/make_template.log" >&2; echo "template build failed" >&2; exit 1; }
# The daemon reads the store as an unprivileged user: everything must be o+r.
unreadable="$(find "$SNAP" ! -perm -o+r | head -n 5)"
[ -z "$unreadable" ] && ok "the snapshot store is world-readable" || { bad "the snapshot store is world-readable"; echo "$unreadable" >&2; }
chmod 0755 "$SNAP" "$JAIL"

METRICS_PORT="$(free_port)"
cat >"$WORK/engine.conf" <<EOF
[daemon]
socket_path = $SOCK
broker_control_socket = $WSROOT/broker.sock
template = $TEMPLATE
allowed_services =
allowed_uids = 0
jailer_uid = 65534
jailer_gid = 65534
vsock_settle_ms = 1000
create_workers = 4
max_creates_per_session = 8
max_creates_per_uid = 8

[pool]
pool_size = 1
max_queue_depth = 8

[cgroup]
cgroup_enable = 1
cgroup_slack_mib = 64

[paths]
jail_root = $JAIL
snapshot_root = $SNAP
privileged_socket = $HELPER_SOCK

[metrics]
metrics_port = $METRICS_PORT
metrics_bind = 127.0.0.1
log_level = info
EOF
chmod 0644 "$WORK/engine.conf"
# The daemon owns its socket, logs, broker socket and volumes -- nothing else.
chown -R "$DAEMON_USER:$DAEMON_USER" "$WSROOT"
touch "$WORK/daemon.log" "$WORK/helper.log"
chown "$DAEMON_USER:$DAEMON_USER" "$WORK/daemon.log"
chmod 0644 "$WORK/helper.log"

# ── the helper (root) and the daemon (sandboxd) ─────────────────────────────
setsid "$HELPER" --socket "$HELPER_SOCK" --daemon-user "$DAEMON_USER" \
    --jail-root "$JAIL" --snapshot-root "$SNAP" --workspace-root "$WSROOT" \
    >"$WORK/helper.log" 2>&1 &
HELPER_PID=$!
for i in $(seq 1 100); do
    [ -S "$HELPER_SOCK" ] && break
    kill -0 "$HELPER_PID" 2>/dev/null || { tail -n 20 "$WORK/helper.log" >&2; echo "helper exited during startup" >&2; exit 1; }
    sleep 0.1
done
[ -S "$HELPER_SOCK" ] || { echo "helper socket never appeared" >&2; exit 1; }

setsid setpriv --reuid "$DAEMON_USER" --regid "$DAEMON_USER" --clear-groups \
    env SANDBOX_WORKSPACE_ROOT="$WSROOT" FIRECRACKER_BIN="$FC_BIN" \
    "$SANDBOXD" --config "$WORK/engine.conf" >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 100); do
    [ -S "$SOCK" ] && break
    kill -0 "$DAEMON_PID" 2>/dev/null || { tail -n 20 "$WORK/daemon.log" >&2; echo "daemon exited during startup" >&2; exit 1; }
    sleep 0.1
done
[ -S "$SOCK" ] || { echo "daemon socket never appeared" >&2; exit 1; }

[ "$(ps -o user= -p "$DAEMON_PID" | tr -d ' ')" = "$DAEMON_USER" ] && ok "the daemon runs as $DAEMON_USER" || bad "the daemon runs as $DAEMON_USER"
[ "$(ps -o user= -p "$HELPER_PID" | tr -d ' ')" = "root" ] && ok "the helper runs as root" || bad "the helper runs as root"

echo "[e2e] waiting for 1 warm sandbox..."
warm=""
for i in $(seq 1 900); do
    warm="$(curl -s --max-time 2 "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null | awk '$1=="sandbox_pool_warm_count"{print $2}')"
    [ -n "${warm:-}" ] && [ "$warm" -ge 1 ] 2>/dev/null && break
    sleep 0.1
done
[ -n "${warm:-}" ] && [ "$warm" -ge 1 ] 2>/dev/null && ok "the pool warms through the helper" || { bad "the pool warms through the helper"; tail -n 30 "$WORK/daemon.log" >&2; }

# ── a live jail keeps the daemon's access with the world locked out ─────────
live_jail="$(find "$JAIL" -maxdepth 1 -mindepth 1 -name 'vm-*' -type d | head -n 1)"
[ -n "$live_jail" ] && ok "a live jail exists" || bad "a live jail exists"
if [ -n "$live_jail" ]; then
    [ "$(stat -c '%a %G' "$live_jail")" = "770 $DAEMON_USER" ] && ok "the jail is 0770 $DAEMON_USER" || bad "the jail is 0770 $DAEMON_USER (got $(stat -c '%a %G' "$live_jail"))"
    if [ -f "$live_jail/serial.log" ]; then
        [ "$(stat -c '%a %G' "$live_jail/serial.log")" = "640 $DAEMON_USER" ] && ok "serial.log is 0640 $DAEMON_USER" || bad "serial.log is 0640 $DAEMON_USER (got $(stat -c '%a %G' "$live_jail/serial.log"))"
    else
        bad "serial.log exists in the live jail"
    fi
    vm_base="$(basename "$live_jail")"
    ip link show "tap-$vm_base" >/dev/null 2>&1 && ok "tap-$vm_base exists" || bad "tap-$vm_base exists"
    [ -d "/sys/fs/cgroup/sandboxd/active/$vm_base" ] && ok "cgroup meters $vm_base" || bad "cgroup meters $vm_base"
fi
grep -q 'NET_UP' "$WORK/helper.log" && grep -q 'SPAWN' "$WORK/helper.log" \
    && ok "the helper served NET_UP and SPAWN" || bad "the helper served NET_UP and SPAWN"

# ── provision, exec, destroy through the helper ─────────────────────────────
out="$("$CLI" run --template "$TEMPLATE" --socket "$SOCK" --exec 'echo helper-e2e-ok' 2>"$WORK/cli.log")"
[ "$out" = "helper-e2e-ok" ] && ok "exec reaches the guest" || { bad "exec reaches the guest"; tail -n 20 "$WORK/cli.log" >&2; }
grep -q 'TEARDOWN' "$WORK/helper.log" && grep -q 'NET_DOWN' "$WORK/helper.log" \
    && ok "the helper served TEARDOWN and NET_DOWN" || bad "the helper served TEARDOWN and NET_DOWN"

# ── a session volume survives death *and* re-attaches (chown round-trip) ────
"$CLI" run --template "$TEMPLATE" --socket "$SOCK" --session-key privsep9 \
    --exec 'echo persisted-9 > /workspace/marker' >"$WORK/sess1.log" 2>&1 \
    && ok "session run 1 writes /workspace/marker" || { bad "session run 1 writes /workspace/marker"; tail -n 20 "$WORK/sess1.log" >&2; }
out2="$("$CLI" run --template "$TEMPLATE" --socket "$SOCK" --session-key privsep9 \
    --exec 'cat /workspace/marker' 2>"$WORK/sess2.log")"
[ "$out2" = "persisted-9" ] && ok "session run 2 reads it back" || { bad "session run 2 reads it back"; tail -n 20 "$WORK/sess2.log" >&2; }
vol="$(find "$WSROOT" -name '*.ext4' | head -n 1)"
[ -n "$vol" ] && [ "$(stat -c '%U' "$vol")" = "$DAEMON_USER" ] \
    && ok "the session volume is $DAEMON_USER-owned after destroy" || bad "the session volume is $DAEMON_USER-owned after destroy"

# ── nothing privileged leaks ────────────────────────────────────────────────
left_taps="$(ip -o link show 2>/dev/null | grep -c 'tap-vm-' || true)"
[ "$left_taps" = "0" ] && ok "no taps leak" || bad "no taps leak ($left_taps left)"
left_fc="$(pgrep -x -c firecracker || true)"
[ "$left_fc" = "0" ] && ok "no Firecracker leaks" || bad "no Firecracker leaks ($left_fc left)"

if [ "$fails" -ne 0 ]; then echo "[e2e] FAILED ($fails)"; exit 1; fi
echo "[e2e] ALL PASSED"
