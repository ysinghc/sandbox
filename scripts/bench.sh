#!/usr/bin/env bash
#
# bench.sh — real-VM benchmark for Sandbox Engine.
#
# Runs as root on a KVM host. It stamps a real template, starts a private
# sandboxd instance in an isolated workspace, and drives live sandboxes with
# bench_client to measure create/destroy latency, throughput, and pause/resume.
#
# Quick start:
#   sudo scripts/bench.sh                       # defaults: 20 iters, conc 4
#   sudo scripts/bench.sh --quick               # fast smoke (5 iters, conc 2)
#   sudo scripts/bench.sh --iterations 50 --concurrency 8 --output results.json
#
# The workspace is removed at the end unless --keep is given.

set -uo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${BENCH_BUILD_DIR:-${REPO_DIR}/build}"
SANDBOXD_BIN="${BUILD_DIR}/sandboxd"
CLI_BIN="${BUILD_DIR}/sandbox-cli"
BENCH_BIN="${BUILD_DIR}/bench_client"
MAKE_TEMPLATE_BIN="${BUILD_DIR}/tests/make_template"

FC_BIN="${FIRECRACKER_BIN:-/usr/local/bin/firecracker}"
KERNEL="${SANDBOX_KERNEL:-/opt/sandbox-assets/vmlinux}"
ROOTFS="${SANDBOX_ROOTFS:-/opt/sandbox-assets/rootfs.ext4}"

ITERATIONS=20
WARMUP=3
CONCURRENCY=4
PAUSE_CYCLES=20
VM_MEMORY=256
VM_VCPUS=1
TEMPLATE="e2e"
POOL_SIZE=0            # 0 => computed
WORKDIR=""
OUTPUT=""
KEEP=0
USE_SYSTEMCTL=1
QUICK=0
FC_SECCOMP=1          # 0 => export SANDBOX_FC_SECCOMP=0 (diagnostic)

# Populated during the run.
BENCH_TS=""
SNAP_ROOT=""
JAIL_ROOT=""
RESULTS=""
CFG=""
SOCK=""
METRICS_PORT="19180"
METRICS_BIND="127.0.0.1"
DAEMON_PID=""
DAEMON_LOG=""
SYSTEM_ACTIVE=0
TEMPLATE_SECONDS=""
WARMUP_SECONDS=""
TMPDIR_CGRP=""

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
    C='\033[0;36m'; BOLD='\033[1m'; N='\033[0m'
else
    R=''; G=''; Y=''; B=''; C=''; BOLD=''; N=''
fi
hdr()  { printf "\n${BOLD}${B}=== %s ===${N}\n" "$1"; }
info() { printf "${C}[info]${N} %s\n" "$1"; }
ok()   { printf "${G}[ ok ]${N} %s\n" "$1"; }
warn() { printf "${Y}[warn]${N} %s\n" "$1"; }
err()  { printf "${R}[FAIL]${N} %s\n" "$1" >&2; }
die()  { err "$1"; exit 1; }

usage() {
    awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "${BASH_SOURCE[0]}"
    cat <<'EOF'

Options:
  --iterations N      measured create/destroy cycles per worker (default 20)
  --warmup N          unmeasured warm-up cycles per worker (default 3)
  --concurrency N     concurrent worker sessions (default 4)
  --pause-cycles N    pause/resume cycles on the first sandbox (default 20)
  --memory MiB        guest memory (default 256)
  --vcpus N           guest vCPUs (default 1)
  --template NAME     template name (default e2e)
  --pool-size N       daemon warm pool target (default: concurrency+2, min 5)
  --output FILE       write a merged JSON report
  --workdir DIR       workspace (default /tmp/sandbox-bench-<timestamp>)
  --keep              keep the workspace and template after the run
  --no-systemctl      do not stop/start the system sandboxd service
  --no-fc-seccomp     disable the engine's seccomp filter (SANDBOX_FC_SECCOMP=0;
                      diagnostic only, for isolating seccomp issues)
  --quick             fast smoke run (5 iterations, concurrency 2, small VM)
  -h, --help          this help
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --iterations)   ITERATIONS="$2"; shift 2 ;;
            --warmup)       WARMUP="$2"; shift 2 ;;
            --concurrency)  CONCURRENCY="$2"; shift 2 ;;
            --pause-cycles) PAUSE_CYCLES="$2"; shift 2 ;;
            --memory)       VM_MEMORY="$2"; shift 2 ;;
            --vcpus)        VM_VCPUS="$2"; shift 2 ;;
            --template)     TEMPLATE="$2"; shift 2 ;;
            --pool-size)    POOL_SIZE="$2"; shift 2 ;;
            --output)       OUTPUT="$2"; shift 2 ;;
            --workdir)      WORKDIR="$2"; shift 2 ;;
            --keep)         KEEP=1; shift ;;
            --no-systemctl) USE_SYSTEMCTL=0; shift ;;
            --no-fc-seccomp) FC_SECCOMP=0; shift ;;
            --quick)        QUICK=1; shift ;;
            -h|--help)      usage; exit 0 ;;
            *)              err "unknown option: $1"; usage; exit 2 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
preflight() {
    hdr "Preflight"
    [ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo scripts/bench.sh)"
    [ -c /dev/kvm ] || die "/dev/kvm not present"
    [ -c /dev/net/tun ] || die "/dev/net/tun not present (needed for per-VM taps)"
    local uffd
    uffd="$(cat /proc/sys/vm/unprivileged_userfaultfd 2>/dev/null || echo '?')"
    if [ ! -c /dev/userfaultfd ] && [ "$uffd" != "1" ]; then
        warn "userfaultfd may be unavailable (/dev/userfaultfd missing, unprivileged_userfaultfd=${uffd})"
    fi
    [ -x "$FC_BIN" ] || die "firecracker not found/executable: $FC_BIN"
    [ -f "$KERNEL" ] || die "kernel asset missing: $KERNEL"
    [ -f "$ROOTFS" ] || die "rootfs asset missing: $ROOTFS"
    for b in "$SANDBOXD_BIN" "$CLI_BIN" "$BENCH_BIN" "$MAKE_TEMPLATE_BIN"; do
        [ -x "$b" ] || die "missing binary: $b (build with: cmake --build build -j)"
    done
    command -v curl >/dev/null 2>&1 || die "curl is required for the metrics checks"
    command -v nft  >/dev/null 2>&1 || warn "nft not found; network rules may fall back"

    ok "root, KVM, TUN present"
    ok "firecracker: $("$FC_BIN" --version 2>&1 | head -1)"
    ok "binaries present in $BUILD_DIR"
}

# ---------------------------------------------------------------------------
# Workspace + isolation
# ---------------------------------------------------------------------------
free_port() {
    command -v python3 >/dev/null 2>&1 || { echo 19180; return; }
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

prepare_workspace() {
    hdr "Workspace"
    BENCH_TS="$(date +%Y%m%d-%H%M%S)"
    [ -n "$WORKDIR" ] || WORKDIR="/tmp/sandbox-bench-${BENCH_TS}"
    SNAP_ROOT="${WORKDIR}/snapshots"
    JAIL_ROOT="${WORKDIR}/jails"
    RESULTS="${WORKDIR}/results"
    CFG="${WORKDIR}/engine.conf"
    SOCK="${WORKDIR}/engine.sock"
    DAEMON_LOG="${RESULTS}/daemon.log"
    METRICS_PORT="$(free_port)"
    mkdir -p "$SNAP_ROOT" "$JAIL_ROOT" "$RESULTS"
    info "workspace: $WORKDIR"
    info "metrics:   127.0.0.1:${METRICS_PORT}"
}

stop_competing() {
    hdr "Isolation"
    # A previously running daemon would hold port 9180 and the default socket,
    # and busy-spin CPU that would pollute latency numbers.
    if [ "$USE_SYSTEMCTL" = 1 ] && command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet sandboxd 2>/dev/null; then
            SYSTEM_ACTIVE=1
            info "stopping system sandboxd for the duration of the run"
            systemctl stop sandboxd 2>/dev/null || true
        fi
    fi
    pkill -9 -x firecracker 2>/dev/null || true
    # Detach any stale mounts under our workspace or the test roots.
    for pat in "$WORKDIR" /tmp/sbtest-; do
        mount 2>/dev/null | grep -F "$pat" | awk '{print $3}' | while read -r m; do
            umount -l "$m" 2>/dev/null || true
        done
    done
    ok "no competing engine processes"
}

# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------
build_template() {
    hdr "Template"
    export SANDBOX_SNAPSHOT_ROOT="$SNAP_ROOT"
    export SANDBOX_JAIL_ROOT="$JAIL_ROOT"
    export FIRECRACKER_BIN="$FC_BIN"
    local t0 t1
    if [ -f "${SNAP_ROOT}/READY" ] && [ -d "${SNAP_ROOT}/${TEMPLATE}" ]; then
        TEMPLATE_SECONDS="0.00"
        if "$CLI_BIN" verify --template "$TEMPLATE" >"${RESULTS}/verify.log" 2>&1; then
            ok "reusing template '${TEMPLATE}' in $SNAP_ROOT"
            return 0
        fi
        warn "existing template failed verification; rebuilding"
    fi
    t0=$(date +%s.%N)
    if ! "$MAKE_TEMPLATE_BIN" >"${RESULTS}/make_template.log" 2>&1; then
        err "template creation failed"
        tail -n 25 "${RESULTS}/make_template.log" >&2
        return 1
    fi
    t1=$(date +%s.%N)
    TEMPLATE_SECONDS="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')"
    [ -f "${SNAP_ROOT}/READY" ] || { err "template READY marker not written"; return 1; }
    if ! "$CLI_BIN" verify --template "$TEMPLATE" >"${RESULTS}/verify.log" 2>&1; then
        err "snapshot integrity check failed for '$TEMPLATE'"
        cat "${RESULTS}/verify.log" >&2
        return 1
    fi
    local size
    size="$(du -sh "${SNAP_ROOT}/${TEMPLATE}" 2>/dev/null | awk '{print $1}')"
    ok "template '${TEMPLATE}' built in ${TEMPLATE_SECONDS}s (${size} on disk, integrity verified)"
}

# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------
write_config() {
    [ "$POOL_SIZE" -gt 0 ] || POOL_SIZE=$(( CONCURRENCY + 2 ))
    [ "$POOL_SIZE" -lt 5 ] && POOL_SIZE=5
    cat >"$CFG" <<EOF
# Generated by bench.sh — isolated benchmark instance.
[daemon]
socket_path = ${SOCK}
broker_control_socket = ${WORKDIR}/broker-control.sock
template = ${TEMPLATE}
allowed_services =
allowed_uids = 0
jailer_uid = 65534
jailer_gid = 65534
vsock_settle_ms = 1000
create_workers = 4
max_creates_per_session = 256
max_creates_per_uid = 256

[pool]
target_size = ${POOL_SIZE}
max_queue_depth = 256
pool_wait_timeout_ms = 2000

[cgroup]
cgroup_enable = 1
cgroup_slack_mib = 64
cgroup_cpu_max = max

[paths]
jail_root = ${JAIL_ROOT}
snapshot_root = ${SNAP_ROOT}

[metrics]
metrics_port = ${METRICS_PORT}
metrics_bind = ${METRICS_BIND}
log_level = info
EOF
}

start_daemon() {
    hdr "Daemon"
    write_config
    : >"$DAEMON_LOG"
    setsid "$SANDBOXD_BIN" --config "$CFG" >>"$DAEMON_LOG" 2>&1 &
    DAEMON_PID=$!
    info "sandboxd pid ${DAEMON_PID}, log ${DAEMON_LOG}"

    local i
    for i in $(seq 1 100); do
        [ -S "$SOCK" ] && break
        kill -0 "$DAEMON_PID" 2>/dev/null || { err "daemon exited during startup"; tail -n 25 "$DAEMON_LOG" >&2; return 1; }
        sleep 0.1
    done
    [ -S "$SOCK" ] || { err "daemon socket never appeared"; tail -n 25 "$DAEMON_LOG" >&2; return 1; }
    ok "socket ready: $SOCK"

    # Wait for the warm pool to be ready (or time out).
    local t0 t1 code
    t0=$(date +%s.%N)
    for i in $(seq 1 600); do   # up to 60s
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://${METRICS_BIND}:${METRICS_PORT}/ready" || echo 000)"
        [ "$code" = "200" ] && break
        sleep 0.1
    done
    t1=$(date +%s.%N)
    WARMUP_SECONDS="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')"
    if [ "$code" = "200" ]; then
        ok "pool warm (${POOL_SIZE} VMs) in ${WARMUP_SECONDS}s"
    else
        warn "pool not ready after ${WARMUP_SECONDS}s (continuing; creates may wait)"
    fi
}

scrape_metrics() { # $1 = output file
    curl -s --max-time 3 "http://${METRICS_BIND}:${METRICS_PORT}/metrics" >"$1" 2>/dev/null || true
}

metric_val() { # $1 file, $2 metric
    awk -v k="$2" '$1 == k {print $2; found=1} END {if (!found) print 0}' "$1" 2>/dev/null | head -1
}

stop_daemon() {
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        for _ in $(seq 1 30); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$DAEMON_PID" 2>/dev/null || true
    fi
    DAEMON_PID=""
}

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------
WARMUP_SECONDS=""
BENCH_RC=0

run_benchmarks() {
    hdr "Benchmarks"
    scrape_metrics "${RESULTS}/metrics.before.txt"

    info "sequential: ${ITERATIONS} iters, warmup ${WARMUP}, ${VM_MEMORY}MiB/${VM_VCPUS}vCPU, pause x${PAUSE_CYCLES}"
    "$BENCH_BIN" -s "$SOCK" -t "$TEMPLATE" \
        -n "$ITERATIONS" -w "$WARMUP" -c 1 -p "$PAUSE_CYCLES" \
        -m "$VM_MEMORY" -v "$VM_VCPUS" -W 2000 -l seq \
        -j "${RESULTS}/seq.json" || BENCH_RC=$?

    info "concurrent: ${CONCURRENCY} sessions x ${ITERATIONS} iters"
    "$BENCH_BIN" -s "$SOCK" -t "$TEMPLATE" \
        -n "$ITERATIONS" -w "$WARMUP" -c "$CONCURRENCY" \
        -m "$VM_MEMORY" -v "$VM_VCPUS" -W 4000 -l conc \
        -j "${RESULTS}/conc.json" || BENCH_RC=$?

    scrape_metrics "${RESULTS}/metrics.after.txt"
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
sla_line() { # $1 label, $2 value, $3 threshold, $4 unit, $5 direction(lt|gt)
    local label="$1" v="$2" t="$3" unit="$4" dir="$5" pass op color
    if [ "$dir" = gt ]; then
        op=">"; pass=$(awk -v v="$v" -v t="$t" 'BEGIN{print (v >= t) ? 1 : 0}')
    else
        op="<"; pass=$(awk -v v="$v" -v t="$t" 'BEGIN{print (v <= t) ? 1 : 0}')
    fi
    if [ "$pass" = 1 ]; then color="${G}PASS${N}"; else color="${R}FAIL${N}"; fi
    printf "  %s  %-34s %s%s   (target %s %s)\n" "$color" "$label" "$v" "$unit" "$op" "${t}${unit}"
}

json_get() { # $1 file, $2 dotted-ish path via python3
    command -v python3 >/dev/null 2>&1 || { echo ""; return; }
    python3 - "$1" "$2" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print(""); raise SystemExit
cur = d
for part in sys.argv[2].split('.'):
    if part == "": continue
    cur = cur[part]
print(cur)
PY
}

report() {
    hdr "Report"

    local host_cpus host_mem kernel cpu
    host_cpus="$(nproc)"
    host_mem="$(free -m | awk 'NR==2{print $2}')"
    kernel="$(uname -r)"
    cpu="$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo | sed 's/^ *//')"
    [ -n "$cpu" ] || cpu="$(uname -m)"

    echo "  host:      ${cpu}  (${host_cpus} CPUs, ${host_mem} MiB RAM, kernel ${kernel})"
    echo "  firecracker: $("$FC_BIN" --version 2>&1 | head -1)"
    echo "  template:  ${TEMPLATE}  built in ${TEMPLATE_SECONDS}s"
    echo "  pool:      target ${POOL_SIZE}, warm in ${WARMUP_SECONDS}s"
    echo "  guest:     ${VM_MEMORY} MiB / ${VM_VCPUS} vCPU"

    local s_created s_failed s_thr s_cp50 s_cp99 s_dp50 s_dp99
    s_created="$(json_get "${RESULTS}/seq.json" totals.created)"
    s_failed="$(json_get "${RESULTS}/seq.json" totals.failed)"
    s_cp50="$(json_get "${RESULTS}/seq.json" latency.create.p50_ms)"
    s_cp99="$(json_get "${RESULTS}/seq.json" latency.create.p99_ms)"
    s_dp50="$(json_get "${RESULTS}/seq.json" latency.destroy.p50_ms)"
    s_dp99="$(json_get "${RESULTS}/seq.json" latency.destroy.p99_ms)"

    local c_created c_failed c_thr c_cp50 c_cp99
    c_created="$(json_get "${RESULTS}/conc.json" totals.created)"
    c_failed="$(json_get "${RESULTS}/conc.json" totals.failed)"
    c_thr="$(json_get "${RESULTS}/conc.json" totals.throughput_creates_per_s)"
    c_cp50="$(json_get "${RESULTS}/conc.json" latency.create.p50_ms)"
    c_cp99="$(json_get "${RESULTS}/conc.json" latency.create.p99_ms)"

    local msum mcount prov_avg uffd crashes
    local before after
    before="${RESULTS}/metrics.before.txt"; after="${RESULTS}/metrics.after.txt"
    local usum ucount
    usum="$(metric_val "$after" sandbox_provision_latency_ms_sum)"
    ucount="$(metric_val "$after" sandbox_provision_latency_ms_count)"
    prov_avg="$(awk -v s="${usum:-0}" -v c="${ucount:-0}" 'BEGIN{printf (c>0)?"%.2f":"0", (c>0)?s/c:0}')"
    uffd="$(metric_val "$after" sandbox_uffd_faults_total)"
    crashes="$(metric_val "$after" sandbox_vmm_crashes_total)"

    echo
    echo "  ${BOLD}Sequential create (single session, warm pool)${N}"
    echo "    created ${s_created}, failed ${s_failed}"
    echo "    create   p50 ${s_cp50}ms   p99 ${s_cp99}ms"
    echo "    destroy  p50 ${s_dp50}ms   p99 ${s_dp99}ms"
    echo
    echo "  ${BOLD}Concurrent (${CONCURRENCY} sessions)${N}"
    echo "    created ${c_created}, failed ${c_failed}"
    echo "    create   p50 ${c_cp50}ms   p99 ${c_cp99}ms"
    echo "    throughput ${c_thr} creates/s"
    echo
    echo "  ${BOLD}Engine (server-side, cumulative)${N}"
    echo "    provision latency avg ${prov_avg}ms over ${ucount} restores"
    echo "    uffd faults served ${uffd}, vmm crashes ${crashes}"

    hdr "SLA"
    [ -n "$s_cp50" ] && sla_line "sequential create p50" "$s_cp50" 100 "ms" lt
    [ -n "$s_cp99" ] && sla_line "sequential create p99" "$s_cp99" 200 "ms" lt
    [ -n "$c_thr" ]  && sla_line "concurrent throughput" "$c_thr" 5 " creates/s" gt
    [ -n "$c_cp99" ] && sla_line "concurrent create p99" "$c_cp99" 500 "ms" lt
    if [ "${crashes:-0}" != "0" ]; then echo "  ${Y}WARN${N}  vmm crashes observed: ${crashes}"; fi
}

write_json() {
    [ -n "$OUTPUT" ] || return 0
    if ! command -v python3 >/dev/null 2>&1; then
        warn "python3 not found; copying sequential results to ${OUTPUT}"
        cp "${RESULTS}/seq.json" "$OUTPUT"
        return 0
    fi
    local host_cpus host_mem kernel cpu
    host_cpus="$(nproc)"; host_mem="$(free -m | awk 'NR==2{print $2}')"
    kernel="$(uname -r)"; cpu="$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo | sed 's/^ *//')"
    python3 - "$RESULTS" "$OUTPUT" "$host_cpus" "$host_mem" "$kernel" "$cpu" \
        "$TEMPLATE_SECONDS" "$WARMUP_SECONDS" "$POOL_SIZE" "$TEMPLATE" <<'PY'
import json, sys, os
results, out, cpus, mem, kernel, cpu, tsec, wsec, pool, template = sys.argv[1:11]
def load(name):
    p = os.path.join(results, name)
    try: return json.load(open(p))
    except Exception: return None
def metrics(name):
    vals = {}
    try:
        for line in open(os.path.join(results, name)):
            if line.startswith('#'): continue
            parts = line.split()
            if len(parts) >= 2:
                try: vals[parts[0]] = float(parts[1])
                except ValueError: pass
    except Exception: pass
    return vals
before, after = metrics('metrics.before.txt'), metrics('metrics.after.txt')
def delta(k): return after.get(k, 0) - before.get(k, 0)
doc = {
    "generated_by": "scripts/bench.sh",
    "host": {"cpu": cpu, "cpus": int(cpus), "mem_mib": int(mem), "kernel": kernel},
    "template": {"name": template, "build_s": float(tsec or 0)},
    "pool": {"target": int(pool), "warm_s": float(wsec or 0)},
    "sequential": load('seq.json'),
    "concurrent": load('conc.json'),
    "engine": {
        "uffd_faults_total": after.get("sandbox_uffd_faults_total", 0),
        "uffd_faults_delta": delta("sandbox_uffd_faults_total"),
        "vmm_crashes_total": after.get("sandbox_vmm_crashes_total", 0),
        "pool_exhaustion_total": after.get("sandbox_pool_exhaustion_total", 0),
        "provision_latency_ms_sum": after.get("sandbox_provision_latency_ms_sum", 0),
        "provision_latency_ms_count": after.get("sandbox_provision_latency_ms_count", 0),
    },
}
json.dump(doc, open(out, "w"), indent=2)
print("  merged results ->", out)
PY
    ok "JSON report written: $OUTPUT"
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    hdr "Cleanup"
    stop_daemon
    pkill -9 -x firecracker 2>/dev/null || true
    [ -n "$JAIL_ROOT" ] && mount 2>/dev/null | grep -F "$JAIL_ROOT" | awk '{print $3}' | while read -r m; do
        umount -l "$m" 2>/dev/null || true
    done
    [ -n "$SNAP_ROOT" ] && mount 2>/dev/null | grep -F "$SNAP_ROOT" | awk '{print $3}' | while read -r m; do
        umount -l "$m" 2>/dev/null || true
    done
    # Best-effort: clear per-VM cgroups left behind.
    for d in /sys/fs/cgroup/sandboxd/active/*; do
        [ -d "$d" ] && rmdir "$d" 2>/dev/null || true
    done
    if [ "$KEEP" = 1 ] || [ "${BENCH_RC:-0}" != 0 ]; then
        info "workspace kept: $WORKDIR"
    else
        rm -rf "$WORKDIR"
        ok "workspace removed"
    fi
    if [ "$SYSTEM_ACTIVE" = 1 ]; then
        info "restarting system sandboxd"
        systemctl start sandboxd 2>/dev/null || true
    fi
    if [ "${BENCH_RC:-0}" != 0 ]; then
        warn "bench_client reported issues (rc=${BENCH_RC}); results kept in ${WORKDIR}/results"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    [ "$QUICK" = 1 ] && { ITERATIONS=5; WARMUP=2; CONCURRENCY=2; VM_MEMORY=128; PAUSE_CYCLES=5; }
    [ "$FC_SECCOMP" = 0 ] && export SANDBOX_FC_SECCOMP=0

    hdr "Sandbox Engine benchmark"
    preflight
    prepare_workspace
    stop_competing

    trap cleanup EXIT INT TERM

    build_template || exit 1
    start_daemon   || exit 1
    run_benchmarks
    report
    write_json
    hdr "Done"
}

main "$@"
