#!/usr/bin/env bash
#
# benchmark.sh — sandbox startup latency.
#
# Measures the wall-clock latency of provisioning N new sandboxes, starting
# from a pool of P already-warm ones. Each sample is one sandbox_create() call:
# from the moment the client asks for a sandbox until it is provisioned and
# returned (i.e. executable). The first P requests are served from the warm
# pool; the rest force a cold restore.
#
# Defaults: 10 sandboxes from an initial pool of 5.
#
#   sudo scripts/benchmark.sh
#   sudo scripts/benchmark.sh --pool 5 --count 10
#
# Runs as root (the jailer needs chroot + setuid). Everything happens in an
# isolated /tmp workspace with its own daemon; the workspace is removed at the
# end unless --keep is given.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${SANDBOX_BUILD_DIR:-${REPO_DIR}/build}"

SANDBOXD="${BUILD_DIR}/sandboxd"
MAKE_TEMPLATE="${BUILD_DIR}/tests/make_template"
LIBSANDBOX="${BUILD_DIR}/libsandbox.so"

FC_BIN="${FIRECRACKER_BIN:-/usr/local/bin/firecracker}"
KERNEL="${SANDBOX_KERNEL:-/opt/sandbox-assets/vmlinux}"
ROOTFS="${SANDBOX_ROOTFS:-/opt/sandbox-assets/rootfs.ext4}"

POOL=5
COUNT=10
VM_MEMORY=256
VM_VCPUS=1
TEMPLATE="bench"
KEEP=0

WORKDIR=""
SNAP_ROOT=""
JAIL_ROOT=""
SOCK=""
CFG=""
DAEMON_PID=""
METRICS_PORT=""
SYSTEM_WAS_ACTIVE=0

if [ -t 1 ]; then
    B='\033[1m'; C='\033[0;36m'; G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; N='\033[0m'
else
    B=''; C=''; G=''; R=''; Y=''; N=''
fi
info() { printf "${C}[info]${N} %s\n" "$1"; }
ok()   { printf "${G}[ ok ]${N} %s\n" "$1"; }
warn() { printf "${Y}[warn]${N} %s\n" "$1"; }
die()  { printf "${R}[fail]${N} %s\n" "$1" >&2; exit 1; }

usage() {
    awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "${BASH_SOURCE[0]}"
    cat <<'EOF'

Options:
  --pool N        initial warm pool size            (default 5)
  --count N       number of sandboxes to start      (default 10)
  --memory MiB    guest memory                      (default 256)
  --vcpus N       guest vCPUs                       (default 1)
  --template NAME   snapshot template name          (default bench)
  --keep          keep the workspace after the run
  -h, --help      this help
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --pool)     POOL="$2"; shift 2 ;;
            --count)    COUNT="$2"; shift 2 ;;
            --memory)   VM_MEMORY="$2"; shift 2 ;;
            --vcpus)    VM_VCPUS="$2"; shift 2 ;;
            --template) TEMPLATE="$2"; shift 2 ;;
            --keep)     KEEP=1; shift ;;
            -h|--help)  usage; exit 0 ;;
            *) die "unknown option: $1 (try --help)" ;;
        esac
    done
    [ "$POOL" -ge 1 ] 2>/dev/null || die "--pool must be a positive integer"
    [ "$COUNT" -ge 1 ] 2>/dev/null || die "--count must be a positive integer"
}

preflight() {
    [ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo scripts/benchmark.sh)"
    [ -c /dev/kvm ] || die "/dev/kvm not present"
    [ -x "$FC_BIN" ] || die "firecracker not found: $FC_BIN"
    [ -f "$KERNEL" ] || die "kernel asset missing: $KERNEL"
    [ -f "$ROOTFS" ] || die "rootfs asset missing: $ROOTFS"
    [ -x "$SANDBOXD" ] || die "missing $SANDBOXD (build with: cmake --build build -j)"
    [ -x "$MAKE_TEMPLATE" ] || die "missing $MAKE_TEMPLATE (build the tests)"
    [ -f "$LIBSANDBOX" ] || die "missing $LIBSANDBOX"
    command -v cc >/dev/null 2>&1 || die "a C compiler (cc) is required"
    command -v curl >/dev/null 2>&1 || die "curl is required"
}

free_port() {
    command -v python3 >/dev/null 2>&1 || { echo 19180; return; }
    python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
}

prepare() {
    WORKDIR="$(mktemp -d /tmp/sandbox-bench.XXXXXX)"
    SNAP_ROOT="${WORKDIR}/snapshots"
    JAIL_ROOT="${WORKDIR}/jails"
    SOCK="${WORKDIR}/engine.sock"
    CFG="${WORKDIR}/engine.conf"
    METRICS_PORT="$(free_port)"
    mkdir -p "$SNAP_ROOT" "$JAIL_ROOT"
    info "workspace: $WORKDIR"

    if systemctl is-active --quiet sandboxd 2>/dev/null; then
        SYSTEM_WAS_ACTIVE=1
        info "stopping the system sandboxd for the run"
        systemctl stop sandboxd 2>/dev/null || true
    fi
    pkill -9 -x firecracker 2>/dev/null || true
}

build_template() {
    export SANDBOX_SNAPSHOT_ROOT="$SNAP_ROOT"
    export SANDBOX_JAIL_ROOT="$JAIL_ROOT"
    export FIRECRACKER_BIN="$FC_BIN"
    if [ -f "${SNAP_ROOT}/READY" ] && [ -d "${SNAP_ROOT}/${TEMPLATE}" ]; then
        ok "reusing template '${TEMPLATE}'"
        return 0
    fi
    info "stamping template '${TEMPLATE}' (cold boot + snapshot)..."
    if ! "$MAKE_TEMPLATE" >"${WORKDIR}/make_template.log" 2>&1; then
        tail -n 20 "${WORKDIR}/make_template.log" >&2
        die "template creation failed"
    fi
    ok "template '${TEMPLATE}' ready"
}

write_config() {
    cat >"$CFG" <<EOF
[daemon]
socket_path = ${SOCK}
broker_control_socket = ${WORKDIR}/broker.sock
template = ${TEMPLATE}
allowed_services =
allowed_uids = 0
jailer_uid = 65534
jailer_gid = 65534
vsock_settle_ms = 1000
create_workers = 8
max_creates_per_session = ${COUNT}
max_creates_per_uid = ${COUNT}

[pool]
pool_size = ${POOL}
max_queue_depth = ${COUNT}

[cgroup]
cgroup_enable = 1
cgroup_slack_mib = 64

[paths]
jail_root = ${JAIL_ROOT}
snapshot_root = ${SNAP_ROOT}

[metrics]
metrics_port = ${METRICS_PORT}
metrics_bind = 127.0.0.1
log_level = warn
EOF
}

start_daemon() {
    write_config
    setsid "$SANDBOXD" --config "$CFG" >"${WORKDIR}/daemon.log" 2>&1 &
    DAEMON_PID=$!
    local i
    for i in $(seq 1 100); do
        [ -S "$SOCK" ] && break
        kill -0 "$DAEMON_PID" 2>/dev/null || { tail -n 20 "${WORKDIR}/daemon.log" >&2; die "daemon exited during startup"; }
        sleep 0.1
    done
    [ -S "$SOCK" ] || die "daemon socket never appeared"

    info "waiting for ${POOL} warm sandboxes..."
    local warm
    for i in $(seq 1 900); do  # up to 90s
        warm="$(curl -s --max-time 2 "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null \
                | awk '$1=="sandbox_pool_warm_count"{print $2}')"
        [ -n "${warm:-}" ] && [ "$warm" -ge "$POOL" ] 2>/dev/null && break
        sleep 0.1
    done
    [ -n "${warm:-}" ] && [ "$warm" -ge "$POOL" ] 2>/dev/null \
        || die "pool did not reach ${POOL} warm sandboxes (got ${warm:-unknown})"
    ok "pool warm: ${warm} sandboxes"
}

# The probe: links libsandbox, creates COUNT sandboxes back-to-back and times
# each sandbox_create() call. Written to disk and compiled because the C API
# keeps one session per process (the stock CLI holds a session open and cannot
# return per-create latency).
write_probe() {
    cat >"${WORKDIR}/probe.c" <<'EOF'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "libsandbox.h"

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int main(int argc, char** argv) {
    if (argc != 7) {
        fprintf(stderr, "usage: probe <socket> <template> <count> <warm> <mem_mib> <vcpus>\n");
        return 2;
    }
    const char* sock = argv[1];
    const char* tmpl = argv[2];
    int count = atoi(argv[3]);
    int warm = atoi(argv[4]);
    uint64_t mem = (uint64_t)strtoull(argv[5], NULL, 10);
    uint32_t vcpus = (uint32_t)strtoul(argv[6], NULL, 10);

    double* ms = calloc((size_t)count, sizeof(double));
    sandbox_handle_t** h = calloc((size_t)count, sizeof(*h));
    if (!ms || !h) return 1;

    if (sandbox_init(sock) != SANDBOX_OK) {
        fprintf(stderr, "sandbox_init(%s) failed\n", sock);
        return 1;
    }

    uint64_t first = 0, last = 0;
    int made = 0;
    for (int i = 0; i < count; i++) {
        sandbox_spec_t spec;
        spec.memory_mib = mem;
        spec.vcpu_count = vcpus;
        spec.template_name = tmpl;
        spec.env_vars = NULL;
        spec.pool_wait_ms = 120000;  // cold restores may wait for provisioning

        uint64_t t0 = now_ns();
        sandbox_error_t rc = sandbox_create(&spec, &h[i]);
        uint64_t t1 = now_ns();
        if (first == 0) first = t0;
        last = t1;
        if (rc != SANDBOX_OK) {
            fprintf(stderr, "sandbox_create #%d failed (err=%d)\n", i + 1, (int)rc);
            break;
        }
        ms[i] = (double)(t1 - t0) / 1e6;
        made++;
    }

    if (made == 0) { sandbox_cleanup(); return 1; }

    double wsum = 0, csum = 0, min = ms[0], max = ms[0], sum = 0;
    int wc = 0, cc = 0;
    printf("\n");
    for (int i = 0; i < made; i++) {
        const char* tag = (i < warm) ? "warm" : "provisioned";
        printf("  sandbox %2d   %9.2f ms   (%s)\n", i + 1, ms[i], tag);
        sum += ms[i];
        if (ms[i] < min) min = ms[i];
        if (ms[i] > max) max = ms[i];
        if (i < warm) { wsum += ms[i]; wc++; } else { csum += ms[i]; cc++; }
    }

    printf("\n  --------------------------------------------\n");
    if (wc) printf("  warm        (%2d)   avg %9.2f ms\n", wc, wsum / wc);
    if (cc) printf("  provisioned (%2d)   avg %9.2f ms\n", cc, csum / cc);
    printf("  all         (%2d)   min %.2f   avg %.2f   max %.2f ms\n",
           made, min, sum / made, max);
    printf("  total wall (first call -> last provisioned): %.2f ms\n",
           (double)(last - first) / 1e6);

    for (int i = 0; i < made; i++) sandbox_destroy(h[i]);
    sandbox_cleanup();
    free(ms);
    free(h);
    return 0;
}
EOF

    info "compiling latency probe..."
    if ! cc -O2 -Wall -I"${REPO_DIR}/include" "${WORKDIR}/probe.c" -o "${WORKDIR}/probe" \
            -L"${BUILD_DIR}" -lsandbox -Wl,-rpath,"${BUILD_DIR}"; then
        die "failed to compile the probe against ${LIBSANDBOX}"
    fi
}

run_probe() {
    printf "\n${B}=== Sandbox startup latency ===${N}\n"
    printf "  template %s, %s MiB / %s vCPU, pool %s warm, starting %s\n" \
        "$TEMPLATE" "$VM_MEMORY" "$VM_VCPUS" "$POOL" "$COUNT"
    "${WORKDIR}/probe" "$SOCK" "$TEMPLATE" "$COUNT" "$POOL" "$VM_MEMORY" "$VM_VCPUS"
}

cleanup() {
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
    sleep 0.3
    [ -n "$DAEMON_PID" ] && kill -9 "$DAEMON_PID" 2>/dev/null
    pkill -9 -x firecracker 2>/dev/null || true
    for pat in "$JAIL_ROOT" "$SNAP_ROOT"; do
        [ -n "$pat" ] && mount 2>/dev/null | grep -F "$pat" | awk '{print $3}' | while read -r m; do
            umount -l "$m" 2>/dev/null || true
        done
    done
    for d in /sys/fs/cgroup/sandboxd/active/*; do
        [ -d "$d" ] && rmdir "$d" 2>/dev/null || true
    done
    if [ "$KEEP" = 1 ]; then
        info "workspace kept: $WORKDIR"
    elif [ -n "$WORKDIR" ]; then
        rm -rf "$WORKDIR"
    fi
    if [ "$SYSTEM_WAS_ACTIVE" = 1 ]; then
        info "restarting the system sandboxd"
        systemctl start sandboxd 2>/dev/null || true
    fi
}

main() {
    parse_args "$@"
    preflight
    prepare
    trap cleanup EXIT INT TERM
    build_template
    start_daemon
    write_probe
    run_probe
}

main "$@"
