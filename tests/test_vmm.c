// SPDX-License-Identifier: GPL-2.0-only
// Phase 6 verification: real Firecracker lifecycle (cold boot, serial
// readiness, pause/resume, snapshot), UFFD restore with post-restore guest
// execution, and pool-managed provision/destroy end to end.
// SKIPs without root + /dev/kvm + assets + the template fixture.

#define _DEFAULT_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "network_manager.h"
#include "pool_manager.h"
#include "snapshot_manager.h"
#include "vmm_manager.h"
#include "cgroup.h"

#define CHECK_RC(rc, what) do { int _rc = (rc); if (_rc != 0) { \
    fprintf(stderr, "FAIL %s: rc=%d errno=%d (%s:%d)\n", (what), _rc, errno, \
            __FILE__, __LINE__); \
    abort(); } } while (0)

#define ASSET_KERNEL "/opt/sandbox-assets/vmlinux"
#define ASSET_ROOTFS "/opt/sandbox-assets/rootfs.ext4"

// Same overrides as tests/make_template.c and scripts/benchmark.sh, so CI can
// cold-boot the guest image it built instead of the operator's asset.
// <env>_DEFAULT is the configure-time fallback from tests/CMakeLists.txt; an
// explicit runtime value always wins.
static const char* asset_path(const char* env, const char* def_env,
                              const char* fallback) {
    const char* v = getenv(env);
    if (v && *v) return v;
    v = getenv(def_env);
    return (v && *v) ? v : fallback;
}

static int have_file(const char* p) {
    struct stat st;
    return stat(p, &st) == 0;
}

static int have_template(void) {
    const char* r = getenv("SANDBOX_SNAPSHOT_ROOT");
    if (!r || !*r) return 0;
    char ready[PATH_MAX];
    snprintf(ready, sizeof(ready), "%s/READY", r);
    return have_file(ready);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void check_state(vm_handle_t* vm, const char* want, const char* what) {
    char state[32] = {0};
    CHECK_RC(vmm_state(vm, state, sizeof(state)), what);
    if (strcmp(state, want) != 0) {
        fprintf(stderr, "FAIL %s: state=%s want %s\n", what, state, want);
        abort();
    }
}

static void test_lifecycle(void) {
    printf("[test] lifecycle...\n");
    fflush(stdout);
    char jail[PATH_MAX];
    snprintf(jail, sizeof(jail), "vmm-t%d", (int)getpid());
    char jail_root[PATH_MAX];
    CHECK_RC(vmm_jail_path(jail, jail_root, sizeof(jail_root)), "jail path");
    template_config_t cfg = { .memory_mib = 128, .vcpu_count = 1,
                              .kernel_path =
                                  asset_path("SANDBOX_KERNEL", "SANDBOX_KERNEL_DEFAULT",
                                             ASSET_KERNEL),
                              .rootfs_path =
                                  asset_path("SANDBOX_ROOTFS", "SANDBOX_ROOTFS_DEFAULT",
                                             ASSET_ROOTFS),
                              .ready_marker = "SANDBOX-READY" };
    vm_handle_t* vm = vmm_cold_boot(&cfg, jail, jail_root, NULL);
    if (!vm) {
        fprintf(stderr, "FAIL cold_boot errno=%d\n", errno);
        abort();
    }
    CHECK_RC(vmm_wait_ready(vm, "SANDBOX-READY", 60000), "wait ready");
    check_state(vm, "Running", "boot state");
    CHECK_RC(vmm_pause_vcpus(vm), "pause");
    check_state(vm, "Paused", "pause state");
    CHECK_RC(vmm_resume_vcpus(vm), "resume");
    check_state(vm, "Running", "resume state");
    // Snapshot requires Paused: pause again, capture to the jail, destroy.
    CHECK_RC(vmm_pause_vcpus(vm), "re-pause");
    CHECK_RC(vmm_snapshot(vm, "/snap.vmstate", "/snap.mem"), "snapshot");
    char host_vs[PATH_MAX], host_mem[PATH_MAX];
    snprintf(host_vs, sizeof(host_vs), "%s/snap.vmstate", jail_root);
    snprintf(host_mem, sizeof(host_mem), "%s/snap.mem", jail_root);
    struct stat st;
    CHECK_RC(stat(host_vs, &st) < 0 ? -1 : 0, "stat vmstate");
    if (st.st_size < 1024 || st.st_size > 10 * 1024 * 1024) abort();
    CHECK_RC(stat(host_mem, &st) < 0 ? -1 : 0, "stat mem");
    if ((uint64_t)st.st_size != 128u * 1024u * 1024u) abort();
    pid_t pid = vm->vmm_pid;
    char api[108], jr[PATH_MAX];
    snprintf(api, sizeof(api), "%s", vm->api_sock_path);
    snprintf(jr, sizeof(jr), "%s", vm->jail_root);
    CHECK_RC(vmm_destroy(vm), "destroy");
    if (kill(pid, 0) == 0) abort();  // process gone
    struct stat st2;
    if (stat(api, &st2) == 0 || stat(jr, &st2) == 0) abort();  // jail gone
    printf("[test] lifecycle: PASS\n");
    fflush(stdout);
}

static void test_restore(void) {
    printf("[test] restore...\n");
    fflush(stdout);
    char vm_id[64];
    snprintf(vm_id, sizeof(vm_id), "vmm-r%d", (int)getpid() % 100000);
    vm_network_t net;
    memset(&net, 0, sizeof(net));
    CHECK_RC(network_setup(vm_id, &net), "net setup");
    uint64_t t0 = now_ms();
    vm_handle_t* vm = vmm_restore("e2e", vm_id, net.tap_name, net.guest_ip, NULL);
    uint64_t restore_ms = now_ms() - t0;
    if (!vm) {
        fprintf(stderr, "FAIL restore errno=%d (filter kill? see log)\n", errno);
        abort();
    }
    vm->net = net;
    vm->has_net = true;
    printf("[test] restore_ms=%lu\n", (unsigned long)restore_ms);
    fflush(stdout);
    check_state(vm, "Running", "restored state");
    // §10.11: the VMM must have been placed in its per-VM cgroup.
    if (cgroup_enabled()) {
        if (!vm->cgroup_dir[0]) {
            fprintf(stderr, "FAIL: cgroup dir not set for %s\n", vm_id);
            abort();
        }
        char procs[PATH_MAX];
        snprintf(procs, sizeof(procs), "%s/cgroup.procs", vm->cgroup_dir);
        FILE* cf = fopen(procs, "r");
        if (!cf) {
            fprintf(stderr, "FAIL: open %s\n", procs);
            abort();
        }
        int found = 0;
        char line[64];
        while (fgets(line, sizeof(line), cf)) {
            if (strtol(line, NULL, 10) == vm->vmm_pid) { found = 1; break; }
        }
        fclose(cf);
        if (!found) {
            fprintf(stderr, "FAIL: vmm pid %d not in %s\n", vm->vmm_pid, procs);
            abort();
        }
        printf("[test] cgroup placement: pid %d in %s\n", vm->vmm_pid,
               vm->cgroup_dir);
    }
    // Post-restore guest execution: the resumed guest continues its heartbeat
    // loop, so a fresh SANDBOX-TICK appears in the restore serial log.
    CHECK_RC(vmm_wait_ready(vm, "SANDBOX-TICK", 30000), "post-restore ticks");
    // Faults served from the snapshot (guest code+timer pages).
    uint64_t end = now_ms() + 10000;
    uint32_t faults = 0;
    while (now_ms() < end) {
        faults = __atomic_load_n(&vm->page_faults, __ATOMIC_ACQUIRE);
        if (faults > 0) break;
        struct timespec nap = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000L };
        nanosleep(&nap, NULL);
    }
    printf("[test] post-restore page_faults=%u\n", faults);
    fflush(stdout);
    if (faults == 0) abort();
    CHECK_RC(vmm_destroy(vm), "destroy restored");
    printf("[test] restore: PASS\n");
    fflush(stdout);
}

static void test_pool_e2e(void) {
    printf("[test] pool_e2e...\n");
    fflush(stdout);
    pool_set_restore_source("e2e");
    pool_manager_t pool;
    CHECK_RC(pool_manager_init(&pool, 2), "pool init");
    // Wait for the pool to fill with real restored VMs.
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        pthread_mutex_lock(&pool.lock);
        int w = pool.warm_count;
        pthread_mutex_unlock(&pool.lock);
        if (w == 2) break;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long ms = (now.tv_sec - start.tv_sec) * 1000L +
                  (now.tv_nsec - start.tv_nsec) / 1000000L;
        if (ms > 60000) {
            fprintf(stderr, "FAIL pool fill timeout\n");
            abort();
        }
        struct timespec nap = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000L };
        nanosleep(&nap, NULL);
    }
    // Pool-hit provision latency vs the <100ms LLD target.
    sandbox_spec_t spec = { .memory_mib = 128, .vcpu_count = 1,
                            .template_name = "e2e", .env_vars = NULL,
                            .pool_wait_ms = 30000 };
    vm_handle_t* a = NULL;
    uint64_t t0 = now_ms();
    CHECK_RC(pool_provision(&pool, &spec, &a) != SANDBOX_OK ? -1 : 0, "provision");
    uint64_t hit_ms = now_ms() - t0;
    if (!a) abort();
    printf("[test] pool_hit_ms=%lu\n", (unsigned long)hit_ms);
    fflush(stdout);
    if (hit_ms > 100) {
        fprintf(stderr, "FAIL pool hit %lu ms\n", (unsigned long)hit_ms);
        abort();
    }
    check_state(a, "Running", "provisioned state");
    CHECK_RC(vmm_destroy(a), "destroy provisioned");
    pool_manager_destroy(&pool);
    printf("[test] pool_e2e: PASS\n");
    fflush(stdout);
}

int main(void) {
    // #22: the /snapshot/load body decides what the guest sees after resume
    // (its clock, its NIC, its vsock UDS). It is pure string construction, so
    // it is asserted here, before the skip checks, and therefore runs on hosted
    // CI too.
    {
        char req[1024];
        unsetenv("SANDBOX_FC_CLOCK_REALTIME");  // test the default, not the escape hatch
        int n = vmm_build_load_request(req, sizeof(req), "tapX");
        bool ok = n > 0 &&
                  strstr(req, "\"host_dev_name\": \"tapX\"") != NULL &&
                  strstr(req, "\"vsock_override\": {\"uds_path\": \"/vsock.sock\"}") != NULL;
#if defined(__x86_64__)
        ok = ok && strstr(req, "\"clock_realtime\": true") != NULL;
#else
        // x86_64-only field: Firecracker rejects it as unknown elsewhere.
        ok = ok && strstr(req, "clock_realtime") == NULL;
#endif
        char tiny[16];
        bool trunc_ok =
            vmm_build_load_request(tiny, sizeof(tiny), "tapX") == -1;
        if (!ok || !trunc_ok) {
            fprintf(stderr, "FAIL load request: %s\n", n > 0 ? req : "(build failed)");
            return 1;
        }
        printf("[test] %-28s PASS\n", "load request: clock/tap/vsock");
    }

    if (geteuid() != 0 || access("/dev/kvm", R_OK | W_OK) < 0 ||
        !have_file(asset_path("SANDBOX_KERNEL", "SANDBOX_KERNEL_DEFAULT",
                              ASSET_KERNEL)) ||
        !have_file(asset_path("SANDBOX_ROOTFS", "SANDBOX_ROOTFS_DEFAULT",
                              ASSET_ROOTFS)) ||
        !have_file("/usr/local/bin/firecracker")) {
        printf("SKIP (need root + /dev/kvm + firecracker + guest assets)\n");
        return 0;
    }
    if (!have_template()) {
        printf("SKIP (template fixture not ready)\n");
        return 0;
    }
    // §10.11: enable cgroups so the restore path exercises per-VM placement.
    cgroup_init();
    test_lifecycle();
    test_restore();
    test_pool_e2e();
    printf("ALL VMM TESTS PASSED\n");
    return 0;
}
