// SPDX-License-Identifier: GPL-2.0-only
// Phase 8 integration test: daemon-side IPC server + client API + engine-side
// broker-control token authority, over the real warm pool (REQUIRES the "e2e"
// template fixture and root). SKIPs where root/KVM/template are unavailable.

#include "broker.h"
#include "ipc_server.h"
#include "lifecycle.h"
#include "libsandbox.h"
#include "pool_manager.h"
#include "telemetry.h"
#include "vmm_manager.h"

#include <pthread.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_fail = 0;
#define CHECK(cond, msg)                              \
    do {                                              \
        if (cond) {                                   \
            fprintf(stderr, "[test] %-28s PASS\n", msg); \
        } else {                                      \
            fprintf(stderr, "[test] %-28s FAIL\n", msg); \
            g_fail++;                                 \
        }                                             \
    } while (0)

// Scan a restored VM's serial log for a marker (guest-side observability).
static int serial_has(vm_handle_t* vm, const char* needle) {
    if (!vm || !vm->jail_root[0]) return 0;
    char path[PATH_MAX + 16];
    snprintf(path, sizeof(path), "%s/serial.log", vm->jail_root);
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    static char buf[1 << 16];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

// Print the (bounded) serial log so the CI log shows the guest's own account of
// a failed guest-side assertion.
static void dump_serial(vm_handle_t* vm, const char* why) {
    if (!vm || !vm->jail_root[0]) return;
    char path[PATH_MAX + 16];
    snprintf(path, sizeof(path), "%s/serial.log", vm->jail_root);
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "--- serial.log (%s) unavailable ---\n", path);
        return;
    }
    static char b[1 << 16];
    size_t n = fread(b, 1, sizeof(b) - 1, f);
    b[n] = '\0';
    fprintf(stderr, "--- serial.log (%s) [%s] ---\n%s\n--- end ---\n", path, why, b);
    fclose(f);
}

static pool_manager_t g_pool;
static char g_engine_sock[256];
static char g_bc_sock[256];

static void* server_main(void* arg) {
    (void)arg;
    ipc_server_run(g_engine_sock);
    return NULL;
}

static sandbox_error_t connect_retry(const char* path, int tries) {
    sandbox_error_t rc = SANDBOX_ERR_DAEMON_UNREACHABLE;
    for (int i = 0; i < tries; i++) {
        rc = sandbox_init(path);
        if (rc == SANDBOX_OK) return rc;
        usleep(20000);
    }
    return rc;
}

int main(void) {
    const char* snap = getenv("SANDBOX_SNAPSHOT_ROOT");
    if (!snap || !*snap || geteuid() != 0 || access("/dev/kvm", R_OK | W_OK) < 0) {
        printf("SKIP test_ipc: needs root + /dev/kvm + template fixture\n");
        return 0;
    }

    snprintf(g_engine_sock, sizeof(g_engine_sock), "/tmp/sbtest-ipc-%d.sock",
             (int)getpid());
    snprintf(g_bc_sock, sizeof(g_bc_sock), "/tmp/sbtest-bc-%d.sock",
             (int)getpid());
    unlink(g_engine_sock);
    unlink(g_bc_sock);

    pool_set_restore_source("e2e");
    if (pool_manager_init(&g_pool, 2) < 0) {
        fprintf(stderr, "FAIL: pool_manager_init\n");
        return 1;
    }
    ipc_server_set_pool(&g_pool);
    ipc_server_set_template("e2e");
    ipc_server_set_allowed_services("api.example.com,*.internal");

    CHECK(ipc_server_start_broker_control(g_bc_sock) == 0, "broker-control start");

    sandbox_spec_t spec;
    memset(&spec, 0, sizeof(spec));
    spec.memory_mib = 128;
    spec.vcpu_count = 1;
    spec.template_name = "e2e";
    spec.pool_wait_ms = 60000;
    const char* envp[] = { "MYKEY=myvalue", "SANDBOX_MODE=test", NULL };
    spec.env_vars = envp;

    // --- Phase 10.1: SO_PEERCRED allowlist. With only an impossible uid
    // allowed, a root (uid 0) client must be rejected. ---
    ipc_server_set_allowed_uids("4294967294");  // any uid but 0
    {
        pthread_t ta;
        if (pthread_create(&ta, NULL, server_main, NULL) != 0) {
            fprintf(stderr, "FAIL: auth server thread\n");
            pool_manager_destroy(&g_pool);
            return 1;
        }
        int rejected = 0;
        sandbox_error_t rca = connect_retry(g_engine_sock, 250);
        if (rca != SANDBOX_OK) {
            rejected = 1;  // refused before we could even talk
        } else {
            sandbox_handle_t* ha = NULL;
            if (sandbox_create(&spec, &ha) != SANDBOX_OK) rejected = 1;
            else sandbox_destroy(ha);
        }
        CHECK(rejected, "peercred: disallowed uid rejected");
        sandbox_cleanup();
        ipc_server_request_stop();  // keep broker-control alive
        pthread_join(ta, NULL);
    }
    ipc_server_set_allowed_uids("");  // default (any) for the rest of the run

    pthread_t th;
    if (pthread_create(&th, NULL, server_main, NULL) != 0) {
        fprintf(stderr, "FAIL: server thread\n");
        pool_manager_destroy(&g_pool);
        return 1;
    }

    sandbox_error_t rc = connect_retry(g_engine_sock, 250);
    CHECK(rc == SANDBOX_OK, "client connect");

    sandbox_handle_t* h = NULL;

    if (rc == SANDBOX_OK) {
        rc = sandbox_create(&spec, &h);
        CHECK(rc == SANDBOX_OK && h != NULL, "sandbox_create");

        sandbox_status_t st;
        rc = sandbox_inspect(h, &st);
        CHECK(rc == SANDBOX_OK && st.sandbox_id != 0, "inspect id");
        CHECK(rc == SANDBOX_OK && st.is_running, "inspect running");

        // Per-VM env injection (Phase 9b): the guest agent echoes a delimited
        // SANDBOX-ENV block to serial after the host streams the env.
        vm_handle_t* hvm = lifecycle_get(st.sandbox_id);
        int seen = 0;
        for (int i = 0; i < 300; i++) {
            if (serial_has(hvm, "MYKEY")) { seen = 1; break; }
            usleep(10000);
        }
        if (!seen && hvm) dump_serial(hvm, "env not seen");
        CHECK(seen, "env: injected into guest");
        CHECK(serial_has(hvm, "SANDBOX-ENV-BEGIN"), "env: guest marker");
        // Phase 10.2: the guest must not echo env *values* to the persistent
        // serial console (only key names).
        CHECK(!serial_has(hvm, "myvalue"), "env: value redacted in serial");

        // #10: the guest must classify the host connection by its vsock CID.
        // The agent logs the CID it actually observed on the first accepted
        // host connection: that is in-guest proof the classification input is
        // real (and is the host's, 2) rather than "every peer is accepted".
        //
        // The negative direction -- a non-CID_HOST peer is refused -- cannot be
        // produced inside this guest: the guest kernel is 4.14 and guest-local
        // vsock (VMADDR_CID_LOCAL) only exists from Linux 5.6, so an in-guest
        // connection to our own listener blocks in connect() instead of
        // completing. It is covered by tests/test_vsock_peer.c, which runs the
        // same classifier against a real non-host AF_VSOCK peer on the host.
        int host_seen = 0;
        for (int i = 0; i < 100; i++) {
            if (serial_has(hvm, "SANDBOX-VSOCK-HOST cid=2")) {
                host_seen = 1;
                break;
            }
            usleep(10000);
        }
        if (!host_seen) dump_serial(hvm, "vsock host peer not classified");
        CHECK(host_seen, "vsock: host peer authenticated as cid 2");
        CHECK(!serial_has(hvm, "SANDBOX-VSOCK-REJECT"),
              "vsock: the host connection was not rejected");

        CHECK(sandbox_pause(h) == SANDBOX_OK, "sandbox_pause");
        CHECK(sandbox_inspect(h, &st) == SANDBOX_OK && !st.is_running,
              "inspect paused");
        CHECK(sandbox_resume(h) == SANDBOX_OK, "sandbox_resume");
        CHECK(sandbox_inspect(h, &st) == SANDBOX_OK && st.is_running,
              "inspect resumed");

        // Engine-side broker-control: the minted token validates and carries
        // the configured allowlist.
        const char* token = sandbox_handle_token(h);
        CHECK(token && strlen(token) == BROKER_TOKEN_HEX_LEN, "token shape");
        int bfd = broker_engine_connect(g_bc_sock);
        CHECK(bfd >= 0, "broker-control connect");
        session_info_t si;
        int vr = (bfd >= 0) ? broker_validate_token(bfd, token, &si)
                            : BROKER_VALIDATE_ERROR;
        CHECK(vr == BROKER_VALIDATE_OK, "token validates");
        CHECK(vr == BROKER_VALIDATE_OK && si.sandbox_id == st.sandbox_id,
              "token sandbox_id");
        CHECK(vr == BROKER_VALIDATE_OK && si.allowed_services &&
                  si.allowed_services[0] &&
                  strcmp(si.allowed_services[0], "api.example.com") == 0,
              "token allowlist");

        // Unknown token is rejected.
        char bad[BROKER_TOKEN_HEX_LEN + 1];
        memset(bad, '0', BROKER_TOKEN_HEX_LEN);
        bad[BROKER_TOKEN_HEX_LEN] = '\0';
        session_info_t si_bad;
        int vrb = broker_validate_token(bfd, bad, &si_bad);
        CHECK(vrb == BROKER_VALIDATE_INVALID, "bad token rejected");

        // --- pidfd VMM crash detection (§4.2): kill the VMM and confirm the
        // event loop reaps it, bumps the crash metric, revokes the token, and
        // stops reporting the sandbox as live. ---
        sandbox_handle_t* h2 = NULL;
        CHECK(sandbox_create(&spec, &h2) == SANDBOX_OK && h2 != NULL,
              "create for crash test");
        sandbox_status_t cst;
        memset(&cst, 0, sizeof(cst));
        if (h2 && sandbox_inspect(h2, &cst) == SANDBOX_OK) {
            uint32_t cid = cst.sandbox_id;
            const char* tok2 = sandbox_handle_token(h2);
            vm_handle_t* cvm = lifecycle_get(cid);
            CHECK(cvm != NULL, "crash: vm registered");
            if (cvm) {
                kill(cvm->vmm_pid, SIGKILL);
                int gone = 0;
                for (int i = 0; i < 200; i++) {
                    if (sandbox_inspect(h2, &cst) != SANDBOX_OK) { gone = 1; break; }
                    usleep(10000);
                }
                CHECK(gone, "crash: reclaim observed");
                CHECK(lifecycle_get(cid) == NULL, "crash: registry cleared");
                if (bfd >= 0 && tok2) {
                    session_info_t s2;
                    CHECK(broker_validate_token(bfd, tok2, &s2) ==
                              BROKER_VALIDATE_INVALID,
                          "crash: token revoked");
                }
            }
        }
        char mbuf[8192];
        telemetry_render(mbuf, sizeof(mbuf));
        CHECK(strstr(mbuf, "sandbox_vmm_crashes_total 1") != NULL,
              "crash: metric bumped");
        CHECK(strstr(mbuf, "sandbox_uffd_faults_total 0") == NULL,
              "metrics: uffd faults served");

        // Destroy revokes the token.
        uint32_t id = st.sandbox_id;
        CHECK(sandbox_destroy(h) == SANDBOX_OK, "sandbox_destroy");
        h = NULL;
        session_info_t si2;
        int vr2 = broker_validate_token(bfd, token, &si2);
        CHECK(vr2 == BROKER_VALIDATE_INVALID, "token revoked");
        (void)id;

        session_info_free(&si);
        if (bfd >= 0) close(bfd);
    }

    sandbox_cleanup();
    ipc_server_stop();
    pthread_join(th, NULL);
    pool_manager_destroy(&g_pool);
    unlink(g_engine_sock);
    unlink(g_bc_sock);

    fprintf(stderr, "[test] ipc: %s\n", g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
