// SPDX-License-Identifier: GPL-2.0-only
// sandbox-cli: create a sandbox and hold the session open (a disconnected
// session reclaims its sandboxes, so a fire-and-forget CLI cannot leave one
// behind). Prints a JSON line with the id, then waits for SIGINT/SIGTERM.

#include "libsandbox.h"
#include "snapshot_manager.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void usage(void) {
    printf("usage:\n"
           "  sandbox-cli run --template NAME [--socket PATH] [--memory MIB] "
           "[--vcpus N] [--wait MS]\n"
           "  sandbox-cli verify --template NAME\n");
}

int main(int argc, char** argv) {
    const char* socket_path = "/var/run/sandbox-engine/engine.sock";
    const char* template_name = NULL;
    uint64_t memory_mib = 128;
    uint32_t vcpus = 1;
    uint32_t wait_ms = 500;
    int do_run = 0;
    int do_verify = 0;

    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        const char* v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strcmp(a, "run") == 0) do_run = 1;
        else if (strcmp(a, "verify") == 0) do_verify = 1;
        else if (strcmp(a, "--socket") == 0 && v) socket_path = argv[++i];
        else if (strcmp(a, "--template") == 0 && v) template_name = argv[++i];
        else if (strcmp(a, "--memory") == 0 && v) memory_mib = strtoull(argv[++i], NULL, 10);
        else if (strcmp(a, "--vcpus") == 0 && v) vcpus = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(a, "--wait") == 0 && v) wait_ms = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage();
            return 0;
        }
    }

    // §10.10: pre-flight integrity check (used by ops and --validate-config).
    if (do_verify) {
        if (!template_name) {
            usage();
            return 2;
        }
        return snapshot_verify(template_name) == 0 ? 0 : 1;
    }

    if (!do_run || !template_name) {
        usage();
        return 2;
    }

    sandbox_error_t rc = sandbox_init(socket_path);
    if (rc != SANDBOX_OK) {
        fprintf(stderr, "sandbox_init(%s): %d\n", socket_path, (int)rc);
        return 1;
    }

    sandbox_spec_t spec;
    memset(&spec, 0, sizeof(spec));
    spec.memory_mib = memory_mib;
    spec.vcpu_count = vcpus;
    spec.template_name = template_name;
    spec.env_vars = NULL;
    spec.pool_wait_ms = wait_ms;

    sandbox_handle_t* h = NULL;
    rc = sandbox_create(&spec, &h);
    if (rc != SANDBOX_OK) {
        fprintf(stderr, "sandbox_create: %d\n", (int)rc);
        sandbox_cleanup();
        return 1;
    }

    sandbox_status_t st;
    if (sandbox_inspect(h, &st) == SANDBOX_OK) {
        printf("{\"event\":\"created\",\"sandbox_id\":%u,\"running\":%s,"
               "\"memory_rss_mib\":%llu}\n",
               st.sandbox_id, st.is_running ? "true" : "false",
               (unsigned long long)st.memory_rss_mib);
    } else {
        printf("{\"event\":\"created\"}\n");
    }
    fflush(stdout);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    while (!g_stop) pause();

    sandbox_destroy(h);
    sandbox_cleanup();
    printf("{\"event\":\"destroyed\"}\n");
    return 0;
}
