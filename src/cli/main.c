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
           "[--vcpus N] [--wait MS] [--session-key KEY] [--exec SCRIPT]...\n"
           "      with --exec: run each SCRIPT (sh -c) in the new sandbox, print its\n"
           "      output, then destroy the sandbox and exit with the first non-zero\n"
           "      exit status (or 0). Without it, hold the sandbox until SIGINT.\n"
           "  sandbox-cli renew --session-key KEY [--extra SECONDS] [--socket PATH]\n"
           "  sandbox-cli verify --template NAME\n");
}

int main(int argc, char** argv) {
    const char* socket_path = "/var/run/sandbox-engine/engine.sock";
    const char* template_name = NULL;
    const char* session_key = NULL;
    uint64_t memory_mib = 128;
    uint32_t vcpus = 1;
    uint32_t wait_ms = 500;
    uint32_t extra_seconds = 0;
    const char* exec_scripts[16];
    int n_exec = 0;
    int do_run = 0;
    int do_verify = 0;
    int do_renew = 0;

    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        const char* v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strcmp(a, "run") == 0) do_run = 1;
        else if (strcmp(a, "verify") == 0) do_verify = 1;
        else if (strcmp(a, "renew") == 0) do_renew = 1;
        else if (strcmp(a, "--socket") == 0 && v) socket_path = argv[++i];
        else if (strcmp(a, "--template") == 0 && v) template_name = argv[++i];
        else if (strcmp(a, "--session-key") == 0 && v) session_key = argv[++i];
        else if (strcmp(a, "--exec") == 0 && v) {
            if (n_exec >= 16) {
                fprintf(stderr, "at most 16 --exec scripts\n");
                return 2;
            }
            exec_scripts[n_exec++] = argv[++i];
        }
        else if (strcmp(a, "--extra") == 0 && v)
            extra_seconds = (uint32_t)strtoul(argv[++i], NULL, 10);
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

    // #23/D5: extend a session without holding a sandbox. The volume outlives
    // every VM, so this is the operation that keeps a quiet conversation's data
    // alive; it is deliberately not tied to a handle.
    if (do_renew) {
        if (!session_key) {
            usage();
            return 2;
        }
        sandbox_error_t rrc = sandbox_init(socket_path);
        if (rrc != SANDBOX_OK) {
            fprintf(stderr, "sandbox_init(%s): %d\n", socket_path, (int)rrc);
            return 1;
        }
        uint64_t expires_at = 0;
        rrc = sandbox_session_renew(session_key, extra_seconds, &expires_at);
        if (rrc != SANDBOX_OK) {
            fprintf(stderr, "sandbox_session_renew: %d (%s)\n", (int)rrc,
                    sandbox_error_string(rrc));
            sandbox_cleanup();
            return 1;
        }
        printf("{\"event\":\"renewed\",\"session_key\":\"%s\","
               "\"expires_at\":%llu}\n",
               session_key, (unsigned long long)expires_at);
        sandbox_cleanup();
        return 0;
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
    spec.session_key = session_key;

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

    // #24: run the requested commands, then leave. The sandbox dies with this
    // session, so there is nothing to hold it open for.
    if (n_exec > 0) {
        int status = 0;
        for (int i = 0; i < n_exec; i++) {
            const char* av[2] = { exec_scripts[i], NULL };
            sandbox_exec_spec_t es;
            memset(&es, 0, sizeof(es));
            es.argv = av;
            es.shell = true;
            sandbox_exec_result_t er;
            sandbox_error_t ec = sandbox_exec(h, &es, &er);
            if (ec != SANDBOX_OK) {
                fprintf(stderr, "sandbox_exec: %d (%s)\n", (int)ec, sandbox_error_string(ec));
                status = status ? status : 1;
                continue;
            }
            if (er.out_len) fwrite(er.out, 1, er.out_len, stdout);
            if (er.err_len) fwrite(er.err, 1, er.err_len, stderr);
            if (er.out_total > er.out_len || er.err_total > er.err_len)
                fprintf(stderr, "[output truncated: kept %zu of %llu stdout, %zu of %llu stderr bytes]\n",
                        er.out_len, (unsigned long long)er.out_total, er.err_len,
                        (unsigned long long)er.err_total);
            fflush(stdout);
            printf("{\"event\":\"exec\",\"index\":%d,\"exit_code\":%d,\"term_signal\":%d,"
                   "\"timed_out\":%s}\n",
                   i, er.exit_code, er.term_signal, er.timed_out ? "true" : "false");
            if (!status && (er.exit_code != 0 || er.timed_out))
                status = er.exit_code > 0 ? er.exit_code : 1;
            sandbox_exec_result_free(&er);
        }
        sandbox_destroy(h);
        sandbox_cleanup();
        return status;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    while (!g_stop) pause();

    sandbox_destroy(h);
    sandbox_cleanup();
    printf("{\"event\":\"destroyed\"}\n");
    return 0;
}
