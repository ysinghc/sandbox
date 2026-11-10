// SPDX-License-Identifier: GPL-2.0-only
// Phase 11: daemon config parser test (no root, no KVM). Verifies the flat
// "key = value" parser recognises every key in the packaged engine.conf
// (sections are ignored) and that env overrides win.

#include "engine_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef SANDBOX_TEST_CONFIG_FILE
#define SANDBOX_TEST_CONFIG_FILE "config/engine.conf"
#endif

static int g_fail = 0;
#define CHECK(cond, msg)                                    \
    do {                                                    \
        if (cond) {                                         \
            fprintf(stderr, "[test] %-30s PASS\n", msg);    \
        } else {                                            \
            fprintf(stderr, "[test] %-30s FAIL\n", msg);    \
            g_fail++;                                       \
        }                                                   \
    } while (0)

#define CHECK_STR(got, want, msg) CHECK(strcmp((got), (want)) == 0, msg)

int main(void) {
    engine_config_t c;

    // 1. Defaults.
    config_defaults(&c);
    CHECK(c.pool_size == 5, "default pool_size");
    CHECK(c.jailer_uid == 65534 && c.jailer_gid == 65534, "default jailer ids");
    CHECK(c.metrics_port == 9180, "default metrics port");
    CHECK_STR(c.metrics_bind, "0.0.0.0", "default metrics bind");
    CHECK_STR(c.privileged_socket, "", "default privileged_socket");

    // 2. A synthetic file with [sections], comments and every key.
    const char* tmp = "/tmp/sbtest-config-XXXXXX";
    char path[64];
    snprintf(path, sizeof(path), "%s", tmp);
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); return 1; }
    const char* body =
        "# comment\n"
        "[daemon]\n"
        "socket_path = /run/x.sock\n"
        "broker_control_socket = /run/bc.sock\n"
        "template = mytmpl\n"
        "jailer_uid = 1234\n"
        "jailer_gid = 5678\n"
        "allowed_uids = 0, 1000\n"
        "allowed_services = a.example, b.example\n"
        "vsock_settle_ms = 1500\n"
        "create_workers = 2\n"
        "max_creates_per_session = 5\n"
        "max_creates_per_uid = 9\n"
        "[cgroup]\n"
        "cgroup_enable = 0\n"
        "cgroup_slack_mib = 12\n"
        "cgroup_cpu_max = 50000 100000\n"
        "log_level = warn\n"
        "[pool]\n"
        "target_size = 7\n"
        "max_queue_depth = 11\n"
        "pool_wait_timeout_ms = 250\n"
        "[paths]\n"
        "jail_root = /var/j\n"
        "snapshot_root = /var/s\n"
        "privileged_socket = /run/p.sock\n"
        "[metrics]\n"
        "metrics_port = 9090\n"
        "metrics_bind = 0.0.0.0\n"
        "unknown_key = ignored\n";
    ssize_t w = write(fd, body, strlen(body));
    (void)w;
    close(fd);

    config_defaults(&c);
    config_load_file(&c, path);
    unlink(path);
    CHECK_STR(c.socket_path, "/run/x.sock", "file socket_path");
    CHECK_STR(c.broker_control_socket, "/run/bc.sock", "file broker_control");
    CHECK_STR(c.template_name, "mytmpl", "file template");
    CHECK(c.pool_size == 7, "file target_size -> pool_size");
    CHECK(c.max_queue_depth == 11, "file max_queue_depth");
    CHECK(c.pool_wait_timeout_ms == 250, "file pool_wait_timeout_ms");
    CHECK(c.jailer_uid == 1234 && c.jailer_gid == 5678, "file jailer ids");
    CHECK(c.vsock_settle_ms == 1500, "file vsock_settle_ms");
    CHECK(c.create_workers == 2, "file create_workers");
    CHECK(c.max_creates_per_session == 5, "file max_creates_per_session");
    CHECK(c.max_creates_per_uid == 9, "file max_creates_per_uid");
    CHECK(c.cgroup_enable == 0, "file cgroup_enable");
    CHECK(c.cgroup_slack_mib == 12, "file cgroup_slack_mib");
    CHECK_STR(c.cgroup_cpu_max, "50000 100000", "file cgroup_cpu_max");
    CHECK_STR(c.log_level, "warn", "file log_level");
    CHECK_STR(c.allowed_uids, "0, 1000", "file allowed_uids");
    CHECK_STR(c.allowed_services, "a.example, b.example", "file allowed_services");
    CHECK_STR(c.jail_root, "/var/j", "file jail_root");
    CHECK_STR(c.snapshot_root, "/var/s", "file snapshot_root");
    CHECK_STR(c.privileged_socket, "/run/p.sock", "file privileged_socket");
    CHECK(c.metrics_port == 9090, "file metrics_port");
    CHECK_STR(c.metrics_bind, "0.0.0.0", "file metrics_bind");

    // 3. The packaged engine.conf must parse without relying on defaults.
    config_defaults(&c);
    config_load_file(&c, SANDBOX_TEST_CONFIG_FILE);
    CHECK_STR(c.socket_path, "/var/run/sandbox-engine/engine.sock",
              "packaged socket_path");
    CHECK_STR(c.template_name, "python-agent", "packaged template");
    CHECK(c.pool_size == 5, "packaged target_size");
    CHECK(c.max_queue_depth == 50, "packaged max_queue_depth");
    CHECK(c.pool_wait_timeout_ms == 500, "packaged pool_wait_timeout_ms");
    CHECK(c.jailer_uid == 65534 && c.jailer_gid == 65534, "packaged jailer ids");
    CHECK(c.vsock_settle_ms == 1000, "packaged vsock_settle_ms");
    CHECK(c.create_workers == 4, "packaged create_workers");
    CHECK(c.max_creates_per_session == 16, "packaged max_creates_per_session");
    CHECK(c.max_creates_per_uid == 64, "packaged max_creates_per_uid");
    CHECK(c.cgroup_enable == 1, "packaged cgroup_enable");
    CHECK(c.cgroup_slack_mib == 64, "packaged cgroup_slack_mib");
    CHECK_STR(c.cgroup_cpu_max, "max", "packaged cgroup_cpu_max");
    CHECK_STR(c.log_level, "info", "packaged log_level");
    CHECK_STR(c.jail_root, "/var/lib/sandbox-engine/jail", "packaged jail_root");
    CHECK_STR(c.snapshot_root, "/var/lib/sandbox-engine/snapshots",
              "packaged snapshot_root");
    CHECK(c.metrics_port == 9180, "packaged metrics_port");
    CHECK_STR(c.allowed_uids, "0", "packaged allowed_uids");

    // 4. Env overrides the file.
    config_defaults(&c);
    setenv("SANDBOX_POOL_SIZE", "3", 1);
    setenv("SANDBOX_TEMPLATE", "envtmpl", 1);
    setenv("SANDBOX_PRIVILEGED_SOCKET", "/run/e.sock", 1);
    config_apply_env(&c);
    CHECK(c.pool_size == 3, "env pool_size");
    CHECK_STR(c.template_name, "envtmpl", "env template");
    CHECK_STR(c.privileged_socket, "/run/e.sock", "env privileged_socket");
    unsetenv("SANDBOX_POOL_SIZE");
    unsetenv("SANDBOX_TEMPLATE");
    unsetenv("SANDBOX_PRIVILEGED_SOCKET");

    // 5. conf.d drop-ins: base < drop-ins, later files win in byte order.
    char dir_template[] = "/tmp/sbtest-confdir-XXXXXX";
    char* tmpd = mkdtemp(dir_template);
    if (!tmpd) { perror("mkdtemp"); return 1; }
    char base[128], ddir[160], f1[192], f2[192], f3[192], f4[192], f5[192];
    snprintf(base, sizeof(base), "%s/engine.conf", tmpd);
    snprintf(ddir, sizeof(ddir), "%s/engine.conf.d", tmpd);
    snprintf(f1, sizeof(f1), "%s/10-x.conf", ddir);
    snprintf(f2, sizeof(f2), "%s/9-x.conf", ddir);
    snprintf(f3, sizeof(f3), "%s/note.txt", ddir);
    snprintf(f4, sizeof(f4), "%s/.hidden.conf", ddir);
    snprintf(f5, sizeof(f5), "%s/sub.conf", ddir);
    FILE* bf = fopen(base, "w");
    fputs("pool_size = 5\n", bf);
    fclose(bf);
    mkdir(ddir, 0700);
    FILE* d1 = fopen(f1, "w");
    fputs("pool_size = 10\n", d1);
    fclose(d1);
    FILE* d2 = fopen(f2, "w");
    fputs("pool_size = 9\n", d2);
    fclose(d2);
    FILE* d3 = fopen(f3, "w");
    fputs("pool_size = 111\n", d3);
    fclose(d3);
    FILE* d4 = fopen(f4, "w");
    fputs("pool_size = 222\n", d4);
    fclose(d4);
    mkdir(f5, 0700);  // ends in .conf but is a directory: skipped
    config_defaults(&c);
    config_load_file(&c, base);
    config_load_conf_d(&c, base);
    // Byte order loads 10-x.conf before 9-x.conf, so 9 wins; the .txt,
    // dotfile and directory never apply.
    CHECK(c.pool_size == 9, "drop-ins order + skips");
    unlink(f1);
    unlink(f2);
    unlink(f3);
    unlink(f4);
    rmdir(f5);
    rmdir(ddir);
    unlink(base);
    rmdir(tmpd);

    // 6. Missing conf.d is fine.
    config_defaults(&c);
    config_load_conf_d(&c, "/tmp/sbtest-no-such-base-XXXXXX");
    config_load_conf_d(&c, NULL);
    CHECK(c.pool_size == 5, "missing conf.d keeps defaults");

    // 7. Template overlays: the matching one applies, others wait.
    config_defaults(&c);
    config_parse_buffer(&c,
                        "template = mytmpl\n"
                        "pool_size = 5\n"
                        "[template \"mytmpl\"]\n"
                        "pool_size = 1\n"
                        "[template \"other\"]\n"
                        "pool_size = 2\n");
    CHECK(c.pool_size == 5, "overlays not auto-applied");
    CHECK(c.n_overlays == 2, "two overlays recorded");
    config_apply_template_overlays(&c);
    CHECK(c.pool_size == 1, "matching overlay applies");
    config_set_key(&c, "template", "other");
    config_apply_template_overlays(&c);
    CHECK(c.pool_size == 2, "re-apply follows the template");

    // 8. service/tenant/unknown scopes parse, store, and never leak global.
    config_defaults(&c);
    config_parse_buffer(&c,
                        "pool_size = 5\n"
                        "[service \"api\"]\n"
                        "pool_size = 42\n"
                        "[tenant \"acme\"]\n"
                        "pool_size = 43\n"
                        "[fleet \"f0\"]\n"
                        "pool_size = 44\n");
    CHECK(c.pool_size == 5, "scoped keys stay out of global");
    const char* v = config_overlay_get(&c, "service", "api", "pool_size");
    CHECK(v && strcmp(v, "42") == 0, "service overlay queryable");
    v = config_overlay_get(&c, "tenant", "acme", "pool_size");
    CHECK(v && strcmp(v, "43") == 0, "tenant overlay queryable");
    v = config_overlay_get(&c, "fleet", "f0", "pool_size");
    CHECK(v && strcmp(v, "44") == 0, "unknown kind stored");
    CHECK(config_overlay_get(&c, "tenant", "acme", "nope") == NULL,
          "missing triple is NULL");
    CHECK(config_overlay_get(&c, NULL, "acme", "pool_size") == NULL,
          "NULL scope is NULL");

    // 9. Malformed headers warn and reset to global; bare headers stay silent.
    config_defaults(&c);
    config_parse_buffer(&c,
                        "[template \"oops\n"
                        "pool_size = 7\n"
                        "[template \"a\" \"b\"]\n"
                        "metrics_port = 1111\n"
                        "[template \"bad name!\"]\n"
                        "metrics_bind = 9.9.9.9\n");
    CHECK(c.pool_size == 7, "unterminated header resets global");
    CHECK(c.metrics_port == 1111, "trailing-text header resets global");
    CHECK_STR(c.metrics_bind, "9.9.9.9", "bad-name header resets global");
    CHECK(c.n_overlays == 0, "malformed headers store nothing");

    // 10. Precedence: env and CLI beat overlays; overlays follow the
    // effective template name, not the file's.
    config_defaults(&c);
    config_parse_buffer(&c,
                        "template = A\n"
                        "pool_size = 5\n"
                        "[template \"A\"]\n"
                        "pool_size = 1\n"
                        "[template \"B\"]\n"
                        "pool_size = 2\n");
    setenv("SANDBOX_POOL_SIZE", "3", 1);
    config_apply_env(&c);
    config_apply_template_overlays(&c);
    CHECK(c.pool_size == 3, "env beats overlay");
    unsetenv("SANDBOX_POOL_SIZE");
    config_set_key_layer(&c, "pool_size", "9", CONFIG_LAYER_CLI);
    config_apply_template_overlays(&c);
    CHECK(c.pool_size == 9, "CLI beats overlay");

    config_defaults(&c);
    config_parse_buffer(&c,
                        "template = A\n"
                        "pool_size = 5\n"
                        "[template \"A\"]\n"
                        "pool_size = 1\n"
                        "[template \"B\"]\n"
                        "pool_size = 2\n");
    setenv("SANDBOX_TEMPLATE", "B", 1);
    config_apply_env(&c);
    config_apply_template_overlays(&c);
    CHECK(c.pool_size == 2, "overlay follows env template");
    unsetenv("SANDBOX_TEMPLATE");

    config_defaults(&c);
    config_parse_buffer(&c,
                        "template = A\n"
                        "pool_size = 5\n"
                        "[template \"A\"]\n"
                        "pool_size = 1\n");
    setenv("SANDBOX_TEMPLATE", "C", 1);
    config_apply_env(&c);
    config_apply_template_overlays(&c);
    CHECK(c.pool_size == 5, "no overlay for unknown template");
    unsetenv("SANDBOX_TEMPLATE");

    // 11. The overlay store caps at 64 and drops the rest deterministically.
    config_defaults(&c);
    char big[8192];
    size_t off = 0;
    for (int i = 0; i < 65; i++) {
        off += (size_t)snprintf(big + off, sizeof(big) - off,
                                "[tenant \"t%d\"]\npool_size = %d\n", i, i);
    }
    config_parse_buffer(&c, big);
    CHECK(c.n_overlays == ENGINE_CONFIG_OVERLAYS_MAX, "overlay cap is 64");
    CHECK(config_overlay_get(&c, "tenant", "t0", "pool_size") != NULL,
          "first overlay kept");
    CHECK(config_overlay_get(&c, "tenant", "t64", "pool_size") == NULL,
          "65th overlay dropped");

    fprintf(stderr, "[test] config: %s\n", g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
