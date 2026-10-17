// Phase 11: daemon config parser test (no root, no KVM). Verifies the flat
// "key = value" parser recognises every key in the packaged engine.conf
// (sections are ignored) and that env overrides win.

#include "engine_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    CHECK(c.metrics_port == 0, "default metrics disabled");

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
        "[pool]\n"
        "target_size = 7\n"
        "max_queue_depth = 11\n"
        "pool_wait_timeout_ms = 250\n"
        "[paths]\n"
        "jail_root = /var/j\n"
        "snapshot_root = /var/s\n"
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
    CHECK_STR(c.allowed_uids, "0, 1000", "file allowed_uids");
    CHECK_STR(c.allowed_services, "a.example, b.example", "file allowed_services");
    CHECK_STR(c.jail_root, "/var/j", "file jail_root");
    CHECK_STR(c.snapshot_root, "/var/s", "file snapshot_root");
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
    CHECK_STR(c.jail_root, "/var/lib/sandbox-engine/jail", "packaged jail_root");
    CHECK_STR(c.snapshot_root, "/var/lib/sandbox-engine/snapshots",
              "packaged snapshot_root");
    CHECK(c.metrics_port == 9180, "packaged metrics_port");
    CHECK_STR(c.allowed_uids, "0", "packaged allowed_uids");

    // 4. Env overrides the file.
    config_defaults(&c);
    setenv("SANDBOX_POOL_SIZE", "3", 1);
    setenv("SANDBOX_TEMPLATE", "envtmpl", 1);
    config_apply_env(&c);
    CHECK(c.pool_size == 3, "env pool_size");
    CHECK_STR(c.template_name, "envtmpl", "env template");

    fprintf(stderr, "[test] config: %s\n", g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
