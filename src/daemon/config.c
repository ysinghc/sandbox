// SPDX-License-Identifier: GPL-2.0-only
// sandboxd configuration parser (Phase 11). Flat "key = value"; [section]
// headers are skipped (a line without '=' is ignored). See engine_config.h.

#include "engine_config.h"

#include "pool_manager.h"  // POOL_MAX_QUEUE_DEPTH default

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void config_defaults(engine_config_t* c) {
    memset(c, 0, sizeof(*c));
    snprintf(c->socket_path, sizeof(c->socket_path),
             "/var/run/sandbox-engine/engine.sock");
    snprintf(c->broker_control_socket, sizeof(c->broker_control_socket),
             "/var/run/sandbox-engine/broker-control.sock");
    snprintf(c->template_name, sizeof(c->template_name), "python-agent");
    c->pool_size = 5;  // §5.1 target; matches the packaged engine.conf
    c->max_queue_depth = POOL_MAX_QUEUE_DEPTH;
    c->pool_wait_timeout_ms = 0;
    c->allowed_services[0] = '\0';
    c->allowed_uids[0] = '\0';
    c->metrics_port = 9180;  // §10.13: metrics on by default
    snprintf(c->metrics_bind, sizeof(c->metrics_bind), "0.0.0.0");
    c->jail_root[0] = '\0';
    c->snapshot_root[0] = '\0';
    c->jailer_uid = 65534;
    c->jailer_gid = 65534;
    c->vsock_settle_ms = 1000;
    c->create_workers = 4;
    c->max_creates_per_session = 16;
    c->max_creates_per_uid = 64;
    c->cgroup_enable = 1;
    c->cgroup_slack_mib = 64;
    snprintf(c->cgroup_cpu_max, sizeof(c->cgroup_cpu_max), "%s", "max");
    snprintf(c->log_level, sizeof(c->log_level), "%s", "info");
}

void config_set_key(engine_config_t* c, const char* key, const char* val) {
    if (strcmp(key, "socket") == 0 || strcmp(key, "socket_path") == 0 ||
        strcmp(key, "engine_socket") == 0) {
        snprintf(c->socket_path, sizeof(c->socket_path), "%s", val);
    } else if (strcmp(key, "broker_control_socket") == 0 ||
               strcmp(key, "broker_control") == 0) {
        snprintf(c->broker_control_socket, sizeof(c->broker_control_socket),
                 "%s", val);
    } else if (strcmp(key, "template") == 0 ||
               strcmp(key, "template_name") == 0) {
        snprintf(c->template_name, sizeof(c->template_name), "%s", val);
    } else if (strcmp(key, "pool_size") == 0 ||
               strcmp(key, "target_size") == 0) {
        c->pool_size = atoi(val);
    } else if (strcmp(key, "max_queue_depth") == 0) {
        c->max_queue_depth = atoi(val);
    } else if (strcmp(key, "pool_wait_timeout_ms") == 0) {
        c->pool_wait_timeout_ms = atoi(val);
    } else if (strcmp(key, "allowed_services") == 0) {
        snprintf(c->allowed_services, sizeof(c->allowed_services), "%s", val);
    } else if (strcmp(key, "allowed_uids") == 0) {
        snprintf(c->allowed_uids, sizeof(c->allowed_uids), "%s", val);
    } else if (strcmp(key, "metrics_bind") == 0) {
        snprintf(c->metrics_bind, sizeof(c->metrics_bind), "%s", val);
    } else if (strcmp(key, "metrics_port") == 0) {
        c->metrics_port = atoi(val);
    } else if (strcmp(key, "jail_root") == 0) {
        snprintf(c->jail_root, sizeof(c->jail_root), "%s", val);
    } else if (strcmp(key, "snapshot_root") == 0) {
        snprintf(c->snapshot_root, sizeof(c->snapshot_root), "%s", val);
    } else if (strcmp(key, "jailer_uid") == 0) {
        c->jailer_uid = atoi(val);
    } else if (strcmp(key, "jailer_gid") == 0) {
        c->jailer_gid = atoi(val);
    } else if (strcmp(key, "vsock_settle_ms") == 0) {
        c->vsock_settle_ms = atoi(val);
    } else if (strcmp(key, "create_workers") == 0) {
        c->create_workers = atoi(val);
    } else if (strcmp(key, "max_creates_per_session") == 0) {
        c->max_creates_per_session = atoi(val);
    } else if (strcmp(key, "max_creates_per_uid") == 0) {
        c->max_creates_per_uid = atoi(val);
    } else if (strcmp(key, "cgroup_enable") == 0) {
        c->cgroup_enable = atoi(val);
    } else if (strcmp(key, "cgroup_slack_mib") == 0) {
        c->cgroup_slack_mib = atoi(val);
    } else if (strcmp(key, "cgroup_cpu_max") == 0) {
        snprintf(c->cgroup_cpu_max, sizeof(c->cgroup_cpu_max), "%s", val);
    } else if (strcmp(key, "log_level") == 0) {
        snprintf(c->log_level, sizeof(c->log_level), "%s", val);
    } else {
        fprintf(stderr, "[sandboxd] unknown config key '%s'\n", key);
    }
}

// Trim + classify one already-NUL-terminated line and apply it. Shared by the
// file loader and config_parse_buffer (so the parser is fuzzable in memory).
static void config_parse_line(engine_config_t* c, char* line) {
    char* p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#' || *p == ';' || *p == '[' || *p == '\n' || *p == '\0')
        return;  // comments and [section] headers
    char* eq = strchr(p, '=');
    if (!eq) return;
    *eq = '\0';
    char* key = p;
    char* val = eq + 1;
    char* end = key + strlen(key);
    while (end > key && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';
    while (*val == ' ' || *val == '\t') val++;
    end = val + strlen(val);
    while (end > val && (end[-1] == '\n' || end[-1] == '\r' ||
                         end[-1] == ' ' || end[-1] == '\t')) {
        *--end = '\0';
    }
    if (*key) config_set_key(c, key, val);
}

void config_parse_buffer(engine_config_t* c, const char* text) {
    if (!c || !text) return;
    char line[2048];
    const char* p = text;
    while (*p) {
        size_t i = 0;
        while (*p && *p != '\n' && i + 1 < sizeof(line)) line[i++] = *p++;
        if (*p == '\n') p++;
        line[i] = '\0';
        config_parse_line(c, line);
    }
}

void config_load_file(engine_config_t* c, const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[sandboxd] config %s: %s (using defaults)\n", path,
                strerror(errno));
        return;
    }
    char line[2048];
    while (fgets(line, sizeof(line), f)) config_parse_line(c, line);
    fclose(f);
}

void config_apply_env(engine_config_t* c) {
    const char* v;
    if ((v = getenv("SANDBOX_ENGINE_SOCK")) && *v) config_set_key(c, "socket", v);
    if ((v = getenv("SANDBOX_BROKER_CONTROL")) && *v)
        config_set_key(c, "broker_control", v);
    if ((v = getenv("SANDBOX_TEMPLATE")) && *v) config_set_key(c, "template", v);
    if ((v = getenv("SANDBOX_POOL_SIZE")) && *v)
        config_set_key(c, "pool_size", v);
    if ((v = getenv("SANDBOX_ALLOWED_SERVICES")))
        config_set_key(c, "allowed_services", v);
    if ((v = getenv("SANDBOX_ALLOWED_UIDS")))
        config_set_key(c, "allowed_uids", v);
    if ((v = getenv("SANDBOX_METRICS_PORT")) && *v)
        config_set_key(c, "metrics_port", v);
    if ((v = getenv("SANDBOX_METRICS_BIND")) && *v)
        config_set_key(c, "metrics_bind", v);
    if ((v = getenv("SANDBOX_MAX_QUEUE_DEPTH")) && *v)
        config_set_key(c, "max_queue_depth", v);
    if ((v = getenv("SANDBOX_POOL_WAIT_MS")) && *v)
        config_set_key(c, "pool_wait_timeout_ms", v);
    if ((v = getenv("SANDBOX_JAIL_ROOT")) && *v) config_set_key(c, "jail_root", v);
    if ((v = getenv("SANDBOX_SNAPSHOT_ROOT")) && *v)
        config_set_key(c, "snapshot_root", v);
    if ((v = getenv("SANDBOX_JAILER_UID")) && *v)
        config_set_key(c, "jailer_uid", v);
    if ((v = getenv("SANDBOX_JAILER_GID")) && *v)
        config_set_key(c, "jailer_gid", v);
    if ((v = getenv("SANDBOX_VSOCK_SETTLE_MS")) && *v)
        config_set_key(c, "vsock_settle_ms", v);
    if ((v = getenv("SANDBOX_CREATE_WORKERS")) && *v)
        config_set_key(c, "create_workers", v);
    if ((v = getenv("SANDBOX_MAX_CREATES_PER_SESSION")) && *v)
        config_set_key(c, "max_creates_per_session", v);
    if ((v = getenv("SANDBOX_MAX_CREATES_PER_UID")) && *v)
        config_set_key(c, "max_creates_per_uid", v);
    if ((v = getenv("SANDBOX_CGROUP_ENABLE")) && *v)
        config_set_key(c, "cgroup_enable", v);
    if ((v = getenv("SANDBOX_CGROUP_SLACK_MIB")) && *v)
        config_set_key(c, "cgroup_slack_mib", v);
    if ((v = getenv("SANDBOX_CGROUP_CPU_MAX")) && *v)
        config_set_key(c, "cgroup_cpu_max", v);
    if ((v = getenv("SANDBOX_LOG_LEVEL")) && *v)
        config_set_key(c, "log_level", v);
}
