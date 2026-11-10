// SPDX-License-Identifier: GPL-2.0-only
// sandboxd configuration parser (Phase 11; hierarchy in #4). "key = value"
// with [section] headers: bare [name] headers are cosmetic (keys apply
// globally), [kind "name"] headers record a scoped overlay. See
// engine_config.h.

#include "engine_config.h"

#include "pool_manager.h"  // POOL_MAX_QUEUE_DEPTH default

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// Canonical key ids, in config_set_key order. Aliases share an id.
enum {
    KEY_SOCKET = 0,
    KEY_BROKER_CONTROL,
    KEY_TEMPLATE,
    KEY_POOL_SIZE,
    KEY_MAX_QUEUE_DEPTH,
    KEY_POOL_WAIT_MS,
    KEY_ALLOWED_SERVICES,
    KEY_ALLOWED_UIDS,
    KEY_METRICS_BIND,
    KEY_METRICS_PORT,
    KEY_JAIL_ROOT,
    KEY_SNAPSHOT_ROOT,
    KEY_JAILER_UID,
    KEY_JAILER_GID,
    KEY_VSOCK_SETTLE_MS,
    KEY_CREATE_WORKERS,
    KEY_MAX_CREATES_PER_SESSION,
    KEY_MAX_CREATES_PER_UID,
    KEY_CGROUP_ENABLE,
    KEY_CGROUP_SLACK_MIB,
    KEY_CGROUP_CPU_MAX,
    KEY_LOG_LEVEL,
    KEY_PRIVILEGED_SOCKET
};

// Map a key or alias to its canonical id, or -1 when unknown.
static int config_key_id(const char* key) {
    if (strcmp(key, "socket") == 0 || strcmp(key, "socket_path") == 0 ||
        strcmp(key, "engine_socket") == 0)
        return KEY_SOCKET;
    if (strcmp(key, "broker_control_socket") == 0 ||
        strcmp(key, "broker_control") == 0)
        return KEY_BROKER_CONTROL;
    if (strcmp(key, "template") == 0 || strcmp(key, "template_name") == 0)
        return KEY_TEMPLATE;
    if (strcmp(key, "pool_size") == 0 || strcmp(key, "target_size") == 0)
        return KEY_POOL_SIZE;
    if (strcmp(key, "max_queue_depth") == 0) return KEY_MAX_QUEUE_DEPTH;
    if (strcmp(key, "pool_wait_timeout_ms") == 0) return KEY_POOL_WAIT_MS;
    if (strcmp(key, "allowed_services") == 0) return KEY_ALLOWED_SERVICES;
    if (strcmp(key, "allowed_uids") == 0) return KEY_ALLOWED_UIDS;
    if (strcmp(key, "metrics_bind") == 0) return KEY_METRICS_BIND;
    if (strcmp(key, "metrics_port") == 0) return KEY_METRICS_PORT;
    if (strcmp(key, "jail_root") == 0) return KEY_JAIL_ROOT;
    if (strcmp(key, "snapshot_root") == 0) return KEY_SNAPSHOT_ROOT;
    if (strcmp(key, "jailer_uid") == 0) return KEY_JAILER_UID;
    if (strcmp(key, "jailer_gid") == 0) return KEY_JAILER_GID;
    if (strcmp(key, "vsock_settle_ms") == 0) return KEY_VSOCK_SETTLE_MS;
    if (strcmp(key, "create_workers") == 0) return KEY_CREATE_WORKERS;
    if (strcmp(key, "max_creates_per_session") == 0)
        return KEY_MAX_CREATES_PER_SESSION;
    if (strcmp(key, "max_creates_per_uid") == 0)
        return KEY_MAX_CREATES_PER_UID;
    if (strcmp(key, "cgroup_enable") == 0) return KEY_CGROUP_ENABLE;
    if (strcmp(key, "cgroup_slack_mib") == 0) return KEY_CGROUP_SLACK_MIB;
    if (strcmp(key, "cgroup_cpu_max") == 0) return KEY_CGROUP_CPU_MAX;
    if (strcmp(key, "log_level") == 0) return KEY_LOG_LEVEL;
    if (strcmp(key, "privileged_socket") == 0) return KEY_PRIVILEGED_SOCKET;
    return -1;
}

void config_defaults(engine_config_t* c) {
    memset(c, 0, sizeof(*c));
    memset(c->key_prov, CONFIG_LAYER_DEFAULT, sizeof(c->key_prov));
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
    c->privileged_socket[0] = '\0';  // in-process until configured (#9)
}

void config_set_key_layer(engine_config_t* c, const char* key, const char* val,
                            int layer) {
    int id = config_key_id(key);
    if (id < 0) {
        fprintf(stderr, "[sandboxd] unknown config key '%s'\n", key);
        return;
    }
    switch (id) {
    case KEY_SOCKET:
        snprintf(c->socket_path, sizeof(c->socket_path), "%s", val);
        break;
    case KEY_BROKER_CONTROL:
        snprintf(c->broker_control_socket, sizeof(c->broker_control_socket),
                 "%s", val);
        break;
    case KEY_TEMPLATE:
        snprintf(c->template_name, sizeof(c->template_name), "%s", val);
        break;
    case KEY_POOL_SIZE:
        c->pool_size = atoi(val);
        break;
    case KEY_MAX_QUEUE_DEPTH:
        c->max_queue_depth = atoi(val);
        break;
    case KEY_POOL_WAIT_MS:
        c->pool_wait_timeout_ms = atoi(val);
        break;
    case KEY_ALLOWED_SERVICES:
        snprintf(c->allowed_services, sizeof(c->allowed_services), "%s", val);
        break;
    case KEY_ALLOWED_UIDS:
        snprintf(c->allowed_uids, sizeof(c->allowed_uids), "%s", val);
        break;
    case KEY_METRICS_BIND:
        snprintf(c->metrics_bind, sizeof(c->metrics_bind), "%s", val);
        break;
    case KEY_METRICS_PORT:
        c->metrics_port = atoi(val);
        break;
    case KEY_JAIL_ROOT:
        snprintf(c->jail_root, sizeof(c->jail_root), "%s", val);
        break;
    case KEY_SNAPSHOT_ROOT:
        snprintf(c->snapshot_root, sizeof(c->snapshot_root), "%s", val);
        break;
    case KEY_JAILER_UID:
        c->jailer_uid = atoi(val);
        break;
    case KEY_JAILER_GID:
        c->jailer_gid = atoi(val);
        break;
    case KEY_VSOCK_SETTLE_MS:
        c->vsock_settle_ms = atoi(val);
        break;
    case KEY_CREATE_WORKERS:
        c->create_workers = atoi(val);
        break;
    case KEY_MAX_CREATES_PER_SESSION:
        c->max_creates_per_session = atoi(val);
        break;
    case KEY_MAX_CREATES_PER_UID:
        c->max_creates_per_uid = atoi(val);
        break;
    case KEY_CGROUP_ENABLE:
        c->cgroup_enable = atoi(val);
        break;
    case KEY_CGROUP_SLACK_MIB:
        c->cgroup_slack_mib = atoi(val);
        break;
    case KEY_CGROUP_CPU_MAX:
        snprintf(c->cgroup_cpu_max, sizeof(c->cgroup_cpu_max), "%s", val);
        break;
    case KEY_LOG_LEVEL:
        snprintf(c->log_level, sizeof(c->log_level), "%s", val);
        break;
    case KEY_PRIVILEGED_SOCKET:
        snprintf(c->privileged_socket, sizeof(c->privileged_socket), "%s",
                 val);
        break;
    }
    c->key_prov[id] = (signed char)layer;
}

void config_set_key(engine_config_t* c, const char* key, const char* val) {
    config_set_key_layer(c, key, val, CONFIG_LAYER_FILE);
}

// Active section while parsing one body. Bare [name] headers (and any
// malformed header) reset to global, so pre-#4 files read identically.
typedef struct {
    char scope[ENGINE_CONFIG_SCOPE_MAX];
    char name[ENGINE_CONFIG_SNAME_MAX];
    int scoped;  // 0 = global keys apply; 1 = record overlays
} section_t;

static int is_sectok(int ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
           (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.';
}

// Parse "[kind \"name\"]" after the '['. Returns 1 and fills sec on success;
// anything else resets sec to global. A bare header ([daemon]) is silent for
// flat-file compatibility; a line that attempts quoting warns.
static int parse_section_header(const char* p, section_t* sec) {
    sec->scoped = 0;
    sec->scope[0] = '\0';
    sec->name[0] = '\0';
    p++;  // consume '['
    while (*p == ' ' || *p == '\t') p++;
    const char* kend = p;
    while (is_sectok((unsigned char)*kend)) kend++;
    size_t klen = (size_t)(kend - p);
    const char* q = kend;
    while (*q == ' ' || *q == '\t') q++;
    if (*q != '"') return 0;  // bare [name]: cosmetic, as before #4
    q++;
    const char* nend = strchr(q, '"');
    if (!nend) {
        fprintf(stderr, "[sandboxd] bad section header (unterminated name)\n");
        return 0;
    }
    size_t nlen = (size_t)(nend - q);
    const char* r = nend + 1;
    while (*r == ' ' || *r == '\t') r++;
    if (*r != ']') {
        fprintf(stderr, "[sandboxd] bad section header (expected ])\n");
        return 0;
    }
    r++;
    while (*r == ' ' || *r == '\t' || *r == '\n' || *r == '\r') r++;
    if (*r != '\0') {
        fprintf(stderr, "[sandboxd] bad section header (trailing text)\n");
        return 0;
    }
    if (klen == 0 || klen >= sizeof(sec->scope) || nlen == 0 ||
        nlen >= sizeof(sec->name)) {
        fprintf(stderr, "[sandboxd] bad section header (empty or too long)\n");
        return 0;
    }
    for (size_t i = 0; i < nlen; i++) {
        if (!is_sectok((unsigned char)q[i])) {
            fprintf(stderr, "[sandboxd] bad section header (bad name chars)\n");
            return 0;
        }
    }
    memcpy(sec->scope, p, klen);
    sec->scope[klen] = '\0';
    memcpy(sec->name, q, nlen);
    sec->name[nlen] = '\0';
    sec->scoped = 1;
    return 1;
}

// Record one scoped pair, replacing an older triple (later files win).
static void overlay_upsert(engine_config_t* c, const section_t* sec,
                           const char* key, const char* val) {
    for (int i = 0; i < c->n_overlays; i++) {
        config_overlay_t* o = &c->overlays[i];
        if (strcmp(o->scope, sec->scope) == 0 &&
            strcmp(o->name, sec->name) == 0 && strcmp(o->key, key) == 0) {
            snprintf(o->value, sizeof(o->value), "%s", val);
            return;
        }
    }
    if (c->n_overlays >= ENGINE_CONFIG_OVERLAYS_MAX) {
        fprintf(stderr, "[sandboxd] overlay store full, dropping %s.%s.%s\n",
                sec->scope, sec->name, key);
        return;
    }
    config_overlay_t* o = &c->overlays[c->n_overlays++];
    snprintf(o->scope, sizeof(o->scope), "%s", sec->scope);
    snprintf(o->name, sizeof(o->name), "%s", sec->name);
    snprintf(o->key, sizeof(o->key), "%s", key);
    snprintf(o->value, sizeof(o->value), "%s", val);
}

// Trim + classify one already-NUL-terminated line and apply it. Shared by the
// file loader and config_parse_buffer (so the parser is fuzzable in memory).
static void config_parse_line(engine_config_t* c, char* line, section_t* sec) {
    char* p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#' || *p == ';' || *p == '\n' || *p == '\0') return;  // comments
    if (*p == '[') {
        parse_section_header(p, sec);
        return;
    }
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
    if (!*key) return;
    if (sec->scoped) {
        overlay_upsert(c, sec, key, val);
        return;
    }
    config_set_key(c, key, val);
}

void config_parse_buffer(engine_config_t* c, const char* text) {
    if (!c || !text) return;
    section_t sec;
    memset(&sec, 0, sizeof(sec));
    char line[2048];
    const char* p = text;
    while (*p) {
        size_t i = 0;
        while (*p && *p != '\n' && i + 1 < sizeof(line)) line[i++] = *p++;
        if (*p == '\n') p++;
        line[i] = '\0';
        config_parse_line(c, line, &sec);
    }
}

static void config_parse_stream(engine_config_t* c, FILE* f) {
    section_t sec;
    memset(&sec, 0, sizeof(sec));
    char line[2048];
    while (fgets(line, sizeof(line), f)) config_parse_line(c, line, &sec);
}

void config_load_file(engine_config_t* c, const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[sandboxd] config %s: %s (using defaults)\n", path,
                strerror(errno));
        return;
    }
    config_parse_stream(c, f);
    fclose(f);
}

static int cmp_strptr(const void* a, const void* b) {
    return strcmp(*(const char* const*)a, *(const char* const*)b);
}

void config_load_conf_d(engine_config_t* c, const char* base_path) {
    if (!c || !base_path || !*base_path) return;
    char dir[1024];
    if (snprintf(dir, sizeof(dir), "%s.d", base_path) >= (int)sizeof(dir)) {
        fprintf(stderr, "[sandboxd] config dir path too long, skipping\n");
        return;
    }
    DIR* d = opendir(dir);
    if (!d) return;  // no drop-ins: the common case
    // Collect *.conf regular files, then load in byte order.
    size_t cap = 16, n = 0;
    char** names = malloc(cap * sizeof(*names));
    if (!names) {
        closedir(d);
        return;
    }
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        const char* name = e->d_name;
        if (name[0] == '.') continue;
        size_t len = strlen(name);
        if (len < 6 || strcmp(name + len - 5, ".conf") != 0) continue;
        if (n == cap) {
            cap *= 2;
            char** grown = realloc(names, cap * sizeof(*names));
            if (!grown) break;
            names = grown;
        }
        names[n] = malloc(len + 1);
        if (!names[n]) break;
        memcpy(names[n], name, len + 1);
        n++;
    }
    closedir(d);
    qsort(names, n, sizeof(*names), cmp_strptr);
    for (size_t i = 0; i < n; i++) {
        char path[2048];
        if (snprintf(path, sizeof(path), "%s/%s", dir, names[i]) >=
            (int)sizeof(path)) {
            fprintf(stderr, "[sandboxd] drop-in path too long, skipping\n");
            free(names[i]);
            continue;
        }
        struct stat st;
        if (stat(path, &st) != 0) {
            fprintf(stderr, "[sandboxd] drop-in %s: %s (skipping)\n", path,
                    strerror(errno));
            free(names[i]);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            free(names[i]);
            continue;  // dirs, fifos, sockets: never parse these
        }
        FILE* f = fopen(path, "r");
        if (!f) {
            fprintf(stderr, "[sandboxd] drop-in %s: %s (skipping)\n", path,
                    strerror(errno));
            free(names[i]);
            continue;
        }
        config_parse_stream(c, f);
        fclose(f);
        free(names[i]);
    }
    free(names);
}

const char* config_overlay_get(const engine_config_t* c, const char* scope,
                               const char* name, const char* key) {
    if (!c || !scope || !name || !key) return NULL;
    for (int i = c->n_overlays - 1; i >= 0; i--) {
        const config_overlay_t* o = &c->overlays[i];
        if (strcmp(o->scope, scope) == 0 && strcmp(o->name, name) == 0 &&
            strcmp(o->key, key) == 0)
            return o->value;
    }
    return NULL;
}

void config_apply_template_overlays(engine_config_t* c) {
    if (!c || c->template_name[0] == '\0') return;
    for (int i = 0; i < c->n_overlays; i++) {
        const config_overlay_t* o = &c->overlays[i];
        if (strcmp(o->scope, "template") != 0 ||
            strcmp(o->name, c->template_name) != 0)
            continue;
        int id = config_key_id(o->key);
        if (id < 0) {
            fprintf(stderr, "[sandboxd] unknown overlay key '%s' (ignored)\n",
                    o->key);
            continue;
        }
        if (c->key_prov[id] >= CONFIG_LAYER_ENV) continue;  // env/CLI win
        config_set_key_layer(c, o->key, o->value, CONFIG_LAYER_FILE);
    }
}

void config_apply_env(engine_config_t* c) {
    const char* v;
    // Every branch marks CONFIG_LAYER_ENV so template overlays yield to it.
    if ((v = getenv("SANDBOX_ENGINE_SOCK")) && *v)
        config_set_key_layer(c, "socket", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_BROKER_CONTROL")) && *v)
        config_set_key_layer(c, "broker_control", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_TEMPLATE")) && *v)
        config_set_key_layer(c, "template", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_POOL_SIZE")) && *v)
        config_set_key_layer(c, "pool_size", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_ALLOWED_SERVICES")))
        config_set_key_layer(c, "allowed_services", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_ALLOWED_UIDS")))
        config_set_key_layer(c, "allowed_uids", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_METRICS_PORT")) && *v)
        config_set_key_layer(c, "metrics_port", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_METRICS_BIND")) && *v)
        config_set_key_layer(c, "metrics_bind", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_MAX_QUEUE_DEPTH")) && *v)
        config_set_key_layer(c, "max_queue_depth", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_POOL_WAIT_MS")) && *v)
        config_set_key_layer(c, "pool_wait_timeout_ms", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_JAIL_ROOT")) && *v)
        config_set_key_layer(c, "jail_root", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_SNAPSHOT_ROOT")) && *v)
        config_set_key_layer(c, "snapshot_root", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_JAILER_UID")) && *v)
        config_set_key_layer(c, "jailer_uid", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_JAILER_GID")) && *v)
        config_set_key_layer(c, "jailer_gid", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_VSOCK_SETTLE_MS")) && *v)
        config_set_key_layer(c, "vsock_settle_ms", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_CREATE_WORKERS")) && *v)
        config_set_key_layer(c, "create_workers", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_MAX_CREATES_PER_SESSION")) && *v)
        config_set_key_layer(c, "max_creates_per_session", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_MAX_CREATES_PER_UID")) && *v)
        config_set_key_layer(c, "max_creates_per_uid", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_CGROUP_ENABLE")) && *v)
        config_set_key_layer(c, "cgroup_enable", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_CGROUP_SLACK_MIB")) && *v)
        config_set_key_layer(c, "cgroup_slack_mib", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_CGROUP_CPU_MAX")) && *v)
        config_set_key_layer(c, "cgroup_cpu_max", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_LOG_LEVEL")) && *v)
        config_set_key_layer(c, "log_level", v, CONFIG_LAYER_ENV);
    if ((v = getenv("SANDBOX_PRIVILEGED_SOCKET")) && *v)
        config_set_key_layer(c, "privileged_socket", v, CONFIG_LAYER_ENV);
}
