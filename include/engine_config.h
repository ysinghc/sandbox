// SPDX-License-Identifier: GPL-2.0-only
#ifndef ENGINE_CONFIG_H
#define ENGINE_CONFIG_H

// sandboxd configuration (Phase 11; hierarchy in #4). Extracted from
// src/daemon/main.c so the parser is unit-testable. The format is a
// "key = value" list with [section] headers. Bare [name] headers are cosmetic
// (keys apply globally, exactly as before #4); [kind "name"] headers record a
// scoped overlay instead. Precedence, lowest first: built-in defaults < base
// file < <base>.d/*.conf drop-ins (byte order) < the [template "N"] overlay
// matching the effective template < environment (SANDBOX_*) < CLI flags.

#define ENGINE_CONFIG_PATH_MAX 256
#define ENGINE_CONFIG_SERVICES_MAX 1024
#define ENGINE_CONFIG_UIDS_MAX 512
#define ENGINE_CONFIG_TEMPLATE_MAX 128
#define ENGINE_CONFIG_BIND_MAX 64
#define ENGINE_CONFIG_VAL_MAX 64

// Overlay store bounds (#4). 64 scoped pairs is far past any real file; the
// 65th warns and is dropped rather than failing the boot.
#define ENGINE_CONFIG_OVERLAYS_MAX 64
#define ENGINE_CONFIG_SCOPE_MAX 16
#define ENGINE_CONFIG_SNAME_MAX 64
#define ENGINE_CONFIG_OKEY_MAX 64
#define ENGINE_CONFIG_OVAL_MAX 256

// Layers that can set a key, in precedence order. Provenance is tracked per
// key so a template overlay never beats the environment or CLI.
typedef enum {
    CONFIG_LAYER_DEFAULT = -1,
    CONFIG_LAYER_FILE = 0,
    CONFIG_LAYER_ENV = 1,
    CONFIG_LAYER_CLI = 2
} config_layer_t;

// One scoped key = value pair from a [kind "name"] section.
typedef struct {
    char scope[ENGINE_CONFIG_SCOPE_MAX];
    char name[ENGINE_CONFIG_SNAME_MAX];
    char key[ENGINE_CONFIG_OKEY_MAX];
    char value[ENGINE_CONFIG_OVAL_MAX];
} config_overlay_t;

#define ENGINE_CONFIG_NKEYS 22

typedef struct {
    char socket_path[ENGINE_CONFIG_PATH_MAX];
    char broker_control_socket[ENGINE_CONFIG_PATH_MAX];
    char template_name[ENGINE_CONFIG_TEMPLATE_MAX];
    int pool_size;
    int max_queue_depth;       // overflow depth (<= POOL_MAX_QUEUE_DEPTH)
    int pool_wait_timeout_ms;  // default Create wait when the request sends 0
    char allowed_services[ENGINE_CONFIG_SERVICES_MAX];
    char allowed_uids[ENGINE_CONFIG_UIDS_MAX];  // CSV of peer uids; empty = any
    int metrics_port;  // 0 = disabled
    char metrics_bind[ENGINE_CONFIG_BIND_MAX];
    char jail_root[ENGINE_CONFIG_PATH_MAX];      // "" = env/default
    char snapshot_root[ENGINE_CONFIG_PATH_MAX];  // "" = env/default
    int jailer_uid;
    int jailer_gid;
    int vsock_settle_ms;  // §10.9 env-inject settle fallback (ms)
    int create_workers;          // §10.8 Create worker pool size
    int max_creates_per_session; // §10.8 per-session concurrency cap
    int max_creates_per_uid;     // §10.8 per-uid concurrency cap
    int cgroup_enable;           // §10.11 per-VM cgroup enforcement (0/1)
    int cgroup_slack_mib;        // memory.max headroom over guest size
    char cgroup_cpu_max[ENGINE_CONFIG_VAL_MAX];  // cpu.max ("max" = unlimited)
    char log_level[16];          // §10.12 debug|info|warn|error
    // #4: scoped overlays and per-key provenance (config_layer_t).
    config_overlay_t overlays[ENGINE_CONFIG_OVERLAYS_MAX];
    int n_overlays;
    signed char key_prov[ENGINE_CONFIG_NKEYS];
} engine_config_t;

// Fill c with built-in defaults.
void config_defaults(engine_config_t* c);

// Apply a single key = value pair. unknown keys are logged and ignored.
// Marks the key FILE layer; use config_set_key_layer for env/CLI callers.
void config_set_key(engine_config_t* c, const char* key, const char* val);

// Apply a pair and record which layer set it (for overlay precedence).
void config_set_key_layer(engine_config_t* c, const char* key, const char* val,
                           int layer);

// Load a "key = value" file (missing file logs and leaves defaults).
// Parse a whole config body from memory (used by the file loader and by the
// config fuzzer). `text` is NUL-terminated.
void config_parse_buffer(engine_config_t* c, const char* text);

void config_load_file(engine_config_t* c, const char* path);

// Load "<base>.d/*.conf" drop-ins in byte order after the base file. A missing
// directory is fine; dotfiles, non-.conf names and non-regular files are
// skipped; an unreadable drop-in warns and the rest still load.
void config_load_conf_d(engine_config_t* c, const char* base_path);

// Apply the [template "N"] overlays matching the effective template name.
// Keys the environment or CLI set are left alone. Call once, after CLI.
void config_apply_template_overlays(engine_config_t* c);

// Look up one scoped pair (for service/tenant consumers in later issues).
// Returns the value or NULL when the triple was never recorded.
const char* config_overlay_get(const engine_config_t* c, const char* scope,
                               const char* name, const char* key);

// Overlay SANDBOX_* environment variables (below CLI, above the file).
void config_apply_env(engine_config_t* c);

#endif // ENGINE_CONFIG_H
