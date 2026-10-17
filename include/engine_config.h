#ifndef ENGINE_CONFIG_H
#define ENGINE_CONFIG_H

// sandboxd configuration (Phase 11). Extracted from src/daemon/main.c so the
// parser is unit-testable. The format is a flat "key = value" list; [section]
// headers are accepted and ignored (keys are matched by name). Precedence:
// CLI flags > environment (SANDBOX_*) > config file > built-in defaults.

#define ENGINE_CONFIG_PATH_MAX 256
#define ENGINE_CONFIG_SERVICES_MAX 1024
#define ENGINE_CONFIG_UIDS_MAX 512
#define ENGINE_CONFIG_TEMPLATE_MAX 128
#define ENGINE_CONFIG_BIND_MAX 64

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
} engine_config_t;

// Fill c with built-in defaults.
void config_defaults(engine_config_t* c);

// Apply a single key = value pair. unknown keys are logged and ignored.
void config_set_key(engine_config_t* c, const char* key, const char* val);

// Load a "key = value" file (missing file logs and leaves defaults).
void config_load_file(engine_config_t* c, const char* path);

// Overlay SANDBOX_* environment variables (below CLI, above the file).
void config_apply_env(engine_config_t* c);

#endif // ENGINE_CONFIG_H
