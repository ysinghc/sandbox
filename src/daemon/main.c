// sandboxd: the engine daemon (§5, §10). Wires the warm pool to the network
// manager and the IPC server, and runs the engine-side broker-control socket
// that the credential broker validates session tokens against.
//
// Config precedence: CLI flags > environment > config file > built-in defaults.
// There is no YAML/std::variant config layer (see SYSTEM DESIGN.md §15.9); the
// file is a flat "key = value" list.

#include "ipc_server.h"
#include "network_manager.h"
#include "pool_manager.h"
#include "telemetry.h"
#include "vmm_manager.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    char socket_path[256];
    char broker_control_socket[256];
    char template_name[128];
    int pool_size;
    char allowed_services[1024];
    int metrics_port;  // 0 = disabled
} engine_config_t;

static void config_defaults(engine_config_t* c) {
    memset(c, 0, sizeof(*c));
    snprintf(c->socket_path, sizeof(c->socket_path),
             "/var/run/sandbox-engine/engine.sock");
    snprintf(c->broker_control_socket, sizeof(c->broker_control_socket),
             "/var/run/sandbox-engine/broker-control.sock");
    snprintf(c->template_name, sizeof(c->template_name), "python-agent");
    c->pool_size = 4;
    c->allowed_services[0] = '\0';
    c->metrics_port = 0;
}

static void set_key(engine_config_t* c, const char* key, const char* val) {
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
    } else if (strcmp(key, "allowed_services") == 0) {
        snprintf(c->allowed_services, sizeof(c->allowed_services), "%s", val);
    } else if (strcmp(key, "metrics_port") == 0) {
        c->metrics_port = atoi(val);
    } else {
        fprintf(stderr, "[sandboxd] unknown config key '%s'\n", key);
    }
}

static void config_load_file(engine_config_t* c, const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[sandboxd] config %s: %s (using defaults)\n", path,
                strerror(errno));
        return;
    }
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';' || *p == '\n' || *p == '\0') continue;
        char* eq = strchr(p, '=');
        if (!eq) continue;
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
        if (*key) set_key(c, key, val);
    }
    fclose(f);
}

static void config_apply_env(engine_config_t* c) {
    const char* v;
    if ((v = getenv("SANDBOX_ENGINE_SOCK")) && *v) set_key(c, "socket", v);
    if ((v = getenv("SANDBOX_BROKER_CONTROL")) && *v)
        set_key(c, "broker_control", v);
    if ((v = getenv("SANDBOX_TEMPLATE")) && *v) set_key(c, "template", v);
    if ((v = getenv("SANDBOX_POOL_SIZE")) && *v) set_key(c, "pool_size", v);
    if ((v = getenv("SANDBOX_ALLOWED_SERVICES")))
        set_key(c, "allowed_services", v);
    if ((v = getenv("SANDBOX_METRICS_PORT")) && *v)
        set_key(c, "metrics_port", v);
}

static void ensure_parent_dir(const char* path) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", path);
    char* slash = strrchr(tmp, '/');
    if (!slash || slash == tmp) return;
    *slash = '\0';
    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static void on_signal(int sig) {
    (void)sig;
    ipc_server_request_stop();  // async-signal-safe
}

static int start_metrics(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0 || listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void* metrics_thread(void* arg) {
    int fd = (int)(intptr_t)arg;
    telemetry_serve(fd);
    return NULL;
}

int main(int argc, char** argv) {
    engine_config_t cfg;
    config_defaults(&cfg);

    const char* config_file = NULL;
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--config") == 0 || strcmp(argv[i], "-c") == 0) &&
            i + 1 < argc) {
            config_file = argv[++i];
        }
    }
    if (!config_file) {
        // §10.2: the packaged config lives at $SANDBOX_STATE_DIR/config.
        static const char* def = "/var/lib/sandbox-engine/config/engine.conf";
        if (access(def, R_OK) == 0) config_file = def;
    }
    if (config_file) config_load_file(&cfg, config_file);
    config_apply_env(&cfg);

    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        const char* v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if ((strcmp(a, "--socket") == 0) && v) set_key(&cfg, "socket", argv[++i]);
        else if ((strcmp(a, "--broker-control") == 0) && v)
            set_key(&cfg, "broker_control", argv[++i]);
        else if ((strcmp(a, "--template") == 0) && v)
            set_key(&cfg, "template", argv[++i]);
        else if ((strcmp(a, "--pool-size") == 0) && v)
            set_key(&cfg, "pool_size", argv[++i]);
        else if ((strcmp(a, "--allowed-services") == 0) && v)
            set_key(&cfg, "allowed_services", argv[++i]);
        else if ((strcmp(a, "--metrics-port") == 0) && v)
            set_key(&cfg, "metrics_port", argv[++i]);
        else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            printf("usage: sandboxd [--config FILE] [--socket PATH] "
                   "[--broker-control PATH] [--template NAME] [--pool-size N] "
                   "[--allowed-services CSV] [--metrics-port N]\n");
            return 0;
        }
    }

    if (cfg.pool_size <= 0 || cfg.pool_size > POOL_MAX_SIZE) {
        fprintf(stderr, "[sandboxd] invalid pool_size %d\n", cfg.pool_size);
        return 1;
    }
    if (cfg.template_name[0] == '\0') {
        fprintf(stderr, "[sandboxd] no template configured\n");
        return 1;
    }

    ensure_parent_dir(cfg.socket_path);
    ensure_parent_dir(cfg.broker_control_socket);

    fprintf(stderr,
            "{\"component\":\"daemon\",\"event\":\"start\",\"template\":\"%s\","
            "\"pool_size\":%d,\"socket\":\"%s\"}\n",
            cfg.template_name, cfg.pool_size, cfg.socket_path);

    if (network_manager_init() < 0) {
        fprintf(stderr, "[sandboxd] network_manager_init failed: %s\n",
                strerror(errno));
        // Non-fatal: a restore that needs the tap will fail per-VM.
    }

    pool_set_restore_source(cfg.template_name);
    pool_manager_t pool;
    if (pool_manager_init(&pool, cfg.pool_size) < 0) {
        fprintf(stderr, "[sandboxd] pool_manager_init failed\n");
        return 1;
    }

    ipc_server_set_pool(&pool);
    ipc_server_set_template(cfg.template_name);
    ipc_server_set_allowed_services(cfg.allowed_services);
    pool_manager_set_live(&pool);
    if (ipc_server_start_broker_control(cfg.broker_control_socket) < 0) {
        fprintf(stderr, "[sandboxd] broker-control start failed\n");
        pool_manager_destroy(&pool);
        return 1;
    }

    if (cfg.metrics_port > 0) {
        int mfd = start_metrics(cfg.metrics_port);
        if (mfd >= 0) {
            pthread_t t;
            if (pthread_create(&t, NULL, metrics_thread,
                               (void*)(intptr_t)mfd) == 0) {
                pthread_detach(t);
                fprintf(stderr, "[sandboxd] metrics on 127.0.0.1:%d\n",
                        cfg.metrics_port);
            } else {
                close(mfd);
            }
        } else {
            fprintf(stderr, "[sandboxd] metrics bind :%d failed\n",
                    cfg.metrics_port);
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    ipc_server_run(cfg.socket_path);
    ipc_server_stop();
    pool_manager_set_live(NULL);
    pool_manager_destroy(&pool);
    fprintf(stderr, "{\"component\":\"daemon\",\"event\":\"stop\"}\n");
    return 0;
}
