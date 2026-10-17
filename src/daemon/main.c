// sandboxd: the engine daemon (§5, §10). Wires the warm pool to the network
// manager and the IPC server, and runs the engine-side broker-control socket
// that the credential broker validates session tokens against.
//
// Config precedence: CLI flags > environment > config file > built-in defaults.
// There is no YAML/std::variant config layer (see SYSTEM DESIGN.md §15.9); the
// file is a flat "key = value" list.

#include "engine_config.h"
#include "cgroup.h"
#include "ipc_server.h"
#include "log.h"
#include "network_manager.h"
#include "pool_manager.h"
#include "snapshot_manager.h"
#include "telemetry.h"
#include "version.h"
#include "vmm_manager.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef SANDBOX_HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif


// Publish the resolved paths/uid/gid back into the environment so the VMM
// layer (which reads SANDBOX_JAIL_ROOT/SNAPSHOT_ROOT/JAILER_UID/GID) sees the
// config-file values, not just CLI/env overrides.
static void apply_paths_to_env(const engine_config_t* c) {
    if (c->jail_root[0]) setenv("SANDBOX_JAIL_ROOT", c->jail_root, 1);
    if (c->snapshot_root[0])
        setenv("SANDBOX_SNAPSHOT_ROOT", c->snapshot_root, 1);
    char buf[16];
    snprintf(buf, sizeof(buf), "%d", c->jailer_uid);
    setenv("SANDBOX_JAILER_UID", buf, 1);
    snprintf(buf, sizeof(buf), "%d", c->jailer_gid);
    setenv("SANDBOX_JAILER_GID", buf, 1);
    snprintf(buf, sizeof(buf), "%d", c->vsock_settle_ms);
    setenv("SANDBOX_VSOCK_SETTLE_MS", buf, 1);
    // §10.11 cgroups (consumed by vmm_manager/cgroup).
    setenv("SANDBOX_CGROUP_ENABLE", c->cgroup_enable ? "1" : "0", 1);
    snprintf(buf, sizeof(buf), "%d", c->cgroup_slack_mib);
    setenv("SANDBOX_CGROUP_SLACK_MIB", buf, 1);
    if (c->cgroup_cpu_max[0])
        setenv("SANDBOX_CGROUP_CPU_MAX", c->cgroup_cpu_max, 1);
}

static const char* effective_root(const char* cfg_val, const char* env_name,
                                  const char* fallback) {
    if (cfg_val && *cfg_val) return cfg_val;
    const char* e = getenv(env_name);
    if (e && *e) return e;
    return fallback;
}

static void notify_systemd(const char* state) {
#ifdef SANDBOX_HAVE_SYSTEMD
    sd_notify(0, state);
#else
    (void)state;
#endif
}

static void* watchdog_thread(void* arg) {
    (void)arg;
#ifdef SANDBOX_HAVE_SYSTEMD
    for (;;) {
        sd_notify(0, "WATCHDOG=1");
        sleep(10);
    }
#else
    return NULL;
#endif
}

// Phase 11: --validate-config pre-flight. Prints a report and returns 0/1.
static int validate_config(const engine_config_t* c, const char* config_file) {
    int ok = 1;
    char path[512];
    printf("sandboxd %s config validation\n", SANDBOX_VERSION);
    printf("  config file:   %s\n",
           config_file ? config_file : "<built-in defaults>");
    printf("  socket:        %s\n", c->socket_path);
    printf("  broker-control:%s\n", c->broker_control_socket);
    printf("  template:      %s\n", c->template_name);

    if (c->pool_size < 1 || c->pool_size > POOL_MAX_SIZE) {
        printf("  pool_size:     %d  FAIL (1..%d)\n", c->pool_size, POOL_MAX_SIZE);
        ok = 0;
    } else {
        printf("  pool_size:     %d  ok\n", c->pool_size);
    }
    if (c->max_queue_depth < 1 || c->max_queue_depth > POOL_MAX_QUEUE_DEPTH) {
        printf("  max_queue:     %d  FAIL (1..%d)\n", c->max_queue_depth,
               POOL_MAX_QUEUE_DEPTH);
        ok = 0;
    } else {
        printf("  max_queue:     %d  ok\n", c->max_queue_depth);
    }
    if (c->metrics_port < 0 || c->metrics_port > 65535) {
        printf("  metrics_port:  %d  FAIL (0..65535)\n", c->metrics_port);
        ok = 0;
    } else {
        printf("  metrics_port:  %d  ok\n", c->metrics_port);
    }
    if (c->jailer_uid < 0 || c->jailer_gid < 0) {
        printf("  jailer uid/gid:%d/%d  FAIL (>=0)\n", c->jailer_uid,
               c->jailer_gid);
        ok = 0;
    } else {
        printf("  jailer uid/gid:%d/%d  ok\n", c->jailer_uid, c->jailer_gid);
    }

    const char* snap_root = effective_root(c->snapshot_root,
                                           "SANDBOX_SNAPSHOT_ROOT",
                                           "/var/lib/sandbox-engine/snapshots");
    snprintf(path, sizeof(path), "%s/%s/manifest.bin", snap_root,
             c->template_name);
    if (access(path, R_OK) == 0) {
        printf("  template img:  %s  ok\n", path);
    } else {
        printf("  template img:  %s  FAIL (missing)\n", path);
        ok = 0;
    }

    const char* jail_root = effective_root(c->jail_root, "SANDBOX_JAIL_ROOT",
                                           "/var/lib/sandbox-engine/jail");
    if (access(jail_root, W_OK) == 0) {
        printf("  jail root:     %s  ok\n", jail_root);
    } else {
        printf("  jail root:     %s  (will be created)\n", jail_root);
    }

    // §10.10: hash-check the snapshot files themselves, not just the manifest.
    if (snapshot_verify(c->template_name) < 0) {
        printf("  integrity:     FAIL (snapshot hash mismatch)\n");
        ok = 0;
    } else {
        printf("  integrity:     ok (memory.snap + vmstate hashes match)\n");
    }

    printf("result: %s\n", ok ? "OK" : "FAILED");
    return ok ? 0 : 1;
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

static int start_metrics(const char* bind_addr, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (!bind_addr || !*bind_addr || strcmp(bind_addr, "*") == 0) {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, bind_addr, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }
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
    bool do_validate = false;
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
        if ((strcmp(a, "--socket") == 0) && v) config_set_key(&cfg, "socket", argv[++i]);
        else if ((strcmp(a, "--broker-control") == 0) && v)
            config_set_key(&cfg, "broker_control", argv[++i]);
        else if ((strcmp(a, "--template") == 0) && v)
            config_set_key(&cfg, "template", argv[++i]);
        else if ((strcmp(a, "--pool-size") == 0) && v)
            config_set_key(&cfg, "pool_size", argv[++i]);
        else if ((strcmp(a, "--allowed-services") == 0) && v)
            config_set_key(&cfg, "allowed_services", argv[++i]);
        else if ((strcmp(a, "--allowed-uids") == 0) && v)
            config_set_key(&cfg, "allowed_uids", argv[++i]);
        else if ((strcmp(a, "--metrics-port") == 0) && v)
            config_set_key(&cfg, "metrics_port", argv[++i]);
        else if ((strcmp(a, "--metrics-bind") == 0) && v)
            config_set_key(&cfg, "metrics_bind", argv[++i]);
        else if ((strcmp(a, "--jail-root") == 0) && v)
            config_set_key(&cfg, "jail_root", argv[++i]);
        else if ((strcmp(a, "--snapshot-root") == 0) && v)
            config_set_key(&cfg, "snapshot_root", argv[++i]);
        else if ((strcmp(a, "--log-level") == 0) && v)
            config_set_key(&cfg, "log_level", argv[++i]);
        else if (strcmp(a, "--validate-config") == 0) do_validate = true;
        else if (strcmp(a, "--version") == 0) {
            printf("sandboxd %s\n", SANDBOX_VERSION);
            return 0;
        }
        else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            printf("usage: sandboxd [--config FILE] [--socket PATH] "
                   "[--broker-control PATH] [--template NAME] [--pool-size N] "
                   "[--allowed-services CSV] [--allowed-uids CSV] "
                   "[--metrics-port N] [--metrics-bind ADDR] "
                   "[--jail-root DIR] [--snapshot-root DIR] "
                   "[--log-level LEVEL] "
                   "[--validate-config] [--version]\n");
            return 0;
        }
    }

    // §10.12: apply the resolved level before anything logs.
    {
        int lvl = log_parse_level(cfg.log_level);
        if (lvl >= 0) log_set_level(lvl);
        else log_init();
    }

    apply_paths_to_env(&cfg);
    if (do_validate) return validate_config(&cfg, config_file);

    if (cfg.pool_size <= 0 || cfg.pool_size > POOL_MAX_SIZE) {
        fprintf(stderr, "[sandboxd] invalid pool_size %d\n", cfg.pool_size);
        return 1;
    }
    if (cfg.template_name[0] == '\0') {
        fprintf(stderr, "[sandboxd] no template configured\n");
        return 1;
    }
    if (cfg.max_queue_depth < 1) cfg.max_queue_depth = 1;
    if (cfg.max_queue_depth > POOL_MAX_QUEUE_DEPTH)
        cfg.max_queue_depth = POOL_MAX_QUEUE_DEPTH;


    ensure_parent_dir(cfg.socket_path);
    ensure_parent_dir(cfg.broker_control_socket);

    LOGF(LOG_INFO, "daemon", "start",
         "\"template\":\"%s\",\"pool_size\":%d,\"socket\":\"%s\"",
         cfg.template_name, cfg.pool_size, cfg.socket_path);

    if (network_manager_init() < 0) {
        fprintf(stderr, "[sandboxd] network_manager_init failed: %s\n",
                strerror(errno));
        // Non-fatal: a restore that needs the tap will fail per-VM.
    }

    // §10.11: set up the per-VM cgroup hierarchy (best-effort).
    cgroup_init();

    // Phase 10.4: prevent the daemon (and every forked jailer) from ever
    // gaining privileges via execve of setuid/file-cap binaries. Capabilities
    // the daemon already holds (needed for mknod/chroot/tap/cgroup) are
    // unaffected; Firecracker's CAP_SYS_PTRACE is delivered via ambient caps.
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "[sandboxd] PR_SET_NO_NEW_PRIVS failed: %s\n",
                strerror(errno));
    }

    pool_set_restore_source(cfg.template_name);
    pool_manager_t pool;
    if (pool_manager_init(&pool, cfg.pool_size) < 0) {
        fprintf(stderr, "[sandboxd] pool_manager_init failed\n");
        return 1;
    }
    pool_manager_set_max_queue_depth(&pool, cfg.max_queue_depth);

    ipc_server_set_pool(&pool);
    ipc_server_set_template(cfg.template_name);
    ipc_server_set_allowed_services(cfg.allowed_services);
    ipc_server_set_allowed_uids(cfg.allowed_uids);
    ipc_server_set_default_pool_wait_ms((uint32_t)cfg.pool_wait_timeout_ms);
    ipc_server_set_create_limits(cfg.create_workers, cfg.max_creates_per_session,
                                 cfg.max_creates_per_uid);
    pool_manager_set_live(&pool);
    if (ipc_server_start_broker_control(cfg.broker_control_socket) < 0) {
        fprintf(stderr, "[sandboxd] broker-control start failed\n");
        pool_manager_destroy(&pool);
        return 1;
    }

    // §10.13: metrics/health/ready endpoint. On by default (port 9180, bind
    // 0.0.0.0); an empty metrics_bind disables it.
    if (cfg.metrics_port > 0 && cfg.metrics_bind[0]) {
        int mfd = start_metrics(cfg.metrics_bind, cfg.metrics_port);
        if (mfd >= 0) {
            pthread_t t;
            if (pthread_create(&t, NULL, metrics_thread,
                               (void*)(intptr_t)mfd) == 0) {
                pthread_detach(t);
                LOGF(LOG_INFO, "daemon", "metrics",
                     "\"bind\":\"%s\",\"port\":%d,"
                     "\"endpoints\":[\"/metrics\",\"/health\",\"/ready\"]",
                     cfg.metrics_bind, cfg.metrics_port);
            } else {
                close(mfd);
            }
        } else {
            fprintf(stderr, "[sandboxd] metrics bind %s:%d failed\n",
                    cfg.metrics_bind, cfg.metrics_port);
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    // Phase 11: tell systemd (Type=notify) we are ready to accept connections.
    notify_systemd("READY=1");
    if (getenv("NOTIFY_SOCKET")) {
        pthread_t wt;
        if (pthread_create(&wt, NULL, watchdog_thread, NULL) == 0)
            pthread_detach(wt);
    }

    ipc_server_run(cfg.socket_path);
    notify_systemd("STOPPING=1");
    ipc_server_stop();
    pool_manager_set_live(NULL);
    pool_manager_destroy(&pool);
    LOGF(LOG_INFO, "daemon", "stop", "");
    return 0;
}
