// SPDX-License-Identifier: GPL-2.0-only
// sandbox-api: the control-plane HTTP API (#27). See docs/API.md.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#include "http_api.h"
#include "log.h"
#include "sha256.h"

static void usage(void) {
    printf("usage:\n"
           "  sandbox-api [--socket PATH] [--listen HOST:PORT] [--tokens FILE] [options]\n"
           "  sandbox-api new-token NAME     print a fresh bearer token and its tokens-file entry\n"
           "\n"
           "listeners (at least one):\n"
           "  --socket PATH         Unix socket; callers are identified by uid\n"
           "                        (default /var/run/sandbox-engine/api.sock; --no-socket to disable)\n"
           "  --listen HOST:PORT    TCP; bearer tokens required, so --tokens too\n"
           "  --allow-public-bind   permit a non-loopback HOST (put TLS in front of it)\n"
           "  --tokens FILE         principals: [name] token_sha256 / max_sessions / templates\n"
           "\n"
           "engine and defaults:\n"
           "  --engine-socket PATH  the engine's IPC socket (default /var/run/sandbox-engine/engine.sock)\n"
           "  --template NAME       default template (python-agent)\n"
           "  --memory MIB  --vcpus N  --ttl SECONDS     defaults for new sessions (256, 1, engine default)\n"
           "  --pool-wait MS        how long creating a VM may wait for a warm one (daemon default)\n"
           "  --max-running N       sandboxes held at once (64)\n"
           "  --max-sessions N      sessions per principal unless its entry says otherwise (16)\n"
           "  --idle SECONDS        reclaim a VM idle this long; the workspace stays (300)\n"
           "\n"
           "Every option also reads SANDBOX_API_<NAME> (e.g. SANDBOX_API_LISTEN).\n");
}

static const char* envs(const char* name) {
    const char* v = getenv(name);
    return (v && *v) ? v : NULL;
}

static int new_token(const char* name) {
    uint8_t raw[32];
    if (getrandom(raw, sizeof(raw), 0) != (ssize_t)sizeof(raw)) { perror("getrandom"); return 1; }
    char tok[65], hash[65];
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { tok[i * 2] = H[raw[i] >> 4]; tok[i * 2 + 1] = H[raw[i] & 15]; }
    tok[64] = '\0';
    uint8_t d[32];
    sha256(tok, 64, d);
    sha256_hex(d, hash);
    printf("token (give this to the client; it is not stored anywhere):\n  %s\n\n", tok);
    printf("add to the tokens file:\n[%s]\ntoken_sha256 = %s\n", name, hash);
    return 0;
}

int main(int argc, char** argv) {
    log_init();
    if (argc >= 2 && !strcmp(argv[1], "new-token")) {
        if (argc != 3) { usage(); return 2; }
        return new_token(argv[2]);
    }
    api_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    const char* engine_socket = envs("SANDBOX_API_ENGINE_SOCKET");
    if (!engine_socket) engine_socket = "/var/run/sandbox-engine/engine.sock";
    const char* sock = envs("SANDBOX_API_SOCKET");
    if (!sock) sock = "/var/run/sandbox-engine/api.sock";
    const char* listen_s = envs("SANDBOX_API_LISTEN");
    cfg.tokens_path = envs("SANDBOX_API_TOKENS");
    cfg.default_template = envs("SANDBOX_API_TEMPLATE");
    if (envs("SANDBOX_API_MEMORY")) cfg.default_memory_mib = strtoull(envs("SANDBOX_API_MEMORY"), NULL, 10);
    if (envs("SANDBOX_API_VCPUS")) cfg.default_vcpus = (uint32_t)strtoul(envs("SANDBOX_API_VCPUS"), NULL, 10);
    if (envs("SANDBOX_API_TTL")) cfg.default_ttl_seconds = (uint32_t)strtoul(envs("SANDBOX_API_TTL"), NULL, 10);
    if (envs("SANDBOX_API_POOL_WAIT")) cfg.pool_wait_ms = (uint32_t)strtoul(envs("SANDBOX_API_POOL_WAIT"), NULL, 10);
    if (envs("SANDBOX_API_MAX_RUNNING")) cfg.max_running = (unsigned)strtoul(envs("SANDBOX_API_MAX_RUNNING"), NULL, 10);
    if (envs("SANDBOX_API_MAX_SESSIONS")) cfg.max_sessions_default = (unsigned)strtoul(envs("SANDBOX_API_MAX_SESSIONS"), NULL, 10);
    if (envs("SANDBOX_API_IDLE")) cfg.idle_vm_seconds = (unsigned)strtoul(envs("SANDBOX_API_IDLE"), NULL, 10);
    int no_socket = 0;

    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        const char* v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--socket") && v) sock = argv[++i];
        else if (!strcmp(a, "--no-socket")) no_socket = 1;
        else if (!strcmp(a, "--listen") && v) listen_s = argv[++i];
        else if (!strcmp(a, "--allow-public-bind")) cfg.allow_public_bind = 1;
        else if (!strcmp(a, "--tokens") && v) cfg.tokens_path = argv[++i];
        else if (!strcmp(a, "--engine-socket") && v) engine_socket = argv[++i];
        else if (!strcmp(a, "--template") && v) cfg.default_template = argv[++i];
        else if (!strcmp(a, "--memory") && v) cfg.default_memory_mib = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--vcpus") && v) cfg.default_vcpus = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--ttl") && v) cfg.default_ttl_seconds = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--pool-wait") && v) cfg.pool_wait_ms = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--max-running") && v) cfg.max_running = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--max-sessions") && v) cfg.max_sessions_default = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--idle") && v) cfg.idle_vm_seconds = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(a, "--help") || !strcmp(a, "-h")) { usage(); return 0; }
        else { fprintf(stderr, "sandbox-api: unknown argument %s (try --help)\n", a); return 2; }
    }
    cfg.unix_path = no_socket ? NULL : sock;

    char host[128];
    if (listen_s) {
        const char* colon = strrchr(listen_s, ':');
        if (!colon || colon == listen_s || (size_t)(colon - listen_s) >= sizeof(host) || atoi(colon + 1) <= 0 || atoi(colon + 1) > 65535) {
            fprintf(stderr, "sandbox-api: --listen wants HOST:PORT (e.g. 127.0.0.1:8088)\n");
            return 2;
        }
        memcpy(host, listen_s, (size_t)(colon - listen_s));
        host[colon - listen_s] = '\0';
        if (host[0] == '[') {  // [::1]:8088
            size_t n = strlen(host);
            if (host[n - 1] != ']') { fprintf(stderr, "sandbox-api: bad IPv6 address\n"); return 2; }
            host[n - 1] = '\0';
            memmove(host, host + 1, n - 1);
        }
        cfg.tcp_host = host;
        cfg.tcp_port = atoi(colon + 1);
    }

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    signal(SIGPIPE, SIG_IGN);

    sandbox_error_t rc = sandbox_init(engine_socket);
    if (rc != SANDBOX_OK) {
        fprintf(stderr, "sandbox-api: cannot reach the engine at %s: %s\n", engine_socket, sandbox_error_string(rc));
        return 1;
    }
    api_server_t* srv = api_server_start(&cfg);
    if (!srv) {
        sandbox_cleanup();
        return 1;
    }
    int sig = 0;
    sigwait(&set, &sig);
    LOGF(LOG_INFO, "http_api", "stopping", "\"signal\":%d", sig);
    api_server_stop(srv);
    sandbox_cleanup();
    return 0;
}
