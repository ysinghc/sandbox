// SPDX-License-Identifier: GPL-2.0-only
// Phase 8 integration test: daemon-side IPC server + client API + engine-side
// broker-control token authority, over the real warm pool (REQUIRES the "e2e"
// template fixture and root). SKIPs where root/KVM/template are unavailable.

#include "broker.h"
#include "guest_rpc.h"
#include "ipc_server.h"
#include "lifecycle.h"
#include "libsandbox.h"
#include "pool_manager.h"
#include "telemetry.h"
#include "vmm_manager.h"

#include <pthread.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// #24: collect streamed exec stdout for the RPC checks below.
struct rpc_cap { char* b; size_t* n; size_t cap; };
static void rpc_on_chunk(int is_stderr, const uint8_t* d, size_t n, void* ud) {
    struct rpc_cap* c = ud;
    if (is_stderr || *c->n + n >= c->cap) return;
    memcpy(c->b + *c->n, d, n);
    *c->n += n;
    c->b[*c->n] = '\0';
}

static int g_fail = 0;
#define CHECK(cond, msg)                              \
    do {                                              \
        if (cond) {                                   \
            fprintf(stderr, "[test] %-28s PASS\n", msg); \
        } else {                                      \
            fprintf(stderr, "[test] %-28s FAIL\n", msg); \
            g_fail++;                                 \
        }                                             \
    } while (0)

// Read the whole serial log. It grows with SANDBOX-TICK, and a marker beyond a
// fixed window is indistinguishable from a missing one — a 64 KiB cap turned a
// real value into "missing marker" once. Bounded so a runaway log cannot eat the
// test host.
#define SERIAL_MAX (8u << 20)
static char* serial_text(vm_handle_t* vm, size_t* out_len) {
    if (!vm || !vm->jail_root[0]) return NULL;
    char path[PATH_MAX + 16];
    snprintf(path, sizeof(path), "%s/serial.log", vm->jail_root);
    FILE* f = fopen(path, "r");
    if (!f) return NULL;
    size_t cap = 1 << 16, n = 0;
    char* b = malloc(cap);
    if (!b) { fclose(f); return NULL; }
    for (;;) {
        if (n + 1 >= cap) {
            if (cap >= SERIAL_MAX) break;
            size_t ncap = cap * 2;
            char* nb = realloc(b, ncap);
            if (!nb) break;
            b = nb;
            cap = ncap;
        }
        size_t r = fread(b + n, 1, cap - 1 - n, f);
        n += r;
        if (r == 0) break;
    }
    fclose(f);
    b[n] = '\0';
    if (out_len) *out_len = n;
    return b;
}

// Scan a restored VM's serial log for a marker (guest-side observability).
static int serial_has(vm_handle_t* vm, const char* needle) {
    char* b = serial_text(vm, NULL);
    if (!b) return 0;
    int hit = strstr(b, needle) != NULL;
    free(b);
    return hit;
}

// Print the (bounded) serial log so the CI log shows the guest's own account of
// a failed guest-side assertion.
static void dump_serial(vm_handle_t* vm, const char* why) {
    size_t n = 0;
    char* b = serial_text(vm, &n);
    if (!b) {
        fprintf(stderr, "--- serial.log for %p unavailable ---\n", (void*)vm);
        return;
    }
    fprintf(stderr, "--- serial.log [%s] (%zu bytes) ---\n", why, n);
    if (n <= (128u << 10)) {
        fwrite(b, 1, n, stderr);
    } else {
        // Head and tail: the boot/ready sequence is at the start, the assertion
        // failure is at the end.
        fwrite(b, 1, 48u << 10, stderr);
        fprintf(stderr, "\n--- [%zu bytes elided] ---\n", n - (96u << 10));
        fwrite(b + (n - (48u << 10)), 1, 48u << 10, stderr);
    }
    fprintf(stderr, "--- end ---\n");
    free(b);
}

// Extract the integer after `marker` from the serial log (-1 if absent).
static long long serial_int(vm_handle_t* vm, const char* marker) {
    char* b = serial_text(vm, NULL);
    if (!b) return -1;
    const char* p = strstr(b, marker);
    long long v = p ? strtoll(p + strlen(marker), NULL, 10) : -1;
    free(b);
    return v;
}

// #23: the guest's workspace probe. The agent appends one checksum line per env
// injection to /workspace/.sandbox-probe and reports the file's shape, so the
// host can see what the *guest* sees. The last line in the serial log describes
// the state after the most recent injection.
typedef struct {
    int lines;
    char first[9];
    char last[9];
} ws_probe_t;

static int serial_probe(vm_handle_t* vm, ws_probe_t* out) {
    char* b = serial_text(vm, NULL);
    if (!b) return 0;
    const char* p = NULL;
    for (const char* q = b; (q = strstr(q, "SANDBOX-WORKSPACE-PROBE")) != NULL; q++) {
        p = q;
    }
    int ok = 0;
    if (p) {
        const char* l = strstr(p, "lines=");
        const char* f = strstr(p, "first=");
        const char* la = strstr(p, "last=");
        if (l && f && la) {
            memset(out, 0, sizeof(*out));
            out->lines = (int)strtol(l + 6, NULL, 10);
            memcpy(out->first, f + 6, 8);
            out->first[8] = '\0';
            memcpy(out->last, la + 5, 8);
            out->last[8] = '\0';
            ok = 1;
        }
    }
    free(b);
    return ok;
}

// Wait until the guest reports at least `lines_want` probe lines.
static int wait_probe(vm_handle_t* vm, ws_probe_t* out, int lines_want) {
    for (int i = 0; i < 300; i++) {
        if (serial_probe(vm, out) && out->lines >= lines_want) return 1;
        usleep(10000);
    }
    return 0;
}

static pool_manager_t g_pool;
static char g_engine_sock[256];
static char g_bc_sock[256];

static void* server_main(void* arg) {
    (void)arg;
    ipc_server_run(g_engine_sock);
    return NULL;
}

static sandbox_error_t connect_retry(const char* path, int tries) {
    sandbox_error_t rc = SANDBOX_ERR_DAEMON_UNREACHABLE;
    for (int i = 0; i < tries; i++) {
        rc = sandbox_init(path);
        if (rc == SANDBOX_OK) return rc;
        usleep(20000);
    }
    return rc;
}

// #12: run a create on its own thread, so two can be in flight on the one
// client connection at the same time. `order` records completion across threads
// and `ms` how long the call took -- together they show that a fast reply
// overtook a slow request instead of the protocol serialising everything.
typedef struct {
    sandbox_spec_t spec;
    sandbox_handle_t* h;
    sandbox_error_t rc;
    int order;
    uint64_t ms;
} conc_arg_t;

static pthread_mutex_t g_conc_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_conc_done;

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void* conc_create(void* p) {
    conc_arg_t* a = p;
    uint64_t t0 = mono_ms();
    a->rc = sandbox_create(&a->spec, &a->h);
    a->ms = mono_ms() - t0;
    pthread_mutex_lock(&g_conc_lock);
    a->order = ++g_conc_done;
    pthread_mutex_unlock(&g_conc_lock);
    return NULL;
}


// ---------------------------------------------------------------------------
// #26 end to end: a real guest reaches an allow-listed host through the real
// broker, and nothing else. The upstream is a mock on 192.0.2.1 (TEST-NET-1,
// aliased onto the host's loopback for the test): an address the guest has no
// route to and the host does, so a request can only get there via the broker.
// Needs an image with curl (the Debian one); the busybox fixture skips.

#include <arpa/inet.h>
#include <curl/curl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define UP_ADDR "192.0.2.1"

static pthread_mutex_t g_up_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_up_last[4096];     // the last request the mock upstream received
static int g_up_hits;
static int g_up_fd = -1;

static void* upstream_loop(void* arg) {
    (void)arg;
    for (;;) {
        int fd = accept(g_up_fd, NULL, NULL);
        if (fd < 0) return NULL;
        char buf[4096];
        size_t n = 0;
        while (n + 1 < sizeof(buf)) {
            ssize_t r = recv(fd, buf + n, sizeof(buf) - 1 - n, 0);
            if (r <= 0) break;
            n += (size_t)r;
            buf[n] = '\0';
            if (strstr(buf, "\r\n\r\n")) break;
        }
        pthread_mutex_lock(&g_up_mu);
        memcpy(g_up_last, buf, n + 1);
        g_up_hits++;
        pthread_mutex_unlock(&g_up_mu);
        char path[256] = "?";
        sscanf(buf, "%*s %255s", path);
        char body[400], resp[600];
        int bl = snprintf(body, sizeof(body), "package-index-ok %s", path);
        int rl = snprintf(resp, sizeof(resp),
                          "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
                          bl, body);
        send(fd, resp, (size_t)rl, MSG_NOSIGNAL);
        close(fd);
    }
}

static void* broker_loop(void* arg) {
    (void)arg;
    broker_run();
    return NULL;
}

// Run `script` in the guest; returns its exit code (-100 if it did not run).
static int gsh(sandbox_handle_t* h, const char* script, char* out, size_t cap) {
    const char* av[2] = { script, NULL };
    sandbox_exec_spec_t es;
    memset(&es, 0, sizeof(es));
    es.argv = av;
    es.shell = true;
    es.timeout_ms = 60000;
    sandbox_exec_result_t er;
    if (out && cap) out[0] = '\0';
    if (sandbox_exec(h, &es, &er) != SANDBOX_OK) return -100;
    if (out && cap) {
        size_t n = er.out_len < cap - 1 ? er.out_len : cap - 1;
        memcpy(out, er.out, n);
        out[n] = '\0';
        while (n && (out[n - 1] == '\n' || out[n - 1] == ' ')) out[--n] = '\0';
    }
    int rc = er.exit_code;
    sandbox_exec_result_free(&er);
    return rc;
}

static void test_guest_network(const sandbox_spec_t* base) {
    if (system("ip addr add " UP_ADDR "/32 dev lo") != 0) {
        printf("SKIP guest network: cannot alias " UP_ADDR " onto lo\n");
        return;
    }
    char creds[PATH_MAX];
    snprintf(creds, sizeof(creds), "/tmp/sbtest-creds-%d.conf", (int)getpid());
    FILE* cf = fopen(creds, "w");
    if (cf) { fputs("# none: package indexes need no credential\n", cf); fclose(cf); }
    chmod(creds, 0600);

    // The broker, in this process, against this daemon's own token authority.
    setenv("SANDBOX_BROKER_CONTROL", g_bc_sock, 1);
    setenv("SANDBOX_BROKER_CREDENTIALS", creds, 1);
    setenv("SANDBOX_BROKER_UPSTREAM_SCHEME", "http", 1);  // the mock speaks plain HTTP
    char listen_addr[64];
    snprintf(listen_addr, sizeof(listen_addr), "0.0.0.0:%d", broker_port());
    setenv("SANDBOX_BROKER_LISTEN", listen_addr, 1);
    setenv("SANDBOX_BROKER_TUNNEL_IDLE_S", "20", 1);
    // broker_run() drops to nobody when started as root, and that would drop this
    // whole process. uid/gid 0 makes the drop a no-op.
    setenv("SANDBOX_BROKER_UID", "0", 1);
    setenv("SANDBOX_BROKER_GID", "0", 1);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    pthread_t bth;
    pthread_create(&bth, NULL, broker_loop, NULL);
    pthread_detach(bth);

    g_up_fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(g_up_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in ua = { .sin_family = AF_INET };
    inet_pton(AF_INET, UP_ADDR, &ua.sin_addr);
    ua.sin_port = 0;
    bind(g_up_fd, (struct sockaddr*)&ua, sizeof(ua));
    listen(g_up_fd, 16);
    socklen_t ul = sizeof(ua);
    getsockname(g_up_fd, (struct sockaddr*)&ua, &ul);
    int up_port = ntohs(ua.sin_port);
    pthread_t uth;
    pthread_create(&uth, NULL, upstream_loop, NULL);
    pthread_detach(uth);
    for (int i = 0; i < 100; i++) {  // wait for the broker's listener
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in ba = { .sin_family = AF_INET, .sin_port = htons((uint16_t)broker_port()) };
        inet_pton(AF_INET, "127.0.0.1", &ba.sin_addr);
        int ok = connect(s, (struct sockaddr*)&ba, sizeof(ba)) == 0;
        close(s);
        if (ok) break;
        usleep(50000);
    }

    char out[2048], cmd[1024];
    sandbox_spec_t sp = *base;
    sp.env_vars = NULL;
    const char* allow[] = { UP_ADDR, "127.0.0.1", NULL };
    sp.egress_allow = allow;
    sandbox_handle_t* h = NULL;
    CHECK(sandbox_create(&sp, &h) == SANDBOX_OK && h != NULL, "net: create with a policy");
    if (!h) return;
    if (gsh(h, "command -v curl >/dev/null", NULL, 0) != 0) {
        printf("SKIP guest network: no curl in this image (the Debian image runs it)\n");
        sandbox_destroy(h);
        return;
    }
    const char* token = sandbox_handle_token(h);

    // The guest was told its address, where the broker is, and its login.
    snprintf(cmd, sizeof(cmd), "echo $http_proxy");
    gsh(h, cmd, out, sizeof(out));
    char want[256];
    snprintf(want, sizeof(want), "http://sandbox:%s@169.254.", token);
    CHECK(strncmp(out, want, strlen(want)) == 0, "net: guest has its proxy settings");
    char broker[96] = "";
    gsh(h, "echo $SANDBOX_BROKER", broker, sizeof(broker));
    CHECK(strchr(broker, ':') != NULL, "net: guest knows the broker address");
    gsh(h, "ip -4 -o addr show | grep -c 'inet 169\\.254\\.'", out, sizeof(out));
    CHECK(strcmp(out, "1") == 0, "net: the NIC carries the assigned /30 address");

    // A request for an allow-listed host is relayed -- and arrives clean.
    snprintf(cmd, sizeof(cmd), "curl -sS --max-time 20 http://" UP_ADDR ":%d/simple/pip/", up_port);
    int rc = gsh(h, cmd, out, sizeof(out));
    CHECK(rc == 0 && strcmp(out, "package-index-ok /simple/pip/") == 0,
          "net: allow-listed host reached through the broker");
    pthread_mutex_lock(&g_up_mu);
    CHECK(strstr(g_up_last, "GET /simple/pip/ HTTP/1.1") != NULL &&
              strstr(g_up_last, "Proxy-Authorization") == NULL &&
              strstr(g_up_last, token) == NULL,
          "net: the upstream never sees the session token");
    pthread_mutex_unlock(&g_up_mu);

    // The same through a CONNECT tunnel (what https_proxy clients use).
    snprintf(cmd, sizeof(cmd), "curl -sS --max-time 20 -p http://" UP_ADDR ":%d/tunnelled", up_port);
    rc = gsh(h, cmd, out, sizeof(out));
    CHECK(rc == 0 && strcmp(out, "package-index-ok /tunnelled") == 0, "net: CONNECT tunnel works end to end");

    // Default deny: anything not on the policy is refused at the broker.
    gsh(h, "curl -s -o /dev/null -w '%{http_code}' --max-time 20 http://not-allowed.example/", out, sizeof(out));
    CHECK(strcmp(out, "403") == 0, "net: a host outside the policy -> 403");
    gsh(h, "curl -s -o /dev/null -w '%{http_code}' --max-time 20 -p https://not-allowed.example/", out, sizeof(out));
    CHECK(strcmp(out, "000") == 0 || strcmp(out, "403") == 0, "net: ...and a CONNECT to it is refused");

    // A name the policy allows still cannot be used to reach the host itself.
    snprintf(cmd, sizeof(cmd),
             "curl -s -o /dev/null -w '%%{http_code}' --max-time 20 --noproxy '' -x \"$http_proxy\" http://127.0.0.1:%d/", up_port);
    gsh(h, cmd, out, sizeof(out));
    CHECK(strcmp(out, "403") == 0, "net: loopback is refused even though the policy names it");

    // The token is the credential: a forged one gets nothing.
    snprintf(cmd, sizeof(cmd),
             "curl -s -o /dev/null -w '%%{http_code}' --max-time 20 -x http://sandbox:%064d@$SANDBOX_BROKER http://" UP_ADDR ":%d/", 0, up_port);
    gsh(h, cmd, out, sizeof(out));
    CHECK(strcmp(out, "407") == 0, "net: a forged token -> 407");

    // No bypass: the host drops everything but the broker's port, so a direct
    // connection to the host on another port times out (drop, not refuse).
    snprintf(cmd, sizeof(cmd),
             "H=${SANDBOX_BROKER%%:*}; P=${SANDBOX_BROKER##*:}; curl --noproxy '*' -s -o /dev/null --max-time 4 http://$H:$((P+1))/; echo $?");
    gsh(h, cmd, out, sizeof(out));
    CHECK(strcmp(out, "28") == 0, "net: no direct route to anything but the broker");

    // The decisions were counted and the bytes measured.
    char mb[8192];
    int mn = broker_metrics_render(mb, sizeof(mb));
    CHECK(mn > 0 && strstr(mb, "{decision=\"allowed\"} 0\n") == NULL &&
              strstr(mb, "{decision=\"denied_policy\"} 0\n") == NULL &&
              strstr(mb, "{decision=\"denied_address\"} 0\n") == NULL &&
              strstr(mb, "{direction=\"to_guest\"} 0\n") == NULL,
          "net: allow/deny decisions and bytes are measured");
    sandbox_destroy(h);

    // deny-all: no address at all, so no network of any kind.
    sandbox_spec_t sd = *base;
    sd.env_vars = NULL;
    sd.egress_deny_all = 1;
    sandbox_handle_t* hd = NULL;
    CHECK(sandbox_create(&sd, &hd) == SANDBOX_OK && hd != NULL, "net: create with deny-all");
    if (hd) {
        gsh(hd, "echo \"[$http_proxy]\"", out, sizeof(out));
        CHECK(strcmp(out, "[]") == 0, "net: deny-all gets no proxy settings");
        gsh(hd, "ip -4 -o addr show | grep -vc ' lo '", out, sizeof(out));
        CHECK(strcmp(out, "0") == 0, "net: deny-all leaves the NIC without an address");
        sandbox_destroy(hd);
    }

    // The spec's own environment now reaches exec'd commands.
    sandbox_spec_t se = *base;
    const char* envp[] = { "MY_SETTING=from-the-spec", NULL };
    se.env_vars = envp;
    se.egress_deny_all = 1;
    sandbox_handle_t* he = NULL;
    CHECK(sandbox_create(&se, &he) == SANDBOX_OK && he != NULL, "env: create with env");
    if (he) {
        gsh(he, "echo $MY_SETTING", out, sizeof(out));
        CHECK(strcmp(out, "from-the-spec") == 0, "env: the spec's env is inherited by exec");
        sandbox_destroy(he);
    }

    // Optional: the real thing. A package index on the real internet, through
    // the real broker, over real TLS, limited to the names the policy lists.
    if (getenv("SANDBOX_E2E_INTERNET")) {
        sandbox_spec_t si = *base;
        si.env_vars = NULL;
        const char* pk[] = { "pypi.org", "*.pythonhosted.org", NULL };
        si.egress_allow = pk;
        sandbox_handle_t* hi = NULL;
        CHECK(sandbox_create(&si, &hi) == SANDBOX_OK && hi != NULL, "net: create for the package index");
        if (hi) {
            rc = gsh(hi, "curl -sS --max-time 45 -H 'Accept: application/vnd.pypi.simple.v1+json' https://pypi.org/simple/pip/ | head -c 300", out, sizeof(out));
            CHECK(rc == 0 && strstr(out, "\"name\":\"pip\"") != NULL, "net: pypi.org simple index through the broker");
            gsh(hi, "curl -s -o /dev/null -w '%{http_code}' --max-time 20 -p https://example.com/", out, sizeof(out));
            CHECK(strcmp(out, "000") == 0 || strcmp(out, "403") == 0, "net: a host outside the policy is refused");
            sandbox_destroy(hi);
        }
    }

    system("ip addr del " UP_ADDR "/32 dev lo");
    unlink(creds);
}

int main(void) {
    const char* snap = getenv("SANDBOX_SNAPSHOT_ROOT");
    if (!snap || !*snap || geteuid() != 0 || access("/dev/kvm", R_OK | W_OK) < 0) {
        printf("SKIP test_ipc: needs root + /dev/kvm + template fixture\n");
        return 0;
    }

    // The broker port is one value for the nft rules and the broker listener; pick
    // one unlikely to clash with whatever already holds 8080 on a CI host.
    setenv("SANDBOX_BROKER_PORT", "18089", 1);
    snprintf(g_engine_sock, sizeof(g_engine_sock), "/tmp/sbtest-ipc-%d.sock",
             (int)getpid());
    snprintf(g_bc_sock, sizeof(g_bc_sock), "/tmp/sbtest-bc-%d.sock",
             (int)getpid());
    unlink(g_engine_sock);
    unlink(g_bc_sock);

    // #22: the guest-clock check below is only meaningful if the snapshot is
    // older than the tolerance it asserts. Firecracker resets the KVM clock's
    // realtime base at load (clock_realtime); without it the guest resumes at
    // the time of capture. Waiting here makes "capture time" and "now" far
    // enough apart that a regression cannot hide behind test timing.
    {
        char vmstate[PATH_MAX];
        snprintf(vmstate, sizeof(vmstate), "%s/e2e/vmstate", snap);
        struct stat st;
        if (stat(vmstate, &st) == 0) {
            long age = (long)(time(NULL) - st.st_mtime);
            if (age < 6) {
                fprintf(stderr, "[test] waiting %lds so the snapshot is older "
                                "than the clock tolerance\n", 6 - age);
                sleep((unsigned)(6 - age));
            }
        }
    }

    pool_set_restore_source("e2e");
    if (pool_manager_init(&g_pool, 2) < 0) {
        fprintf(stderr, "FAIL: pool_manager_init\n");
        return 1;
    }
    ipc_server_set_pool(&g_pool);
    ipc_server_set_template("e2e");
    // 192.0.2.1 / 127.0.0.1 are what the guest-network test names; the pypi names
    // are for its optional real-internet leg. The first entry stays what the
    // token checks below expect.
    ipc_server_set_allowed_services("api.example.com,*.internal,192.0.2.1,127.0.0.1,pypi.org,*.pythonhosted.org");

    CHECK(ipc_server_start_broker_control(g_bc_sock) == 0, "broker-control start");

    sandbox_spec_t spec;
    memset(&spec, 0, sizeof(spec));
    spec.memory_mib = 128;
    spec.vcpu_count = 1;
    spec.template_name = "e2e";
    spec.pool_wait_ms = 60000;
    const char* envp[] = { "MYKEY=myvalue", "SANDBOX_MODE=test", NULL };
    spec.env_vars = envp;

    // --- Phase 10.1: SO_PEERCRED allowlist. With only an impossible uid
    // allowed, a root (uid 0) client must be rejected. ---
    ipc_server_set_allowed_uids("4294967294");  // any uid but 0
    {
        pthread_t ta;
        if (pthread_create(&ta, NULL, server_main, NULL) != 0) {
            fprintf(stderr, "FAIL: auth server thread\n");
            pool_manager_destroy(&g_pool);
            return 1;
        }
        int rejected = 0;
        sandbox_error_t rca = connect_retry(g_engine_sock, 250);
        if (rca != SANDBOX_OK) {
            rejected = 1;  // refused before we could even talk
        } else {
            sandbox_handle_t* ha = NULL;
            if (sandbox_create(&spec, &ha) != SANDBOX_OK) rejected = 1;
            else sandbox_destroy(ha);
        }
        CHECK(rejected, "peercred: disallowed uid rejected");
        sandbox_cleanup();
        ipc_server_request_stop();  // keep broker-control alive
        pthread_join(ta, NULL);
    }
    ipc_server_set_allowed_uids("");  // default (any) for the rest of the run

    pthread_t th;
    if (pthread_create(&th, NULL, server_main, NULL) != 0) {
        fprintf(stderr, "FAIL: server thread\n");
        pool_manager_destroy(&g_pool);
        return 1;
    }

    sandbox_error_t rc = connect_retry(g_engine_sock, 250);
    CHECK(rc == SANDBOX_OK, "client connect");

    // --- #12: two Creates in flight on one connection ---------------------
    // A session create clones a volume and takes a dedicated restore; an
    // ephemeral one acquires a warm VM and pays only the env-injection
    // handshake. Both are sent before either reply is read, and the cheaper one
    // must come back first: that is exactly what the old protocol forbade (it
    // serialised a session's Creates so replies stayed in request order). A
    // reply is matched to its caller only by the echoed id, so a broken
    // correlation fails here rather than handing a caller someone else's
    // sandbox.
    {
        // The ordering check is only meaningful if the ephemeral create really
        // does take a warm VM -- a restore would make the two comparable. The
        // replenishment thread fills the pool asynchronously, so wait for it.
        for (int i = 0; i < 500 && pool_manager_warm_count(&g_pool) < 1; i++)
            usleep(10000);
        CHECK(pool_manager_warm_count(&g_pool) >= 1, "concurrent: pool is warm");

        conc_arg_t slow, fast;
        memset(&slow, 0, sizeof(slow));
        memset(&fast, 0, sizeof(fast));
        slow.spec = spec;
        slow.spec.session_key = "e2e-concurrent-12";
        slow.spec.ttl_seconds = 3600;
        fast.spec = spec;

        pthread_t ts, tf;
        int have_slow = pthread_create(&ts, NULL, conc_create, &slow) == 0;
        CHECK(have_slow, "concurrent: session create started");
        if (have_slow) usleep(20000);  // its request reaches the daemon first
        int have_fast = pthread_create(&tf, NULL, conc_create, &fast) == 0;
        CHECK(have_fast, "concurrent: ephemeral create started");
        if (have_slow) pthread_join(ts, NULL);
        if (have_fast) pthread_join(tf, NULL);

        CHECK(slow.rc == SANDBOX_OK && slow.h != NULL,
              "concurrent: session create succeeded");
        CHECK(fast.rc == SANDBOX_OK && fast.h != NULL,
              "concurrent: ephemeral create succeeded");

        sandbox_status_t sslow, sfast;
        memset(&sslow, 0, sizeof(sslow));
        memset(&sfast, 0, sizeof(sfast));
        CHECK(slow.h && sandbox_inspect(slow.h, &sslow) == SANDBOX_OK &&
                  sslow.sandbox_id != 0,
              "concurrent: session handle names its own sandbox");
        CHECK(fast.h && sandbox_inspect(fast.h, &sfast) == SANDBOX_OK &&
                  sfast.sandbox_id != 0,
              "concurrent: ephemeral handle names its own sandbox");
        CHECK(slow.h && fast.h && sslow.sandbox_id != sfast.sandbox_id,
              "concurrent: the two replies named different sandboxes");
        CHECK(fast.order < slow.order,
              "concurrent: fast reply overtook the slow request (out of order)");
        printf("[test] concurrent: session=%llu ms ephemeral=%llu ms "
               "(order %d then %d)\n",
               (unsigned long long)slow.ms, (unsigned long long)fast.ms,
               fast.order, slow.order);

        if (slow.h) sandbox_destroy(slow.h);
        if (fast.h) sandbox_destroy(fast.h);
    }

    sandbox_handle_t* h = NULL;

    if (rc == SANDBOX_OK) {
        rc = sandbox_create(&spec, &h);
        CHECK(rc == SANDBOX_OK && h != NULL, "sandbox_create");

        sandbox_status_t st;
        rc = sandbox_inspect(h, &st);
        CHECK(rc == SANDBOX_OK && st.sandbox_id != 0, "inspect id");
        CHECK(rc == SANDBOX_OK && st.is_running, "inspect running");

        // Per-VM env injection (Phase 9b): the guest agent echoes a delimited
        // SANDBOX-ENV block to serial after the host streams the env.
        vm_handle_t* hvm = lifecycle_get(st.sandbox_id);
        int seen = 0;
        for (int i = 0; i < 300; i++) {
            if (serial_has(hvm, "MYKEY")) { seen = 1; break; }
            usleep(10000);
        }
        if (!seen && hvm) dump_serial(hvm, "env not seen");
        CHECK(seen, "env: injected into guest");
        CHECK(serial_has(hvm, "SANDBOX-ENV-BEGIN"), "env: guest marker");
        // Phase 10.2: the guest must not echo env *values* to the persistent
        // serial console (only key names).
        CHECK(!serial_has(hvm, "myvalue"), "env: value redacted in serial");

        // #10: the guest must classify the host connection by its vsock CID.
        // The agent logs the CID it actually observed on the first accepted
        // host connection: that is in-guest proof the classification input is
        // real (and is the host's, 2) rather than "every peer is accepted".
        //
        // The negative direction -- a non-CID_HOST peer is refused -- cannot be
        // produced inside this guest: the pinned 6.18 kernel knows
        // VMADDR_CID_LOCAL, but Firecracker's CI config disables
        // CONFIG_VSOCKETS_LOOPBACK, so an in-guest connection to our own
        // listener has no local transport to complete on. It is covered by
        // tests/test_vsock_peer.c, which runs the same classifier against a real
        // non-host AF_VSOCK peer on the host.
        int host_seen = 0;
        for (int i = 0; i < 100; i++) {
            if (serial_has(hvm, "SANDBOX-VSOCK-HOST cid=2")) {
                host_seen = 1;
                break;
            }
            usleep(10000);
        }
        if (!host_seen) dump_serial(hvm, "vsock host peer not classified");
        CHECK(host_seen, "vsock: host peer authenticated as cid 2");
        CHECK(!serial_has(hvm, "SANDBOX-VSOCK-REJECT"),
              "vsock: the host connection was not rejected");

        // #22: the guest must see host wall-clock time, not the time the
        // template was captured. The snapshot is at least 6 s old by now (see
        // main), so a missing clock_realtime on /snapshot/load would show up as
        // a skew of >= 6 s and fail here.
        long long guest_now = -1;
        for (int i = 0; i < 100; i++) {
            guest_now = serial_int(hvm, "SANDBOX-GUEST-CLOCK epoch=");
            if (guest_now > 0) break;
            usleep(10000);
        }
        if (guest_now <= 0) dump_serial(hvm, "guest clock marker missing");
        CHECK(guest_now > 0, "clock: guest reported its clock");
#if defined(__x86_64__)
        long long skew = guest_now - (long long)time(NULL);
        fprintf(stderr, "[test] guest clock skew vs host: %llds\n", skew);
        if (skew > 3 || skew < -3) dump_serial(hvm, "clock skew out of range");
        CHECK(skew <= 3 && skew >= -3, "clock: guest tracks host time");
#else
        // clock_realtime is an x86_64-only Firecracker field, so on aarch64 the
        // guest keeps the captured clock and the eventual fix is a guest-side
        // time sync. Assert only that the value is plausible, and say why.
        fprintf(stderr, "[test] aarch64: clock_realtime unsupported by FC; "
                        "guest clock is not reset on load\n");
        CHECK(guest_now > 1600000000LL, "clock: guest clock is plausible");
#endif

        // --- #24: exec and file RPC against the *restored* guest. This is the
        // part tests/test_guest_rpc.c cannot show: the real vsock transport
        // through Firecracker's UDS, the host-CID gate in the agent, and a
        // listener that must have been re-announced after the snapshot restore.
        {
            char out[512] = {0};
            size_t on = 0;
            struct rpc_cap cap = { out, &on, sizeof(out) };
            char msg[160];
            grpc_exec_res_t xr;
            const char* script[] = { "echo rpc-hello; pwd; echo oops >&2; exit 5" };
            grpc_exec_req_t rq = { .argv = script, .argc = 1, .flags = GRPC_F_SHELL,
                                   .timeout_ms = 10000 };
            int fd = grpc_connect_uds(hvm->vsock_uds, GRPC_PORT, 10000);
            int rc = fd < 0 ? -1 : grpc_exec(fd, &rq, rpc_on_chunk, &cap, 20000, &xr, msg, sizeof(msg));
            if (rc != 0 || xr.exit_code != 5) dump_serial(hvm, "rpc exec failed");
            CHECK(rc == 0 && xr.exit_code == 5 && strstr(out, "rpc-hello\n/workspace\n"),
                  "rpc: exec in the restored guest (stdout, cwd, exit code)");

            const char* body = "written over vsock\n";
            rc = grpc_write_file(grpc_connect_uds(hvm->vsock_uds, GRPC_PORT, 10000),
                                 "/workspace/rpc.txt", (const uint8_t*)body, strlen(body),
                                 0644, 0, 10000, msg, sizeof(msg));
            uint8_t* rd = NULL; size_t rl = 0; int tr = 0;
            int rc2 = grpc_read_file(grpc_connect_uds(hvm->vsock_uds, GRPC_PORT, 10000),
                                     "/workspace/rpc.txt", 0, 0, 10000, &rd, &rl, &tr,
                                     msg, sizeof(msg));
            CHECK(rc == 0 && rc2 == 0 && rl == strlen(body) && !memcmp(rd, body, rl),
                  "rpc: file written and read back through the guest");
            free(rd);

            rc = grpc_read_file(grpc_connect_uds(hvm->vsock_uds, GRPC_PORT, 10000),
                                "/etc/passwd", 0, 0, 10000, &rd, &rl, &tr, msg, sizeof(msg));
            CHECK(rc == GRPC_E_DENIED, "rpc: a path outside /workspace is refused");

            const char* slow[] = { "sleep 60" };
            grpc_exec_req_t sq = { .argv = slow, .argc = 1, .flags = GRPC_F_SHELL,
                                   .timeout_ms = 700 };
            rc = grpc_exec(grpc_connect_uds(hvm->vsock_uds, GRPC_PORT, 10000), &sq, NULL,
                           NULL, 20000, &xr, msg, sizeof(msg));
            CHECK(rc == 0 && (xr.flags & GRPC_X_TIMED_OUT), "rpc: guest-side timeout kills the command");
        }

        // --- #24 through the daemon: the same operations by way of libsandbox,
        // which is what a client actually calls (ownership check, worker pool,
        // chunked transfer, reply framing). ---
        {
            const char* av[] = { "echo via-daemon; echo e >&2; exit 3", NULL };
            sandbox_exec_spec_t es = { .argv = av, .shell = true, .timeout_ms = 10000 };
            sandbox_exec_result_t er;
            sandbox_error_t ec = sandbox_exec(h, &es, &er);
            CHECK(ec == SANDBOX_OK && er.exit_code == 3 && er.out_len == 11 &&
                      !memcmp(er.out, "via-daemon\n", 11) && er.err_len == 2,
                  "daemon rpc: sandbox_exec returns output and exit code");
            sandbox_exec_result_free(&er);

            // 100 KiB: more than one IPC frame each way.
            size_t n = 100 * 1024;
            uint8_t* blob = malloc(n);
            for (size_t i = 0; i < n; i++) blob[i] = (uint8_t)(i * 31 + 7);
            ec = sandbox_write_file(h, "/workspace/blob.bin", blob, n, 0, 0);
            uint8_t* back = NULL; size_t bn = 0;
            sandbox_error_t ec2 = sandbox_read_file(h, "/workspace/blob.bin", &back, &bn);
            CHECK(ec == SANDBOX_OK && ec2 == SANDBOX_OK && bn == n && !memcmp(back, blob, n),
                  "daemon rpc: 100 KiB file round-trips in the guest, byte for byte");
            free(back);
            // The guest's own view of it, not the library's: a guest process
            // (ls) reports the size. Only applets both images have: the busybox
            // fixture links just sh, echo, cat, ls, mkdir, touch, sleep, ps.
            const char* ck[] = { "set -- $(ls -l /workspace/blob.bin); echo $5", NULL };
            sandbox_exec_spec_t cs = { .argv = ck, .shell = true, .timeout_ms = 10000 };
            ec = sandbox_exec(h, &cs, &er);
            CHECK(ec == SANDBOX_OK && er.exit_code == 0 && atol((const char*)er.out) == (long)n,
                  "daemon rpc: a guest process sees the full 100 KiB");
            sandbox_exec_result_free(&er);
            free(blob);

            CHECK(sandbox_read_file(h, "/etc/passwd", &back, &bn) == SANDBOX_ERR_PATH_DENIED,
                  "daemon rpc: a path outside /workspace is refused");
            sandbox_dirent_t* ents = NULL; size_t ne = 0; bool tr = false;
            ec = sandbox_list_dir(h, "/workspace", &ents, &ne, &tr);
            int seen = 0;
            for (size_t i = 0; ec == SANDBOX_OK && i < ne; i++)
                if (!strcmp(ents[i].name, "blob.bin") && ents[i].size == n) seen = 1;
            CHECK(ec == SANDBOX_OK && seen, "daemon rpc: list_dir sees the file with its size");
            free(ents);
        }

        // --- #23: session workspaces. A sandbox created with a session key gets
        // a *persistent* /workspace: its files survive the sandbox being
        // destroyed, because the volume belongs to the session, not the VM. The
        // guest proves it from the inside -- the agent appends a checksum of each
        // injected payload to /workspace/.sandbox-probe and reports the file's
        // line count, first line and last line -- so this is in-guest evidence,
        // not the host reading back a file it wrote itself. ---
        {
            const char* payload_a[] = { "MYKEY=myvalue", "SANDBOX_MODE=test", NULL };
            const char* payload_b[] = { "SECOND=injection", NULL };
            sandbox_status_t wst;
            memset(&wst, 0, sizeof(wst));

            sandbox_spec_t s = spec;
            s.session_key = "e2e-session-23";
            s.ttl_seconds = 3600;
            s.env_vars = payload_a;

            sandbox_handle_t* w1 = NULL;
            CHECK(sandbox_create(&s, &w1) == SANDBOX_OK && w1 != NULL,
                  "session: create with a session key");
            ws_probe_t p1;
            memset(&p1, 0, sizeof(p1));
            vm_handle_t* w1vm = (w1 && sandbox_inspect(w1, &wst) == SANDBOX_OK)
                                    ? lifecycle_get(wst.sandbox_id) : NULL;
            int got1 = w1vm && wait_probe(w1vm, &p1, 1);
            if (!got1 && w1vm) dump_serial(w1vm, "workspace probe missing");
            CHECK(got1, "session: guest mounted /workspace");
            CHECK(got1 && p1.lines == 1, "session: a new volume starts empty");
            char first_before[9];
            memcpy(first_before, p1.first, sizeof(first_before));

            // #24: what an assistant does -- a *command* writes into /workspace,
            // and the next sandbox for the same session reads it back over the
            // API. The destroy below flushes the volume before the VM is killed.
            const char* wr[] = { "echo remembered-across-sandboxes > /workspace/note.txt", NULL };
            sandbox_exec_spec_t wes = { .argv = wr, .shell = true, .timeout_ms = 10000 };
            sandbox_exec_result_t wer;
            sandbox_error_t wec = w1 ? sandbox_exec(w1, &wes, &wer) : SANDBOX_ERR_INVALID_SPEC;
            CHECK(wec == SANDBOX_OK && wer.exit_code == 0,
                  "session rpc: a command in sandbox 1 writes a file into /workspace");
            if (wec == SANDBOX_OK) sandbox_exec_result_free(&wer);

            // Destroy the sandbox: the volume is the session's and must stay.
            CHECK(sandbox_destroy(w1) == SANDBOX_OK, "session: destroy the sandbox");

            // Re-create the *same* session with a different payload. The file now
            // has two lines: the one written before the destroy is still first.
            sandbox_spec_t s2 = s;
            s2.env_vars = payload_b;
            sandbox_handle_t* w2 = NULL;
            CHECK(sandbox_create(&s2, &w2) == SANDBOX_OK && w2 != NULL,
                  "session: re-create with the same key");
            ws_probe_t p2;
            memset(&p2, 0, sizeof(p2));
            vm_handle_t* w2vm = (w2 && sandbox_inspect(w2, &wst) == SANDBOX_OK)
                                    ? lifecycle_get(wst.sandbox_id) : NULL;
            int got2 = w2vm && wait_probe(w2vm, &p2, 2);
            if (!got2 && w2vm) dump_serial(w2vm, "workspace probe missing on recreate");
            CHECK(got2 && p2.lines == 2, "session: the file survived the destroy");
            CHECK(got2 && strcmp(p2.first, first_before) == 0,
                  "session: the pre-destroy line is still the first line");
            CHECK(got2 && strcmp(p2.last, first_before) != 0,
                  "session: the second injection appended its own line");
            uint8_t* note = NULL; size_t nn = 0;
            sandbox_error_t nrc = w2 ? sandbox_read_file(w2, "/workspace/note.txt", &note, &nn)
                                     : SANDBOX_ERR_INVALID_SPEC;
            CHECK(nrc == SANDBOX_OK && nn == 28 && !memcmp(note, "remembered-across-sandboxes\n", 28),
                  "session rpc: sandbox 2 reads the file sandbox 1's command wrote");
            free(note);
            if (w2) sandbox_destroy(w2);

            // A different key must not see any of that: one volume per session.
            sandbox_spec_t s3 = spec;
            s3.session_key = "e2e-session-23-other";
            s3.ttl_seconds = 3600;
            s3.env_vars = payload_a;
            sandbox_handle_t* w3 = NULL;
            CHECK(sandbox_create(&s3, &w3) == SANDBOX_OK && w3 != NULL,
                  "session: create with a different key");
            ws_probe_t p3;
            memset(&p3, 0, sizeof(p3));
            vm_handle_t* w3vm = (w3 && sandbox_inspect(w3, &wst) == SANDBOX_OK)
                                    ? lifecycle_get(wst.sandbox_id) : NULL;
            int got3 = w3vm && wait_probe(w3vm, &p3, 1);
            CHECK(got3 && p3.lines == 1,
                  "session: another key gets its own empty volume");
            if (w3) sandbox_destroy(w3);

            // #23/D5 renewal. Keyed by the session key, so it works with no
            // sandbox alive (that is the point: the volume outlives the VM).
            uint64_t e1 = 0, e2 = 0;
            CHECK(sandbox_session_renew("e2e-session-23", 60, &e1) == SANDBOX_OK &&
                      e1 > 0,
                  "session: renew by key with no sandbox alive");
            CHECK(sandbox_session_renew("e2e-session-23", 86400, &e2) == SANDBOX_OK &&
                      e2 > e1,
                  "session: renewal extends the deadline");
            uint64_t e3 = 0;
            CHECK(sandbox_session_renew("no-such-session-23", 60, &e3) ==
                      SANDBOX_ERR_SESSION_UNKNOWN,
                  "session: renewing an unknown key is refused");
            CHECK(sandbox_session_renew("", 60, &e3) == SANDBOX_ERR_INVALID_SPEC,
                  "session: renewing an empty key is refused");
        }

        CHECK(sandbox_pause(h) == SANDBOX_OK, "sandbox_pause");        CHECK(sandbox_inspect(h, &st) == SANDBOX_OK && !st.is_running,
              "inspect paused");
        CHECK(sandbox_resume(h) == SANDBOX_OK, "sandbox_resume");
        CHECK(sandbox_inspect(h, &st) == SANDBOX_OK && st.is_running,
              "inspect resumed");

        // Engine-side broker-control: the minted token validates and carries
        // the configured allowlist.
        const char* token = sandbox_handle_token(h);
        CHECK(token && strlen(token) == BROKER_TOKEN_HEX_LEN, "token shape");
        int bfd = broker_engine_connect(g_bc_sock);
        CHECK(bfd >= 0, "broker-control connect");
        session_info_t si;
        int vr = (bfd >= 0) ? broker_validate_token(bfd, token, &si)
                            : BROKER_VALIDATE_ERROR;
        CHECK(vr == BROKER_VALIDATE_OK, "token validates");
        CHECK(vr == BROKER_VALIDATE_OK && si.sandbox_id == st.sandbox_id,
              "token sandbox_id");
        CHECK(vr == BROKER_VALIDATE_OK && si.allowed_services &&
                  si.allowed_services[0] &&
                  strcmp(si.allowed_services[0], "api.example.com") == 0,
              "token allowlist");

        // Unknown token is rejected.
        char bad[BROKER_TOKEN_HEX_LEN + 1];
        memset(bad, '0', BROKER_TOKEN_HEX_LEN);
        bad[BROKER_TOKEN_HEX_LEN] = '\0';
        session_info_t si_bad;
        int vrb = broker_validate_token(bfd, bad, &si_bad);
        CHECK(vrb == BROKER_VALIDATE_INVALID, "bad token rejected");

        // --- #26 per-session egress policy: the token carries the policy this
        // sandbox was created with, not the daemon-wide list. The daemon list is
        // "api.example.com,*.internal". ---
        {
            sandbox_spec_t ps = spec;
            ps.env_vars = NULL;
            const char* narrow[] = {"api.example.com", NULL};
            ps.egress_allow = narrow;
            sandbox_handle_t* hp = NULL;
            CHECK(sandbox_create(&ps, &hp) == SANDBOX_OK && hp != NULL,
                  "egress: create with a narrowed policy");
            session_info_t sp;
            memset(&sp, 0, sizeof(sp));
            if (hp && bfd >= 0 &&
                broker_validate_token(bfd, sandbox_handle_token(hp), &sp) == BROKER_VALIDATE_OK) {
                int cnt = 0;
                while (sp.allowed_services && sp.allowed_services[cnt]) cnt++;
                CHECK(cnt == 1 && strcmp(sp.allowed_services[0], "api.example.com") == 0,
                      "egress: the token carries exactly the session's policy");
                session_info_free(&sp);
            } else {
                CHECK(0, "egress: narrowed token validates");
            }
            if (hp) sandbox_destroy(hp);

            ps.egress_allow = NULL;
            ps.egress_deny_all = 1;
            sandbox_handle_t* hd = NULL;
            CHECK(sandbox_create(&ps, &hd) == SANDBOX_OK && hd != NULL,
                  "egress: create with deny-all");
            memset(&sp, 0, sizeof(sp));
            if (hd && bfd >= 0 &&
                broker_validate_token(bfd, sandbox_handle_token(hd), &sp) == BROKER_VALIDATE_OK) {
                CHECK(sp.allowed_services && sp.allowed_services[0] == NULL,
                      "egress: deny-all token has an empty list");
                session_info_free(&sp);
            } else {
                CHECK(0, "egress: deny-all token validates");
            }
            if (hd) sandbox_destroy(hd);

            // Wider than the daemon allows: refused, and nothing was provisioned.
            const char* wide[] = {"evil.example", NULL};
            ps.egress_deny_all = 0;
            ps.egress_allow = wide;
            sandbox_handle_t* hw = NULL;
            CHECK(sandbox_create(&ps, &hw) == SANDBOX_ERR_INVALID_SPEC && hw == NULL,
                  "egress: a policy wider than the daemon's is refused");
            // A narrower entry under a ceiling wildcard is fine.
            const char* under[] = {"db.internal:5432", NULL};
            ps.egress_allow = under;
            sandbox_handle_t* hu = NULL;
            CHECK(sandbox_create(&ps, &hu) == SANDBOX_OK && hu != NULL,
                  "egress: an entry under the daemon's wildcard is accepted");
            if (hu) sandbox_destroy(hu);
        }

        // --- pidfd VMM crash detection (§4.2): kill the VMM and confirm the
        // event loop reaps it, bumps the crash metric, revokes the token, and
        // stops reporting the sandbox as live. ---
        sandbox_handle_t* h2 = NULL;
        CHECK(sandbox_create(&spec, &h2) == SANDBOX_OK && h2 != NULL,
              "create for crash test");
        sandbox_status_t cst;
        memset(&cst, 0, sizeof(cst));
        if (h2 && sandbox_inspect(h2, &cst) == SANDBOX_OK) {
            uint32_t cid = cst.sandbox_id;
            const char* tok2 = sandbox_handle_token(h2);
            vm_handle_t* cvm = lifecycle_get(cid);
            CHECK(cvm != NULL, "crash: vm registered");
            if (cvm) {
                kill(cvm->vmm_pid, SIGKILL);
                int gone = 0;
                for (int i = 0; i < 200; i++) {
                    if (sandbox_inspect(h2, &cst) != SANDBOX_OK) { gone = 1; break; }
                    usleep(10000);
                }
                CHECK(gone, "crash: reclaim observed");
                CHECK(lifecycle_get(cid) == NULL, "crash: registry cleared");
                if (bfd >= 0 && tok2) {
                    session_info_t s2;
                    CHECK(broker_validate_token(bfd, tok2, &s2) ==
                              BROKER_VALIDATE_INVALID,
                          "crash: token revoked");
                }
            }
        }
        char mbuf[8192];
        telemetry_render(mbuf, sizeof(mbuf));
        CHECK(strstr(mbuf, "sandbox_vmm_crashes_total 1") != NULL,
              "crash: metric bumped");
        CHECK(strstr(mbuf, "sandbox_uffd_faults_total 0") == NULL,
              "metrics: uffd faults served");

        // Destroy revokes the token.
        uint32_t id = st.sandbox_id;
        CHECK(sandbox_destroy(h) == SANDBOX_OK, "sandbox_destroy");
        h = NULL;
        session_info_t si2;
        int vr2 = broker_validate_token(bfd, token, &si2);
        CHECK(vr2 == BROKER_VALIDATE_INVALID, "token revoked");
        (void)id;

        session_info_free(&si);
        if (bfd >= 0) close(bfd);

        test_guest_network(&spec);
    }

    sandbox_cleanup();
    ipc_server_stop();
    pthread_join(th, NULL);
    pool_manager_destroy(&g_pool);
    unlink(g_engine_sock);
    unlink(g_bc_sock);

    fprintf(stderr, "[test] ipc: %s\n", g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
