// SPDX-License-Identifier: GPL-2.0-only
// test_ipc_guest.c -- #24: guest operations through the whole IPC stack, with no
// VM, root or KVM.
//
//   libsandbox  ->  daemon IPC server  ->  guest-op worker pool  ->  Firecracker-
//   style hybrid-vsock UDS  ->  the real guest server (src/guest_rpc_server.c)
//
// The only fakes are the VM (a vm_handle_t that carries just a UDS path) and that
// UDS, which here speaks the same "CONNECT <port>\n" / "OK <n>\n" handshake as
// Firecracker and hands each connection to the real guest server. Everything
// above and below that -- the codec, the client transport, ownership checks, the
// per-session cap, the worker pool, result delivery, error mapping, chunked
// file transfer -- is the production code.
//
// What this cannot show is the transport itself (a real vsock through a real
// Firecracker); tests/test_ipc.c does that on the privileged runner.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "guest_rpc.h"
#include "ipc_codec.h"
#include "ipc_internal.h"
#include "ipc_server.h"
#include "libsandbox.h"
#include "lifecycle.h"

static int g_fail, g_total;

static void check(int cond, const char* msg) {
    g_total++;
    printf("[test] %-66s %s\n", msg, cond ? "PASS" : "FAIL");
    if (!cond) g_fail++;
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// ── fake guest: the real server behind a hybrid-vsock UDS ───────────────────

static grpc_server_t* g_gsrv;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
#define CHECK_RC(got, want, msg) check((got) == (want), (msg))

static int g_stop;  // atomic: read by helper threads, set by main
static char g_dir[PATH_MAX], g_ws[PATH_MAX], g_uds[PATH_MAX], g_ipc[PATH_MAX];
static int g_uds_fd = -1;

static void* guest_step_thread(void* a) {
    (void)a;
    while (!__atomic_load_n(&g_stop, __ATOMIC_ACQUIRE)) {
        pthread_mutex_lock(&g_mu);
        grpc_server_step(g_gsrv);
        pthread_mutex_unlock(&g_mu);
        usleep(200);
    }
    return NULL;
}

static void* uds_accept_thread(void* a) {
    (void)a;
    while (!__atomic_load_n(&g_stop, __ATOMIC_ACQUIRE)) {
        int fd = accept(g_uds_fd, NULL, NULL);
        if (fd < 0) { if (__atomic_load_n(&g_stop, __ATOMIC_ACQUIRE)) break; continue; }
        char line[64];
        size_t n = 0;
        while (n < sizeof(line) - 1) {
            if (read(fd, line + n, 1) != 1) break;
            if (line[n++] == '\n') break;
        }
        line[n] = '\0';
        if (strcmp(line, "CONNECT 5002\n") != 0) { close(fd); continue; }
        static const char ok[] = "OK 1073741824\n";
        if (write(fd, ok, sizeof(ok) - 1) != (ssize_t)sizeof(ok) - 1) { close(fd); continue; }
        pthread_mutex_lock(&g_mu);
        grpc_server_adopt(g_gsrv, fd);
        pthread_mutex_unlock(&g_mu);
    }
    return NULL;
}

static void* ipc_thread(void* a) {
    (void)a;
    ipc_server_run(g_ipc);
    return NULL;
}

// ── helpers ─────────────────────────────────────────────────────────────────

static sandbox_handle_t* g_h;

static char* W(const char* rel, char* buf, size_t cap) {
    snprintf(buf, cap, "%s/%s", g_ws, rel);
    return buf;
}

static int sh(const char* script, uint32_t timeout_ms, uint32_t max_out, const char* in,
              sandbox_exec_result_t* r) {
    const char* av[2] = { script, NULL };
    sandbox_exec_spec_t sp = { .argv = av, .shell = true, .timeout_ms = timeout_ms,
                               .max_output = max_out, .stdin_data = (const uint8_t*)in,
                               .stdin_len = in ? strlen(in) : 0 };
    return sandbox_exec(g_h, &sp, r);
}

static int raw_connect(void) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    strcpy(a.sun_path, g_ipc);
    if (fd < 0 || connect(fd, (struct sockaddr*)&a, sizeof(a)) != 0) return -1;
    return fd;
}

// Send a guest request on a raw connection and return the decoded reply code
// (0 = success reply, else the error_code), or INT_MIN on a transport problem.
static int raw_guest(int fd, uint64_t rid, uint32_t sandbox_id, uint32_t op, const char* path) {
    ipc_request_t q;
    ipc_request_init(&q);
    q.kind = IPC_REQ_GUEST;
    q.request_id = rid;
    q.sandbox_id = sandbox_id;
    q.guest_op = op;
    snprintf(q.path, sizeof(q.path), "%s", path);
    uint8_t buf[IPC_FRAME_MAX];
    size_t n = 0;
    if (ipc_encode_request(&q, buf, sizeof(buf), &n) < 0 || ipc_send_frame(fd, buf, n) < 0) return INT_MIN;
    size_t rn = 0;
    if (ipc_recv_frame(fd, buf, sizeof(buf), &rn) < 0) return INT_MIN;
    ipc_response_t r;
    if (ipc_decode_response(buf, rn, &r) < 0) return INT_MIN;
    int code = r.is_error ? r.error_code : 0;
    ipc_response_clear(&r);
    return code;
}

// ── tests ───────────────────────────────────────────────────────────────────

static void test_exec(void) {
    sandbox_exec_result_t r;
    int rc = sh("echo hi; echo oops >&2; exit 4", 5000, 0, NULL, &r);
    check(rc == SANDBOX_OK && r.exit_code == 4 && r.out_len == 3 && !memcmp(r.out, "hi\n", 3) &&
              r.err_len == 5 && !memcmp(r.err, "oops\n", 5),
          "exec: output, stderr and exit code cross the whole stack");
    sandbox_exec_result_free(&r);

    rc = sh("cat", 5000, 0, "stdin payload", &r);
    check(rc == SANDBOX_OK && r.out_len == 13 && !memcmp(r.out, "stdin payload", 13), "exec: stdin delivered");
    sandbox_exec_result_free(&r);

    const char* av[] = { "echo", "a b", "c", NULL };
    const char* env[] = { "K=V", NULL };
    sandbox_exec_spec_t sp = { .argv = av, .env = env, .timeout_ms = 5000 };
    rc = sandbox_exec(g_h, &sp, &r);
    check(rc == SANDBOX_OK && r.out_len == 6 && !memcmp(r.out, "a b c\n", 6), "exec: argv without a shell keeps its arguments intact");
    sandbox_exec_result_free(&r);

    int64_t t0 = now_ms();
    rc = sh("sleep 30", 400, 0, NULL, &r);
    check(rc == SANDBOX_OK && r.timed_out && r.term_signal == 9 && now_ms() - t0 < 6000, "exec: timeout reported, not an error");
    sandbox_exec_result_free(&r);

    // The reply frame is 64 KiB: a command that writes far more must still get
    // an answer, with the head kept and the true size reported.
    rc = sh("awk 'BEGIN{for(i=0;i<20000;i++) printf \"line-%05d\\n\", i}'; head -c 50000 /dev/zero | tr '\\0' E >&2",
            20000, 0, NULL, &r);
    check(rc == SANDBOX_OK && r.out_total == 20000u * 11 && r.out_len == IPC_EXEC_OUT_KEEP &&
              !memcmp(r.out, "line-00000\nline-00001\n", 22),
          "exec: stdout head kept at 32 KiB, true total reported");
    check(rc == SANDBOX_OK && r.err_total == 50000 && r.err_len == IPC_EXEC_ERR_KEEP,
          "exec: stderr head kept at 16 KiB, true total reported");
    sandbox_exec_result_free(&r);

    rc = sh("yes", 20000, 5000, NULL, &r);
    check(rc == SANDBOX_OK && r.output_truncated && r.out_total + r.err_total == 5000, "exec: agent-side output cap kills the command");
    sandbox_exec_result_free(&r);

    const char* none[] = { NULL };
    sandbox_exec_spec_t bad = { .argv = none };
    check(sandbox_exec(g_h, &bad, &r) == SANDBOX_ERR_INVALID_SPEC, "exec: empty argv refused");
    char big[IPC_MAX_PATH + 8];
    memset(big, 'x', sizeof(big) - 1); big[sizeof(big) - 1] = 0;
    sandbox_exec_spec_t cw = { .argv = (const char* const[]){ "true", NULL }, .cwd = big };
    check(sandbox_exec(g_h, &cw, &r) == SANDBOX_ERR_INVALID_SPEC, "exec: over-long cwd refused");
}

static void test_files(void) {
    char p[300];
    uint8_t* d; size_t n;

    check(sandbox_write_file(g_h, W("small.txt", p, sizeof(p)), (const uint8_t*)"hello", 5, 0, 0) == SANDBOX_OK &&
              sandbox_read_file(g_h, p, &d, &n) == SANDBOX_OK && n == 5 && !memcmp(d, "hello", 5),
          "files: small write then read");
    free(d);

    // 200 KiB crosses four message chunks each way.
    size_t big = 200 * 1024;
    uint8_t* blob = malloc(big);
    for (size_t i = 0; i < big; i++) blob[i] = (uint8_t)((i * 2654435761u) >> 24);
    int rc = sandbox_write_file(g_h, W("big.bin", p, sizeof(p)), blob, big, 0600, 0);
    struct stat sb;
    check(rc == SANDBOX_OK && stat(p, &sb) == 0 && (size_t)sb.st_size == big && (sb.st_mode & 0777) == 0600,
          "files: 200 KiB write is chunked and lands whole, with its mode");
    rc = sandbox_read_file(g_h, p, &d, &n);
    check(rc == SANDBOX_OK && n == big && !memcmp(d, blob, big), "files: 200 KiB read comes back byte for byte");
    free(d);
    free(blob);

    size_t lim = SANDBOX_MAX_FILE;
    uint8_t* lb = malloc(lim + 1);
    memset(lb, 'L', lim + 1);
    rc = sandbox_write_file(g_h, W("limit.bin", p, sizeof(p)), lb, lim, 0, 0);
    int rc2 = sandbox_read_file(g_h, p, &d, &n);
    check(rc == SANDBOX_OK && rc2 == SANDBOX_OK && n == lim && !memcmp(d, lb, lim), "files: a file at the 4 MiB limit round-trips");
    free(d);
    check(sandbox_write_file(g_h, W("over.bin", p, sizeof(p)), lb, lim + 1, 0, 0) == SANDBOX_ERR_TOO_LARGE && stat(p, &sb) != 0,
          "files: one byte over the limit is refused before anything is sent");
    free(lb);

    // The guest holds a bigger file than the library will return.
    int fd = open(W("huge.bin", p, sizeof(p)), O_WRONLY | O_CREAT, 0644);
    if (fd >= 0 && ftruncate(fd, (off_t)lim + 4096) == 0) { /* sparse */ }
    if (fd >= 0) close(fd);
    check(sandbox_read_file(g_h, p, &d, &n) == SANDBOX_ERR_TOO_LARGE, "files: reading a file over the limit -> TOO_LARGE");

    sandbox_write_file(g_h, W("a.log", p, sizeof(p)), (const uint8_t*)"one\n", 4, 0, 0);
    sandbox_write_file(g_h, p, (const uint8_t*)"two\n", 4, 0, SANDBOX_WRITE_APPEND);
    sandbox_read_file(g_h, p, &d, &n);
    check(n == 8 && !memcmp(d, "one\ntwo\n", 8), "files: append");
    free(d);
    check(sandbox_write_file(g_h, p, (const uint8_t*)"x", 1, 0, SANDBOX_WRITE_EXCL) == SANDBOX_ERR_EXISTS, "files: exclusive write -> EXISTS");
    check(sandbox_write_file(g_h, W("nope/x", p, sizeof(p)), (const uint8_t*)"x", 1, 0, 0) == SANDBOX_ERR_NOT_FOUND, "files: missing parent -> NOT_FOUND");
    check(sandbox_write_file(g_h, W("nope/x", p, sizeof(p)), (const uint8_t*)"x", 1, 0, SANDBOX_WRITE_PARENTS) == SANDBOX_OK, "files: parents created on request");
    check(sandbox_write_file(g_h, W("empty", p, sizeof(p)), NULL, 0, 0, 0) == SANDBOX_OK && stat(p, &sb) == 0 && sb.st_size == 0, "files: an empty file can be written");

    sandbox_fstat_t st;
    check(sandbox_stat(g_h, W("a.log", p, sizeof(p)), &st) == SANDBOX_OK && st.type == 1 && st.size == 8, "files: stat");
    check(sandbox_mkdir(g_h, W("d1/d2", p, sizeof(p)), 0, true) == SANDBOX_OK && sandbox_stat(g_h, p, &st) == SANDBOX_OK && st.type == 2, "files: mkdir -p");
    check(sandbox_remove(g_h, W("d1", p, sizeof(p)), false) != SANDBOX_OK, "files: non-empty directory needs recursive");
    check(sandbox_remove(g_h, W("d1", p, sizeof(p)), true) == SANDBOX_OK && stat(p, &sb) != 0, "files: recursive remove");
    check(sandbox_remove(g_h, W("d1", p, sizeof(p)), true) == SANDBOX_ERR_NOT_FOUND, "files: remove of a missing path -> NOT_FOUND");
}

static void test_paths_denied(void) {
    uint8_t* d; size_t n; sandbox_fstat_t st;
    check(sandbox_read_file(g_h, "/etc/passwd", &d, &n) == SANDBOX_ERR_PATH_DENIED, "paths: outside the workspace -> PATH_DENIED");
    char p[300];
    snprintf(p, sizeof(p), "%s/../x", g_ws);
    check(sandbox_stat(g_h, p, &st) == SANDBOX_ERR_PATH_DENIED, "paths: '..' -> PATH_DENIED");
    check(sandbox_write_file(g_h, "relative", (const uint8_t*)"x", 1, 0, 0) == SANDBOX_ERR_PATH_DENIED, "paths: relative -> PATH_DENIED");
    check(sandbox_remove(g_h, g_ws, true) == SANDBOX_ERR_PATH_DENIED, "paths: the workspace root cannot be removed");
    char big[IPC_MAX_PATH + 8];
    memset(big, 'a', sizeof(big) - 1); big[0] = '/'; big[sizeof(big) - 1] = 0;
    check(sandbox_stat(g_h, big, &st) == SANDBOX_ERR_INVALID_SPEC, "paths: a path too long for the frame is refused client-side");
    // The refusal must not have poisoned the shared connection.
    check(sandbox_stat(g_h, g_ws, &st) == SANDBOX_OK && st.type == 2, "paths: ...and the connection is still usable afterwards");
}

static void test_list(void) {
    char p[300];
    // Names long enough that the listing cannot fit one frame.
    char nm[220];
    memset(nm, 'n', 200);
    for (int i = 0; i < 300; i++) {
        snprintf(nm + 200, sizeof(nm) - 200, "%04d", i);
        snprintf(p, sizeof(p), "%s/lsdir/%s", g_ws, nm);
        if (i == 0) { char dd[300]; snprintf(dd, sizeof(dd), "%s/lsdir", g_ws); mkdir(dd, 0755); }
        int fd = open(p, O_WRONLY | O_CREAT, 0644);
        if (fd >= 0) close(fd);
    }
    sandbox_dirent_t* e = NULL; size_t n = 0; bool tr = false;
    snprintf(p, sizeof(p), "%s/lsdir", g_ws);
    int rc = sandbox_list_dir(g_h, p, &e, &n, &tr);
    check(rc == SANDBOX_OK && tr && n > 100 && n < 300, "list: 300 long names -> cut to fit one reply, truncation flagged");
    free(e);
    // A small directory lists completely.
    char sm[300]; snprintf(sm, sizeof(sm), "%s/smalldir", g_ws);
    mkdir(sm, 0755);
    snprintf(p, sizeof(p), "%s/smalldir/f", g_ws);
    int fd = open(p, O_WRONLY | O_CREAT, 0644); if (fd >= 0) close(fd);
    rc = sandbox_list_dir(g_h, sm, &e, &n, &tr);
    check(rc == SANDBOX_OK && !tr && n == 1 && !strcmp(e[0].name, "f") && e[0].type == 1, "list: a small directory is complete");
    free(e);
}

typedef struct { int rc; sandbox_exec_result_t r; } cw_t;
static void* conc_exec(void* a) {
    cw_t* c = a;
    c->rc = sh("sleep 0.3; echo done", 10000, 0, NULL, &c->r);
    return NULL;
}

static void test_concurrency_and_limits(void) {
    pthread_t th[8]; cw_t cc[8];
    int64_t t0 = now_ms();
    for (int i = 0; i < 8; i++) pthread_create(&th[i], NULL, conc_exec, &cc[i]);
    int ok = 1;
    for (int i = 0; i < 8; i++) {
        pthread_join(th[i], NULL);
        ok &= cc[i].rc == SANDBOX_OK && cc[i].r.out_len == 5;
        sandbox_exec_result_free(&cc[i].r);
    }
    int64_t took = now_ms() - t0;
    check(ok, "concurrency: 8 simultaneous execs all answered");
    check(took < 1500, "concurrency: they overlap (8 x 0.3 s in well under 2.4 s)");

    // 20 long ops against a per-session cap of 16: the excess is refused with a
    // retryable code rather than queued without bound.
    pthread_t t2[20]; cw_t c2[20];
    for (int i = 0; i < 20; i++) pthread_create(&t2[i], NULL, conc_exec, &c2[i]);
    int served = 0, refused = 0;
    for (int i = 0; i < 20; i++) {
        pthread_join(t2[i], NULL);
        if (c2[i].rc == SANDBOX_OK) served++;
        else if (c2[i].rc == SANDBOX_ERR_GUEST_UNAVAILABLE) refused++;
        sandbox_exec_result_free(&c2[i].r);
    }
    check(served + refused == 20 && refused >= 1 && served >= 8, "limits: ops beyond the per-session cap get a retryable refusal");
}

static void test_ownership_and_protocol(void) {
    int fd = raw_connect();
    check(fd >= 0 && raw_guest(fd, 5, 7, GRPC_OP_STAT, g_ws) == SANDBOX_ERR_PERMISSION_DENIED,
          "auth: a session that does not own the sandbox is refused");
    check(raw_guest(fd, 0, 7, GRPC_OP_STAT, g_ws) == SANDBOX_ERR_INVALID_SPEC,
          "protocol: request_id 0 is refused for guest ops");
    close(fd);

    // A session that owns a sandbox whose guest channel is gone.
    ipc_server_test_grant_next_session(8);
    fd = raw_connect();
    check(fd >= 0 && raw_guest(fd, 9, 8, GRPC_OP_STAT, g_ws) == SANDBOX_ERR_GUEST_UNAVAILABLE,
          "errors: a sandbox without a guest channel -> GUEST_UNAVAILABLE");
    lifecycle_remove(8);  // see main(): a dropped session destroys what it owns
    close(fd);
    ipc_server_test_grant_next_session(9);
    fd = raw_connect();
    check(fd >= 0 && raw_guest(fd, 9, 9, GRPC_OP_STAT, g_ws) == SANDBOX_ERR_GUEST_UNAVAILABLE,
          "errors: a dead UDS (VM destroyed mid-flight) -> GUEST_UNAVAILABLE, not a hang");
    lifecycle_remove(9);
    close(fd);
}

// #26: the egress policy is settled in the daemon before anything is provisioned.
// There is no pool here, so a policy the daemon accepts reaches the "pool not
// configured" refusal (SANDBOX_ERR_INTERNAL) and one it rejects stops earlier
// with INVALID_SPEC -- the two outcomes tell the cases apart.
static sandbox_error_t create_with(const char** allow, int deny_all) {
    sandbox_spec_t sp;
    memset(&sp, 0, sizeof(sp));
    sp.memory_mib = 128;
    sp.vcpu_count = 1;
    sp.egress_allow = allow;
    sp.egress_deny_all = deny_all;
    sandbox_handle_t* h = NULL;
    sandbox_error_t rc = sandbox_create(&sp, &h);
    if (h) sandbox_destroy(h);
    return rc;
}

static void test_egress_policy(void) {
    // The daemon-wide list is "pypi.org,*.pythonhosted.org" (set in main()).
    CHECK_RC(create_with(NULL, 0), SANDBOX_ERR_INTERNAL, "egress: no policy inherits the daemon list");
    const char* ok1[] = {"pypi.org", NULL};
    CHECK_RC(create_with(ok1, 0), SANDBOX_ERR_INTERNAL, "egress: a listed host is accepted");
    const char* ok2[] = {"files.pythonhosted.org:443", "pypi.org:443", NULL};
    CHECK_RC(create_with(ok2, 0), SANDBOX_ERR_INTERNAL, "egress: narrower than the daemon list is accepted");
    CHECK_RC(create_with(NULL, 1), SANDBOX_ERR_INTERNAL, "egress: deny-all is accepted");
    const char* evil[] = {"evil.example", NULL};
    CHECK_RC(create_with(evil, 0), SANDBOX_ERR_INVALID_SPEC, "egress: a host outside the daemon list is refused");
    const char* mixed[] = {"pypi.org", "evil.example", NULL};
    CHECK_RC(create_with(mixed, 0), SANDBOX_ERR_INVALID_SPEC, "egress: one bad entry refuses the whole policy");
    const char* star[] = {"*", NULL};
    CHECK_RC(create_with(star, 0), SANDBOX_ERR_INVALID_SPEC, "egress: a session cannot ask for '*'");
    const char* wide[] = {"*.org", NULL};
    CHECK_RC(create_with(wide, 0), SANDBOX_ERR_INVALID_SPEC, "egress: a wider wildcard than the daemon's is refused");
    const char* junk[] = {"not a host", NULL};
    CHECK_RC(create_with(junk, 0), SANDBOX_ERR_INVALID_SPEC, "egress: a malformed entry is refused");
    CHECK_RC(create_with(ok1, 1), SANDBOX_ERR_INVALID_SPEC, "egress: deny-all plus entries is a contradiction");
    const char* many[IPC_MAX_EGRESS + 2];
    for (int i = 0; i < IPC_MAX_EGRESS + 1; i++) many[i] = "pypi.org";
    many[IPC_MAX_EGRESS + 1] = NULL;
    CHECK_RC(create_with(many, 0), SANDBOX_ERR_INVALID_SPEC, "egress: too many entries is refused client-side");
}

int main(void) {
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    setvbuf(stdout, NULL, _IOLBF, 0);
    snprintf(g_dir, sizeof(g_dir), "/tmp/sbipcg-%d", (int)getpid());
    snprintf(g_ws, sizeof(g_ws), "%s/ws", g_dir);
    snprintf(g_uds, sizeof(g_uds), "%s/vsock.sock", g_dir);
    snprintf(g_ipc, sizeof(g_ipc), "%s/ipc.sock", g_dir);
    if (mkdir(g_dir, 0700) != 0 || mkdir(g_ws, 0755) != 0) { perror("mkdir"); return 1; }

    g_gsrv = grpc_server_new(g_ws, NULL);
    g_uds_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un ua = { .sun_family = AF_UNIX };
    strcpy(ua.sun_path, g_uds);
    if (!g_gsrv || bind(g_uds_fd, (struct sockaddr*)&ua, sizeof(ua)) != 0 || listen(g_uds_fd, 64) != 0) {
        perror("uds");
        return 1;
    }
    pthread_t t_step, t_acc, t_ipc;
    pthread_create(&t_step, NULL, guest_step_thread, NULL);
    pthread_create(&t_acc, NULL, uds_accept_thread, NULL);

    // Sandboxes 7 (live), 8 (no channel), 9 (a UDS path that does not exist).
    vm_handle_t* vm7 = calloc(1, sizeof(*vm7));
    vm_handle_t* vm8 = calloc(1, sizeof(*vm8));
    vm_handle_t* vm9 = calloc(1, sizeof(*vm9));
    vm7->sandbox_id = 7; snprintf(vm7->vsock_uds, sizeof(vm7->vsock_uds), "%s", g_uds);
    vm8->sandbox_id = 8;
    vm9->sandbox_id = 9; snprintf(vm9->vsock_uds, sizeof(vm9->vsock_uds), "%s/gone.sock", g_dir);
    lifecycle_track(vm7); lifecycle_track(vm8); lifecycle_track(vm9);

    ipc_server_set_allowed_services("pypi.org,*.pythonhosted.org");
    pthread_create(&t_ipc, NULL, ipc_thread, NULL);
    for (int i = 0; i < 200 && access(g_ipc, F_OK) != 0; i++) usleep(10000);

    ipc_server_test_grant_next_session(7);
    if (sandbox_init(g_ipc) != SANDBOX_OK) { fprintf(stderr, "sandbox_init failed\n"); return 1; }
    g_h = lifecycle_test_handle(7);
    sandbox_fstat_t probe;
    // A round trip proves the session was accepted (and granted) before we go on.
    for (int i = 0; i < 100 && sandbox_stat(g_h, g_ws, &probe) != SANDBOX_OK; i++) usleep(20000);

    test_exec();
    test_files();
    test_paths_denied();
    test_list();
    test_concurrency_and_limits();
    test_ownership_and_protocol();
    test_egress_policy();

    // Take the fake VM out of the registry *before* the session drops: the server
    // tears a dropped session's VMs down with the real vmm_destroy(), which must
    // not find (and free) a handle that is not a real VM.
    lifecycle_remove(7);
    sandbox_cleanup();
    ipc_server_request_stop();
    pthread_join(t_ipc, NULL);
    __atomic_store_n(&g_stop, 1, __ATOMIC_RELEASE);
    shutdown(g_uds_fd, SHUT_RDWR);
    close(g_uds_fd);
    pthread_join(t_step, NULL);
    pthread_cancel(t_acc);
    pthread_join(t_acc, NULL);
    grpc_server_free(g_gsrv);
    free(g_h); free(vm7); free(vm8); free(vm9);

    char cmd[PATH_MAX + 16];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* best effort */ }
    printf("[test] ipc_guest: %d/%d passed\n", g_total - g_fail, g_total);
    return g_fail ? 1 : 0;
}
