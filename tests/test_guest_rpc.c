// SPDX-License-Identifier: GPL-2.0-only
// test_guest_rpc.c -- #24: exec and file RPC, the real guest server against the
// real host client, with no VM.
//
// The server (src/guest_rpc_server.c) is the code the guest agent links; it takes
// an already-accepted fd, so a socketpair stands in for the vsock connection and
// every operation runs for real: processes are forked, files are written, process
// groups are killed. What a socketpair cannot show is the transport itself (the
// CID check, Firecracker's UDS handshake); tests/test_vsock_peer.c covers the
// former and the privileged suite (tests/test_vmm.c) boots a guest for the latter.
//
// No root and no KVM: runs on the hosted CI too.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "guest_rpc.h"

static int g_fail, g_total;

static void check(int cond, const char* msg) {
    g_total++;
    printf("[test] %-62s %s\n", msg, cond ? "PASS" : "FAIL");
    if (!cond) g_fail++;
}

// ── harness: one server, driven by a thread ─────────────────────────────────

static grpc_server_t* g_srv;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_stop;  // atomic: read by helper threads, set by main
static int g_ready = 1;
static char g_root[128];

static int pre_op(void) { return g_ready ? 0 : -1; }

static void* server_thread(void* a) {
    (void)a;
    while (!__atomic_load_n(&g_stop, __ATOMIC_ACQUIRE)) {
        pthread_mutex_lock(&g_mu);
        grpc_server_step(g_srv);
        pthread_mutex_unlock(&g_mu);
        usleep(200);
    }
    return NULL;
}

// A fresh client fd whose peer end the server owns.
static int conn_new(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) return -1;
    pthread_mutex_lock(&g_mu);
    grpc_server_adopt(g_srv, sv[1]);
    pthread_mutex_unlock(&g_mu);
    return sv[0];
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

typedef struct { char out[1 << 16]; size_t no; char err[4096]; size_t ne; size_t tot_out, tot_err; } cap_t;

static void on_chunk(int is_err, const uint8_t* d, size_t n, void* ud) {
    cap_t* c = ud;
    if (is_err) {
        c->tot_err += n;
        if (c->ne + n < sizeof(c->err)) { memcpy(c->err + c->ne, d, n); c->ne += n; }
    } else {
        c->tot_out += n;
        if (c->no + n < sizeof(c->out)) { memcpy(c->out + c->no, d, n); c->no += n; }
    }
}

static int run_exec(const char* const* argv, uint32_t argc, uint32_t flags, const char* cwd,
                    uint32_t timeout_ms, uint32_t max_out, const char* in, cap_t* cap,
                    grpc_exec_res_t* res, char* msg) {
    grpc_exec_req_t rq = { .cwd = cwd, .argv = argv, .argc = argc, .flags = flags,
                           .timeout_ms = timeout_ms, .max_output = max_out,
                           .stdin_data = (const uint8_t*)in, .stdin_len = in ? strlen(in) : 0 };
    memset(cap, 0, sizeof(*cap));
    return grpc_exec(conn_new(), &rq, on_chunk, cap, 20000, res, msg, 160);
}

static int sh(const char* script, uint32_t timeout_ms, uint32_t max_out, const char* in,
              cap_t* cap, grpc_exec_res_t* res) {
    const char* a[1] = { script };
    char msg[160];
    return run_exec(a, 1, GRPC_F_SHELL, NULL, timeout_ms, max_out, in, cap, res, msg);
}

static int pid_alive(long pid) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%ld/stat", pid);
    FILE* f = fopen(p, "r");
    if (!f) return 0;
    char buf[256];
    int alive = 0;
    if (fgets(buf, sizeof(buf), f)) {
        char* rp = strrchr(buf, ')');
        alive = rp && rp[2] != 'Z' && rp[2] != 'X';  // a zombie is already dead
    }
    fclose(f);
    return alive;
}

static int dies_within(long pid, int ms) {
    int64_t end = now_ms() + ms;
    while (now_ms() < end) {
        if (!pid_alive(pid)) return 1;
        usleep(20000);
    }
    return !pid_alive(pid);
}

static int rd_file(const char* path, char* b, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, b, cap - 1);
    close(fd);
    if (n < 0) return -1;
    b[n] = '\0';
    return (int)n;
}

static char* P(const char* rel, char* buf, size_t cap) {
    snprintf(buf, cap, "%s/%s", g_root, rel);
    return buf;
}

// ── tests ───────────────────────────────────────────────────────────────────

static void test_paths(void) {
    char o[64];
    check(grpc_path_canon("/workspace//a/b/", o, sizeof(o)) == 0 && !strcmp(o, "/workspace/a/b"),
          "paths: duplicate and trailing slashes canonicalise");
    check(grpc_path_canon("/", o, sizeof(o)) == 0 && !strcmp(o, "/"), "paths: root");
    check(grpc_path_canon("/workspace/../etc", o, sizeof(o)) < 0, "paths: '..' refused, not resolved");
    check(grpc_path_canon("/workspace/./x", o, sizeof(o)) < 0, "paths: '.' refused");
    check(grpc_path_canon("workspace/x", o, sizeof(o)) < 0, "paths: relative refused");
    check(grpc_path_canon("", o, sizeof(o)) < 0, "paths: empty refused");
    check(grpc_path_canon("/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                          o, sizeof(o)) < 0, "paths: over-long refused");
    check(grpc_path_within("/workspace/a", "/workspace") && grpc_path_within("/workspace", "/workspace"),
          "paths: inside root");
    check(!grpc_path_within("/workspace2/a", "/workspace") && !grpc_path_within("/etc", "/workspace"),
          "paths: sibling prefix is not inside");
}

static void test_codec(void) {
    uint8_t b[64];
    grpc_wr_t w;
    grpc_wr_init(&w, b, sizeof(b));
    grpc_wr_u8(&w, 7); grpc_wr_u32(&w, 0xdeadbeef); grpc_wr_u64(&w, 0x0102030405060708ull);
    grpc_wr_str(&w, "hi");
    grpc_rd_t r;
    grpc_rd_init(&r, b, w.len);
    uint32_t n;
    int ok = grpc_rd_u8(&r) == 7 && grpc_rd_u32(&r) == 0xdeadbeef &&
             grpc_rd_u64(&r) == 0x0102030405060708ull;
    const char* s = grpc_rd_str(&r, &n);
    check(ok && s && n == 2 && !memcmp(s, "hi", 2) && !r.err && r.off == w.len, "codec: round trip");
    grpc_rd_init(&r, b, 3);
    grpc_rd_u32(&r);
    check(r.err, "codec: short read sets the sticky error");
    uint8_t big[4] = { 0xff, 0xff, 0xff, 0x7f };
    grpc_rd_init(&r, big, 4);
    (void)grpc_rd_str(&r, &n);
    check(r.err, "codec: string longer than the buffer is rejected");
    grpc_wr_init(&w, b, 4);
    grpc_wr_u64(&w, 1);
    check(w.err && w.len == 0, "codec: writer refuses to overflow");
    uint8_t h[GRPC_HDR_LEN], t; uint32_t l;
    grpc_frame_hdr(h, GRPC_T_RESULT, 99);
    check(grpc_frame_parse(h, &t, &l) == 0 && t == GRPC_T_RESULT && l == 99, "codec: frame header round trip");
    h[5] = 1;
    check(grpc_frame_parse(h, &t, &l) < 0, "codec: non-zero reserved byte rejected");
    grpc_frame_hdr(h, 1, GRPC_MAX_FRAME + 1);
    check(grpc_frame_parse(h, &t, &l) < 0, "codec: oversize frame rejected");
}

static void test_exec(void) {
    cap_t c; grpc_exec_res_t res; char msg[160];
    const char* echo[] = { "/bin/echo", "hello", "world" };
    int rc = run_exec(echo, 3, 0, NULL, 5000, 0, NULL, &c, &res, msg);
    check(rc == 0 && res.exit_code == 0 && !strcmp(c.out, "hello world\n"), "exec: argv run, stdout streamed, exit 0");

    rc = sh("echo out; echo err >&2; exit 7", 5000, 0, NULL, &c, &res);
    check(rc == 0 && res.exit_code == 7 && !strcmp(c.out, "out\n") && !strcmp(c.err, "err\n"),
          "exec: stderr kept apart, exit code 7 returned");

    rc = sh("cat; echo done", 5000, 0, "from stdin\n", &c, &res);
    check(rc == 0 && !strcmp(c.out, "from stdin\ndone\n"), "exec: stdin delivered then closed");

    rc = sh("kill -9 $$", 5000, 0, NULL, &c, &res);
    check(rc == 0 && res.exit_code == -1 && res.term_signal == SIGKILL, "exec: death by signal reported");

    rc = sh("pwd", 5000, 0, NULL, &c, &res);
    char want[160]; snprintf(want, sizeof(want), "%s\n", g_root);
    char real[PATH_MAX]; if (realpath(g_root, real)) snprintf(want, sizeof(want), "%.140s\n", real);
    check(rc == 0 && !strcmp(c.out, want), "exec: default cwd is the workspace");

    const char* en[] = { "FOO=bar baz" };
    grpc_exec_req_t rq = { .argv = (const char* const[]){ "echo \"$FOO|$HOME|${PATH%%:*}\"" }, .argc = 1,
                           .env = en, .envc = 1, .flags = GRPC_F_SHELL, .timeout_ms = 5000 };
    memset(&c, 0, sizeof(c));
    rc = grpc_exec(conn_new(), &rq, on_chunk, &c, 20000, &res, msg, sizeof(msg));
    check(rc == 0 && strstr(c.out, "bar baz|") && strstr(c.out, "|/usr/local/sbin"), "exec: env passed, HOME and PATH defaulted");

    const char* nx[] = { "/no/such/binary" };
    rc = run_exec(nx, 1, 0, NULL, 5000, 0, NULL, &c, &res, msg);
    check(rc == 0 && res.exit_code == 127, "exec: missing binary -> exit 127, not a hang");

    rc = run_exec(echo, 3, 0, "/etc", 5000, 0, NULL, &c, &res, msg);
    check(rc == GRPC_E_DENIED, "exec: cwd outside the workspace denied");
    rc = run_exec((const char* const[]){ "pwd" }, 1, GRPC_F_ALLOW_OUTSIDE, "/etc", 5000, 0, NULL, &c, &res, msg);
    check(rc == 0 && !strcmp(c.out, "/etc\n"), "exec: cwd outside allowed only with the explicit flag");
}

static void test_exec_limits(void) {
    cap_t c; grpc_exec_res_t res;
    int64_t t0 = now_ms();
    int rc = sh("sleep 30", 300, 0, NULL, &c, &res);
    int64_t took = now_ms() - t0;
    check(rc == 0 && (res.flags & GRPC_X_TIMED_OUT) && res.term_signal == SIGKILL && took < 5000,
          "limits: timeout kills the command promptly");

    // The group, not just the child: a background grandchild must die too.
    rc = sh("sleep 30 & echo $!; wait", 400, 0, NULL, &c, &res);
    long gpid = atol(c.out);
    check(rc == 0 && (res.flags & GRPC_X_TIMED_OUT) && gpid > 1 && dies_within(gpid, 3000),
          "limits: timeout kills the whole process group");

    rc = sh("yes", 20000, 1000, NULL, &c, &res);
    check(rc == 0 && (res.flags & GRPC_X_TRUNCATED) && c.tot_out == 1000, "limits: output capped at exactly max_output");

    rc = sh("head -c 3000000 /dev/zero", 20000, 0, NULL, &c, &res);
    check(rc == 0 && c.tot_out == 3000000 && res.exit_code == 0 && !(res.flags & GRPC_X_TRUNCATED),
          "limits: 3 MB streams through intact");

    // Host goes away mid-command => cancellation.
    int fd = conn_new();
    grpc_exec_req_t rq = { .argv = (const char* const[]){ "echo $$; sleep 30" }, .argc = 1,
                           .flags = GRPC_F_SHELL, .timeout_ms = 60000 };
    // Drive the request by hand so we can drop the connection after the pid.
    uint8_t buf[256]; grpc_wr_t w;
    grpc_wr_init(&w, buf, sizeof(buf));
    grpc_wr_u8(&w, GRPC_VERSION); grpc_wr_u8(&w, GRPC_OP_EXEC); grpc_wr_u32(&w, rq.flags);
    grpc_wr_str(&w, ""); grpc_wr_u32(&w, 1); grpc_wr_str(&w, rq.argv[0]);
    grpc_wr_u32(&w, 0); grpc_wr_u32(&w, 60000); grpc_wr_u32(&w, 0); grpc_wr_u32(&w, 0);
    uint8_t h[GRPC_HDR_LEN]; grpc_frame_hdr(h, GRPC_T_REQUEST, (uint32_t)w.len);
    ssize_t wr = write(fd, h, sizeof(h)); wr = write(fd, buf, w.len); (void)wr;
    long pid = 0;
    int64_t end = now_ms() + 5000;
    while (!pid && now_ms() < end) {
        uint8_t hh[GRPC_HDR_LEN], t; uint32_t l;
        if (read(fd, hh, sizeof(hh)) != (ssize_t)sizeof(hh) || grpc_frame_parse(hh, &t, &l) < 0) break;
        char body[64] = {0};
        if (l < sizeof(body) && read(fd, body, l) == (ssize_t)l && t == GRPC_T_STDOUT) pid = atol(body);
    }
    int alive_before = pid > 1 && pid_alive(pid);
    close(fd);
    check(alive_before && dies_within(pid, 3000), "limits: dropped connection cancels and kills the command");
}

static void test_files(void) {
    char p[256], p2[256], msg[160], b[64];
    int rc = grpc_write_file(conn_new(), P("a.txt", p, sizeof(p)), (const uint8_t*)"one", 3, 0644, 0, 5000, msg, sizeof(msg));
    check(rc == 0 && rd_file(p, b, sizeof(b)) == 3 && !strcmp(b, "one"), "files: write creates the file");

    rc = grpc_write_file(conn_new(), p, (const uint8_t*)"two!", 4, 0644, 0, 5000, msg, sizeof(msg));
    check(rc == 0 && rd_file(p, b, sizeof(b)) == 4 && !strcmp(b, "two!"), "files: write replaces atomically");
    char ls[512]; snprintf(ls, sizeof(ls), "ls -a %s | grep -c sbtmp", g_root);
    FILE* f = popen(ls, "r"); int leftover = 1; if (f) { if (fscanf(f, "%d", &leftover) != 1) leftover = 1; pclose(f); }
    check(leftover == 0, "files: no temp file left behind");

    rc = grpc_write_file(conn_new(), p, (const uint8_t*)"+x", 2, 0644, GRPC_F_APPEND, 5000, msg, sizeof(msg));
    check(rc == 0 && rd_file(p, b, sizeof(b)) == 6 && !strcmp(b, "two!+x"), "files: append");

    rc = grpc_write_file(conn_new(), p, (const uint8_t*)"z", 1, 0644, GRPC_F_EXCL, 5000, msg, sizeof(msg));
    check(rc == GRPC_E_EXISTS, "files: exclusive write refuses to overwrite");

    uint8_t* data; size_t len; int tr;
    rc = grpc_read_file(conn_new(), p, 0, 0, 5000, &data, &len, &tr, msg, sizeof(msg));
    check(rc == 0 && len == 6 && !memcmp(data, "two!+x", 6) && !tr, "files: read returns the content");
    free(data);
    rc = grpc_read_file(conn_new(), p, 2, 3, 5000, &data, &len, &tr, msg, sizeof(msg));
    check(rc == 0 && len == 3 && !memcmp(data, "o!+", 3) && tr, "files: ranged read, truncation flagged");
    free(data);
    rc = grpc_read_file(conn_new(), P("missing", p2, sizeof(p2)), 0, 0, 5000, &data, &len, &tr, msg, sizeof(msg));
    check(rc == GRPC_E_NOT_FOUND, "files: read of a missing file -> NOT_FOUND");

    rc = grpc_write_file(conn_new(), P("deep/er/f", p2, sizeof(p2)), (const uint8_t*)"x", 1, 0600, 0, 5000, msg, sizeof(msg));
    check(rc == GRPC_E_NOT_FOUND, "files: missing parents are an error by default");
    rc = grpc_write_file(conn_new(), p2, (const uint8_t*)"x", 1, 0600, GRPC_F_PARENTS, 5000, msg, sizeof(msg));
    check(rc == 0 && rd_file(p2, b, sizeof(b)) == 1, "files: parents created on request");

    grpc_stat_t st;
    rc = grpc_stat(conn_new(), p2, 0, 5000, &st, msg, sizeof(msg));
    check(rc == 0 && st.type == GRPC_FT_FILE && st.size == 1 && (st.mode & 0777) == 0600, "files: stat reports type, size, mode");
    rc = grpc_stat(conn_new(), P("deep", p2, sizeof(p2)), 0, 5000, &st, msg, sizeof(msg));
    check(rc == 0 && st.type == GRPC_FT_DIR, "files: stat of a directory");

    grpc_dirent_t* ent; size_t n;
    rc = grpc_list_dir(conn_new(), g_root, 0, 5000, &ent, &n, &tr, msg, sizeof(msg));
    int sa = 0, sd = 0;
    for (size_t i = 0; rc == 0 && i < n; i++) {
        if (!strcmp(ent[i].name, "a.txt") && ent[i].type == GRPC_FT_FILE) sa = 1;
        if (!strcmp(ent[i].name, "deep") && ent[i].type == GRPC_FT_DIR) sd = 1;
    }
    check(rc == 0 && sa && sd, "files: list shows files and directories");
    if (rc == 0) free(ent);

    rc = grpc_mkdir(conn_new(), P("m1/m2", p2, sizeof(p2)), 0755, 0, 5000, msg, sizeof(msg));
    check(rc == GRPC_E_NOT_FOUND, "files: mkdir without parents fails");
    rc = grpc_mkdir(conn_new(), p2, 0755, GRPC_F_PARENTS, 5000, msg, sizeof(msg));
    check(rc == 0, "files: mkdir -p");
    rc = grpc_mkdir(conn_new(), p2, 0755, GRPC_F_PARENTS, 5000, msg, sizeof(msg));
    check(rc == 0, "files: mkdir -p on an existing directory is fine");
    rc = grpc_mkdir(conn_new(), p2, 0755, 0, 5000, msg, sizeof(msg));
    check(rc == GRPC_E_EXISTS, "files: plain mkdir on an existing directory -> EXISTS");

    rc = grpc_remove(conn_new(), P("m1", p2, sizeof(p2)), 0, 5000, msg, sizeof(msg));
    check(rc != 0, "files: removing a non-empty directory needs recursive");
    rc = grpc_remove(conn_new(), p2, GRPC_F_RECURSIVE, 5000, msg, sizeof(msg));
    struct stat sb;
    check(rc == 0 && stat(p2, &sb) != 0, "files: recursive remove");
    rc = grpc_remove(conn_new(), p, 0, 5000, msg, sizeof(msg));
    check(rc == 0 && stat(p, &sb) != 0, "files: remove a file");
    rc = grpc_remove(conn_new(), p, 0, 5000, msg, sizeof(msg));
    check(rc == GRPC_E_NOT_FOUND, "files: remove of a missing file -> NOT_FOUND");
}

static void test_file_limits(void) {
    char p[256], msg[160];
    size_t big = GRPC_MAX_FILE;
    uint8_t* blob = malloc(big + 1);
    memset(blob, 'q', big + 1);
    int rc = grpc_write_file(conn_new(), P("big", p, sizeof(p)), blob, big, 0644, 0, 20000, msg, sizeof(msg));
    struct stat sb;
    check(rc == 0 && stat(p, &sb) == 0 && (size_t)sb.st_size == big, "file limits: a file at the limit is written");
    uint8_t* data; size_t len; int tr;
    rc = grpc_read_file(conn_new(), p, 0, 0, 20000, &data, &len, &tr, msg, sizeof(msg));
    check(rc == 0 && len == big && !tr && !memcmp(data, blob, big), "file limits: and read back whole");
    free(data);
    rc = grpc_write_file(conn_new(), P("big2", p, sizeof(p)), blob, big + 1, 0644, 0, 20000, msg, sizeof(msg));
    check(rc == GRPC_E_TOO_LARGE && stat(p, &sb) != 0, "file limits: one byte over is refused, nothing written");
    rc = grpc_read_file(conn_new(), p, 0, GRPC_MAX_FILE + 1, 20000, &data, &len, &tr, msg, sizeof(msg));
    check(rc == GRPC_E_TOO_LARGE, "file limits: oversize max_bytes refused");
    free(blob);
}

static void test_evil_paths(void) {
    char p[256], msg[160], b[64];
    uint8_t* data; size_t len; int tr; grpc_stat_t st;
    int rc = grpc_read_file(conn_new(), "/etc/passwd", 0, 0, 5000, &data, &len, &tr, msg, sizeof(msg));
    check(rc == GRPC_E_DENIED, "evil: absolute path outside the workspace");
    rc = grpc_read_file(conn_new(), P("../../etc/passwd", p, sizeof(p)), 0, 0, 5000, &data, &len, &tr, msg, sizeof(msg));
    check(rc == GRPC_E_DENIED, "evil: '..' traversal");
    rc = grpc_read_file(conn_new(), "relative/path", 0, 0, 5000, &data, &len, &tr, msg, sizeof(msg));
    check(rc == GRPC_E_DENIED, "evil: relative path");
    char sib[200]; snprintf(sib, sizeof(sib), "%s2/x", g_root);
    rc = grpc_stat(conn_new(), sib, 0, 5000, &st, msg, sizeof(msg));
    check(rc == GRPC_E_DENIED, "evil: sibling directory sharing the prefix");

    // A symlink planted inside the workspace that points out of it.
    char link[256]; P("escape", link, sizeof(link));
    if (symlink("/etc", link) != 0) perror("symlink");
    char via[300]; snprintf(via, sizeof(via), "%s/passwd", link);
    rc = grpc_read_file(conn_new(), via, 0, 0, 5000, &data, &len, &tr, msg, sizeof(msg));
    check(rc == GRPC_E_DENIED, "evil: read through a symlinked directory");
    rc = grpc_write_file(conn_new(), via, (const uint8_t*)"x", 1, 0644, 0, 5000, msg, sizeof(msg));
    check(rc == GRPC_E_DENIED, "evil: write through a symlinked directory");
    rc = grpc_list_dir(conn_new(), link, 0, 5000, (grpc_dirent_t**)&data, &len, &tr, msg, sizeof(msg));
    check(rc == GRPC_E_DENIED, "evil: list a symlink that leaves the workspace");
    rc = grpc_write_file(conn_new(), P("deep2/x/../../../../etc/zz", p, sizeof(p)), (const uint8_t*)"x", 1, 0644, GRPC_F_PARENTS, 5000, msg, sizeof(msg));
    check(rc == GRPC_E_DENIED, "evil: parents + traversal");

    // A link to a file outside: read follows only if the target stays inside.
    struct stat pw_before;
    int have_pw = stat("/etc/passwd", &pw_before) == 0;
    char flink[256]; P("pw", flink, sizeof(flink));
    if (symlink("/etc/passwd", flink) != 0) perror("symlink");
    rc = grpc_read_file(conn_new(), flink, 0, 0, 5000, &data, &len, &tr, msg, sizeof(msg));
    check(rc == GRPC_E_DENIED, "evil: read of a file symlink that leaves the workspace");
    rc = grpc_write_file(conn_new(), flink, (const uint8_t*)"X", 1, 0644, 0, 5000, msg, sizeof(msg));
    check(rc == 0 && lstat(flink, &(struct stat){0}) == 0, "evil: write replaces the link itself");
    struct stat pw_after;
    check(have_pw && stat("/etc/passwd", &pw_after) == 0 && pw_after.st_size == pw_before.st_size &&
              pw_after.st_mtime == pw_before.st_mtime && pw_after.st_ino == pw_before.st_ino,
          "evil: the host file behind the link is untouched");
    check(rd_file(flink, b, sizeof(b)) == 1 && b[0] == 'X', "evil: the replacement is a regular file in the workspace");

    rc = grpc_remove(conn_new(), g_root, GRPC_F_RECURSIVE, 5000, msg, sizeof(msg));
    check(rc == GRPC_E_DENIED && access(g_root, F_OK) == 0, "evil: the workspace root itself cannot be removed");
    rc = grpc_remove(conn_new(), "/", GRPC_F_RECURSIVE | GRPC_F_ALLOW_OUTSIDE, 5000, msg, sizeof(msg));
    check(rc == GRPC_E_DENIED, "evil: '/' is never removable, even with the opt-in");

    // Embedded NUL: the policy and the syscall must not see different strings.
    int fd = conn_new();
    uint8_t buf[128]; grpc_wr_t w; grpc_wr_init(&w, buf, sizeof(buf));
    grpc_wr_u8(&w, GRPC_VERSION); grpc_wr_u8(&w, GRPC_OP_STAT); grpc_wr_u32(&w, 0);
    char evil[64]; int en = snprintf(evil, sizeof(evil), "%s/ok", g_root); evil[en] = '\0';
    memcpy(evil + en + 1, "/../../etc", 10);
    grpc_wr_u32(&w, (uint32_t)(en + 11)); grpc_wr_raw(&w, evil, (size_t)en + 11);
    grpc_reply_t rp;
    rc = grpc_call_fd(fd, buf, w.len, NULL, NULL, 5000, &rp);
    check(rc == 0 && rp.status == GRPC_E_BAD_REQUEST, "evil: NUL byte inside a path is a bad request");
    grpc_reply_free(&rp);
}

static int raw_reply(int fd, uint8_t* status) {
    uint8_t h[GRPC_HDR_LEN], t; uint32_t l;
    if (read(fd, h, sizeof(h)) != (ssize_t)sizeof(h) || grpc_frame_parse(h, &t, &l) < 0) return -1;
    uint8_t body[512];
    if (l > sizeof(body) || read(fd, body, l) != (ssize_t)l || t != GRPC_T_RESULT || l < 1) return -1;
    *status = body[0];
    return 0;
}

static void test_forged(void) {
    // "Forged" here means malformed or hostile frames from a peer that already
    // passed the CID check: none of them may crash, hang or be acted on.
    uint8_t st;
    int fd = conn_new();
    uint8_t bad[GRPC_HDR_LEN] = { 0, 0, 0, 0, GRPC_T_REQUEST, 0x7f };  // reserved byte set
    ssize_t w = write(fd, bad, sizeof(bad)); (void)w;
    check(raw_reply(fd, &st) == 0 && st == GRPC_E_BAD_REQUEST, "forged: non-zero reserved byte -> BAD_REQUEST");
    close(fd);

    fd = conn_new();
    uint8_t huge[GRPC_HDR_LEN]; grpc_frame_hdr(huge, GRPC_T_REQUEST, 0); huge[3] = 0x7f;
    w = write(fd, huge, sizeof(huge));
    check(raw_reply(fd, &st) == 0 && st == GRPC_E_BAD_REQUEST, "forged: 2 GiB frame length refused before allocating");
    close(fd);

    fd = conn_new();
    uint8_t wrongtype[GRPC_HDR_LEN]; grpc_frame_hdr(wrongtype, GRPC_T_RESULT, 0);
    w = write(fd, wrongtype, sizeof(wrongtype));
    check(raw_reply(fd, &st) == 0 && st == GRPC_E_BAD_REQUEST, "forged: a result frame sent as a request");
    close(fd);

    uint8_t body[8]; grpc_wr_t wr;
    for (int k = 0; k < 3; k++) {
        fd = conn_new();
        grpc_wr_init(&wr, body, sizeof(body));
        grpc_wr_u8(&wr, k == 0 ? 99 : GRPC_VERSION);     // version
        grpc_wr_u8(&wr, k == 1 ? 200 : GRPC_OP_STAT);    // op
        grpc_wr_u32(&wr, 0);
        if (k == 2) wr.len = 3;                          // truncated header
        uint8_t h[GRPC_HDR_LEN]; grpc_frame_hdr(h, GRPC_T_REQUEST, (uint32_t)wr.len);
        w = write(fd, h, sizeof(h)); w = write(fd, body, wr.len);
        int ok = raw_reply(fd, &st) == 0;
        check(ok && st == (k == 0 ? GRPC_E_BAD_VERSION : GRPC_E_BAD_REQUEST),
              k == 0 ? "forged: unknown protocol version" : k == 1 ? "forged: unknown operation" : "forged: truncated request header");
        close(fd);
    }

    // A request that dies mid-frame must not leak a slot or wedge the server.
    for (int i = 0; i < 40; i++) {
        fd = conn_new();
        uint8_t h[GRPC_HDR_LEN]; grpc_frame_hdr(h, GRPC_T_REQUEST, 1000);
        w = write(fd, h, sizeof(h)); w = write(fd, "abc", 3);
        close(fd);
    }
    usleep(100000);
    cap_t c; grpc_exec_res_t res;
    check(sh("echo alive", 5000, 0, NULL, &c, &res) == 0 && !strcmp(c.out, "alive\n"),
          "forged: 40 half-sent requests later the server still serves");
}

static void test_limits_and_state(void) {
    // Connection limit: the 17th concurrent connection is told BUSY, not left hanging.
    int fds[16];
    for (int i = 0; i < 16; i++) fds[i] = conn_new();
    int extra = conn_new();
    uint8_t st = 0xff;
    check(raw_reply(extra, &st) == 0 && st == GRPC_E_BUSY, "state: connection limit answers BUSY");
    close(extra);
    for (int i = 0; i < 16; i++) close(fds[i]);
    usleep(100000);

    g_ready = 0;
    char msg[160]; grpc_stat_t s;
    int rc = grpc_stat(conn_new(), g_root, 0, 5000, &s, msg, sizeof(msg));
    check(rc == GRPC_E_NOT_READY, "state: unmounted workspace -> NOT_READY");
    g_ready = 1;
    rc = grpc_stat(conn_new(), g_root, 0, 5000, &s, msg, sizeof(msg));
    check(rc == 0 && s.type == GRPC_FT_DIR, "state: ready again, same server");
}

typedef struct { int id; int ok; } conc_t;

static void* conc_worker(void* a) {
    conc_t* c = a;
    char path[256], want[64], got[64], script[96], msg[160];
    snprintf(path, sizeof(path), "%s/conc-%d", g_root, c->id);
    snprintf(want, sizeof(want), "payload-%d", c->id);
    int ok = 1;
    for (int i = 0; i < 5 && ok; i++) {
        cap_t cap; grpc_exec_res_t res;
        snprintf(script, sizeof(script), "sleep 0.05; echo id-%d", c->id);
        const char* av[1] = { script };
        grpc_exec_req_t rq = { .argv = av, .argc = 1, .flags = GRPC_F_SHELL, .timeout_ms = 10000 };
        memset(&cap, 0, sizeof(cap));
        ok &= grpc_exec(conn_new(), &rq, on_chunk, &cap, 20000, &res, msg, sizeof(msg)) == 0;
        char exp[32]; snprintf(exp, sizeof(exp), "id-%d\n", c->id);
        ok &= !strcmp(cap.out, exp) && res.exit_code == 0;
        ok &= grpc_write_file(conn_new(), path, (const uint8_t*)want, strlen(want), 0644, 0, 10000, msg, sizeof(msg)) == 0;
        uint8_t* d; size_t l; int tr;
        if (ok && grpc_read_file(conn_new(), path, 0, 0, 10000, &d, &l, &tr, msg, sizeof(msg)) == 0) {
            memcpy(got, d, l < sizeof(got) ? l : sizeof(got) - 1); got[l < sizeof(got) ? l : sizeof(got) - 1] = 0;
            ok &= !strcmp(got, want);
            free(d);
        } else ok = 0;
    }
    c->ok = ok;
    return NULL;
}

static void test_concurrency(void) {
    pthread_t th[8]; conc_t cc[8];
    int64_t t0 = now_ms();
    for (int i = 0; i < 8; i++) { cc[i].id = i; cc[i].ok = 0; pthread_create(&th[i], NULL, conc_worker, &cc[i]); }
    int all = 1;
    for (int i = 0; i < 8; i++) { pthread_join(th[i], NULL); all &= cc[i].ok; }
    int64_t took = now_ms() - t0;
    check(all, "concurrency: 8 clients x (exec + write + read) never cross streams");
    // 8 x 5 x 50 ms of sleeps serially is 2 s; overlapping they finish well under.
    check(took < 1800, "concurrency: operations genuinely overlap, not queue");
}

int main(void) {
    // Orphaned grandchildren reparent to us, and the server reaps them: the
    // same arrangement as the guest agent being PID 1.
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    setvbuf(stdout, NULL, _IOLBF, 0);

    snprintf(g_root, sizeof(g_root), "/tmp/sbrpc-test-%d", (int)getpid());
    if (mkdir(g_root, 0755) != 0) { perror("mkdir"); return 1; }
    char sibling[160]; snprintf(sibling, sizeof(sibling), "%s2", g_root);
    mkdir(sibling, 0755);

    g_srv = grpc_server_new(g_root, pre_op);
    if (!g_srv) { fprintf(stderr, "server_new failed\n"); return 1; }
    pthread_t th;
    pthread_create(&th, NULL, server_thread, NULL);

    test_paths();
    test_codec();
    test_exec();
    test_exec_limits();
    test_files();
    test_file_limits();
    test_evil_paths();
    test_forged();
    test_limits_and_state();
    test_concurrency();

    __atomic_store_n(&g_stop, 1, __ATOMIC_RELEASE);
    pthread_join(th, NULL);
    grpc_server_free(g_srv);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s' '%s'", g_root, sibling);
    if (system(cmd) != 0) { /* best effort */ }

    printf("[test] guest_rpc: %d/%d passed\n", g_total - g_fail, g_total);
    return g_fail ? 1 : 0;
}
