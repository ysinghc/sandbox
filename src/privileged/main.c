// SPDX-License-Identifier: GPL-2.0-only
// main.c -- #9: sandbox-privileged, the root half of the daemon.
//
// The unprivileged daemon (User=sandboxd) cannot create taps, nftables rules,
// device nodes, bind mounts, chroots, uid transitions, or cgroup entries, nor
// kill or reap VMMs. This small root helper does exactly that and nothing
// else, over the protocol in include/privsep.h on a SOCK_SEQPACKET unix
// socket. Exactly one peer uid (the daemon's, resolved from --daemon-user at
// startup) may connect; every request is re-validated on receipt, including
// path roots and file ownership, so a compromised daemon can only aim
// privileged operations at its own files.
//
// Crash semantics (unchanged from the pre-#9 daemon, see §15):
//   * daemon restart reuses vm ids from vm-1 while the helper still tracks
//     the old VMs, so the two units restart together (BindsTo=); a lone
//     helper restart makes live guests un-trackable, exactly as a lone
//     daemon restart orphaned them before.
//   * a dead child is reaped opportunistically (SIGCHLD flag + waitpid in
//     the loop) and its status cached, so POLL stays accurate and no zombie
//     accumulates when the daemon never asks.
//   * the helper never kills guests on its own exit; SWEEP reclaims only
//     non-live jails.
#define _GNU_SOURCE  // struct ucred for the SO_PEERCRED gate
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cgroup.h"
#include "jailer.h"
#include "network_manager.h"
#include "privsep.h"
#include "privsep_service.h"
#include "snapshot_manager.h"
#include "version.h"
#include "workspace.h"

#define SNAPSHOT_ROOT_DEFAULT "/var/lib/sandbox-engine/snapshots"

typedef struct {
    const char* sock_path;
    const char* daemon_user;
    uid_t daemon_uid;
    gid_t daemon_gid;
    const char* jail_root;
    const char* snapshot_root;
    const char* workspace_root;
} helper_config_t;

// ---- children ------------------------------------------------------------
// One slot per spawned VM. The helper is the parent, so only it can reap;
// POLL reports the cached status once the child is gone.
typedef struct {
    bool used;
    char vm_id[PRIVSEP_VM_ID_MAX + 1];
    pid_t pid;
    char jail_dir[PATH_MAX];
    char cgroup_dir[PATH_MAX];
    // Writable binds the helper chowned to the jailed uid; TEARDOWN hands
    // them back to the daemon so the next SPAWN's ownership check passes.
    char workspace[PATH_MAX];
    char outdir[PATH_MAX];
    bool exited;
    int exit_status;  // exit code, or 0 when signalled
    int termsig;      // signal number, or 0 when exited
    int jail_step;    // 1-16 when the jailer died pre-exec, else 0
} child_t;

static child_t g_children[PRIVSEP_MAX_CHILDREN];
static volatile sig_atomic_t g_sigchld = 0;

static void on_sigchld(int sig) {
    (void)sig;
    g_sigchld = 1;
}

static void log_msg(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[privileged] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static child_t* child_find(const char* vm_id) {
    for (size_t i = 0; i < PRIVSEP_MAX_CHILDREN; i++)
        if (g_children[i].used && strcmp(g_children[i].vm_id, vm_id) == 0)
            return &g_children[i];
    return NULL;
}

static child_t* child_find_pid(pid_t pid) {
    for (size_t i = 0; i < PRIVSEP_MAX_CHILDREN; i++)
        if (g_children[i].used && !g_children[i].exited &&
            g_children[i].pid == pid)
            return &g_children[i];
    return NULL;
}

// Record a wait status the way cold_fail() reads it: exit codes 1-16 are the
// numbered jailer steps (see spawn_jailed), anything else is Firecracker.
static void child_mark_exited(child_t* c, int st) {
    c->exited = true;
    c->exit_status = 0;
    c->termsig = 0;
    c->jail_step = 0;
    if (WIFEXITED(st)) {
        c->exit_status = WEXITSTATUS(st);
        if (c->exit_status >= 1 && c->exit_status <= 16)
            c->jail_step = c->exit_status;
    } else if (WIFSIGNALED(st)) {
        c->termsig = WTERMSIG(st);
    }
}

// Reap whatever died into the table. Runs in the main loop (never in the
// signal handler), so it cannot race POLL/TEARDOWN's waitpid calls: this
// process is single-threaded and the handler only raises the flag.
static void reap_children(void) {
    for (;;) {
        int st = 0;
        pid_t pid = waitpid(-1, &st, WNOHANG);
        if (pid <= 0) break;  // none left (or ECHILD)
        child_t* c = child_find_pid(pid);
        if (!c) {
            log_msg("reaped untracked pid %d", (int)pid);
            continue;
        }
        child_mark_exited(c, st);
    }
}

// ---- request validation --------------------------------------------------
// Template inputs must resolve inside the snapshot root: the store is
// operator-written (sandbox-cli template builds, never the daemon), but the
// realpath check keeps a misconfigured store from becoming a host-wide
// read primitive via a planted symlink.
static bool input_under_root(const char* path, const char* root, char* resolved,
                             size_t n) {
    if (!privsep_path_ok(path, &root, 1)) return false;
    char canon[PATH_MAX];
    if (!realpath(path, canon)) return false;
    if (!privsep_path_ok(canon, &root, 1)) return false;
    if (snprintf(resolved, n, "%s", canon) >= (int)n) return false;
    return true;
}

// Files the helper chowns to the jailed uid (the writable binds) must already
// belong to the daemon: no privilege is gained by re-owning your own file,
// and another principal's file can never be named.
static bool daemon_owned(const char* path, const struct stat* st,
                         const helper_config_t* cfg, bool want_dir) {
    (void)path;
    if (want_dir ? !S_ISDIR(st->st_mode) : !S_ISREG(st->st_mode)) return false;
    return st->st_uid == cfg->daemon_uid;
}

// The serial log is opened O_CREAT|O_APPEND as root, so it is scoped tighter
// than the jail root: exactly <jail-root>/<vm-id>/<basename>, never a
// symlink, never an existing non-regular file.
static bool serial_ok(const char* path, const char* jail_dir) {
    size_t dl = strlen(jail_dir);
    size_t pl = strlen(path);
    if (pl <= dl + 1 || memcmp(path, jail_dir, dl) != 0 ||
        path[dl] != '/')
        return false;
    const char* base = path + dl + 1;
    if (strchr(base, '/') || !privsep_vm_id_ok(base)) return false;
    struct stat st;
    if (lstat(path, &st) < 0) return errno == ENOENT;
    if (S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode)) return false;
    return true;
}

// ---- handlers ------------------------------------------------------------
// Each fills the reply record and returns its length (0 = connection dead).
// REQUEST means the caller's bug (nothing ran); FAILED means it ran and the
// errno is real; NOT_FOUND names an untracked VM.

static size_t handle_hello(const uint8_t* body, uint32_t len, uint8_t* out,
                           size_t cap) {
    if (privsep_parse_hello(body, len) != 0)
        return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);
    return privsep_reply_hello(out, cap);
}

static size_t handle_net_up(const uint8_t* body, uint32_t len, uint8_t* out,
                            size_t cap) {
    privsep_req_id_t req;
    if (privsep_parse_id(body, len, &req) != 0)
        return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);
    vm_network_t net;
    memset(&net, 0, sizeof(net));
    if (network_setup(req.vm_id, &net) < 0) {
        int e = errno;
        log_msg("NET_UP %s: %s", req.vm_id, strerror(e));
        return privsep_reply_err(out, cap, PRIVSEP_ERR_FAILED, e, 0);
    }
    uint32_t host_ip = 0, guest_ip = 0;
    if (network_subnet_addrs(req.vm_id, &host_ip, &guest_ip) < 0) {
        int e = errno;
        network_cleanup(&net);
        return privsep_reply_err(out, cap, PRIVSEP_ERR_FAILED, e, 0);
    }
    log_msg("NET_UP %s -> %s", req.vm_id, net.tap_name);
    return privsep_reply_net_up(out, cap, net.tap_name, host_ip, guest_ip);
}

static size_t handle_net_down(const uint8_t* body, uint32_t len, uint8_t* out,
                              size_t cap) {
    privsep_req_id_t req;
    if (privsep_parse_id(body, len, &req) != 0)
        return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);
    // network_cleanup is best-effort and always succeeds, so DOWN is
    // idempotent: bringing down a VM with no tap still answers OK.
    vm_network_t net;
    memset(&net, 0, sizeof(net));
    net.tap_fd = -1;
    if (privsep_tap_name(req.vm_id, net.tap_name, sizeof(net.tap_name)) != 0 ||
        network_subnet_addrs(req.vm_id, &(uint32_t){ 0 }, &net.guest_ip) < 0)
        return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);
    network_cleanup(&net);
    log_msg("NET_DOWN %s", req.vm_id);
    return privsep_reply_ok_empty(out, cap);
}

// Best-effort cgroup for a restore: the memory bound comes from the manifest
// sitting next to the vmstate file, exactly as vmm_restore computed it (guest
// bytes plus the slack knob, no swap, whole-group OOM kill). Cold boots carry
// no vmstate and run unmetered, as before.
static void spawn_cgroup(const char* vm_id, const char* vmstate,
                         char* procs_out, size_t n, char* dir_out, size_t dir_n) {
    if (procs_out && n) procs_out[0] = '\0';
    if (dir_out && dir_n) dir_out[0] = '\0';
    if (!vmstate || !*vmstate || !cgroup_enabled()) return;
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", vmstate);
    char* slash = strrchr(dir, '/');
    if (!slash) return;
    *slash = '\0';
    char mpath[PATH_MAX];
    if (snprintf(mpath, sizeof(mpath), "%s/manifest.bin", dir) >= (int)sizeof(mpath))
        return;
    snap_manifest_t* m = NULL;
    if (read_manifest_file(mpath, &m) < 0 || !m) return;
    uint64_t mem_mib = m->guest_mem_size / (1024 * 1024);
    free(m);
    cgroup_limits_t clim;
    memset(&clim, 0, sizeof(clim));
    const char* slack = getenv("SANDBOX_CGROUP_SLACK_MIB");
    uint64_t slack_mib = (slack && *slack) ? strtoull(slack, NULL, 10) : 64;
    clim.memory_max_mib = mem_mib ? mem_mib + slack_mib : 0;
    clim.memory_swap_max_mib = 0;
    const char* cpu = getenv("SANDBOX_CGROUP_CPU_MAX");
    clim.cpu_max = (cpu && *cpu) ? cpu : "max";
    clim.oom_group = true;
    char cdir[PATH_MAX] = "";
    if (cgroup_add_vm(vm_id, &clim, cdir, sizeof(cdir)) == 0 && cdir[0]) {
        snprintf(procs_out, n, "%s/cgroup.procs", cdir);
        snprintf(dir_out, dir_n, "%s", cdir);
    }
}

static size_t handle_spawn(const helper_config_t* cfg, const uint8_t* body,
                           uint32_t len, uint8_t* out, size_t cap) {
    privsep_req_spawn_t req;
    if (privsep_parse_spawn(body, len, &req) != 0 ||
        !privsep_jail_ids_ok(req.jailer_uid, req.jailer_gid, cfg->daemon_uid,
                             cfg->daemon_gid) ||
        !privsep_spawn_flags_ok(req.flags))
        return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);

    char jail_dir[PATH_MAX];
    if (snprintf(jail_dir, sizeof(jail_dir), "%s/%s", cfg->jail_root,
                 req.vm_id) >= (int)sizeof(jail_dir))
        return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, ENAMETOOLONG,
                                 0);

    // Resolve the read-only inputs under the snapshot root.
    char kernel[PATH_MAX] = "", rootfs[PATH_MAX] = "", vmstate[PATH_MAX] = "",
         mem[PATH_MAX] = "";
    const char* in_paths[] = { req.kernel, req.rootfs, req.vmstate, req.mem };
    char* in_resolved[] = { kernel, rootfs, vmstate, mem };
    for (size_t i = 0; i < 4; i++) {
        if (!in_paths[i][0]) continue;
        if (!input_under_root(in_paths[i], cfg->snapshot_root, in_resolved[i],
                              PATH_MAX))
            return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);
    }
    // The writable binds must additionally belong to the daemon.
    char outdir[PATH_MAX] = "", workspace[PATH_MAX] = "";
    struct stat st;
    if (req.outdir[0]) {
        if (!input_under_root(req.outdir, cfg->snapshot_root, outdir,
                              sizeof(outdir)) ||
            stat(outdir, &st) < 0 || !daemon_owned(outdir, &st, cfg, true))
            return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);
    }
    if (req.workspace[0]) {
        if (!input_under_root(req.workspace, cfg->workspace_root, workspace,
                              sizeof(workspace)) ||
            stat(workspace, &st) < 0 || !daemon_owned(workspace, &st, cfg,
                                                      false))
            return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);
    }
    if (req.serial[0] && !serial_ok(req.serial, jail_dir))
        return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);

    child_t* slot = child_find(req.vm_id);
    if (slot && !slot->exited)
        return privsep_reply_err(out, cap, PRIVSEP_ERR_BUSY, EAGAIN, 0);
    if (!slot) {
        for (size_t i = 0; i < PRIVSEP_MAX_CHILDREN; i++)
            if (!g_children[i].used) {
                slot = &g_children[i];
                break;
            }
        if (!slot)
            return privsep_reply_err(out, cap, PRIVSEP_ERR_BUSY, EAGAIN, 0);
    }

    // A previous run killed before TEARDOWN leaves a stale jail whose api.sock
    // a new Firecracker cannot rebind; clear it first, as vmm_restore does.
    jail_cleanup(jail_dir);

    char cg_procs[PATH_MAX] = "", cg_dir[PATH_MAX] = "";
    spawn_cgroup(req.vm_id, vmstate, cg_procs, sizeof(cg_procs), cg_dir,
                 sizeof(cg_dir));
    jailer_config_t jcfg = { .jailer_uid = (uid_t)req.jailer_uid,
                             .jailer_gid = (gid_t)req.jailer_gid,
                             .cgroup_path = cg_procs[0] ? cg_procs : NULL,
                             .daemon_gid = cfg->daemon_gid };
    jail_files_t files = { .firecracker_bin = jailer_firecracker_bin(),
                           .kernel_path = kernel[0] ? kernel : NULL,
                           .rootfs_path = rootfs[0] ? rootfs : NULL,
                           .snap_state_src = vmstate[0] ? vmstate : NULL,
                           .snap_mem_src = mem[0] ? mem : NULL,
                           .out_dir = outdir[0] ? outdir : NULL,
                           .workspace_path = workspace[0] ? workspace : NULL };
    char* argv[8];
    int ai = 0;
    argv[ai++] = (char*)"/firecracker";
    argv[ai++] = (char*)"--api-sock";
    argv[ai++] = (char*)"/api.sock";
    argv[ai++] = (char*)"--id";
    argv[ai++] = req.vm_id;
    argv[ai++] = (char*)"--no-seccomp";
    if (req.flags & PRIVSEP_SPAWN_PCI) argv[ai++] = (char*)"--enable-pci";
    argv[ai++] = NULL;
    // NOTE: a child that dies in the jail sequence (steps 1-16) is reported
    // through POLL, not here: spawn_jailed returns the pid while the child is
    // still setting up, exactly as the in-process path behaved.
    pid_t pid = spawn_jailed(jail_dir, &jcfg, "/firecracker", argv, true,
                             (req.flags & PRIVSEP_SPAWN_SECCOMP) != 0, &files,
                             req.serial[0] ? req.serial : NULL);
    if (pid <= 0) {
        int e = errno;
        log_msg("SPAWN %s: %s", req.vm_id, strerror(e));
        return privsep_reply_err(out, cap, PRIVSEP_ERR_FAILED, e, 0);
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    strcpy(slot->vm_id, req.vm_id);
    slot->pid = pid;
    snprintf(slot->jail_dir, sizeof(slot->jail_dir), "%s", jail_dir);
    snprintf(slot->cgroup_dir, sizeof(slot->cgroup_dir), "%s", cg_dir);
    snprintf(slot->workspace, sizeof(slot->workspace), "%s", workspace);
    snprintf(slot->outdir, sizeof(slot->outdir), "%s", outdir);
    log_msg("SPAWN %s -> pid %d", req.vm_id, (int)pid);
    return privsep_reply_pid(out, cap, (int32_t)pid);
}

static size_t handle_poll(const uint8_t* body, uint32_t len, uint8_t* out,
                          size_t cap) {
    privsep_req_id_t req;
    if (privsep_parse_id(body, len, &req) != 0)
        return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);
    child_t* c = child_find(req.vm_id);
    if (!c)
        return privsep_reply_err(out, cap, PRIVSEP_ERR_NOT_FOUND, ENOENT, 0);
    if (!c->exited) {
        int st = 0;
        pid_t r = waitpid(c->pid, &st, WNOHANG);
        if (r < 0) {
            int e = errno;
            if (e != ECHILD)
                return privsep_reply_err(out, cap, PRIVSEP_ERR_FAILED, e, 0);
            // Reaped behind our back (never in this single-threaded loop, but
            // fail honest rather than hang): the child is gone.
            c->exited = true;
        } else if (r > 0) {
            child_mark_exited(c, st);
        }
    }
    if (!c->exited)
        return privsep_reply_poll(out, cap, PRIVSEP_POLL_RUNNING, 0, 0, 0);
    return privsep_reply_poll(out, cap, PRIVSEP_POLL_EXITED, c->exit_status,
                              c->termsig, c->jail_step);
}

static size_t handle_teardown(const helper_config_t* cfg, const uint8_t* body,
                              uint32_t len, uint8_t* out, size_t cap) {
    privsep_req_id_t req;
    if (privsep_parse_id(body, len, &req) != 0)
        return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);
    child_t* c = child_find(req.vm_id);
    // Untracked on purpose: cleaning a jail by name alone could detach a live
    // guest the helper no longer tracks (after its own restart). Crash
    // residue is SWEEP's job; it skips live jails via /proc.
    if (!c)
        return privsep_reply_err(out, cap, PRIVSEP_ERR_NOT_FOUND, ENOENT, 0);
    if (!c->exited) {
        // The VMM runs as the jailed uid; only root (here, not the daemon)
        // may signal and reap it.
        if (kill(c->pid, SIGKILL) < 0 && errno != ESRCH)
            log_msg("TEARDOWN %s: kill: %s", req.vm_id, strerror(errno));
        int st = 0;
        while (waitpid(c->pid, &st, 0) < 0 && errno == EINTR) {
        }
        c->exited = true;
    }
    if (c->cgroup_dir[0]) cgroup_remove_vm(c->cgroup_dir);
    // Hand the writable binds back to the daemon (best-effort: the VMM is
    // already reaped, so a failure here only affects the next SPAWN's
    // ownership check, which will then fail closed).
    if (c->workspace[0] &&
        chown(c->workspace, cfg->daemon_uid, cfg->daemon_gid) < 0)
        log_msg("TEARDOWN %s: chown back %s: %s", req.vm_id, c->workspace,
                strerror(errno));
    if (c->outdir[0] && chown(c->outdir, cfg->daemon_uid, cfg->daemon_gid) < 0)
        log_msg("TEARDOWN %s: chown back %s: %s", req.vm_id, c->outdir,
                strerror(errno));
    jail_cleanup(c->jail_dir);
    memset(c, 0, sizeof(*c));
    log_msg("TEARDOWN %s", req.vm_id);
    return privsep_reply_ok_empty(out, cap);
}

static size_t handle_sweep(const helper_config_t* cfg, const uint8_t* body,
                           uint32_t len, uint8_t* out, size_t cap) {
    uint32_t min_age = 0;
    if (privsep_parse_sweep(body, len, &min_age) != 0)
        return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);
    int removed = 0;
    if (jail_sweep(cfg->jail_root, min_age, &removed) < 0) {
        int e = errno;
        return privsep_reply_err(out, cap, PRIVSEP_ERR_FAILED, e, 0);
    }
    return privsep_reply_u32(out, cap, (uint32_t)removed);
}

// ---- serving --------------------------------------------------------------

static size_t dispatch(const helper_config_t* cfg, uint8_t op,
                       const uint8_t* body, uint32_t body_len, uint8_t* out,
                       size_t cap) {
    switch (op) {
        case PRIVSEP_OP_HELLO: return handle_hello(body, body_len, out, cap);
        case PRIVSEP_OP_NET_UP: return handle_net_up(body, body_len, out, cap);
        case PRIVSEP_OP_NET_DOWN:
            return handle_net_down(body, body_len, out, cap);
        case PRIVSEP_OP_SPAWN:
            return handle_spawn(cfg, body, body_len, out, cap);
        case PRIVSEP_OP_POLL: return handle_poll(body, body_len, out, cap);
        case PRIVSEP_OP_TEARDOWN:
            return handle_teardown(cfg, body, body_len, out, cap);
        case PRIVSEP_OP_SWEEP:
            return handle_sweep(cfg, body, body_len, out, cap);
        default: break;
    }
    return privsep_reply_err(out, cap, PRIVSEP_ERR_REQUEST, EINVAL, 0);
}

// Serve one connection until EOF or error. SOCK_SEQPACKET preserves record
// boundaries: one recvmsg is one request, one send is one reply.
static void serve(int conn, const helper_config_t* cfg) {
    static uint8_t in[PRIVSEP_MAX_MSG];
    static uint8_t out[PRIVSEP_MAX_MSG];
    for (;;) {
        struct iovec iov = { in, sizeof(in) };
        struct msghdr mh;
        memset(&mh, 0, sizeof(mh));
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        ssize_t rn = recvmsg(conn, &mh, 0);
        if (rn == 0) return;  // orderly shutdown
        if (rn < 0) {
            if (errno == EINTR) continue;
            return;
        }
        size_t reply_len = 0;
        if (mh.msg_flags & MSG_TRUNC) {
            reply_len = privsep_reply_err(out, sizeof(out),
                                          PRIVSEP_ERR_REQUEST, EMSGSIZE, 0);
        } else {
            uint8_t ver = 0, op = 0;
            const uint8_t* body = NULL;
            uint32_t body_len = 0;
            if (privsep_decode(in, (size_t)rn, &ver, &op, &body, &body_len) !=
                    0 ||
                !privsep_op_ok(op)) {
                reply_len = privsep_reply_err(out, sizeof(out),
                                              PRIVSEP_ERR_REQUEST, EINVAL, 0);
            } else {
                reply_len = dispatch(cfg, op, body, body_len, out, sizeof(out));
            }
        }
        if (!reply_len) return;
        ssize_t wn = send(conn, out, reply_len, MSG_NOSIGNAL);
        if (wn < 0 || (size_t)wn != reply_len) return;
    }
}

static int peer_uid(int conn, uid_t* uid) {
    struct ucred cred;
    memset(&cred, 0, sizeof(cred));
    socklen_t n = sizeof(cred);
    if (getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cred, &n) < 0) return -1;
    *uid = cred.uid;
    return 0;
}

static void usage(const char* prog) {
    printf("usage: %s [--socket PATH] [--daemon-user NAME] [--jail-root DIR]\n"
           "               [--snapshot-root DIR] [--workspace-root DIR]\n",
           prog);
}

int main(int argc, char** argv) {
    helper_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.sock_path = PRIVSEP_DEFAULT_SOCK;
    cfg.daemon_user = "sandboxd";
    cfg.jail_root = getenv("SANDBOX_JAIL_ROOT");
    if (!cfg.jail_root || !*cfg.jail_root) cfg.jail_root = JAIL_ROOT_DEFAULT;
    cfg.snapshot_root = getenv("SANDBOX_SNAPSHOT_ROOT");
    if (!cfg.snapshot_root || !*cfg.snapshot_root)
        cfg.snapshot_root = SNAPSHOT_ROOT_DEFAULT;
    cfg.workspace_root = getenv("SANDBOX_WORKSPACE_ROOT");
    if (!cfg.workspace_root || !*cfg.workspace_root)
        cfg.workspace_root = workspace_root();

    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        const char* v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strcmp(a, "--socket") == 0 && v)
            cfg.sock_path = argv[++i];
        else if (strcmp(a, "--daemon-user") == 0 && v)
            cfg.daemon_user = argv[++i];
        else if (strcmp(a, "--jail-root") == 0 && v)
            cfg.jail_root = argv[++i];
        else if (strcmp(a, "--snapshot-root") == 0 && v)
            cfg.snapshot_root = argv[++i];
        else if (strcmp(a, "--workspace-root") == 0 && v)
            cfg.workspace_root = argv[++i];
        else if (strcmp(a, "--version") == 0) {
            printf("sandbox-privileged %s\n", SANDBOX_VERSION);
            return 0;
        } else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "sandbox-privileged: unknown argument '%s'\n", a);
            usage(argv[0]);
            return 1;
        }
    }
    if (!cfg.sock_path[0] || strlen(cfg.sock_path) >= sizeof(((struct sockaddr_un*)0)->sun_path)) {
        fprintf(stderr, "sandbox-privileged: bad socket path\n");
        return 1;
    }

    // The helper without root is a locked door with no wall behind it: every
    // operation would fail, so fail fast with a clear error instead.
    if (geteuid() != 0) {
        fprintf(stderr, "sandbox-privileged: must run as root\n");
        return 1;
    }
    errno = 0;
    struct passwd* pw = getpwnam(cfg.daemon_user);
    if (!pw) {
        fprintf(stderr, "sandbox-privileged: unknown user '%s'\n",
                cfg.daemon_user);
        return 1;
    }
    cfg.daemon_uid = pw->pw_uid;
    cfg.daemon_gid = pw->pw_gid;
    if (cfg.daemon_uid == 0) {
        fprintf(stderr, "sandbox-privileged: refusing uid 0 as the daemon\n");
        return 1;
    }

    // The socket directory (/run/...) may not exist yet at boot.
    char sockdir[PATH_MAX];
    snprintf(sockdir, sizeof(sockdir), "%s", cfg.sock_path);
    char* slash = strrchr(sockdir, '/');
    if (slash && slash != sockdir) {
        *slash = '\0';
        if (mkdir_recursive(sockdir, 0755) < 0 && errno != EEXIST) {
            fprintf(stderr, "sandbox-privileged: mkdir %s: %s\n", sockdir,
                    strerror(errno));
            return 1;
        }
    }
    unlink(cfg.sock_path);  // stale socket from a crash
    int listen_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (listen_fd < 0) {
        fprintf(stderr, "sandbox-privileged: socket: %s\n", strerror(errno));
        return 1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, cfg.sock_path);
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(listen_fd, 8) < 0) {
        fprintf(stderr, "sandbox-privileged: bind %s: %s\n", cfg.sock_path,
                strerror(errno));
        close(listen_fd);
        return 1;
    }
    // Defense in depth behind the SO_PEERCRED gate: only the daemon uid can
    // even connect.
    if (chown(cfg.sock_path, (uid_t)cfg.daemon_uid, (gid_t)-1) < 0 ||
        chmod(cfg.sock_path, 0700) < 0) {
        fprintf(stderr, "sandbox-privileged: protect %s: %s\n", cfg.sock_path,
                strerror(errno));
        close(listen_fd);
        return 1;
    }

    cgroup_init();  // best-effort; spawn proceeds unmetered when disabled
    if (network_manager_init() < 0)
        log_msg("warning: nftables init: %s", strerror(errno));

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigchld;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    log_msg("listening on %s for uid %u (%s), jail %s", cfg.sock_path,
            (unsigned)cfg.daemon_uid, cfg.daemon_user, cfg.jail_root);
    for (;;) {
        // Reap between connections; a connection's own waiters (POLL,
        // TEARDOWN) reap inside serve().
        if (g_sigchld) {
            g_sigchld = 0;
            reap_children();
        }
        int conn = accept(listen_fd, NULL, NULL);
        if (conn < 0) {
            if (errno == EINTR) continue;
            log_msg("accept: %s", strerror(errno));
            return 1;
        }
        uid_t peer = (uid_t)-1;
        if (peer_uid(conn, &peer) < 0 || peer != cfg.daemon_uid) {
            log_msg("refused connection from uid %u", (unsigned)peer);
            close(conn);
            continue;
        }
        serve(conn, &cfg);
        close(conn);
    }
}
