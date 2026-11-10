// SPDX-License-Identifier: GPL-2.0-only
// privsep_client.c -- #9: the daemon side of the helper boundary.
//
// One helper connection per process, one in-flight RPC at a time (a
// process-global mutex serialises calls: provisions are rare and the helper
// answers sequentially anyway). Every call validates its arguments with the
// shared validators before sending; the helper re-validates on receipt, so a
// client-side bug can only deny service to its own caller, never smuggle a
// bad request past the boundary.
#include "privsep.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

int privsep_connect(const char* sock_path) {
    if (!sock_path || !*sock_path || strlen(sock_path) >= sizeof(((struct sockaddr_un*)0)->sun_path)) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sock_path);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

int privsep_rpc(int fd, uint8_t op, const uint8_t* req, uint32_t req_len,
                uint8_t* reply, uint32_t reply_cap, uint32_t* reply_len,
                uint8_t* status, int timeout_ms) {
    if (fd < 0 || !privsep_op_ok(op) || (req_len && !req) || !reply ||
        !reply_len || !status || timeout_ms < 0) {
        errno = EINVAL;
        return -1;
    }
    uint8_t msg[PRIVSEP_MAX_MSG];
    size_t msg_len = 0;
    if (privsep_encode(PRIVSEP_VERSION, op, req, req_len, msg, sizeof(msg),
                       &msg_len) != 0) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&g_mu);
    int rc = -1;
    int err = EIO;
    ssize_t wn = send(fd, msg, msg_len, MSG_NOSIGNAL);
    if (wn < 0 || (size_t)wn != msg_len) {
        err = (wn < 0 && errno == EPIPE) ? ECONNRESET : EIO;
        goto out;
    }
    int64_t deadline = 0;
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        deadline = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + timeout_ms;
    }
    for (;;) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        int64_t now = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        int wait_ms = deadline > now ? (int)(deadline - now) : 0;
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, wait_ms);
        if (pr < 0) {
            if (errno == EINTR) continue;
            err = EIO;
            goto out;
        }
        if (pr == 0) {
            err = ETIMEDOUT;
            goto out;
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            err = ECONNRESET;
            goto out;
        }
        uint8_t rbuf[PRIVSEP_MAX_MSG];
        ssize_t rn = recv(fd, rbuf, sizeof(rbuf), 0);
        if (rn < 0) {
            if (errno == EINTR) continue;
            err = EIO;
            goto out;
        }
        if (rn == 0) {
            err = ECONNRESET;  // the helper went away mid-call
            goto out;
        }
        uint8_t ver = 0, st = 0;
        const uint8_t* rbody = NULL;
        uint32_t rlen = 0;
        if (privsep_decode(rbuf, (size_t)rn, &ver, &st, &rbody, &rlen) != 0 ||
            !privsep_status_ok(st) || rlen > reply_cap) {
            err = EBADMSG;
            goto out;
        }
        if (rlen) memcpy(reply, rbody, rlen);
        *reply_len = rlen;
        *status = st;
        rc = 0;
        goto out;
    }
out:
    pthread_mutex_unlock(&g_mu);
    if (rc != 0) errno = err;
    return rc;
}

// Map a reply status to errno. Returns 0 on OK (caller decodes the body).
static int status_to_errno(uint8_t status, const uint8_t* body,
                           uint32_t body_len, int* jail_step) {
    if (jail_step) *jail_step = 0;
    switch (status) {
        case PRIVSEP_OK: return 0;
        case PRIVSEP_ERR_NOT_FOUND: return ENOENT;
        case PRIVSEP_ERR_REQUEST: return EINVAL;  // always a client bug
        case PRIVSEP_ERR_BUSY: return EAGAIN;
        case PRIVSEP_ERR_FAILED:
            if (body_len < 8) return EBADMSG;
            if (jail_step) *jail_step = (int32_t)privsep_get_u32(body + 4);
            return (int)privsep_get_u32(body);
        default: return EBADMSG;
    }
}

int privsep_hello(int fd) {
    uint8_t req[1] = { PRIVSEP_VERSION };
    uint8_t reply[16];
    uint32_t rlen = 0;
    uint8_t status = 0;
    if (privsep_rpc(fd, PRIVSEP_OP_HELLO, req, sizeof(req), reply,
                    sizeof(reply), &rlen, &status, 5000) != 0)
        return -1;
    if (status != PRIVSEP_OK || rlen != 1 || reply[0] != PRIVSEP_VERSION) {
        errno = EBADMSG;
        return -1;
    }
    return 0;
}

int privsep_net_up(int fd, const char* vm_id, char* tap, size_t tap_cap,
                   uint32_t* host_ip, uint32_t* guest_ip) {
    if (!privsep_vm_id_ok(vm_id) || !tap || !tap_cap || !host_ip || !guest_ip) {
        errno = EINVAL;
        return -1;
    }
    uint8_t reply[128];
    uint32_t rlen = 0;
    uint8_t status = 0;
    size_t id_len = strlen(vm_id) + 1;
    if (privsep_rpc(fd, PRIVSEP_OP_NET_UP, (const uint8_t*)vm_id,
                    (uint32_t)id_len, reply, sizeof(reply), &rlen, &status,
                    15000) != 0)
        return -1;
    int se = status_to_errno(status, reply, rlen, NULL);
    if (se) {
        errno = se;
        return -1;
    }
    // Body is tap NUL + two addrs; the tap must equal the derived name (the
    // helper derives it too, so anything else is a corrupt or hostile reply).
    size_t tlen = 0;
    while (tlen < rlen && reply[tlen]) tlen++;
    if (tlen + 1 + 8 != rlen) {
        errno = EBADMSG;
        return -1;
    }
    char want[PRIVSEP_VM_ID_MAX + 5];
    if (privsep_tap_name(vm_id, want, sizeof(want)) != 0 ||
        strcmp((const char*)reply, want) != 0 || strlen(want) + 1 > tap_cap) {
        errno = EBADMSG;
        return -1;
    }
    memcpy(tap, reply, strlen(want) + 1);
    *host_ip = privsep_get_u32(reply + tlen + 1);
    *guest_ip = privsep_get_u32(reply + tlen + 5);
    return 0;
}

int privsep_net_down(int fd, const char* vm_id) {
    if (!privsep_vm_id_ok(vm_id)) {
        errno = EINVAL;
        return -1;
    }
    uint8_t reply[16];
    uint32_t rlen = 0;
    uint8_t status = 0;
    if (privsep_rpc(fd, PRIVSEP_OP_NET_DOWN, (const uint8_t*)vm_id,
                    (uint32_t)strlen(vm_id) + 1, reply, sizeof(reply), &rlen,
                    &status, 15000) != 0)
        return -1;
    int se = status_to_errno(status, reply, rlen, NULL);
    if (se) {
        errno = se;
        return -1;
    }
    return 0;
}

// Append a NUL-terminated path (NULL/"" encodes as a bare NUL = absent).
static int put_path(uint8_t* buf, size_t cap, size_t* off, const char* path,
                    const char* root) {
    if (!path || !*path) {
        if (*off + 1 > cap) return -1;
        buf[(*off)++] = 0;
        return 0;
    }
    if (!privsep_path_ok(path, &root, 1)) return -1;
    size_t n = strlen(path) + 1;
    if (*off + n > cap) return -1;
    memcpy(buf + *off, path, n);
    *off += n;
    return 0;
}

int privsep_spawn(int fd, const privsep_spawn_args_t* args,
                  const char* snapshot_root, const char* workspace_root,
                  const char* jail_root, pid_t* pid, int* jail_step) {
    if (pid) *pid = 0;
    if (jail_step) *jail_step = 0;
    if (!args || !privsep_vm_id_ok(args->vm_id) ||
        !privsep_jail_ids_ok(args->jailer_uid, args->jailer_gid,
                             (uint32_t)geteuid(), (uint32_t)getegid()) ||
        !privsep_spawn_flags_ok(args->flags) || !snapshot_root ||
        !workspace_root || !jail_root || !pid) {
        errno = EINVAL;
        return -1;
    }
    uint8_t req[PRIVSEP_MAX_MSG];
    size_t off = 0;
    size_t id_len = strlen(args->vm_id) + 1;
    memcpy(req + off, args->vm_id, id_len);
    off += id_len;
    privsep_put_u32(req + off, args->jailer_uid);
    off += 4;
    privsep_put_u32(req + off, args->jailer_gid);
    off += 4;
    privsep_put_u32(req + off, args->flags);
    off += 4;
    const char* snap_paths[] = { args->kernel, args->rootfs, args->vmstate,
                                 args->mem, args->outdir };
    for (size_t i = 0; i < 5; i++) {
        if (put_path(req, sizeof(req), &off, snap_paths[i], snapshot_root) != 0) {
            errno = EINVAL;
            return -1;
        }
    }
    if (put_path(req, sizeof(req), &off, args->workspace, workspace_root) != 0 ||
        put_path(req, sizeof(req), &off, args->serial, jail_root) != 0) {
        errno = EINVAL;
        return -1;
    }
    uint8_t reply[16];
    uint32_t rlen = 0;
    uint8_t status = 0;
    if (privsep_rpc(fd, PRIVSEP_OP_SPAWN, req, (uint32_t)off, reply,
                    sizeof(reply), &rlen, &status, 60000) != 0)
        return -1;
    int se = status_to_errno(status, reply, rlen, jail_step);
    if (se) {
        errno = se;
        return -1;
    }
    if (rlen != 4) {
        errno = EBADMSG;
        return -1;
    }
    int32_t got = (int32_t)privsep_get_u32(reply);
    if (got <= 0) {
        errno = EBADMSG;
        return -1;
    }
    *pid = (pid_t)got;
    return 0;
}

int privsep_poll(int fd, const char* vm_id, int* state, int* status,
                 int* termsig, int* jail_step) {
    if (!privsep_vm_id_ok(vm_id) || !state || !status || !termsig || !jail_step) {
        errno = EINVAL;
        return -1;
    }
    uint8_t reply[32];
    uint32_t rlen = 0;
    uint8_t st = 0;
    if (privsep_rpc(fd, PRIVSEP_OP_POLL, (const uint8_t*)vm_id,
                    (uint32_t)strlen(vm_id) + 1, reply, sizeof(reply), &rlen,
                    &st, 10000) != 0)
        return -1;
    int se = status_to_errno(st, reply, rlen, NULL);
    if (se) {
        errno = se;
        return -1;
    }
    if (rlen != 16 || (reply[0] != PRIVSEP_POLL_RUNNING &&
                       reply[0] != PRIVSEP_POLL_EXITED)) {
        errno = EBADMSG;
        return -1;
    }
    *state = reply[0];
    *status = (int32_t)privsep_get_u32(reply + 4);
    *termsig = (int32_t)privsep_get_u32(reply + 8);
    *jail_step = (int32_t)privsep_get_u32(reply + 12);
    return 0;
}

int privsep_teardown(int fd, const char* vm_id) {
    if (!privsep_vm_id_ok(vm_id)) {
        errno = EINVAL;
        return -1;
    }
    uint8_t reply[16];
    uint32_t rlen = 0;
    uint8_t status = 0;
    if (privsep_rpc(fd, PRIVSEP_OP_TEARDOWN, (const uint8_t*)vm_id,
                    (uint32_t)strlen(vm_id) + 1, reply, sizeof(reply), &rlen,
                    &status, 60000) != 0)
        return -1;
    int se = status_to_errno(status, reply, rlen, NULL);
    if (se) {
        errno = se;
        return -1;
    }
    return 0;
}

int privsep_sweep(int fd, uint32_t min_age_s, uint32_t* swept) {
    if (!swept) {
        errno = EINVAL;
        return -1;
    }
    uint8_t req[4];
    privsep_put_u32(req, min_age_s);
    uint8_t reply[16];
    uint32_t rlen = 0;
    uint8_t status = 0;
    if (privsep_rpc(fd, PRIVSEP_OP_SWEEP, req, sizeof(req), reply,
                    sizeof(reply), &rlen, &status, 120000) != 0)
        return -1;
    int se = status_to_errno(status, reply, rlen, NULL);
    if (se) {
        errno = se;
        return -1;
    }
    if (rlen != 4) {
        errno = EBADMSG;
        return -1;
    }
    *swept = privsep_get_u32(reply);
    return 0;
}
