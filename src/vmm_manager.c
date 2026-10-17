// VMM Manager — Firecracker lifecycle over the jail + Unix-socket HTTP API
// (v1.17.0 live spec): spawn, configure, boot/restore, pause/resume, snapshot,
// destroy. Templates boot *with* a network interface and snapshot it; restores
// retarget that interface's host tap through the load request's
// `network_overrides` field. (A tap fd cannot be shared across VMs, and
// Firecracker only supports post-restore device attach — hot-plug — on the PCI
// transport, which this environment cannot use; `network_overrides` works on
// MMIO and is the supported path.)

#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include "vmm_manager.h"

#include "jailer.h"
#include "sandbox_seccomp.h"
#include "snapshot_manager.h"
#include "uffd_handler.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FC_BIN_DEFAULT "/usr/local/bin/firecracker"
#define FC_API_SOCK_JAILVIEW "/api.sock"
#define FC_UFFD_SOCK_JAILVIEW "/uffd.sock"
#define FC_KERNEL_JAILVIEW "/vmlinux"
#define FC_ROOTFS_JAILVIEW "/rootfs.ext4"
#define FC_STATE_JAILVIEW "/vmstate"
#define FC_MEM_JAILVIEW "/memory.snap"
#define FC_BOOT_ARGS "console=ttyS0 reboot=k panic=1 init=/init root=/dev/vda ro"
#define FC_TEMPLATE_IFACE "net1"  // template NIC id; restores retarget its tap
#define FC_VSOCK_JAILVIEW "/vsock.sock"  // per-VM vsock host backend UDS
#define FC_VSOCK_GUEST_CID 3
#define FC_VSOCK_ENV_PORT 5001  // must match scripts/sandbox-agent.c ENV_PORT
#define FC_ACCEPT_TIMEOUT_MS 30000
#define FC_FILE_WAIT_MS 10000
#define FC_READY_DEFAULT "SANDBOX-READY"
#define FC_RESPONSE_MAX 131072  // 128KB for Firecracker API responses

static atomic_uint_fast32_t next_id = 1;

static const char* fc_bin(void) {
    const char* e = getenv("FIRECRACKER_BIN");
    return (e && *e) ? e : FC_BIN_DEFAULT;
}

static const char* jail_parent(void) {
    const char* e = getenv("SANDBOX_JAIL_ROOT");
    return (e && *e) ? e : "/var/lib/sandbox-engine/jail";
}

static const char* snapshot_parent(void) {
    const char* e = getenv("SANDBOX_SNAPSHOT_ROOT");
    return (e && *e) ? e : "/var/lib/sandbox-engine/snapshots";
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int write_full(int fd, const void* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, (const char*)buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

// VirtIO transport must match between template capture and restore
// (snapshot load validates device layout). The aarch64 CI kernel does not boot
// the guest under Firecracker's PCI transport on this host (no working GIC ITS
// → MSI-X setup fails → virtio-blk never registers → "Cannot open root device"),
// so MMIO is the default. Set SANDBOX_FC_PCI=1 to opt into PCI where it works;
// both capture and restore follow the same setting.
static bool pci_enabled(void) {
    const char* e = getenv("SANDBOX_FC_PCI");
    return e && strcmp(e, "0") != 0 && *e != '\0';
}

// aarch64 needs keep_bootcon (per Firecracker guide); CI kernels ship with
// CONFIG_CMDLINE="" so root= must come from us (Firecracker appends nothing).
static void fc_boot_args(char* out, size_t n) {
    const char* extra = "";
    struct utsname u;
    if (uname(&u) == 0 && strcmp(u.machine, "aarch64") == 0)
        extra = "keep_bootcon ";
    snprintf(out, n, "%s%s", extra, FC_BOOT_ARGS);
}

// NOTE on guest MAC: Firecracker's network_overrides can only retarget the
// host tap on restore, not the guest MAC, so restored VMs inherit the
// template's NIC MAC (assigned at capture). Host-side isolation is per-VM via
// the unique tap; guest MACs are not unique across restored VMs.

// --- minimal HTTP/1.1 client over AF_UNIX (Firecracker API socket) ---
// Firecracker keeps connections alive, so responses are framed by
// Content-Length, never by EOF. Every wait is poll-bounded.

static int poll_in(int fd, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) {
        errno = (rc == 0) ? ETIMEDOUT : errno;
        return -1;
    }
    return 0;
}

// Connect to the API socket (retry while the socket file lags process start).
static int fc_connect(const char* sock_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
    for (int i = 0; i < 200; i++) {
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) return fd;
        struct timespec nap = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000L };
        nanosleep(&nap, NULL);
    }
    close(fd);
    return -1;
}

// Send one request; returns a connected fd positioned to read the response,
// or -1. The caller owns the fd (pass it to fc_read_response / close).
// Split from the response read so /snapshot/load can be in flight while the
// UFFD handler is brought up (Firecracker faults on guest memory during load).
static int fc_send_request(const char* sock_path, const char* method,
                           const char* url_path, const char* body) {
    int fd = fc_connect(sock_path);
    if (fd < 0) return -1;
    size_t body_len = body ? strlen(body) : 0;
    char req[8192];
    int n = snprintf(req, sizeof(req),
                     "%s %s HTTP/1.1\r\nHost: localhost\r\n"
                     "Accept: application/json\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     method, url_path, body_len, body ? body : "");
    if (n <= 0 || (size_t)n >= sizeof(req)) { close(fd); return -1; }
    size_t off = 0;
    while (off < (size_t)n) {
        ssize_t w = send(fd, req + off, (size_t)n - off, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        off += (size_t)w;
    }
    return fd;
}

// Read + parse the response on fd (always closes fd). Returns HTTP status.
static int fc_read_response(int fd, char* rbody, size_t body_cap, size_t* out_len) {
    // Dynamic response buffer with cap
    char* resp = malloc(FC_RESPONSE_MAX);
    if (!resp) { close(fd); return -1; }
    size_t total = 0;
    for (;;) {
        if (poll_in(fd, 15000) < 0) { free(resp); close(fd); return -1; }
        ssize_t r = recv(fd, resp + total, FC_RESPONSE_MAX - 1 - total, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(resp); close(fd);
            return -1;
        }
        if (r == 0) break;  // server closed: body runs to EOF
        total += (size_t)r;
        if (total >= FC_RESPONSE_MAX - 1) break;
        resp[total] = '\0';
        char* hend = strstr(resp, "\r\n\r\n");
        if (hend) {
            // Headers complete: body length is authoritative from here.
            long clen = -1;
            char* cl = strcasestr(resp, "content-length:");
            if (cl && cl < hend) clen = atol(cl + strlen("content-length:"));
            if (clen < 0) break;  // no length: whatever arrived is the body
            size_t have = total - (size_t)(hend + 4 - resp);
            while (have < (size_t)clen) {
                if (poll_in(fd, 15000) < 0) { free(resp); close(fd); return -1; }
                ssize_t r = recv(fd, resp + total, FC_RESPONSE_MAX - 1 - total, 0);
                if (r <= 0) break;
                total += (size_t)r;
                have += (size_t)r;
                if (total >= FC_RESPONSE_MAX - 1) break;
            }
            break;
        }
        if (total >= FC_RESPONSE_MAX - 1) break;
    }
    close(fd);
    resp[total] = '\0';
    int code = -1;
    if (sscanf(resp, "HTTP/1.1 %d", &code) != 1) { free(resp); return -1; }
    char* hend = strstr(resp, "\r\n\r\n");
    size_t blen = hend ? total - (size_t)(hend + 4 - resp) : 0;
    if (blen >= body_cap) blen = body_cap - 1;
    if (hend && blen) memcpy(rbody, hend + 4, blen);
    rbody[blen] = '\0';
    if (out_len) *out_len = blen;
    free(resp);
    return code;
}

// Send method+path+JSON body; collect status + up to *body_cap response body
// bytes. Returns HTTP status or -1.
static int fc_transact(const char* sock_path, const char* method, const char* url_path,
                       const char* body, char* rbody, size_t body_cap, size_t* out_len) {
    int fd = fc_send_request(sock_path, method, url_path, body);
    if (fd < 0) return -1;
    return fc_read_response(fd, rbody, body_cap, out_len);
}

static int fc_request(const char* sock_path, const char* method, const char* url_path,
                      const char* body) {
    char rbody[1024];
    int code = fc_transact(sock_path, method, url_path, body, rbody, sizeof(rbody), NULL);
    if (code < 0) return -1;
    if (code < 200 || code >= 300) {
        // Surface Firecracker's fault_message (best effort).
        const char* fm = strstr(rbody, "fault_message");
        char detail[256] = {0};
        if (fm) {
            const char* q1 = strchr(fm, ':');
            const char* q2 = q1 ? strchr(q1, '"') : NULL;
            const char* q3 = q2 ? strchr(q2 + 1, '"') : NULL;
            if (q3 && (size_t)(q3 - q2 - 1) < sizeof(detail)) {
                memcpy(detail, q2 + 1, (size_t)(q3 - q2 - 1));
                detail[q3 - q2 - 1] = '\0';
            }
        }
        fprintf(stderr, "firecracker %s %s -> HTTP %d %s\n", method, url_path,
                code, detail);
        return -1;
    }
    return code;
}

static int fc_put(const char* sock, const char* path, const char* body) {
    return fc_request(sock, "PUT", path, body) < 0 ? -1 : 0;
}

static int fc_patch(const char* sock, const char* path, const char* body) {
    return fc_request(sock, "PATCH", path, body) < 0 ? -1 : 0;
}

// Current "state" value from GET / (Running/Paused/...). 0 ok, -1 error.
static int fc_state(const char* sock, char* out, size_t n) {
    char rbody[1024];
    int code = fc_transact(sock, "GET", "/", NULL, rbody, sizeof(rbody), NULL);
    if (code < 200 || code >= 300) return -1;
    const char* k = strstr(rbody, "\"state\"");
    const char* c = k ? strchr(k, ':') : NULL;
    const char* q1 = c ? strchr(c, '"') : NULL;
    const char* q2 = q1 ? strchr(q1 + 1, '"') : NULL;
    if (!q2 || (size_t)(q2 - q1 - 1) >= n) return -1;
    memcpy(out, q1 + 1, (size_t)(q2 - q1 - 1));
    out[q2 - q1 - 1] = '\0';
    return 0;
}

static int wait_for_file(const char* path, int timeout_ms) {
    uint64_t end = now_ms() + (uint64_t)timeout_ms;
    struct stat st;
    while (now_ms() < end) {
        if (stat(path, &st) == 0) return 0;
        struct timespec nap = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000L };
        nanosleep(&nap, NULL);
    }
    return -1;
}

// Unmount everything spawn_jailed may have bound, then remove the jail.
static void jail_cleanup(const char* jail_root) {
    if (!jail_root || !*jail_root) return;
    const char* subs[] = { "/dev/kvm", "/dev/net/tun", "/dev/userfaultfd",
                           "/vmlinux", "/rootfs.ext4", "/vmstate", "/memory.snap",
                           "/out" };
    char p[PATH_MAX];
    for (size_t i = 0; i < sizeof(subs) / sizeof(subs[0]); i++) {
        snprintf(p, sizeof(p), "%s%s", jail_root, subs[i]);
        umount2(p, MNT_DETACH);
    }
    char cmd[PATH_MAX + 16];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", jail_root);
    int rc = system(cmd);
    (void)rc;
}

int vmm_jail_path(const char* vm_id, char* out, size_t n) {
    if (!vm_id || !*vm_id || !out || n == 0) {
        errno = EINVAL;
        return -1;
    }
    if (snprintf(out, n, "%s/%s", jail_parent(), vm_id) >= (int)n) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static void cold_fail(vm_handle_t* vm) {
    if (!vm) return;
    if (vm->vmm_pid > 0) {
        // Try WNOHANG first: child may have already exited with a step code
        // (1-15 = jailer step, 15 = execve failed, >15 = Firecracker itself).
        int st = 0;
        pid_t r = waitpid(vm->vmm_pid, &st, WNOHANG);
        if (r == 0) {
            // Still running — kill it then reap
            kill(vm->vmm_pid, SIGKILL);
            while (waitpid(vm->vmm_pid, &st, 0) < 0 && errno == EINTR) {}
        } else if (r < 0) {
            kill(vm->vmm_pid, SIGKILL);
        }
        if (WIFEXITED(st))
            fprintf(stderr, "[cold_fail] child exit code %d "
                    "(jailer steps: 1=mkdir 2=chown 3=copy 4=xattr 5=dev "
                    "6=bind 7=cgrp 8=serial 9=chroot 10=chdir 11=caps "
                    "12=gid 13=uid 14=seccomp 15=execve)\n",
                    WEXITSTATUS(st));
        else if (WIFSIGNALED(st))
            fprintf(stderr, "[cold_fail] child killed by signal %d\n",
                    WTERMSIG(st));
    }
    jail_cleanup(vm->jail_root);
    free(vm);
}

vm_handle_t* vmm_cold_boot(const void* config, const char* vm_id,
                           const char* jail_root, const char* out_dir) {
    const template_config_t* cfg = config;
    if (!cfg || !vm_id || !*vm_id || !jail_root || !*jail_root || !cfg->kernel_path ||
        !cfg->rootfs_path || cfg->memory_mib == 0 || cfg->vcpu_count == 0) {
        errno = EINVAL;
        return NULL;
    }
    vm_handle_t* vm = calloc(1, sizeof(*vm));
    if (!vm) return NULL;
    vm->sandbox_id = atomic_fetch_add(&next_id, 1);
    vm->vmm_pid = -1;
    vm->uffd_fd = -1;
    snprintf(vm->jail_root, sizeof(vm->jail_root), "%s", jail_root);
    snprintf(vm->api_sock_path, sizeof(vm->api_sock_path), "%s/api.sock", jail_root);

    jail_files_t files = { .firecracker_bin = fc_bin(),
                           .kernel_path = cfg->kernel_path,
                           .rootfs_path = cfg->rootfs_path,
                           .snap_state_src = NULL, .snap_mem_src = NULL,
                           .out_dir = out_dir };
    char serial[PATH_MAX];
    snprintf(serial, sizeof(serial), "%s/serial.log", jail_root);
    jailer_config_t jcfg = { .jailer_uid = 65534, .jailer_gid = 65534,
                             .cgroup_path = NULL };
    // Transport must match the restore path (see pci_enabled()).
    char* argv[8];
    int ai = 0;
    argv[ai++] = (char*)"/firecracker";
    argv[ai++] = (char*)"--api-sock"; argv[ai++] = (char*)"/api.sock";
    argv[ai++] = (char*)"--id"; argv[ai++] = (char*)vm_id;
    argv[ai++] = (char*)"--no-seccomp";
    if (pci_enabled()) argv[ai++] = (char*)"--enable-pci";
    argv[ai++] = NULL;
    bool seccomp = getenv("SANDBOX_FC_SECCOMP") == NULL ||
                   strcmp(getenv("SANDBOX_FC_SECCOMP"), "0") != 0;
    pid_t pid = spawn_jailed(jail_root, &jcfg, "/firecracker", argv, true, seccomp,
                             &files, serial);
    if (pid <= 0) {
        free(vm);
        return NULL;
    }
    vm->vmm_pid = pid;
    if (wait_for_file(vm->api_sock_path, FC_FILE_WAIT_MS) < 0) {
        cold_fail(vm);
        return NULL;
    }

    char body[1024];
    char boot_args[512];
    fc_boot_args(boot_args, sizeof(boot_args));
    snprintf(body, sizeof(body), "{\"vcpu_count\": %u, \"mem_size_mib\": %llu}",
             cfg->vcpu_count, (unsigned long long)cfg->memory_mib);
    if (fc_put(vm->api_sock_path, "/machine-config", body) < 0) {
        cold_fail(vm);
        return NULL;
    }
    snprintf(body, sizeof(body),
             "{\"kernel_image_path\": \"%s\", \"boot_args\": \"%s\"}",
             FC_KERNEL_JAILVIEW, boot_args);
    if (fc_put(vm->api_sock_path, "/boot-source", body) < 0) {
        cold_fail(vm);
        return NULL;
    }
    snprintf(body, sizeof(body),
             "{\"drive_id\": \"rootfs\", \"path_on_host\": \"%s\", "
             "\"is_root_device\": true, \"is_read_only\": true}",
             FC_ROOTFS_JAILVIEW);
    if (fc_put(vm->api_sock_path, "/drives/rootfs", body) < 0) {
        cold_fail(vm);
        return NULL;
    }
    // Optional NIC: the template snapshots *with* this interface so that
    // restores can retarget its tap via network_overrides. Firecracker assigns
    // the guest MAC here; snapshot restore cannot change it (tap only).
    if (cfg->tap_name && *cfg->tap_name) {
        snprintf(body, sizeof(body),
                 "{\"iface_id\": \"%s\", \"host_dev_name\": \"%s\"}",
                 FC_TEMPLATE_IFACE, cfg->tap_name);
        if (fc_put(vm->api_sock_path, "/network-interfaces/" FC_TEMPLATE_IFACE, body) < 0) {
            cold_fail(vm);
            return NULL;
        }
    }
    // vsock device (Phase 9b): configured before boot so the captured snapshot
    // carries it; restores retarget its host UDS via the load request's
    // vsock_override. The jailed guest agent listens on FC_VSOCK_ENV_PORT.
    snprintf(vm->vsock_uds, sizeof(vm->vsock_uds), "%s" FC_VSOCK_JAILVIEW, jail_root);
    snprintf(body, sizeof(body),
             "{\"vsock_id\": \"vsock0\", \"guest_cid\": %d, \"uds_path\": \"%s\"}",
             FC_VSOCK_GUEST_CID, FC_VSOCK_JAILVIEW);
    if (fc_put(vm->api_sock_path, "/vsock", body) < 0) {
        cold_fail(vm);
        return NULL;
    }
    usleep(15000);  // async API settle before InstanceStart (per FC docs)
    if (fc_put(vm->api_sock_path, "/actions", "{\"action_type\": \"InstanceStart\"}") < 0) {
        cold_fail(vm);
        return NULL;
    }
    vm->resume_time_ms = now_ms();
    return vm;
}

int vmm_state(vm_handle_t* vm, char* out, size_t n) {
    if (!vm || !out || n == 0) {
        errno = EINVAL;
        return -1;
    }
    return fc_state(vm->api_sock_path, out, n);
}

int vmm_wait_ready(vm_handle_t* vm, const char* marker, int timeout_ms) {
    if (!vm) {
        errno = EINVAL;
        return -1;
    }
    if (!marker) marker = FC_READY_DEFAULT;
    char logpath[PATH_MAX];
    snprintf(logpath, sizeof(logpath), "%s/serial.log", vm->jail_root);
    size_t mlen = strlen(marker);
    uint64_t end = now_ms() + (uint64_t)timeout_ms;
    char* buf = NULL;
    size_t cap = 0;
    int found = 0;
    while (now_ms() < end && !found) {
        FILE* f = fopen(logpath, "r");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            if (sz > 0) {
                if ((size_t)sz + 1 > cap) {
                    cap = (size_t)sz + 1;
                    buf = realloc(buf, cap);
                }
                if (buf) {
                    fseek(f, 0, SEEK_SET);
                    size_t n = fread(buf, 1, (size_t)sz, f);
                    for (size_t i = 0; i + mlen <= n; i++) {
                        if (memcmp(buf + i, marker, mlen) == 0) {
                            found = 1;
                            break;
                        }
                    }
                }
            }
            fclose(f);
        }
        if (!found) {
            struct timespec nap = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000L };
            nanosleep(&nap, NULL);
        }
    }
    if (!found) {
        // Dump serial log so we can see what the guest printed before timeout.
        // This log is destroyed by vmm_destroy shortly after, so capture now.
        fprintf(stderr, "[vmm_wait_ready] TIMEOUT after %dms waiting for \"%s\".\n"
                        "[vmm_wait_ready] Serial log (%s):\n", timeout_ms, marker, logpath);
        FILE* sf = fopen(logpath, "r");
        if (sf) {
            char line[512];
            while (fgets(line, sizeof(line), sf))
                fputs(line, stderr);
            fclose(sf);
            // Also stash a copy outside the jail before destroy
            char stash[PATH_MAX];
            snprintf(stash, sizeof(stash), "/tmp/serial-last-%u.log", vm->sandbox_id);
            char cp_cmd[PATH_MAX * 2 + 16];
            snprintf(cp_cmd, sizeof(cp_cmd), "cp %s %s 2>/dev/null || true", logpath, stash);
            system(cp_cmd);
            fprintf(stderr, "[vmm_wait_ready] Stashed to %s\n", stash);
        } else {
            fprintf(stderr, "[vmm_wait_ready] serial log not found (FC never wrote to it?)\n");
        }
    }

    free(buf);
    return found ? 0 : -1;
}


int vmm_pause_vcpus(vm_handle_t* vm) {
    if (!vm) {
        errno = EINVAL;
        return -1;
    }
    return fc_patch(vm->api_sock_path, "/vm", "{\"state\": \"Paused\"}");
}

int vmm_resume_vcpus(vm_handle_t* vm) {
    if (!vm) {
        errno = EINVAL;
        return -1;
    }
    if (fc_patch(vm->api_sock_path, "/vm", "{\"state\": \"Resumed\"}") < 0) return -1;
    vm->resume_time_ms = now_ms();
    return 0;
}

// Per-VM env injection (Phase 9b). Connects to this VM's Firecracker vsock UDS
// and speaks the hybrid-vsock handshake ("CONNECT <port>\n" -> "OK <host>\n"),
// then streams KEY=VALUE lines and half-closes; the guest agent reads to EOF.
int vmm_inject_env(vm_handle_t* vm, const char* const* env_vars) {
    if (!vm || !env_vars || !env_vars[0]) return 0;  // nothing to inject
    if (!vm->vsock_uds[0]) {
        errno = ENOTSUP;
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(vm->vsock_uds) >= sizeof(addr.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strncpy(addr.sun_path, vm->vsock_uds, sizeof(addr.sun_path) - 1);

    // Let Firecracker's vsock muxer settle after resume before the first
    // CONNECT. A host connection issued while the muxer is still setting up
    // its restored endpoint is accepted but never answered, and that stuck
    // half-open state wedges the port: every subsequent attempt then times
    // out too (measured: ~10-20% of immediate connects wedge all 8 retries,
    // while a 1 s settle before the first attempt succeeds in ~1 ms 10/10).
    sleep(1);

    // The backend UDS appears shortly after the load request, and the *guest*
    // side of the vsock can lag the host's UDS by a few hundred ms after a
    // restore. Retry the whole connect+handshake+write sequence, recreating the
    // socket each time (a reset connection leaves the fd unusable).
    int rc = -1;
    for (int attempt = 0; attempt < 8 && rc != 0; attempt++) {
        if (attempt) {
            struct timespec nap = { .tv_sec = 0, .tv_nsec = 250 * 1000 * 1000L };
            nanosleep(&nap, NULL);
        }
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return -1;

        int cres = -1;
        for (int i = 0; i < 100; i++) {
            if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                cres = 0;
                break;
            }
            if (errno != ENOENT && errno != ECONNREFUSED) break;
            struct timespec nap = { .tv_sec = 0, .tv_nsec = 20 * 1000 * 1000L };
            nanosleep(&nap, NULL);
        }
        if (cres < 0) {
            fprintf(stderr, "[vmm_inject_env] connect %s failed: %s (attempt %d)\n",
                    vm->vsock_uds, strerror(errno), attempt);
            close(fd);
            continue;
        }

        // Bound the handshake/write: if Firecracker's muxer stalls (or the
        // guest never drains the connection) we must not block forever.
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        char hs[64];
        int hn = snprintf(hs, sizeof(hs), "CONNECT %d\n", FC_VSOCK_ENV_PORT);
        if (write_full(fd, hs, (size_t)hn) < 0) {
            fprintf(stderr, "[vmm_inject_env] handshake write failed: %s (attempt %d)\n",
                    strerror(errno), attempt);
            close(fd);
            continue;
        }
        char rbuf[64];
        size_t roff = 0;
        int hfail = 0;
        for (;;) {
            if (roff >= sizeof(rbuf) - 1) { hfail = 1; break; }
            ssize_t r = read(fd, rbuf + roff, 1);
            if (r < 0) {
                if (errno == EINTR) continue;
                fprintf(stderr, "[vmm_inject_env] handshake read failed: %s (attempt %d)\n",
                        strerror(errno), attempt);
                hfail = 1;
                break;
            }
            if (r == 0) break;
            if (rbuf[roff++] == '\n') break;
        }
        rbuf[roff] = '\0';
        if (hfail) {
            close(fd);
            continue;
        }
        if (strncmp(rbuf, "OK", 2) != 0) {
            fprintf(stderr, "[vmm_inject_env] handshake got '%s' (attempt %d)\n",
                    rbuf, attempt);
            close(fd);
            continue;
        }

        int wfail = 0;
        for (int i = 0; env_vars[i]; i++) {
            if (write_full(fd, env_vars[i], strlen(env_vars[i])) < 0 ||
                write_full(fd, "\n", 1) < 0) {
                fprintf(stderr, "[vmm_inject_env] env write failed: %s (attempt %d)\n",
                        strerror(errno), attempt);
                wfail = 1;
                break;
            }
        }
        close(fd);
        if (wfail) continue;
        rc = 0;
    }
    if (rc != 0) errno = EPROTO;
    return rc;
}

// Snapshot the paused VM's state+memory to jail-view paths.
int vmm_snapshot(vm_handle_t* vm, const char* vmstate_jailview, const char* mem_jailview) {
    if (!vm || !vmstate_jailview || !mem_jailview) {
        errno = EINVAL;
        return -1;
    }
    char body[1024];
    snprintf(body, sizeof(body),
             "{\"snapshot_type\": \"Full\", \"snapshot_path\": \"%s\", "
             "\"mem_file_path\": \"%s\"}",
             vmstate_jailview, mem_jailview);
    // Use fc_transact (not fc_put) to capture the response body on failure.
    // Firecracker's fault_message tells us exactly what went wrong
    // (EPERM on /out, bad jail-view path, wrong VM state, etc.).
    char rbody[4096];
    size_t rlen = 0;
    int code = fc_transact(vm->api_sock_path, "PUT", "/snapshot/create",
                           body, rbody, sizeof(rbody), &rlen);
    if (code < 0) {
        fprintf(stderr, "[vmm_snapshot] FAIL: fc_transact error errno=%d\n", errno);
        return -1;
    }
    if (code < 200 || code >= 300) {
        rbody[rlen < sizeof(rbody) - 1 ? rlen : sizeof(rbody) - 1] = '\0';
        fprintf(stderr, "[vmm_snapshot] FAIL HTTP %d: %s\n", code, rbody);
        return -1;
    }
    return 0;
}

int vmm_destroy(vm_handle_t* vm) {
    if (!vm) {
        errno = EINVAL;
        return -1;
    }
    if (vm->vmm_pid > 0) {
        kill(vm->vmm_pid, SIGKILL);
        int st = 0;
        while (waitpid(vm->vmm_pid, &st, 0) < 0 && errno == EINTR) {
        }
        vm->vmm_pid = -1;
    }
    uffd_stop(vm);
    if (vm->has_net) {
        network_cleanup(&vm->net);
        vm->has_net = false;
    }
    jail_cleanup(vm->jail_root);
    free(vm);
    return 0;
}

vm_handle_t* vmm_restore(const char* template_name, const char* vm_id,
                         const char* tap_name, uint32_t guest_ip) {
    if (!template_name || !vm_id || !*vm_id || !tap_name) {
        errno = EINVAL;
        return NULL;
    }
    (void)guest_ip;  // tap retarget only; the guest MAC is fixed by the snapshot
    char store[PATH_MAX], state_src[PATH_MAX], mem_src[PATH_MAX];
    snprintf(store, sizeof(store), "%s/%s", snapshot_parent(), template_name);
    snprintf(state_src, sizeof(state_src), "%s/vmstate", store);
    snprintf(mem_src, sizeof(mem_src), "%s/memory.snap", store);
    struct stat st;
    if (stat(state_src, &st) < 0 || stat(mem_src, &st) < 0) {
        errno = ENOENT;
        return NULL;
    }
    snap_manifest_t* manifest = NULL;
    if (read_manifest(template_name, &manifest) < 0) return NULL;
    long hps = sysconf(_SC_PAGESIZE);
    if (manifest->page_size != (uint32_t)(hps > 0 ? hps : 4096)) {
        free(manifest);
        errno = EINVAL;
        return NULL;
    }

    vm_handle_t* vm = calloc(1, sizeof(*vm));
    if (!vm) {
        free(manifest);
        return NULL;
    }
    vm->sandbox_id = atomic_fetch_add(&next_id, 1);
    vm->vmm_pid = -1;
    vm->uffd_fd = -1;
    char jail_root[PATH_MAX];
    snprintf(jail_root, sizeof(jail_root), "%s/%s", jail_parent(), vm_id);
    snprintf(vm->jail_root, sizeof(vm->jail_root), "%s", jail_root);
    snprintf(vm->api_sock_path, sizeof(vm->api_sock_path), "%s/api.sock", jail_root);
    char uds_host[PATH_MAX];
    snprintf(uds_host, sizeof(uds_host), "%s/uffd.sock", jail_root);
    // A previous run killed before vmm_destroy can leave a stale jail whose
    // api.sock Firecracker cannot rebind (connect then fails ECONNREFUSED
    // forever, and wait_for_file passes on the stale file). Clear it first.
    jail_cleanup(jail_root);
    // 0700: the jail holds the per-VM vsock UDS (env injection channel); only
    // root and the jailed uid may traverse it (Phase 10.3).
    if (mkdir_recursive(jail_root, 0700) < 0) {
        free(manifest);
        free(vm);
        return NULL;
    }

    // Handler UDS: listening before load so no fault is ever unhandled.
    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        free(manifest);
        free(vm);
        return NULL;
    }
    struct sockaddr_un uaddr;
    memset(&uaddr, 0, sizeof(uaddr));
    uaddr.sun_family = AF_UNIX;
    snprintf(uaddr.sun_path, sizeof(uaddr.sun_path), "%s", uds_host);
    unlink(uds_host);
    if (bind(listen_fd, (struct sockaddr*)&uaddr, sizeof(uaddr)) < 0 ||
        listen(listen_fd, 1) < 0) {
        close(listen_fd);
        free(manifest);
        free(vm);
        return NULL;
    }
    // Firecracker connects as the jailed uid; the socket lives in the jail.
    if (chmod(uds_host, 0777) < 0) {
        close(listen_fd);
        free(manifest);
        free(vm);
        return NULL;
    }

    jail_files_t files = { .firecracker_bin = fc_bin(), .kernel_path = NULL,
                           .rootfs_path = NULL, .snap_state_src = state_src,
                           .snap_mem_src = mem_src, .out_dir = NULL };
    // Rootfs backing must exist at the same jail path as at capture time.
    char tpl_rootfs[PATH_MAX];
    snprintf(tpl_rootfs, sizeof(tpl_rootfs), "%s/rootfs.ext4", store);
    if (stat(tpl_rootfs, &st) == 0) files.rootfs_path = tpl_rootfs;
    char serial[PATH_MAX];
    snprintf(serial, sizeof(serial), "%s/serial.log", jail_root);
    jailer_config_t jcfg = { .jailer_uid = 65534, .jailer_gid = 65534,
                             .cgroup_path = NULL };
    char* argv[8];
    int ai = 0;
    argv[ai++] = (char*)"/firecracker";
    argv[ai++] = (char*)"--api-sock"; argv[ai++] = (char*)"/api.sock";
    argv[ai++] = (char*)"--id"; argv[ai++] = (char*)vm_id;
    argv[ai++] = (char*)"--no-seccomp";
    if (pci_enabled()) argv[ai++] = (char*)"--enable-pci";
    argv[ai++] = NULL;
    bool seccomp = getenv("SANDBOX_FC_SECCOMP") == NULL ||
                   strcmp(getenv("SANDBOX_FC_SECCOMP"), "0") != 0;
    pid_t pid = spawn_jailed(jail_root, &jcfg, "/firecracker", argv, true, seccomp,
                             &files, serial);
    if (pid <= 0) {
        close(listen_fd);
        free(manifest);
        free(vm);
        return NULL;
    }
    vm->vmm_pid = pid;
    if (wait_for_file(vm->api_sock_path, FC_FILE_WAIT_MS) < 0) {
        fprintf(stderr, "[vmm_restore] FAIL: wait_for_file(%s) errno=%d\n", vm->api_sock_path, errno);
        close(listen_fd);
        cold_fail(vm);
        free(manifest);
        return NULL;
    }
    fprintf(stderr, "[vmm_restore] api.sock ready: %s\n", vm->api_sock_path);

    // Firecracker faults on guest memory *during* /snapshot/load (it writes
    // boot/device state into the registered region and blocks in the kernel on
    // handle_userfault). So the UFFD handler must be live while the load
    // request is in flight: send the request without waiting, accept + start
    // the handler, then read the response.
    char mem_host[PATH_MAX];
    snprintf(mem_host, sizeof(mem_host), "%s/memory.snap", store);
    // Per-VM vsock backend (Phase 9b): retarget the template's vsock device at
    // load so each VM gets its own host UDS for env injection.
    snprintf(vm->vsock_uds, sizeof(vm->vsock_uds), "%s" FC_VSOCK_JAILVIEW, jail_root);
    unlink(vm->vsock_uds);
    fprintf(stderr, "[vmm_restore] sending /snapshot/load...\n");
    char load_req[1024];
    snprintf(load_req, sizeof(load_req),
             "{\"snapshot_path\": \"/vmstate\", \"mem_backend\": "
             "{\"backend_path\": \"/uffd.sock\", \"backend_type\": \"Uffd\"}, "
             "\"network_overrides\": [{\"iface_id\": \"%s\", \"host_dev_name\": \"%s\"}], "
             "\"vsock_override\": {\"uds_path\": \"%s\"}, "
             "\"resume_vm\": false}",
             FC_TEMPLATE_IFACE, tap_name, FC_VSOCK_JAILVIEW);
    int load_fd = fc_send_request(vm->api_sock_path, "PUT", "/snapshot/load", load_req);
    if (load_fd < 0) {
        fprintf(stderr, "[vmm_restore] FAIL: send /snapshot/load errno=%d\n", errno);
        close(listen_fd);
        cold_fail(vm);
        free(manifest);
        return NULL;
    }
    fprintf(stderr, "[vmm_restore] uffd_accept_handler: mem_host=%s timeout=%d\n", mem_host, FC_ACCEPT_TIMEOUT_MS);
    if (uffd_accept_handler(vm, listen_fd, mem_host, manifest, FC_ACCEPT_TIMEOUT_MS) < 0) {
        int saved_errno = errno;
        close(load_fd);
        close(listen_fd);
        cold_fail(vm);
        free(manifest);  // accept failed: ownership never transferred
        errno = saved_errno;  // preserve the real error across cold_fail cleanup
        return NULL;
    }
    close(listen_fd);
    if (uffd_start_handler(vm) < 0 || uffd_start_prefault(vm) < 0) {
        close(load_fd);
        uffd_stop(vm);
        cold_fail(vm);
        return NULL;
    }
    // Handler is now serving the faults Firecracker is blocked on; the load
    // request completes once restore finishes.
    char load_body[1024];
    int load_code = fc_read_response(load_fd, load_body, sizeof(load_body), NULL);
    if (load_code < 0 || load_code < 200 || load_code >= 300) {
        fprintf(stderr, "[vmm_restore] FAIL: /snapshot/load -> %d %s\n",
                load_code, load_body);
        uffd_stop(vm);
        cold_fail(vm);
        return NULL;
    }
    fprintf(stderr, "[vmm_restore] /snapshot/load ok\n");

    // Tap was retargeted in the load request; just resume vCPUs.
    if (vmm_resume_vcpus(vm) < 0) {
        uffd_stop(vm);
        cold_fail(vm);
        return NULL;
    }
    return vm;
}

// --- pool glue: template source is global (restore takes no args per LLD) ---

static char g_template[64] = "";
static atomic_uint_fast32_t g_vm_counter = 1;

void pool_set_restore_source(const char* template_name) {
    snprintf(g_template, sizeof(g_template), "%s", template_name ? template_name : "");
}

vm_handle_t* restore_vm_from_snapshot(void) {
    if (g_template[0] == '\0') {
        usleep(83000);  // no source configured: keep the restore latency shape
        return NULL;
    }
    if (strcmp(g_template, "TEST-DUMMY") == 0) {
        // Unit-test hook (pool/snapshot tests without a template): dummy
        // handle after the simulated restore latency. Never used in
        // production (the daemon always sets a real template).
        usleep(83000);
        vm_handle_t* dummy = calloc(1, sizeof(*dummy));
        if (dummy) {
            dummy->sandbox_id = atomic_fetch_add(&next_id, 1);
            dummy->vmm_pid = -1;
            dummy->uffd_fd = -1;
        }
        return dummy;
    }
    char vm_id[32];
    snprintf(vm_id, sizeof(vm_id), "vm-%u",
             (unsigned)atomic_fetch_add(&g_vm_counter, 1));
    vm_network_t net;
    memset(&net, 0, sizeof(net));
    if (network_setup(vm_id, &net) < 0) return NULL;
    vm_handle_t* vm = vmm_restore(g_template, vm_id, net.tap_name, net.guest_ip);
    if (!vm) {
        network_cleanup(&net);
        return NULL;
    }
    vm->net = net;
    vm->has_net = true;
    return vm;
}
