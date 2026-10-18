// SPDX-License-Identifier: GPL-2.0-only
// Network Manager (§5.7): tap devices plus nftables rules forcing guest
// traffic through the broker. Phase 10.5: rules and cleanup run through
// libnftables (no shell). A system() fallback is kept for builds without the
// library. Names flowing in here are validated at the IPC boundary.

#include "network_manager.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef SANDBOX_HAVE_LIBNFTABLES
#include <nftables/libnftables.h>
#endif

#define BROKER_PORT 8080

// Per-VM /30 subnets from 169.254.0.0/16 (16384 slots): subnet i holds
// .4i+1 (host) and .4i+2 (guest). FNV-1a hash keeps string vm_ids stable.
int network_subnet_addrs(const char* vm_id, uint32_t* out_host_ip,
                         uint32_t* out_guest_ip) {
    if (!vm_id || !out_host_ip || !out_guest_ip) {
        errno = EINVAL;
        return -1;
    }
    uint32_t h = 2166136261u;
    for (const unsigned char* p = (const unsigned char*)vm_id; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    uint32_t base = (h % 16384u) * 4;
    uint32_t host = (169u << 24) | (254u << 16) | base | 1u;
    uint32_t guest = (169u << 24) | (254u << 16) | base | 2u;
    *out_host_ip = htonl(host);
    *out_guest_ip = htonl(guest);
    return 0;
}

// Execute one nft command (no "nft" prefix). nft's stdout is ALWAYS captured:
// a non-NULL out receives it, otherwise it is discarded. Capturing must not be
// conditional — an un-buffered libnftables context writes command output (e.g.
// the `list chain` probes in ensure_chain) straight to the process stdout,
// which leaked into the daemon log. Returns 0 iff the command succeeded.
static int nft_exec(const char* cmd, char* out, size_t outlen) {
#ifdef SANDBOX_HAVE_LIBNFTABLES
    struct nft_ctx* ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) return -1;
    nft_ctx_buffer_output(ctx);
    if (out && outlen) nft_ctx_output_set_flags(ctx, NFT_CTX_OUTPUT_HANDLE);
    int rc = nft_run_cmd_from_buffer(ctx, cmd);
    if (out && outlen) {
        const char* o = nft_ctx_get_output_buffer(ctx);
        snprintf(out, outlen, "%s", o ? o : "");
    }
    nft_ctx_unbuffer_output(ctx);
    nft_ctx_free(ctx);
    return rc;
#else
    char full[1024];
    if (out && outlen) {
        snprintf(full, sizeof(full), "nft %s", cmd);
        FILE* fp = popen(full, "r");
        if (!fp) return -1;
        size_t n = fread(out, 1, outlen - 1, fp);
        out[n] = '\0';
        return (pclose(fp) == 0) ? 0 : -1;
    }
    snprintf(full, sizeof(full), "nft %s >/dev/null 2>&1", cmd);
    int rc = system(full);
    return (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) ? 0 : -1;
#endif
}

// LLD assumes the chains exist; create table + forward/input chains on use.
static int ensure_chain(const char* chain, const char* hook) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "list chain ip sandbox_policy %s", chain);
    if (nft_exec(cmd, NULL, 0) == 0) return 0;
    nft_exec("add table ip sandbox_policy", NULL, 0);
    snprintf(cmd, sizeof(cmd),
             "add chain ip sandbox_policy %s "
             "{ type filter hook %s priority 0; policy accept; }",
             chain, hook);
    return nft_exec(cmd, NULL, 0);
}

static int ensure_policy_chains(void) {
    if (ensure_chain("forward", "forward") < 0) return -1;
    if (ensure_chain("input", "input") < 0) return -1;
    return 0;
}

// Called once on daemon startup; setup ensures it too.
int network_manager_init(void) {
    return ensure_policy_chains();
}

// Attach to an existing tap by name (no TUNSETIFF flags beyond tap/no-pi).
// Used for frame injection in tests; the VMM never holds a tap fd.
int network_tap_open(const vm_network_t* net) {
    if (!net || !net->tap_name[0]) { errno = EINVAL; return -1; }
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", net->tap_name);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Destroy a persistent tap: attach, clear persist, release. The kernel drops
// the interface once the last fd (ours here) is closed.
static int network_tap_delete(const char* name) {
    if (!name || !*name) return -1;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }
    // By value: 0 clears the persistent flag, so closing removes the device.
    if (ioctl(fd, TUNSETPERSIST, 0) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int network_setup(const char* vm_id, vm_network_t* out_net) {
    if (!vm_id || !out_net) { errno = EINVAL; return -1; }
    char tap_name[IFNAMSIZ];
    if (snprintf(tap_name, sizeof(tap_name), "tap-%s", vm_id) >= (int)sizeof(tap_name)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    // 1. Create the tap device, make it persistent, then release our fd.
    //    Firecracker opens the tap itself by name; while a non-multiqueue fd
    //    is held, a second TUNSETIFF attach fails EBUSY. A persistent device
    //    survives the close and can be reopened by name (VMM attach, tests).
    int tap_fd = open("/dev/net/tun", O_RDWR);
    if (tap_fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap_name);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(tap_fd, TUNSETIFF, &ifr) < 0) {
        close(tap_fd);
        return -1;
    }
    // TUNSETPERSIST takes the value directly (not a pointer); a non-zero value
    // keeps the device alive after the last fd closes.
    if (ioctl(tap_fd, TUNSETPERSIST, 1) < 0) {
        close(tap_fd);
        return -1;
    }
    close(tap_fd);
    tap_fd = -1;  // no fd held; the device lives on (persistent)

    // 2. Bring tap interface up
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) goto fail_tap;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap_name);
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) { close(sock); goto fail_tap; }

    // 3. Assign host-side IP from this VM's /30 (mask /30, not classful).
    uint32_t host_ip, guest_ip;
    if (network_subnet_addrs(vm_id, &host_ip, &guest_ip) < 0) { close(sock); goto fail_tap; }
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap_name);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = host_ip;
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) { close(sock); goto fail_tap; }
    // Bare SIOCSIFADDR leaves a /32 with no connected route, so guest replies
    // would route out the default interface. Set the /30 netmask.
    struct sockaddr_in* mask = (struct sockaddr_in*)&ifr.ifr_netmask;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap_name);
    mask->sin_family = AF_INET;
    mask->sin_addr.s_addr = htonl(0xFFFFFFFCu);
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) { close(sock); goto fail_tap; }
    close(sock);

    // 4. nftables: only this VM's broker endpoint reachable, rest drops.
    // Forward chain covers routed traffic; input chain covers host-local
    // services (without it guests can port-scan the host).
    if (ensure_policy_chains() < 0) goto fail_tap;
    char host_ip_s[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &host_ip, host_ip_s, sizeof(host_ip_s))) goto fail_tap;
    char nft_cmd[1024];
    const char* chains[2] = { "forward", "input" };
    for (int c = 0; c < 2; c++) {
        snprintf(nft_cmd, sizeof(nft_cmd),
            "add rule ip sandbox_policy %s "
            "iifname %s ip daddr %s tcp dport %d accept",
            chains[c], tap_name, host_ip_s, BROKER_PORT);
        if (nft_exec(nft_cmd, NULL, 0) != 0) goto fail_tap;
        snprintf(nft_cmd, sizeof(nft_cmd),
            "add rule ip sandbox_policy %s iifname %s drop",
            chains[c], tap_name);
        if (nft_exec(nft_cmd, NULL, 0) != 0) goto fail_tap;
    }

    // 5. Return guest IP + tap name (no fd: Firecracker owns the device)
    out_net->tap_fd = -1;
    out_net->guest_ip = guest_ip;
    snprintf(out_net->tap_name, IFNAMSIZ, "%s", tap_name);
    return 0;

fail_tap:
    network_tap_delete(tap_name);
    return -1;
}

// Delete every rule in a chain matching this tap (handles resolved at
// cleanup time, so no handle tracking is needed in vm_network_t).
static void delete_tap_rules(const char* chain, const char* tap_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "list chain ip sandbox_policy %s", chain);
    size_t cap = 65536;
    char* out = malloc(cap);
    if (!out) return;
    out[0] = '\0';
    if (nft_exec(cmd, out, cap) != 0) {
        free(out);
        return;
    }
    long handles[64];
    int n = 0;
    char match[IFNAMSIZ + 16];
    snprintf(match, sizeof(match), "iifname \"%s\"", tap_name);
    for (char* line = strtok(out, "\n"); line && n < 64;
         line = strtok(NULL, "\n")) {
        if (!strstr(line, match)) continue;
        char* h = strstr(line, "# handle ");
        if (h) handles[n++] = atol(h + strlen("# handle "));
    }
    free(out);
    for (int i = 0; i < n; i++) {
        snprintf(cmd, sizeof(cmd),
                 "delete rule ip sandbox_policy %s handle %ld",
                 chain, handles[i]);
        nft_exec(cmd, NULL, 0);
    }
}

int network_cleanup(const vm_network_t* net) {
    if (!net) { errno = EINVAL; return -1; }
    // 1. Delete nftables rules from both chains
    delete_tap_rules("forward", net->tap_name);
    delete_tap_rules("input", net->tap_name);

    // 2. Drop any locally held fd (tests reopen the tap for injection), then
    //    destroy the persistent device by name. The VMM holds no fd.
    if (net->tap_fd >= 0) close(net->tap_fd);
    network_tap_delete(net->tap_name);

    return 0;
}
