// Network Manager (§5.7): tap devices plus nftables rules forcing guest
// traffic through the broker. nftables via system() per LLD (libnftables TODO).

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

static int run_cmd(const char* cmd) {
    int rc = system(cmd);
    return (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) ? 0 : -1;
}

// LLD assumes the chains exist; create table + forward/input chains on use.
static int ensure_chain(const char* chain, const char* hook) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nft list chain ip sandbox_policy %s >/dev/null 2>&1",
             chain);
    if (run_cmd(cmd) == 0) return 0;
    run_cmd("nft add table ip sandbox_policy >/dev/null 2>&1");
    snprintf(cmd, sizeof(cmd),
             "nft add chain ip sandbox_policy %s "
             "'{ type filter hook %s priority 0; policy accept; }'",
             chain, hook);
    return run_cmd(cmd);
}

static int ensure_policy_chains(void) {
    if (ensure_chain("forward", "forward") < 0) return -1;
    if (ensure_chain("input", "input") < 0) return -1;
    return 0;
}

// Called once on daemon startup (Phase 8 wires the call); setup ensures too.
int network_manager_init(void) {
    return ensure_policy_chains();
}

int network_setup(const char* vm_id, vm_network_t* out_net) {
    if (!vm_id || !out_net) { errno = EINVAL; return -1; }
    char tap_name[IFNAMSIZ];
    if (snprintf(tap_name, sizeof(tap_name), "tap-%s", vm_id) >= (int)sizeof(tap_name)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    // 1. Create tap device
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

    // 2. Bring tap interface up
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { close(tap_fd); return -1; }
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap_name);
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        close(sock);
        close(tap_fd);
        return -1;
    }

    // 3. Assign host-side IP from this VM's /30 (mask /30, not classful).
    uint32_t host_ip, guest_ip;
    if (network_subnet_addrs(vm_id, &host_ip, &guest_ip) < 0) {
        close(sock);
        close(tap_fd);
        return -1;
    }
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap_name);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = host_ip;
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        close(sock);
        close(tap_fd);
        return -1;
    }
    // Bare SIOCSIFADDR leaves a /32 with no connected route, so guest replies
    // would route out the default interface. Set the /30 netmask.
    struct sockaddr_in* mask = (struct sockaddr_in*)&ifr.ifr_netmask;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap_name);
    mask->sin_family = AF_INET;
    mask->sin_addr.s_addr = htonl(0xFFFFFFFCu);
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        close(sock);
        close(tap_fd);
        return -1;
    }
    close(sock);

    // 4. nftables: only this VM's broker endpoint reachable, rest drops.
    // Forward chain covers routed traffic; input chain covers host-local
    // services (without it guests can port-scan the host).
    if (ensure_policy_chains() < 0) { close(tap_fd); return -1; }
    char host_ip_s[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &host_ip, host_ip_s, sizeof(host_ip_s))) {
        close(tap_fd);
        return -1;
    }
    char nft_cmd[1024];
    const char* chains[2] = { "forward", "input" };
    for (int c = 0; c < 2; c++) {
        snprintf(nft_cmd, sizeof(nft_cmd),
            "nft add rule ip sandbox_policy %s "
            "iifname %s ip daddr %s tcp dport %d accept",
            chains[c], tap_name, host_ip_s, BROKER_PORT);
        if (run_cmd(nft_cmd) < 0) { close(tap_fd); return -1; }
        snprintf(nft_cmd, sizeof(nft_cmd),
            "nft add rule ip sandbox_policy %s iifname %s drop",
            chains[c], tap_name);
        if (run_cmd(nft_cmd) < 0) { close(tap_fd); return -1; }
    }

    // 5. Return tap_fd and guest IP to vmm_manager (Firecracker will use this fd)
    out_net->tap_fd = tap_fd;
    out_net->guest_ip = guest_ip;
    snprintf(out_net->tap_name, IFNAMSIZ, "%s", tap_name);

    return 0;
}

// Delete every rule in a chain matching this tap (handles resolved at
// cleanup time, so no handle tracking is needed in vm_network_t).
static void delete_tap_rules(const char* chain, const char* tap_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nft -a list chain ip sandbox_policy %s 2>/dev/null",
             chain);
    FILE* fp = popen(cmd, "r");
    if (!fp) return;
    char line[1024];
    long handles[64];
    int n = 0;
    char match[IFNAMSIZ + 16];
    snprintf(match, sizeof(match), "iifname \"%s\"", tap_name);
    while (fgets(line, sizeof(line), fp) && n < 64) {
        if (!strstr(line, match)) continue;
        char* h = strstr(line, "# handle ");
        if (h) handles[n++] = atol(h + strlen("# handle "));
    }
    pclose(fp);
    for (int i = 0; i < n; i++) {
        snprintf(cmd, sizeof(cmd),
                 "nft delete rule ip sandbox_policy %s handle %ld >/dev/null 2>&1",
                 chain, handles[i]);
        run_cmd(cmd);
    }
}

int network_cleanup(const vm_network_t* net) {
    if (!net) { errno = EINVAL; return -1; }
    // 1. Delete nftables rules from both chains
    delete_tap_rules("forward", net->tap_name);
    delete_tap_rules("input", net->tap_name);

    // 2. Close tap fd (kernel removes interface)
    close(net->tap_fd);

    return 0;
}
