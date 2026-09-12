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

#define BROKER_IP "169.254.0.1"
#define GUEST_IP "169.254.0.2"
#define BROKER_PORT 8080

static int run_cmd(const char* cmd) {
    int rc = system(cmd);
    return (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) ? 0 : -1;
}

// LLD assumes the chain exists; create table + forward chain on first use.
static int ensure_policy_chain(void) {
    if (run_cmd("nft list chain ip sandbox_policy forward >/dev/null 2>&1") == 0)
        return 0;
    run_cmd("nft add table ip sandbox_policy >/dev/null 2>&1");
    return run_cmd("nft add chain ip sandbox_policy forward "
                   "'{ type filter hook forward priority 0; policy accept; }'");
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

    // 3. Assign host-side IP (169.254.0.1)
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap_name);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(BROKER_IP);
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        close(sock);
        close(tap_fd);
        return -1;
    }
    // Bare SIOCSIFADDR leaves a /32 with no connected route, so guest replies
    // would route out the default interface. Set the /16 link-local netmask.
    struct sockaddr_in* mask = (struct sockaddr_in*)&ifr.ifr_netmask;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap_name);
    mask->sin_family = AF_INET;
    mask->sin_addr.s_addr = inet_addr("255.255.0.0");
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        close(sock);
        close(tap_fd);
        return -1;
    }
    close(sock);

    // 4. nftables: only broker reachable, everything else drops.
    if (ensure_policy_chain() < 0) { close(tap_fd); return -1; }
    char nft_cmd[1024];
    snprintf(nft_cmd, sizeof(nft_cmd),
        "nft add rule ip sandbox_policy forward "
        "iifname %s ip daddr %s tcp dport %d accept",
        tap_name, BROKER_IP, BROKER_PORT);
    if (run_cmd(nft_cmd) < 0) { close(tap_fd); return -1; }
    snprintf(nft_cmd, sizeof(nft_cmd),
        "nft add rule ip sandbox_policy forward iifname %s drop",
        tap_name);
    if (run_cmd(nft_cmd) < 0) { close(tap_fd); return -1; }

    // 5. Return tap_fd and guest IP to vmm_manager (Firecracker will use this fd)
    out_net->tap_fd = tap_fd;
    out_net->guest_ip = inet_addr(GUEST_IP);
    snprintf(out_net->tap_name, IFNAMSIZ, "%s", tap_name);

    return 0;
}

// Delete every rule in the forward chain matching this tap (handles resolved
// at cleanup time, so no handle tracking is needed in vm_network_t).
static void delete_tap_rules(const char* tap_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nft -a list chain ip sandbox_policy forward 2>/dev/null");
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
                 "nft delete rule ip sandbox_policy forward handle %ld >/dev/null 2>&1",
                 handles[i]);
        run_cmd(cmd);
    }
}

int network_cleanup(const vm_network_t* net) {
    if (!net) { errno = EINVAL; return -1; }
    // 1. Delete nftables rules
    delete_tap_rules(net->tap_name);

    // 2. Close tap fd (kernel removes interface)
    close(net->tap_fd);

    return 0;
}
