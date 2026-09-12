// Phase 3 verification (root only): tap setup per §5.7, nft rules present as
// specified, and packet-level proof from the guest side (frames written to
// the tap fd): 169.254.0.1:8080 answers SYN-ACK, non-broker destinations are
// dropped by OUR rule (proven by deleting it as a control and watching the
// SYN-ACK come through, then restoring it).

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "network_manager.h"

#define CHECK_RC(rc, what) do { int _rc = (rc); if (_rc != 0) { \
    fprintf(stderr, "FAIL %s: rc=%d (%s:%d)\n", (what), _rc, __FILE__, __LINE__); \
    abort(); } } while (0)
#define CHECK_SYS(call, what) do { if ((call) < 0) { \
    fprintf(stderr, "FAIL %s: %s (%s:%d)\n", (what), strerror(errno), __FILE__, __LINE__); \
    abort(); } } while (0)

#define OUTER_IP_S "192.0.2.1"  // TEST-NET-1: unroutable stand-in for "internet"
static const uint8_t GUEST_MAC[6] = {0x02, 0x00, 0x0a, 0x00, 0x00, 0x02};

// Per-run addresses from network_subnet_addrs() (network byte order + strings).
static uint32_t g_host_ip, g_guest_ip;
static char g_host_s[INET_ADDRSTRLEN], g_guest_s[INET_ADDRSTRLEN];

static int run(const char* cmd) {
    int rc = system(cmd);
    return (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) ? 0 : -1;
}

// stdout of cmd (first 64KB). Caller frees.
static char* capture(const char* cmd) {
    FILE* fp = popen(cmd, "r");
    if (!fp) abort();
    static char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    pclose(fp);
    char* out = malloc(n + 1);
    memcpy(out, buf, n + 1);
    return out;
}

static uint16_t csum(const uint8_t* data, size_t len) {
    uint32_t s = 0;
    while (len > 1) {
        s += ((uint16_t)data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }
    if (len) s += (uint16_t)data[0] << 8;
    s = (s >> 16) + (s & 0xffff);
    s += s >> 16;
    return (uint16_t)~s;
}

static uint16_t tcp_csum(const uint8_t* src, const uint8_t* dst,
                         const uint8_t* seg, size_t len) {
    uint32_t s = 0;
    for (int i = 0; i < 4; i += 2) s += ((uint16_t)src[i] << 8) | src[i + 1];
    for (int i = 0; i < 4; i += 2) s += ((uint16_t)dst[i] << 8) | dst[i + 1];
    s += 6;
    s += (uint16_t)len;
    while (len > 1) {
        s += ((uint16_t)seg[0] << 8) | seg[1];
        seg += 2;
        len -= 2;
    }
    if (len) s += (uint16_t)seg[0] << 8;
    s = (s >> 16) + (s & 0xffff);
    s += s >> 16;
    return (uint16_t)~s;
}

static void get_tap_mac(const char* tap, uint8_t* mac) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) abort();
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) abort();
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(s);
}

// Ethernet + IPv4 + TCP SYN from guest to dst_ip:dport.
static size_t build_syn(uint8_t* frame, const uint8_t* dst_mac,
                        uint32_t sport, uint32_t dport, uint32_t seq, uint32_t dst_ip) {
    uint32_t src_ip = g_guest_ip;
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, GUEST_MAC, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;
    uint8_t* ip = frame + 14;
    ip[0] = 0x45;
    ip[1] = 0;
    uint16_t tot = htons(20 + 20);
    memcpy(ip + 2, &tot, 2);
    memset(ip + 4, 0, 4);
    ip[8] = 64;
    ip[9] = 6;
    memset(ip + 10, 0, 2);
    memcpy(ip + 12, &src_ip, 4);
    memcpy(ip + 16, &dst_ip, 4);
    uint16_t ipc = htons(csum(ip, 20));
    memcpy(ip + 10, &ipc, 2);
    uint8_t* tcp = ip + 20;
    uint16_t sp = htons((uint16_t)sport), dp = htons((uint16_t)dport);
    memcpy(tcp, &sp, 2);
    memcpy(tcp + 2, &dp, 2);
    uint32_t sq = htonl(seq);
    memcpy(tcp + 4, &sq, 4);
    memset(tcp + 8, 0, 4);
    tcp[12] = 0x50;
    tcp[13] = 0x02;  // SYN
    uint16_t win = htons(64240);
    memcpy(tcp + 14, &win, 2);
    memset(tcp + 16, 0, 4);
    uint8_t srcb[4], dstb[4];
    memcpy(srcb, &src_ip, 4);
    memcpy(dstb, &dst_ip, 4);
    uint16_t tc = htons(tcp_csum(srcb, dstb, tcp, 20));
    memcpy(tcp + 16, &tc, 2);
    return 14 + 20 + 20;
}

static void send_arp_reply(int fd, const uint8_t* tap_mac, const uint8_t* req) {
    // req: an ARP who-has for the guest IP. Answer with GUEST_MAC.
    uint8_t f[42];
    memcpy(f, req + 6, 6);       // dst = requester
    memcpy(f + 6, GUEST_MAC, 6); // src = guest
    f[12] = 0x08;
    f[13] = 0x06;
    f[14] = 0x00; f[15] = 0x01; f[16] = 0x08; f[17] = 0x00;
    f[18] = 0x06; f[19] = 0x04; f[20] = 0x00; f[21] = 0x02;
    memcpy(f + 22, GUEST_MAC, 6);
    uint32_t gip = g_guest_ip;
    memcpy(f + 28, &gip, 4);
    memcpy(f + 32, req + 6, 6);
    memcpy(f + 38, req + 28, 4);
    (void)tap_mac;
    if (write(fd, f, sizeof(f)) != (ssize_t)sizeof(f)) abort();
}

static int is_arp_for_guest(const uint8_t* f, ssize_t n) {
    if (n < 42 || f[12] != 0x08 || f[13] != 0x06 || f[20] != 0x00 || f[21] != 0x01)
        return 0;
    uint32_t gip = g_guest_ip, tip;
    memcpy(&tip, f + 38, 4);
    return tip == gip;
}

// Wait up to timeout_ms for a SYN-ACK matching (sport_s, dport_s, seq).
// Answers ARP for the guest along the way. Returns 0 on match.
static int await_synack(int fd, const uint8_t* tap_mac, uint32_t sport_s,
                        uint32_t dport_s, uint32_t seq, uint32_t server_ip,
                        int timeout_ms) {
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_sec += timeout_ms / 1000;
    end.tv_nsec += (timeout_ms % 1000) * 1000000L;
    uint32_t guest_ip = g_guest_ip;
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int remain = (int)((end.tv_sec - now.tv_sec) * 1000 +
                           (end.tv_nsec - now.tv_nsec) / 1000000);
        if (remain <= 0) return -1;
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, remain) <= 0) return -1;
        uint8_t f[2048];
        ssize_t n = read(fd, f, sizeof(f));
        if (n < 14) continue;
        if (is_arp_for_guest(f, n)) {
            send_arp_reply(fd, tap_mac, f);
            continue;
        }
        if (n < 54 || f[12] != 0x08 || f[13] != 0x00) continue;
        const uint8_t* ip = f + 14;
        if ((ip[0] >> 4) != 4 || ip[9] != 6) continue;
        uint32_t s, d;
        memcpy(&s, ip + 12, 4);
        memcpy(&d, ip + 16, 4);
        if (s != server_ip || d != guest_ip) continue;
        const uint8_t* tcp = ip + 20;
        uint16_t sp, dp;
        memcpy(&sp, tcp, 2);
        memcpy(&dp, tcp + 2, 2);
        uint32_t ack;
        memcpy(&ack, tcp + 8, 4);
        if (ntohs(sp) == (uint16_t)dport_s && ntohs(dp) == (uint16_t)sport_s &&
            (tcp[13] & 0x12) == 0x12 && ntohl(ack) == seq + 1)
            return 0;  // SYN-ACK, seq acknowledged
    }
}

// Returns 0 if no IPv4 frame arrives within ms (drop verdict).
// Non-IPv4 noise (ARP, IPv6 MLD on fresh interfaces) is ignored.
static int expect_silence(int fd, int ms) {
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_sec += ms / 1000;
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int remain = (int)((end.tv_sec - now.tv_sec) * 1000 +
                           (end.tv_nsec - now.tv_nsec) / 1000000);
        if (remain <= 0) return 0;
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int rc = poll(&pfd, 1, remain);
        if (rc < 0) abort();
        if (rc == 0) return 0;
        uint8_t f[2048];
        ssize_t n = read(fd, f, sizeof(f));
        if (n >= 14 && f[12] == 0x08 && f[13] == 0x00) return -1;  // IPv4 leaked
    }
}

// RST to tear down an embryonic connection (stops SYN-ACK retransmits from
// polluting later silence windows). seq_no = our ISN + 1.
static void send_rst(int fd, const uint8_t* dst_mac, uint32_t sport,
                     uint32_t dport, uint32_t seq_no, uint32_t dst_ip) {
    uint32_t src_ip = g_guest_ip;
    uint8_t frame[54];
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, GUEST_MAC, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;
    uint8_t* ip = frame + 14;
    ip[0] = 0x45;
    ip[1] = 0;
    uint16_t tot = htons(40);
    memcpy(ip + 2, &tot, 2);
    memset(ip + 4, 0, 4);
    ip[8] = 64;
    ip[9] = 6;
    memset(ip + 10, 0, 2);
    memcpy(ip + 12, &src_ip, 4);
    memcpy(ip + 16, &dst_ip, 4);
    uint16_t ipc = htons(csum(ip, 20));
    memcpy(ip + 10, &ipc, 2);
    uint8_t* tcp = ip + 20;
    uint16_t sp = htons((uint16_t)sport), dp = htons((uint16_t)dport);
    memcpy(tcp, &sp, 2);
    memcpy(tcp + 2, &dp, 2);
    uint32_t sq = htonl(seq_no);
    memcpy(tcp + 4, &sq, 4);
    memset(tcp + 8, 0, 4);
    tcp[12] = 0x50;
    tcp[13] = 0x04;  // RST
    memset(tcp + 14, 0, 6);
    uint8_t srcb[4], dstb[4];
    memcpy(srcb, &src_ip, 4);
    memcpy(dstb, &dst_ip, 4);
    uint16_t tc = htons(tcp_csum(srcb, dstb, tcp, 20));
    memcpy(tcp + 16, &tc, 2);
    if (write(fd, frame, sizeof(frame)) != (ssize_t)sizeof(frame)) abort();
}

static long drop_rule_handle(const char* tap) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nft -a list chain ip sandbox_policy forward 2>/dev/null");
    char* out = capture(cmd);
    char match[IFNAMSIZ + 32];
    snprintf(match, sizeof(match), "iifname \"%s\"", tap);
    long handle = -1;
    for (char* line = strtok(out, "\n"); line; line = strtok(NULL, "\n")) {
        if (strstr(line, match) && strstr(line, " drop")) {
            char* h = strstr(line, "# handle ");
            if (h) handle = atol(h + strlen("# handle "));
        }
    }
    free(out);
    return handle;
}

static int ip_forward_saved = -1;
static void set_ip_forward(int v) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "echo %d > /proc/sys/net/ipv4/ip_forward", v);
    CHECK_RC(run(cmd), "set ip_forward");
}

int main(void) {
    if (geteuid() != 0) {
        printf("SKIP (needs root: tap + nftables)\n");
        return 0;
    }
    char vm_id[64];
    snprintf(vm_id, sizeof(vm_id), "vmt%d", (int)getpid() % 100000);

    // This VM's /30 addrs; everything below derives from these.
    CHECK_RC(network_subnet_addrs(vm_id, &g_host_ip, &g_guest_ip), "subnet addrs");
    if (!inet_ntop(AF_INET, &g_host_ip, g_host_s, sizeof(g_host_s))) abort();
    if (!inet_ntop(AF_INET, &g_guest_ip, g_guest_s, sizeof(g_guest_s))) abort();

    // Save ip_forward for the cleanup fixture (restores it even on abort).
    FILE* ipf = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    if (ipf) {
        int v = fgetc(ipf);
        fclose(ipf);
        FILE* sv = fopen("/tmp/sandbox_ipforward.txt", "w");
        if (sv) {
            fputc(v, sv);
            fclose(sv);
        }
    }

    // Best-effort cleanup of fixed-name artifacts leaked by aborted runs.
    // NOTE: backgrounded children must redirect all fds, or popen's fread
    // blocks until they exit (this once delayed the test past the listener's
    // own timeout and broke the control phase).
    run("pkill -9 -f '[1]92\\.0\\.2\\.1' 2>/dev/null");
    run("for ns in $(ip netns list 2>/dev/null | grep -o 'sbtest[0-9]*'); do "
        "ip netns del $ns 2>/dev/null; done; true");
    char groute[64];
    snprintf(groute, sizeof(groute), "ip route del %s/32 2>/dev/null; ", g_guest_s);
    run(groute);
    run("ip route del 192.0.2.1/32 2>/dev/null; true");

    // --- setup + state ---
    printf("[test] setup_state...\n");
    fflush(stdout);
    vm_network_t net;
    CHECK_RC(network_setup(vm_id, &net), "network_setup");
    char tap[IFNAMSIZ];
    snprintf(tap, sizeof(tap), "tap-%s", vm_id);
    if (net.tap_fd < 0) abort();
    if (net.guest_ip != g_guest_ip) abort();
    if (if_nametoindex(tap) == 0) abort();
    int ds = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap);
    CHECK_SYS(ioctl(ds, SIOCGIFFLAGS, &ifr), "SIOCGIFFLAGS");
    if (!(ifr.ifr_flags & IFF_UP)) abort();
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tap);
    CHECK_SYS(ioctl(ds, SIOCGIFADDR, &ifr), "SIOCGIFADDR");
    struct sockaddr_in* a = (struct sockaddr_in*)&ifr.ifr_addr;
    if (a->sin_addr.s_addr != g_host_ip) abort();
    close(ds);
    char* rules = capture("nft -a list chain ip sandbox_policy forward 2>/dev/null");
    char want[IFNAMSIZ + 16];
    snprintf(want, sizeof(want), "iifname \"%s\"", tap);
    if (!strstr(rules, want) || !strstr(rules, "dport 8080 accept") || !strstr(rules, " drop")) {
        fprintf(stderr, "rules missing:\n%s\n", rules);
        abort();
    }
    free(rules);
    rules = capture("nft -a list chain ip sandbox_policy input 2>/dev/null");
    if (!strstr(rules, want) || !strstr(rules, "dport 8080 accept") || !strstr(rules, " drop")) {
        fprintf(stderr, "input rules missing:\n%s\n", rules);
        abort();
    }
    free(rules);
    printf("[test] setup_state: PASS\n");
    fflush(stdout);

    // --- broker path: SYN to 169.254.0.1:8080 gets SYN-ACK ---
    printf("[test] broker_path...\n");
    fflush(stdout);
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in la = { .sin_family = AF_INET,
                              .sin_port = htons(8080),
                              .sin_addr.s_addr = g_host_ip };
    CHECK_SYS(bind(listen_fd, (struct sockaddr*)&la, sizeof(la)), "bind 8080");
    CHECK_SYS(listen(listen_fd, 5), "listen");
    uint8_t tap_mac[6];
    get_tap_mac(tap, tap_mac);
    uint8_t frame[256];
    uint32_t broker_ip = g_host_ip;
    size_t flen = build_syn(frame, tap_mac, 40001, 8080, 0x10000001, broker_ip);
    CHECK_SYS(write(net.tap_fd, frame, flen), "inject SYN");
    if (await_synack(net.tap_fd, tap_mac, 40001, 8080, 0x10000001, broker_ip, 3000) < 0) {
        fprintf(stderr, "FAIL broker_path: no SYN-ACK\n");
        abort();
    }
    close(listen_fd);
    send_rst(net.tap_fd, tap_mac, 40001, 8080, 0x10000002, broker_ip);
    printf("[test] broker_path: PASS\n");
    fflush(stdout);

    // --- forward drop with control: netns "internet" at 192.0.2.1 ---
    printf("[test] forward_drop...\n");
    fflush(stdout);
    char ns[64], cmd[512], vh[16], vn[16];
    snprintf(ns, sizeof(ns), "sbtest%d", (int)getpid());
    snprintf(vh, sizeof(vh), "vh%d", (int)getpid() % 100000);
    snprintf(vn, sizeof(vn), "vn%d", (int)getpid() % 100000);
    FILE* ff = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    if (!ff) abort();
    ip_forward_saved = fgetc(ff) == '1' ? 1 : 0;
    fclose(ff);
    set_ip_forward(1);
    snprintf(cmd, sizeof(cmd), "ip netns add %s", ns);
    CHECK_RC(run(cmd), "netns add");
    // The netns ARPs for the guest IP on its veth; in production the guest
    // kernel answers on the tap, but here nothing owns .2 on that wire. Pin a
    // static neighbor to VH'S MAC (frames with a foreign dst MAC die as
    // PACKET_OTHERHOST on ingress); the host then re-resolves .2 via the tap,
    // where this test answers ARP on the fd like a real guest would.
    uint8_t vh_mac[6];
    snprintf(cmd, sizeof(cmd),
             "ip link add %s type veth peer name %s && "
             "ip link set %s netns %s && "
             "ip addr add 192.0.2.254/32 dev %s && ip link set %s up",
             vh, vn, vn, ns, vh, vh);
    CHECK_RC(run(cmd), "veth pair");
    get_tap_mac(vh, vh_mac);
    char vh_mac_s[18];
    snprintf(vh_mac_s, sizeof(vh_mac_s), "%02x:%02x:%02x:%02x:%02x:%02x",
             vh_mac[0], vh_mac[1], vh_mac[2], vh_mac[3], vh_mac[4], vh_mac[5]);
    snprintf(cmd, sizeof(cmd),
             "ip netns exec %s sh -c 'ip addr add 192.0.2.1/32 dev %s && ip link set %s up && ip link set lo up && ip route add default dev %s && ip neigh add %s lladdr %s dev %s nud permanent' && "
             "ip route add 192.0.2.1/32 dev %s && "
             "ip route add %s/32 dev %s",
             ns, vn, vn, vn, g_guest_s, vh_mac_s, vn, vh, g_guest_s, tap);
    CHECK_RC(run(cmd), "veth/routes");
    snprintf(cmd, sizeof(cmd),
             "ip netns exec %s python3 -c 'import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"192.0.2.1\",80)); s.listen(5); s.settimeout(150); "
             "exec(\"try:\\n while True:\\n  c,a=s.accept()\\n  time.sleep(20)\\nexcept Exception:\\n pass\")' >/dev/null 2>&1 & echo $!",
             ns);
    char* pid_s = capture(cmd);
    pid_t listener_pid = (pid_t)atoi(pid_s);
    free(pid_s);
    if (listener_pid <= 0) abort();
    sleep(1);

    uint32_t outer_ip;
    inet_pton(AF_INET, OUTER_IP_S, &outer_ip);
    flen = build_syn(frame, tap_mac, 40002, 80, 0x20000001, outer_ip);
    CHECK_SYS(write(net.tap_fd, frame, flen), "inject outer SYN");
    if (expect_silence(net.tap_fd, 1000) < 0) {
        fprintf(stderr, "FAIL forward_drop: reply despite drop rule\n");
        abort();
    }
    // Control: remove ONLY the drop rule -> SYN-ACK must arrive.
    long h = drop_rule_handle(tap);
    if (h < 0) abort();
    snprintf(cmd, sizeof(cmd),
             "nft delete rule ip sandbox_policy forward handle %ld", h);
    CHECK_RC(run(cmd), "delete drop rule");
    flen = build_syn(frame, tap_mac, 40003, 80, 0x20000002, outer_ip);
    CHECK_SYS(write(net.tap_fd, frame, flen), "inject outer SYN 2");
    if (await_synack(net.tap_fd, tap_mac, 40003, 80, 0x20000002, outer_ip, 3000) < 0) {
        fprintf(stderr, "FAIL forward_drop control: no SYN-ACK without drop rule\n");
        abort();
    }
    // Restore the drop rule -> silence again.
    send_rst(net.tap_fd, tap_mac, 40003, 80, 0x20000003, outer_ip);
    snprintf(cmd, sizeof(cmd),
             "nft add rule ip sandbox_policy forward iifname %s drop", tap);
    CHECK_RC(run(cmd), "re-add drop rule");
    flen = build_syn(frame, tap_mac, 40004, 80, 0x20000003, outer_ip);
    CHECK_SYS(write(net.tap_fd, frame, flen), "inject outer SYN 3");
    if (expect_silence(net.tap_fd, 1000) < 0) {
        fprintf(stderr, "FAIL forward_drop: reply after rule restore\n");
        abort();
    }
    printf("[test] forward_drop: PASS (drop enforced by our rule, proven by control)\n");
    fflush(stdout);

    // --- input drop: closed host-local port is silenced, not RST ---
    printf("[test] input_drop...\n");
    fflush(stdout);
    flen = build_syn(frame, tap_mac, 40005, 9999, 0x30000001, broker_ip);
    CHECK_SYS(write(net.tap_fd, frame, flen), "inject local SYN");
    if (expect_silence(net.tap_fd, 1000) < 0) {
        fprintf(stderr, "FAIL input_drop: reply from closed local port\n");
        abort();
    }
    printf("[test] input_drop: PASS\n");
    fflush(stdout);

    // --- two VMs: distinct /30s, no cross-talk either direction ---
    printf("[test] two_vm...\n");
    fflush(stdout);
    char vm2_id[64];
    snprintf(vm2_id, sizeof(vm2_id), "vmt2-%d", (int)getpid() % 100000);
    uint32_t host2_ip, guest2_ip;
    CHECK_RC(network_subnet_addrs(vm2_id, &host2_ip, &guest2_ip), "subnet2");
    if (host2_ip == g_host_ip || guest2_ip == g_guest_ip) {
        fprintf(stderr, "FAIL two_vm: subnet collision\n");
        abort();
    }
    if ((host2_ip & htonl(0xFFFFFFFCu)) == (g_host_ip & htonl(0xFFFFFFFCu))) {
        fprintf(stderr, "FAIL two_vm: same /30\n");
        abort();
    }
    vm_network_t net2;
    CHECK_RC(network_setup(vm2_id, &net2), "network_setup 2");
    // Guest A -> B-host:8080 (local to host, wrong VM): input drop on tap A.
    flen = build_syn(frame, tap_mac, 40006, 8080, 0x40000001, host2_ip);
    CHECK_SYS(write(net.tap_fd, frame, flen), "inject cross SYN");
    if (expect_silence(net.tap_fd, 1000) < 0) {
        fprintf(stderr, "FAIL two_vm: cross-VM host reply\n");
        abort();
    }
    // Guest A -> B-guest:80 (forwarded): forward drop on tap A.
    flen = build_syn(frame, tap_mac, 40007, 80, 0x40000002, guest2_ip);
    CHECK_SYS(write(net.tap_fd, frame, flen), "inject cross SYN 2");
    if (expect_silence(net.tap_fd, 1000) < 0) {
        fprintf(stderr, "FAIL two_vm: cross-VM guest reply\n");
        abort();
    }
    CHECK_RC(network_cleanup(&net2), "network_cleanup 2");
    // A's rules must survive B's cleanup.
    rules = capture("nft -a list chain ip sandbox_policy forward 2>/dev/null");
    int agone = (strstr(rules, tap) == NULL);
    free(rules);
    if (agone) abort();
    printf("[test] two_vm: PASS\n");
    fflush(stdout);

    // --- cleanup ---
    kill(listener_pid, SIGKILL);
    waitpid(listener_pid, NULL, 0);
    snprintf(cmd, sizeof(cmd),
             "ip netns del %s; ip route del 192.0.2.1/32 dev %s 2>/dev/null; "
             "ip route del %s/32 dev %s 2>/dev/null; true",
             ns, vh, g_guest_s, tap);
    run(cmd);
    set_ip_forward(ip_forward_saved);
    CHECK_RC(network_cleanup(&net), "network_cleanup");
    if (if_nametoindex(tap) != 0) abort();
    rules = capture("nft -a list chain ip sandbox_policy forward 2>/dev/null");
    int leftover = (strstr(rules, tap) != NULL);
    free(rules);
    rules = capture("nft -a list chain ip sandbox_policy input 2>/dev/null");
    leftover = leftover || (strstr(rules, tap) != NULL);
    free(rules);
    if (leftover) abort();
    printf("[test] cleanup: PASS\n");
    printf("ALL NETWORK TESTS PASSED\n");
    return 0;
}
