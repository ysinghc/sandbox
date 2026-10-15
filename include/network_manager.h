#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <net/if.h>
#include <stdint.h>

typedef struct {
    int tap_fd;  // -1: no fd held (Firecracker owns the persistent tap)
    uint32_t guest_ip;
    char tap_name[IFNAMSIZ];
} vm_network_t;

int network_setup(const char* vm_id, vm_network_t* out_net);
int network_cleanup(const vm_network_t* net);

// Attach to the (persistent) tap for frame injection; caller closes it.
// Returns a fresh fd, or -1. The VMM does not use this (Firecracker opens
// the tap itself by name).
int network_tap_open(const vm_network_t* net);

// Idempotent table+chain creation for daemon startup (setup ensures it too).
int network_manager_init(void);

// Deterministic per-VM /30 addrs (network order). Same vm_id always maps to
// the same subnet; callers needing the host IP (broker bind, tests) use this.
int network_subnet_addrs(const char* vm_id, uint32_t* out_host_ip,
                         uint32_t* out_guest_ip);

#endif // NETWORK_MANAGER_H
