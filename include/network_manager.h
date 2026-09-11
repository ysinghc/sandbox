#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <net/if.h>
#include <stdint.h>

typedef struct {
    int tap_fd;
    uint32_t guest_ip;
    char tap_name[IFNAMSIZ];
} vm_network_t;

int network_setup(const char* vm_id, vm_network_t* out_net);
int network_cleanup(const vm_network_t* net);

#endif // NETWORK_MANAGER_H
