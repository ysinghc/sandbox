#include "network_manager.h"

int network_setup(const char* vm_id, vm_network_t* out_net) {
    (void)vm_id; (void)out_net;
    return 0;
}

int network_cleanup(const vm_network_t* net) {
    (void)net;
    return 0;
}
