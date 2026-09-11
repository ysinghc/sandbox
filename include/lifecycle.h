#ifndef LIFECYCLE_H
#define LIFECYCLE_H

#include "vmm_manager.h"

int lifecycle_track(vm_handle_t* vm);
int lifecycle_remove(uint32_t sandbox_id);

#endif // LIFECYCLE_H
