// SPDX-License-Identifier: GPL-2.0-only
#ifndef LIFECYCLE_H
#define LIFECYCLE_H

#include <stdbool.h>
#include <stdint.h>

#include "libsandbox.h"
#include "vmm_manager.h"

// Live-VM registry owned by the daemon. Thread-safe.
int lifecycle_track(vm_handle_t* vm);
int lifecycle_remove(uint32_t sandbox_id);

// Borrowed pointer for an owned sandbox, or NULL. Valid until lifecycle_remove.
vm_handle_t* lifecycle_get(uint32_t sandbox_id);

// Number of tracked VMs (test helper / metrics).
int lifecycle_count(void);

// Test helper: the 64-hex session token a handle carries (NULL if no handle).
// Not part of the public libsandbox.h API.
const char* sandbox_handle_token(const sandbox_handle_t* handle);

#endif // LIFECYCLE_H
