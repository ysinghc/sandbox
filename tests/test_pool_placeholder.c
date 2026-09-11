// Phase 0 placeholder: proves the tests/ target links against libsandbox.
// Replaced by the real TSan concurrency test in Phase 1.
#include <assert.h>
#include "pool_manager.h"

int main(void) {
    pool_manager_t pool;
    assert(pool_manager_init(&pool, 5) == 0);
    pool_manager_destroy(&pool);
    return 0;
}
