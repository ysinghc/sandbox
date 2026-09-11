// Jailer seccomp policy (§5.5). Whitelist is verbatim from the LLD.
#define _GNU_SOURCE  // CLONE_VM under strict C11

#include "sandbox_seccomp.h"

#include <errno.h>
#include <sched.h>  // CLONE_VM
#include <seccomp.h>

#ifdef NDEBUG
  #define JAILER_SECCOMP_DEFAULT SCMP_ACT_KILL_PROCESS  // Release
#else
  #define JAILER_SECCOMP_DEFAULT SCMP_ACT_ERRNO(EPERM)  // Debug
#endif

int apply_seccomp_filter(void) {
    scmp_filter_ctx ctx = seccomp_init(JAILER_SECCOMP_DEFAULT);
    if (!ctx) return -1;

#define ALLOW(syscall_nr) do { \
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syscall_nr), 0) < 0) \
        goto fail; \
} while (0)

    // KVM interaction
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
                         SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFF00, 0xAE00)) < 0)
        goto fail;  // KVM_* ioctls only

    // Memory management
    ALLOW(mmap);
    ALLOW(munmap);
    ALLOW(mprotect);
    ALLOW(mremap);
    ALLOW(madvise);

    // File I/O (snapshot files, API socket)
    ALLOW(read);
    ALLOW(write);
    ALLOW(open);
    ALLOW(openat);
    ALLOW(close);
    ALLOW(fstat);
    ALLOW(lseek);

    // Signaling
    ALLOW(signalfd);
    ALLOW(rt_sigaction);
    ALLOW(rt_sigprocmask);

    // Epoll/event loop
    ALLOW(epoll_create1);
    ALLOW(epoll_ctl);
    ALLOW(epoll_wait);
    ALLOW(eventfd);

    // Threading
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
                         SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_VM, CLONE_VM)) < 0)
        goto fail;  // Thread creation only
    ALLOW(futex);
    ALLOW(set_robust_list);

    // Process lifecycle
    ALLOW(exit_group);
    ALLOW(getpid);
    ALLOW(tgkill);

    // Time
    ALLOW(clock_gettime);
    ALLOW(clock_nanosleep);

#undef ALLOW

    // Load filter
    if (seccomp_load(ctx) < 0) goto fail;
    seccomp_release(ctx);
    return 0;

fail:
    seccomp_release(ctx);
    return -1;
}
