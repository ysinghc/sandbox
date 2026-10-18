// SPDX-License-Identifier: GPL-2.0-only
// Jailer seccomp policy (§5.5). Our filter is the *only* one — Firecracker is
// exec'd with --no-seccomp — and the jailer installs it *before* dup2/execve,
// so it must also cover the calls Firecracker makes before it would install its
// own per-thread filters (thread creation, socket bind/listen, uname, ...).
//
// The base syscall set mirrors Firecracker v1.17's *aarch64* policy
// (resources/seccomp/aarch64-unknown-linux-musl.json — the union of its vmm,
// api and vcpu thread filters) plus those pre-filter calls. Verified against a
// full cold-boot + snapshot + UFFD-restore + pool run under SCMP_ACT_LOG.
//
// x86_64 additionally needs dup2 (jailer), arch_prctl (musl TLS at FC
// startup), open/stat (its policy delta vs aarch64) and poll (an FC startup
// call the aarch64 policy never exercised). Found by running Firecracker under
// the real filter with strace on x86_64; see the comments at each rule. dup2,
// arch_prctl, open and stat are guarded so aarch64 builds are unaffected; poll
// is allowed on both (it is a no-op addition there).
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

    // ioctl: KVM_* (type 0xAE) plus the tap/block/terminal requests Firecracker
    // uses. The LLD's "KVM-only" mask is too narrow — FC opens its tap and
    // probes its backing file through ioctl as well.
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
                         SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFF00, 0xAE00)) < 0)
        goto fail;
    // UFFD control class (type 0xAA): Firecracker creates the userfaultfd
    // (USERFAULTFD_IOC_NEW) and registers the guest-memory regions itself before
    // handing the fd to the external handler over the UDS.
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
                         SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFF00, 0xAA00)) < 0)
        goto fail;
    static const uint32_t extra_ioctls[] = {
        4712,         // BLKSSZGET
        4727,         // BLKDISCARD
        4728,         // BLKIOMIN
        4729,         // BLKIOOPT
        4731,         // BLKPBSZGET
        21505,        // TCGETS
        21506,        // TCSETS
        21523,        // TIOCGWINSZ
        21537,        // FIONBIO
        1074025674,   // TUNSETIFF
        1074025680,   // TUNSETOFFLOAD
        1074025688,   // TUNSETVNETHDRSZ
    };
    for (size_t i = 0; i < sizeof(extra_ioctls) / sizeof(extra_ioctls[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
                             SCMP_A1(SCMP_CMP_EQ,
                                     (scmp_datum_t)extra_ioctls[i])) < 0)
            goto fail;
    }

    // Firecracker runtime set (union of its vmm/api/vcpu policies).
    ALLOW(accept4);      // UDS API accept
    ALLOW(bind);         // API socket bind (pre-filter)
    ALLOW(brk);
    ALLOW(clock_gettime);
    ALLOW(close);
    ALLOW(connect);      // UFFD socket connect
    ALLOW(dup);          // fds (pre-filter)
    ALLOW(dup3);         // what dup2() lowers to on aarch64 (jailer dup2)
    ALLOW(epoll_ctl);
    ALLOW(epoll_create1);
    ALLOW(epoll_pwait);
    ALLOW(eventfd2);
    ALLOW(exit);
    ALLOW(exit_group);
    ALLOW(fallocate);
    ALLOW(fcntl);
    ALLOW(fstat);
    ALLOW(fsync);
    ALLOW(ftruncate);
    ALLOW(futex);
    ALLOW(getrandom);
    ALLOW(gettid);
    ALLOW(io_uring_enter);
    ALLOW(io_uring_register);
    ALLOW(io_uring_setup);
    ALLOW(listen);       // API socket listen (pre-filter)
    ALLOW(lseek);
    ALLOW(madvise);
    ALLOW(memfd_create);
    ALLOW(mincore);
    ALLOW(mmap);
    ALLOW(mprotect);
    ALLOW(mremap);
    ALLOW(msync);
    ALLOW(munmap);
    ALLOW(newfstatat);
    ALLOW(openat);
    ALLOW(ppoll);
    ALLOW(poll);         // pre-filter startup check on stdin/stdout/stderr (x86_64)
    ALLOW(prlimit64);    // Rust stdlib init reads resource limits
    ALLOW(read);
    ALLOW(readv);
    ALLOW(recvfrom);
    ALLOW(recvmsg);
    ALLOW(restart_syscall);
    ALLOW(rt_sigaction);
    ALLOW(rt_sigprocmask);
    ALLOW(rt_sigreturn);
    ALLOW(sched_yield);
    ALLOW(sendmsg);
    ALLOW(sendto);
    ALLOW(sigaltstack);
    ALLOW(socket);
    ALLOW(timerfd_create);
    ALLOW(timerfd_settime);
    ALLOW(tkill);
    ALLOW(uname);        // host CPU identification (pre-filter)
    ALLOW(write);
    ALLOW(writev);

    // Thread/runtime plumbing Firecracker performs before its own filters land.
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
                         SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_VM, CLONE_VM)) < 0)
        goto fail;  // Thread creation only
    ALLOW(prctl);
    ALLOW(set_robust_list);
    ALLOW(set_tid_address);
    ALLOW(getpid);

    // The set above mirrors Firecracker's *aarch64* filter (the original
    // target). x86_64 needs four more, or the jailed child dies with SIGSYS:
    //   dup2       - the jailer calls dup2() *after* installing this filter
    //                (jailer.c). aarch64 has no dup2 syscall, so glibc lowers
    //                dup2() to dup3 (already allowed); x86_64 does not.
    //   arch_prctl - ARCH_SET_FS: static-pie musl installs its thread pointer
    //                this way at Firecracker startup. aarch64 sets TPIDR_EL0
    //                directly, with no syscall.
    //   open, stat - the exact delta between Firecracker v1.17's x86_64 and
    //                aarch64 policies (v1.17 x86_64: open/stat; aarch64:
    //                openat/newfstatat, which stay in the common set above and
    //                are harmless on x86_64).
#if defined(__x86_64__)
    ALLOW(dup2);
    ALLOW(arch_prctl);
    ALLOW(open);
    ALLOW(stat);
#endif

    // Jailer hand-off.
    ALLOW(execve);       // Jailer execs firecracker

#undef ALLOW

    // Load filter
    if (seccomp_load(ctx) < 0) goto fail;
    seccomp_release(ctx);
    return 0;

fail:
    seccomp_release(ctx);
    return -1;
}
