// UFFD Handler (§5.2): serve guest page faults on-demand from the mmap'd
// snapshot. Registration MUST complete before vmm_resume_vcpus(); the kernel
// holds faulting vCPUs until the handler serves them, so there is no window
// for unhandled guest access. fd is NONBLOCK + poll() so destroy is clean.

#define _GNU_SOURCE

#include "uffd_handler.h"
#include "prefault_worker.h"
#include "snapshot_manager.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define UFFD_POLL_MS 100

static long uffd_page_size(void) {
    long ps = sysconf(_SC_PAGESIZE);
    return (ps > 0) ? ps : 4096;
}

// Steps 1-2 of the setup sequence: mmap snapshot, create + init uffd,
// register the guest range. Returns 0 with vm fields populated.
int uffd_setup_region(vm_handle_t* vm, const char* snap_path,
                      void* guest_mem, uint64_t guest_mem_size) {
    if (!vm || !snap_path || !guest_mem || guest_mem_size == 0) {
        errno = EINVAL;
        return -1;
    }
    long ps = uffd_page_size();
    if (guest_mem_size % (uint64_t)ps != 0) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(snap_path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || (uint64_t)st.st_size < guest_mem_size) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    uint64_t snap_size = (uint64_t)st.st_size;
    void* snap_base = mmap(NULL, snap_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (snap_base == MAP_FAILED) return -1;

    // Manifest lives alongside memory.snap per the §5.6 layout.
    char dir[PATH_MAX], mpath[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", snap_path);
    char* slash = strrchr(dir, '/');
    if (!slash) {
        munmap(snap_base, snap_size);
        errno = EINVAL;
        return -1;
    }
    *slash = '\0';
    snprintf(mpath, sizeof(mpath), "%s/manifest.bin", dir);
    snap_manifest_t* manifest = NULL;
    int mfd = open(mpath, O_RDONLY);
    if (mfd >= 0) {
        snap_manifest_t hdr;
        ssize_t n = read(mfd, &hdr, sizeof(hdr));
        if (n == (ssize_t)sizeof(hdr) && hdr.magic == SNAP_MAGIC &&
            hdr.page_size == (uint32_t)ps) {
            size_t total = sizeof(hdr) + (hdr.page_count + 7u) / 8u;
            manifest = malloc(total);
            if (manifest) {
                memcpy(manifest, &hdr, sizeof(hdr));
                size_t rest = total - sizeof(hdr);
                uint8_t* p = manifest->page_bitmap;
                while (rest > 0) {
                    ssize_t r = read(mfd, p, rest);
                    if (r < 0) {
                        if (errno == EINTR) continue;
                        break;
                    }
                    if (r == 0) break;
                    p += (size_t)r;
                    rest -= (size_t)r;
                }
                if (rest != 0) {
                    free(manifest);
                    manifest = NULL;
                }
            }
        }
        close(mfd);
    }
    if (!manifest) {
        munmap(snap_base, snap_size);
        errno = EINVAL;
        return -1;
    }

    int uffd = (int)syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd < 0) {
        free(manifest);
        munmap(snap_base, snap_size);
        return -1;
    }
    struct uffdio_api api = { .api = UFFD_API, .features = 0 };
    if (ioctl(uffd, UFFDIO_API, &api) < 0 || api.api != UFFD_API) {
        close(uffd);
        free(manifest);
        munmap(snap_base, snap_size);
        return -1;
    }
    struct uffdio_register reg = {
        .range = { .start = (uint64_t)(uintptr_t)guest_mem, .len = guest_mem_size },
        .mode = UFFDIO_REGISTER_MODE_MISSING,
    };
    if (ioctl(uffd, UFFDIO_REGISTER, &reg) < 0) {
        close(uffd);
        free(manifest);
        munmap(snap_base, snap_size);
        return -1;
    }

    vm->uffd_fd = uffd;
    vm->guest_mem_base = guest_mem;
    vm->guest_mem_size = guest_mem_size;
    vm->snap_base = snap_base;
    vm->snap_size = snap_size;
    vm->manifest = manifest;
    return 0;
}

// Step 3: spawn the fault handler. Call BEFORE vmm_resume_vcpus().
int uffd_start_handler(vm_handle_t* vm) {
    if (!vm || vm->uffd_fd < 0 || vm->uffd_thread_started) {
        errno = EINVAL;
        return -1;
    }
    if (pthread_create(&vm->uffd_thread, NULL, uffd_thread_fn, vm) != 0) return -1;
    vm->uffd_thread_started = true;
    return 0;
}

// Spawn the prefault worker (also before resume, so it races from t=0).
int uffd_start_prefault(vm_handle_t* vm) {
    if (!vm || vm->prefault_thread_started) {
        errno = EINVAL;
        return -1;
    }
    if (pthread_create(&vm->prefault_thread, NULL, prefault_worker_fn, vm) != 0)
        return -1;
    vm->prefault_thread_started = true;
    return 0;
}

void* uffd_thread_fn(void* arg) {
    vm_handle_t* vm = arg;
    long ps = uffd_page_size();
    struct uffd_msg msg;

    for (;;) {
        struct pollfd pfd = { .fd = vm->uffd_fd, .events = POLLIN };
        int prc = poll(&pfd, 1, UFFD_POLL_MS);
        if (prc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (prc == 0) {
            // Timeout: re-check destroy flag so stop() always joins.
            if (__atomic_load_n(&vm->destroyed, __ATOMIC_ACQUIRE)) break;
            continue;
        }
        ssize_t nread = read(vm->uffd_fd, &msg, sizeof(msg));
        if (nread <= 0) {
            if (nread < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            break;  // fd closed (VM destroyed) or error
        }
        if (msg.event != UFFD_EVENT_PAGEFAULT) continue;

        uint64_t fault_addr = msg.arg.pagefault.address & ~((uint64_t)ps - 1);
        uint64_t base = (uint64_t)(uintptr_t)vm->guest_mem_base;
        if (fault_addr < base || fault_addr - base >= vm->guest_mem_size) continue;
        uint64_t offset = fault_addr - base;

        if (snapshot_page_present(vm->manifest, offset)) {
            struct uffdio_copy copy = {
                .dst = fault_addr,
                .src = (uint64_t)(uintptr_t)((uint8_t*)vm->snap_base + offset),
                .len = (uint64_t)ps,
                .mode = 0,
            };
            if (ioctl(vm->uffd_fd, UFFDIO_COPY, &copy) == 0 &&
                copy.copy == (int64_t)ps)
                __atomic_fetch_add(&vm->page_faults, 1u, __ATOMIC_RELAXED);
            // Short copy: page stays missing, guest refaults on retry.
        } else {
            struct uffdio_zeropage zero = {
                .range = { .start = fault_addr, .len = (uint64_t)ps },
                .mode = 0,
            };
            if (ioctl(vm->uffd_fd, UFFDIO_ZEROPAGE, &zero) == 0)
                __atomic_fetch_add(&vm->page_faults, 1u, __ATOMIC_RELAXED);
        }
    }
    return NULL;
}

// Joins handler + prefault, then releases snapshot resources. Shutdown is
// ordered flag -> join -> release (never close-to-wake): the handler only
// observes the fd before the join, so no close-vs-use race exists. Worst
// case the join waits out one poll quantum (~100ms).
void uffd_stop(vm_handle_t* vm) {
    if (!vm) return;
    __atomic_store_n(&vm->destroyed, true, __ATOMIC_RELEASE);
    if (vm->uffd_thread_started) {
        pthread_join(vm->uffd_thread, NULL);
        vm->uffd_thread_started = false;
    }
    if (vm->prefault_thread_started) {
        pthread_join(vm->prefault_thread, NULL);
        vm->prefault_thread_started = false;
    }
    if (vm->uffd_fd >= 0) {
        close(vm->uffd_fd);
        vm->uffd_fd = -1;
    }
    if (vm->snap_base && vm->snap_size) munmap(vm->snap_base, vm->snap_size);
    vm->snap_base = NULL;
    vm->snap_size = 0;
    free(vm->manifest);
    vm->manifest = NULL;
}
