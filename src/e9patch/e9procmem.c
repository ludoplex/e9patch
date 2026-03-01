/*
 * e9procmem.c - Unified Process Memory API Implementation
 *
 * Backends:
 *   Linux:   process_vm_readv/writev (preferred, no ptrace)
 *   Windows: ReadProcessMemory/WriteProcessMemory
 *   macOS:   mach_vm_read/write (TODO)
 *   Self:    mprotect + direct memory access
 *
 * Copyright (C) 2024 E9Studio Contributors
 * License: GPLv3+
 */

#define _GNU_SOURCE
#include "e9procmem.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>

#ifdef __COSMOPOLITAN__
  #define _COSMO_SOURCE
  #include <libc/dce.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Platform Detection
 * ═══════════════════════════════════════════════════════════════════════════ */

static int get_os(void) {
#ifdef __COSMOPOLITAN__
    if (IsLinux()) return PROCMEM_OS_LINUX;
    if (IsWindows()) return PROCMEM_OS_WINDOWS;
    if (IsXnu()) return PROCMEM_OS_MACOS;
    if (IsBsd()) return PROCMEM_OS_BSD;
    return PROCMEM_OS_UNKNOWN;
#elif defined(__linux__)
    return PROCMEM_OS_LINUX;
#elif defined(_WIN32)
    return PROCMEM_OS_WINDOWS;
#elif defined(__APPLE__)
    return PROCMEM_OS_MACOS;
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    return PROCMEM_OS_BSD;
#else
    return PROCMEM_OS_UNKNOWN;
#endif
}

static int get_arch(void) {
#if defined(__x86_64__) || defined(_M_X64)
    return PROCMEM_ARCH_X86_64;
#elif defined(__aarch64__) || defined(_M_ARM64)
    return PROCMEM_ARCH_AARCH64;
#else
    return PROCMEM_ARCH_UNKNOWN;
#endif
}

void e9_procmem_get_platform(E9PlatformInfo *info) {
    memset(info, 0, sizeof(*info));
    info->os = get_os();
    info->arch = get_arch();
    info->page_size = (uint32_t)sysconf(_SC_PAGESIZE);
    info->can_self = 1;  /* Always can self-patch */

    switch (info->os) {
        case PROCMEM_OS_LINUX:
            info->can_remote = 1;
            strncpy(info->backend, "process_vm", sizeof(info->backend) - 1);
            break;
        case PROCMEM_OS_WINDOWS:
            info->can_remote = 1;
            strncpy(info->backend, "win32", sizeof(info->backend) - 1);
            break;
        case PROCMEM_OS_MACOS:
            info->can_remote = 1;
            strncpy(info->backend, "mach", sizeof(info->backend) - 1);
            break;
        default:
            info->can_remote = 0;
            strncpy(info->backend, "self", sizeof(info->backend) - 1);
            break;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Linux: process_vm_readv/writev
 * ═══════════════════════════════════════════════════════════════════════════ */

#if defined(__linux__) || (defined(__COSMOPOLITAN__) && !defined(_WIN32))
#include <sys/uio.h>

static int linux_read(E9ProcHandle *handle, uint64_t addr, void *buf, size_t len) {
    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = len };

    ssize_t n = process_vm_readv(handle->pid, &local, 1, &remote, 1, 0);
    if (n < 0) {
        handle->error_code = errno;
        snprintf(handle->error_msg, sizeof(handle->error_msg),
                 "process_vm_readv failed: %s", strerror(errno));
        return PROCMEM_ERR_ACCESS;
    }
    return PROCMEM_OK;
}

static int linux_write(E9ProcHandle *handle, uint64_t addr, const void *buf, size_t len) {
    struct iovec local = { .iov_base = (void *)buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = len };

    ssize_t n = process_vm_writev(handle->pid, &local, 1, &remote, 1, 0);
    if (n < 0) {
        handle->error_code = errno;
        snprintf(handle->error_msg, sizeof(handle->error_msg),
                 "process_vm_writev failed: %s", strerror(errno));
        return PROCMEM_ERR_ACCESS;
    }
    return PROCMEM_OK;
}
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Windows: ReadProcessMemory/WriteProcessMemory
 * ═══════════════════════════════════════════════════════════════════════════ */

#if defined(_WIN32) || defined(__COSMOPOLITAN__)
#ifdef __COSMOPOLITAN__
/* Cosmo provides these via ntdll */
extern int OpenProcess(int, int, int);
extern int ReadProcessMemory(int, void *, void *, size_t, size_t *);
extern int WriteProcessMemory(int, void *, const void *, size_t, size_t *);
extern int CloseHandle(int);
#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE 0x0020
#define PROCESS_VM_OPERATION 0x0008
#endif

static int win32_open(E9ProcHandle *handle, int pid, uint32_t flags) {
#if defined(_WIN32) || defined(__COSMOPOLITAN__)
    int access = 0;
    if (flags & PROCMEM_READ) access |= PROCESS_VM_READ;
    if (flags & PROCMEM_WRITE) access |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION;

    handle->handle = (uint64_t)OpenProcess(access, 0, pid);
    if (handle->handle == 0) {
        handle->error_code = -1;
        snprintf(handle->error_msg, sizeof(handle->error_msg),
                 "OpenProcess failed for PID %d", pid);
        return PROCMEM_ERR_ACCESS;
    }
    return PROCMEM_OK;
#else
    (void)handle; (void)pid; (void)flags;
    return PROCMEM_ERR_PLATFORM;
#endif
}

static int win32_read(E9ProcHandle *handle, uint64_t addr, void *buf, size_t len) {
#if defined(_WIN32) || defined(__COSMOPOLITAN__)
    size_t bytes_read = 0;
    if (!ReadProcessMemory((int)handle->handle, (void *)addr, buf, len, &bytes_read)) {
        handle->error_code = -1;
        snprintf(handle->error_msg, sizeof(handle->error_msg),
                 "ReadProcessMemory failed at 0x%lx", (unsigned long)addr);
        return PROCMEM_ERR_ACCESS;
    }
    return PROCMEM_OK;
#else
    (void)handle; (void)addr; (void)buf; (void)len;
    return PROCMEM_ERR_PLATFORM;
#endif
}

static int win32_write(E9ProcHandle *handle, uint64_t addr, const void *buf, size_t len) {
#if defined(_WIN32) || defined(__COSMOPOLITAN__)
    size_t bytes_written = 0;
    if (!WriteProcessMemory((int)handle->handle, (void *)addr, buf, len, &bytes_written)) {
        handle->error_code = -1;
        snprintf(handle->error_msg, sizeof(handle->error_msg),
                 "WriteProcessMemory failed at 0x%lx", (unsigned long)addr);
        return PROCMEM_ERR_ACCESS;
    }
    return PROCMEM_OK;
#else
    (void)handle; (void)addr; (void)buf; (void)len;
    return PROCMEM_ERR_PLATFORM;
#endif
}

static void win32_close(E9ProcHandle *handle) {
#if defined(_WIN32) || defined(__COSMOPOLITAN__)
    if (handle->handle) {
        CloseHandle((int)handle->handle);
        handle->handle = 0;
    }
#else
    (void)handle;
#endif
}
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Self-patching (all platforms)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int self_read(uint64_t addr, void *buf, size_t len) {
    memcpy(buf, (void *)addr, len);
    return PROCMEM_OK;
}

static int self_write(uint64_t addr, const void *buf, size_t len, E9ProcHandle *handle) {
    /* Make page writable */
    uint64_t page = addr & ~0xFFFULL;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);

    if (mprotect((void *)page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        handle->error_code = errno;
        snprintf(handle->error_msg, sizeof(handle->error_msg),
                 "mprotect failed: %s", strerror(errno));
        return PROCMEM_ERR_PERM;
    }

    memcpy((void *)addr, buf, len);
    return PROCMEM_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

int e9_procmem_open(E9ProcHandle *handle, int pid, uint32_t flags) {
    memset(handle, 0, sizeof(*handle));
    handle->pid = pid;
    handle->flags = flags;

    if (pid == 0 || pid == getpid()) {
        /* Self-patching - no handle needed */
        handle->pid = 0;
        return PROCMEM_OK;
    }

    int os = get_os();

#if defined(__linux__) || defined(__COSMOPOLITAN__)
    if (os == PROCMEM_OS_LINUX) {
        /* Linux: process_vm_* doesn't need a handle, just check access */
        if (kill(pid, 0) != 0) {
            handle->error_code = errno;
            snprintf(handle->error_msg, sizeof(handle->error_msg),
                     "Process %d not found", pid);
            return PROCMEM_ERR_NOTFOUND;
        }
        return PROCMEM_OK;
    }
#endif

#if defined(_WIN32) || defined(__COSMOPOLITAN__)
    if (os == PROCMEM_OS_WINDOWS) {
        return win32_open(handle, pid, flags);
    }
#endif

    snprintf(handle->error_msg, sizeof(handle->error_msg),
             "Remote process access not supported on this platform");
    return PROCMEM_ERR_PLATFORM;
}

void e9_procmem_close(E9ProcHandle *handle) {
    int os = get_os();
#if defined(_WIN32) || defined(__COSMOPOLITAN__)
    if (os == PROCMEM_OS_WINDOWS && handle->handle) {
        win32_close(handle);
    }
#endif
    (void)os;
    memset(handle, 0, sizeof(*handle));
}

int e9_procmem_read(E9ProcHandle *handle, uint64_t addr, void *buf, size_t len) {
    if (handle->pid == 0) {
        return self_read(addr, buf, len);
    }

    int os = get_os();

#if defined(__linux__) || defined(__COSMOPOLITAN__)
    if (os == PROCMEM_OS_LINUX) {
        return linux_read(handle, addr, buf, len);
    }
#endif

#if defined(_WIN32) || defined(__COSMOPOLITAN__)
    if (os == PROCMEM_OS_WINDOWS) {
        return win32_read(handle, addr, buf, len);
    }
#endif

    (void)os;
    return PROCMEM_ERR_PLATFORM;
}

int e9_procmem_write(E9ProcHandle *handle, uint64_t addr, const void *buf, size_t len) {
    if (handle->pid == 0) {
        return self_write(addr, buf, len, handle);
    }

    int os = get_os();

#if defined(__linux__) || defined(__COSMOPOLITAN__)
    if (os == PROCMEM_OS_LINUX) {
        return linux_write(handle, addr, buf, len);
    }
#endif

#if defined(_WIN32) || defined(__COSMOPOLITAN__)
    if (os == PROCMEM_OS_WINDOWS) {
        return win32_write(handle, addr, buf, len);
    }
#endif

    (void)os;
    return PROCMEM_ERR_PLATFORM;
}

int e9_procmem_protect(E9ProcHandle *handle, uint64_t addr, size_t len, uint32_t flags) {
    int prot = 0;
    if (flags & PROCMEM_READ) prot |= PROT_READ;
    if (flags & PROCMEM_WRITE) prot |= PROT_WRITE;
    if (flags & PROCMEM_EXECUTE) prot |= PROT_EXEC;

    uint64_t page = addr & ~0xFFFULL;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t total = ((addr + len + page_size - 1) & ~0xFFFULL) - page;

    if (mprotect((void *)page, total, prot) != 0) {
        handle->error_code = errno;
        snprintf(handle->error_msg, sizeof(handle->error_msg),
                 "mprotect failed: %s", strerror(errno));
        return PROCMEM_ERR_PERM;
    }
    return PROCMEM_OK;
}

void e9_procmem_flush_icache(uint64_t addr, size_t len) {
#if defined(__x86_64__) || defined(_M_X64)
    /* x86-64: CPUID serializes instruction stream */
    __asm__ volatile("cpuid" ::: "eax", "ebx", "ecx", "edx", "memory");
#elif defined(__aarch64__)
    /* AArch64: explicit cache maintenance */
    for (uint64_t p = addr; p < addr + len; p += 64) {
        __asm__ volatile(
            "dc cvau, %0\n"
            "dsb ish\n"
            "ic ivau, %0\n"
            "dsb ish\n"
            "isb\n"
            :: "r"(p)
        );
    }
#endif
    (void)addr;
    (void)len;
}

const char *e9_procmem_error(E9ProcHandle *handle) {
    return handle->error_msg[0] ? handle->error_msg : "No error";
}
