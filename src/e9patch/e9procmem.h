/*
 * e9procmem.h - Unified Process Memory API
 *
 * Cross-platform hot-patching without ptrace:
 *   Linux:   process_vm_readv/writev (no stop required)
 *   Windows: ReadProcessMemory/WriteProcessMemory
 *   Self:    mprotect + direct access
 *
 * Generated types from: specs/domain/procmem.schema
 */

#ifndef E9_PROCMEM_H
#define E9_PROCMEM_H

#include <stdint.h>
#include <stddef.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Constants
 * ═══════════════════════════════════════════════════════════════════════════ */

#define PROCMEM_READ    0x01
#define PROCMEM_WRITE   0x02
#define PROCMEM_EXECUTE 0x04

/* OS types */
#define PROCMEM_OS_UNKNOWN  0
#define PROCMEM_OS_LINUX    1
#define PROCMEM_OS_WINDOWS  2
#define PROCMEM_OS_MACOS    3
#define PROCMEM_OS_BSD      4

/* Arch types */
#define PROCMEM_ARCH_UNKNOWN 0
#define PROCMEM_ARCH_X86_64  1
#define PROCMEM_ARCH_AARCH64 2

/* Status codes */
#define PROCMEM_OK           0
#define PROCMEM_ERR_ACCESS  -1
#define PROCMEM_ERR_NOTFOUND -2
#define PROCMEM_ERR_PERM    -3
#define PROCMEM_ERR_PLATFORM -4

/* ═══════════════════════════════════════════════════════════════════════════
 * Types (mirrors generated procmem_types.h)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    int32_t  pid;           /* Process ID (0 = self) */
    uint64_t handle;        /* Platform handle */
    uint32_t flags;         /* Access flags */
    int32_t  error_code;
    char     error_msg[256];
} E9ProcHandle;

typedef struct {
    int32_t  os;
    int32_t  arch;
    uint32_t page_size;
    int32_t  can_remote;    /* Can patch other processes */
    int32_t  can_self;      /* Can self-patch (always 1) */
    char     backend[32];   /* "process_vm", "win32", "mach", "self" */
} E9PlatformInfo;

/* ═══════════════════════════════════════════════════════════════════════════
 * API
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Get platform info (call once at startup) */
void e9_procmem_get_platform(E9PlatformInfo *info);

/* Open process for memory access (pid=0 for self) */
int e9_procmem_open(E9ProcHandle *handle, int pid, uint32_t flags);

/* Close handle */
void e9_procmem_close(E9ProcHandle *handle);

/* Read memory from process */
int e9_procmem_read(E9ProcHandle *handle, uint64_t addr, void *buf, size_t len);

/* Write memory to process */
int e9_procmem_write(E9ProcHandle *handle, uint64_t addr, const void *buf, size_t len);

/* Make memory executable (for self-patching) */
int e9_procmem_protect(E9ProcHandle *handle, uint64_t addr, size_t len, uint32_t flags);

/* Flush instruction cache */
void e9_procmem_flush_icache(uint64_t addr, size_t len);

/* Get last error message */
const char *e9_procmem_error(E9ProcHandle *handle);

#endif /* E9_PROCMEM_H */
