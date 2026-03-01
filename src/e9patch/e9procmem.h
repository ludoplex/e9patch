/*
 * e9procmem.h - Unified Process Memory API
 *
 * Cross-platform hot-patching without ptrace:
 *   Linux:   process_vm_readv/writev (no stop required)
 *   Windows: ReadProcessMemory/WriteProcessMemory
 *   Self:    mprotect + direct access
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * RING 0 COMPOSABILITY:
 *   Types:     procmem.schema → schemagen → procmem_types.h
 *   Constants: procmem.def → X-macro expansion (below)
 * ═══════════════════════════════════════════════════════════════════════════
 */

#ifndef E9_PROCMEM_H
#define E9_PROCMEM_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * X-Macro Definitions (from specs/domain/procmem.def)
 * Single source of truth for all constants
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Memory Access Flags */
#define MEMACCESS_XMACRO(X) \
    X(PROCMEM_READ,    0x01, "READ")    \
    X(PROCMEM_WRITE,   0x02, "WRITE")   \
    X(PROCMEM_EXECUTE, 0x04, "EXECUTE")

/* Operating System */
#define PROCMEM_OS_XMACRO(X) \
    X(PROCMEM_OS_UNKNOWN, 0, "unknown") \
    X(PROCMEM_OS_LINUX,   1, "linux")   \
    X(PROCMEM_OS_WINDOWS, 2, "windows") \
    X(PROCMEM_OS_MACOS,   3, "macos")   \
    X(PROCMEM_OS_BSD,     4, "bsd")

/* Architecture */
#define PROCMEM_ARCH_XMACRO(X) \
    X(PROCMEM_ARCH_UNKNOWN, 0, "unknown") \
    X(PROCMEM_ARCH_X86_64,  1, "x86_64")  \
    X(PROCMEM_ARCH_AARCH64, 2, "aarch64")

/* Status Codes */
#define PROCMEM_STATUS_XMACRO(X) \
    X(PROCMEM_OK,           0,  "ok")        \
    X(PROCMEM_ERR_ACCESS,  -1,  "access")    \
    X(PROCMEM_ERR_NOTFOUND,-2,  "notfound")  \
    X(PROCMEM_ERR_PERM,    -3,  "perm")      \
    X(PROCMEM_ERR_PLATFORM,-4,  "platform")

/* ═══════════════════════════════════════════════════════════════════════════
 * Constants (expanded from X-macros)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Expand X-macros to #define constants */
#define X(name, val, str) static const int name = val;
MEMACCESS_XMACRO(X)
PROCMEM_OS_XMACRO(X)
PROCMEM_ARCH_XMACRO(X)
PROCMEM_STATUS_XMACRO(X)
#undef X

/* ═══════════════════════════════════════════════════════════════════════════
 * Types (from specs/domain/procmem.schema via schemagen)
 * Could #include "procmem_types.h" but inlined for standalone use
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
 * String Conversion (generated from X-macros)
 * ═══════════════════════════════════════════════════════════════════════════ */

static inline const char* procmem_os_str(int os) {
    switch(os) {
#define X(name, val, str) case val: return str;
        PROCMEM_OS_XMACRO(X)
#undef X
    }
    return "unknown";
}

static inline const char* procmem_arch_str(int arch) {
    switch(arch) {
#define X(name, val, str) case val: return str;
        PROCMEM_ARCH_XMACRO(X)
#undef X
    }
    return "unknown";
}

static inline const char* procmem_status_str(int status) {
    switch(status) {
#define X(name, val, str) case val: return str;
        PROCMEM_STATUS_XMACRO(X)
#undef X
    }
    return "unknown";
}

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
