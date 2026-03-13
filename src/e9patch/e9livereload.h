/*
 * e9livereload.h
 * Live Reload Integration for APE Binary Hot-Patching
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Connects:
 *   File Watcher → cosmocc Recompile → Binaryen Diff → APE Patch → ICache Flush
 *
 * This enables viewing C source code changes in real-time by updating
 * the running APE binary in place.
 *
 * Usage:
 *   1. e9_livereload_init() - Initialize with target APE
 *   2. e9_livereload_watch() - Start watching source directory
 *   3. [automatic] - Changes detected, compiled, diffed, patched
 *   4. e9_livereload_shutdown() - Cleanup
 *
 * Architecture:
 *   - Uses PE sections (via e9ape.h) for address translation
 *   - Uses Binaryen (via e9binaryen.h) for object diffing
 *   - Uses WAMR host (via e9wasm_host.h) for icache flush
 *   - Both ELF and PE views map shared code sections
 *
 * Pure C implementation for cosmo-bde dogfooding.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9LIVERELOAD_H
#define E9LIVERELOAD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════
 * Configuration
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *source_dir;          /* Directory to watch for .c changes */
    const char *compiler;            /* Compiler path (NULL = "cosmocc") */
    const char *compiler_flags;      /* Additional compiler flags */
    const char *cache_dir;           /* Object cache dir (NULL = ".e9cache") */

    uint32_t watch_interval_ms;      /* Watch interval (default: 100ms) */
    bool enable_hot_patch;           /* Apply patches to running binary */
    bool enable_file_patch;          /* Also write patched file to disk */

    size_t max_patch_size;           /* Max single patch size (default: 64KB) */
    size_t max_pending_patches;      /* Max queued patches (default: 256) */

    bool verbose;                    /* Verbose logging */
} E9LiveReloadConfig;

/* Default config initializer */
#define E9_LIVERELOAD_CONFIG_DEFAULT { \
    .source_dir = ".", \
    .compiler = NULL, \
    .compiler_flags = "-O2 -g", \
    .cache_dir = NULL, \
    .watch_interval_ms = 100, \
    .enable_hot_patch = true, \
    .enable_file_patch = false, \
    .max_patch_size = 65536, \
    .max_pending_patches = 256, \
    .verbose = false, \
}

/* ═══════════════════════════════════════════════════════════════════════
 * Events
 * ═══════════════════════════════════════════════════════════════════════ */

typedef enum {
    E9_LR_EVENT_FILE_CHANGE = 1,     /* Source file modified */
    E9_LR_EVENT_COMPILE_START,       /* Starting compilation */
    E9_LR_EVENT_COMPILE_DONE,        /* Compilation succeeded */
    E9_LR_EVENT_COMPILE_ERROR,       /* Compilation failed */
    E9_LR_EVENT_PATCH_GENERATED,     /* Patch created from diff */
    E9_LR_EVENT_PATCH_APPLIED,       /* Patch applied to binary */
    E9_LR_EVENT_PATCH_FAILED,        /* Patch application failed */
    E9_LR_EVENT_PATCH_REVERTED,      /* Patch was reverted */
} E9LiveReloadEventType;

typedef struct {
    E9LiveReloadEventType type;
    uint64_t timestamp;

    /* File change info */
    const char *file_path;

    /* Patch info */
    uint32_t patch_id;
    const char *function_name;
    uint64_t patch_address;
    size_t patch_size;

    /* Error info */
    int error_code;
    const char *error_msg;
} E9LiveReloadEvent;

/* Event callback */
typedef void (*E9LiveReloadCallback)(const E9LiveReloadEvent *event,
                                      void *userdata);

/* ═══════════════════════════════════════════════════════════════════════
 * Patch Info
 * ═══════════════════════════════════════════════════════════════════════ */

typedef enum {
    E9_PATCH_TARGET_FILE_OFFSET = 0, /* Direct file offset */
    E9_PATCH_TARGET_PE_RVA = 1,      /* PE relative virtual address */
    E9_PATCH_TARGET_VA = 2,          /* Virtual address (legacy) */
} E9PatchTargetType;

typedef enum {
    E9_PATCH_STATUS_PENDING = 0,
    E9_PATCH_STATUS_APPLIED = 1,
    E9_PATCH_STATUS_FAILED = 2,
    E9_PATCH_STATUS_REVERTED = 3,
} E9PatchStatus;

typedef struct {
    uint32_t id;
    const char *source_file;
    const char *function_name;

    E9PatchTargetType target_type;
    uint64_t target_address;

    const uint8_t *old_bytes;
    size_t old_size;
    const uint8_t *new_bytes;
    size_t new_size;

    E9PatchStatus status;
    const char *error_msg;
    uint64_t timestamp;
} E9PatchInfo;

/* ═══════════════════════════════════════════════════════════════════════
 * Lifecycle
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Initialize live reload for a target APE binary.
 *
 * If target_path is NULL, operates on self (the running executable).
 * This is the primary use case - hot-patching the running program.
 *
 * Returns 0 on success, -1 on error.
 */
int e9_livereload_init(const char *target_path,
                        const E9LiveReloadConfig *config);

/*
 * Shutdown live reload and cleanup resources.
 */
void e9_livereload_shutdown(void);

/*
 * Check if live reload is initialized.
 */
bool e9_livereload_is_ready(void);

/* ═══════════════════════════════════════════════════════════════════════
 * Watch Control
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Start watching for source file changes.
 * This is non-blocking - use e9_livereload_poll() to process events.
 *
 * Returns 0 on success, -1 on error.
 */
int e9_livereload_watch(void);

/*
 * Stop watching for changes.
 */
void e9_livereload_unwatch(void);

/*
 * Poll for file changes and process pending patches.
 * Call this in your main loop.
 *
 * Returns number of events processed, or -1 on error.
 */
int e9_livereload_poll(void);

/*
 * Set callback for live reload events.
 */
void e9_livereload_set_callback(E9LiveReloadCallback callback, void *userdata);

/* ═══════════════════════════════════════════════════════════════════════
 * Manual Operations
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Manually trigger recompilation and patching for a source file.
 * Useful for testing without file watcher.
 *
 * Returns number of patches applied, or -1 on error.
 */
int e9_livereload_reload_file(const char *source_path);

/*
 * Apply a raw patch to the target binary.
 *
 * target_type: E9_PATCH_TARGET_FILE_OFFSET, E9_PATCH_TARGET_PE_RVA, or
 *              E9_PATCH_TARGET_VA
 * address: Target address (interpretation depends on target_type)
 * patch: Patch bytes
 * patch_size: Number of bytes to patch
 *
 * Returns patch ID on success, or 0 on error.
 */
uint32_t e9_livereload_apply_patch(E9PatchTargetType target_type,
                                    uint64_t address,
                                    const uint8_t *patch,
                                    size_t patch_size);

/*
 * Revert a previously applied patch.
 *
 * Returns 0 on success, -1 on error.
 */
int e9_livereload_revert_patch(uint32_t patch_id);

/*
 * Flush instruction cache for a memory range.
 * Typically called automatically after patching.
 */
void e9_livereload_flush_icache(void *addr, size_t size);

/* ═══════════════════════════════════════════════════════════════════════
 * Query
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Get number of pending patches.
 */
size_t e9_livereload_pending_count(void);

/*
 * Get list of pending patches.
 * Returns number of patches copied to buffer.
 */
size_t e9_livereload_get_pending(E9PatchInfo *patches, size_t max_patches);

/*
 * Get number of applied patches.
 */
size_t e9_livereload_applied_count(void);

/*
 * Get statistics.
 */
typedef struct {
    uint64_t changes_detected;
    uint64_t patches_generated;
    uint64_t patches_applied;
    uint64_t patches_failed;
    uint64_t patches_reverted;
    uint64_t total_bytes_patched;
    uint64_t last_change_time;
    uint64_t last_patch_time;
} E9LiveReloadStats;

void e9_livereload_get_stats(E9LiveReloadStats *stats);

/* ═══════════════════════════════════════════════════════════════════════
 * Utilities
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Get last error message.
 */
const char *e9_livereload_get_error(void);

/*
 * Clear error state.
 */
void e9_livereload_clear_error(void);

/*
 * Check if compiler is available.
 */
bool e9_livereload_compiler_available(void);

/*
 * Get compiler version string.
 */
const char *e9_livereload_compiler_version(void);

#ifdef __cplusplus
}
#endif

#endif /* E9LIVERELOAD_H */
