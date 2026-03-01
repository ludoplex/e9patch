/*
 * e9binaryen.h
 * Binaryen WASM Optimizer Integration for E9Studio
 *
 * Provides access to Binaryen's optimization passes through WAMR.
 * Binaryen can be loaded as either:
 *   1. binaryen.wasm - Standalone WASM module via WAMR
 *   2. Native library - Direct linking (optional)
 *
 * This enables:
 *   - WASM module optimization (wasm-opt passes)
 *   - WASM assembly/disassembly (wasm-as, wasm-dis)
 *   - WASM validation
 *   - Code size reduction for patches
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9BINARYEN_H
#define E9BINARYEN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * Binaryen Runtime State
 * ============================================================================
 */

/*
 * Backend execution mode
 */
typedef enum {
    E9_BINARYEN_WASM,      /* binaryen.wasm via WAMR (default, portable) */
    E9_BINARYEN_NATIVE,    /* Native Binaryen library (faster, less portable) */
} E9BinaryenBackend;

/*
 * Optimization level
 */
typedef enum {
    E9_BINARYEN_OPT_NONE = 0,    /* No optimization */
    E9_BINARYEN_OPT_O1 = 1,      /* Basic optimization */
    E9_BINARYEN_OPT_O2 = 2,      /* Full optimization */
    E9_BINARYEN_OPT_O3 = 3,      /* Aggressive optimization */
    E9_BINARYEN_OPT_OS = 4,      /* Optimize for size */
    E9_BINARYEN_OPT_OZ = 5,      /* Aggressive size optimization */
} E9BinaryenOptLevel;

/*
 * Initialize Binaryen runtime
 * backend: E9_BINARYEN_WASM loads binaryen.wasm from ZipOS
 *          E9_BINARYEN_NATIVE uses linked library
 * Returns 0 on success, -1 on error
 */
int e9_binaryen_init(E9BinaryenBackend backend);

/*
 * Shutdown Binaryen runtime
 */
void e9_binaryen_shutdown(void);

/*
 * Check if Binaryen is initialized
 */
bool e9_binaryen_is_ready(void);

/*
 * Get Binaryen version string
 */
const char *e9_binaryen_version(void);

/*
 * ============================================================================
 * Module Operations
 * ============================================================================
 */

/*
 * Opaque module handle
 */
typedef struct E9BinaryenModule *E9BinaryenModuleRef;

/*
 * Create empty module
 */
E9BinaryenModuleRef e9_binaryen_module_create(void);

/*
 * Parse module from WASM binary
 */
E9BinaryenModuleRef e9_binaryen_module_read(const uint8_t *data, size_t size);

/*
 * Write module to WASM binary
 * Returns size written, or 0 on error
 * If out is NULL, returns required buffer size
 */
size_t e9_binaryen_module_write(E9BinaryenModuleRef module,
                                 uint8_t *out, size_t out_size);

/*
 * Free module
 */
void e9_binaryen_module_dispose(E9BinaryenModuleRef module);

/*
 * Validate module
 * Returns true if valid
 */
bool e9_binaryen_module_validate(E9BinaryenModuleRef module);

/*
 * Print module as WAT (text format)
 * Returns allocated string (caller must free)
 */
char *e9_binaryen_module_print(E9BinaryenModuleRef module);

/*
 * ============================================================================
 * Optimization
 * ============================================================================
 */

/*
 * Set optimization level for subsequent operations
 */
void e9_binaryen_set_opt_level(E9BinaryenOptLevel level);

/*
 * Set shrink level (0=none, 1=moderate, 2=aggressive)
 */
void e9_binaryen_set_shrink_level(int level);

/*
 * Run standard optimization passes
 */
int e9_binaryen_optimize(E9BinaryenModuleRef module);

/*
 * Run specific optimization pass by name
 * Common passes:
 *   "dce" - Dead code elimination
 *   "inlining" - Function inlining
 *   "coalesce-locals" - Local variable coalescing
 *   "reorder-functions" - Reorder for better compression
 *   "vacuum" - Remove unreachable code
 */
int e9_binaryen_run_pass(E9BinaryenModuleRef module, const char *pass_name);

/*
 * Run multiple passes
 */
int e9_binaryen_run_passes(E9BinaryenModuleRef module,
                            const char **pass_names, int num_passes);

/*
 * ============================================================================
 * Binary Patching Support
 * ============================================================================
 */

/*
 * Optimize a code fragment for patching
 * Takes raw machine code, converts to WASM, optimizes, converts back
 *
 * arch: Target architecture (E9_ARCH_X86_64, E9_ARCH_AARCH64)
 * code: Input machine code
 * size: Input size
 * out: Output buffer (optimized code)
 * out_size: Output buffer size
 *
 * Returns optimized code size, or 0 on error
 */
size_t e9_binaryen_optimize_patch(int arch,
                                   const uint8_t *code, size_t size,
                                   uint8_t *out, size_t out_size);

/*
 * Merge multiple WASM modules into one
 * Useful for combining multiple patch modules
 */
E9BinaryenModuleRef e9_binaryen_merge_modules(E9BinaryenModuleRef *modules,
                                               int num_modules);

/*
 * ============================================================================
 * Code Generation
 * ============================================================================
 */

/*
 * Assemble WAT text to WASM binary
 * Returns allocated buffer (caller must free via free())
 */
uint8_t *e9_binaryen_wat_to_wasm(const char *wat, size_t *out_size);

/*
 * Disassemble WASM binary to WAT text
 * Returns allocated string (caller must free)
 */
char *e9_binaryen_wasm_to_wat(const uint8_t *wasm, size_t size);

/*
 * ============================================================================
 * Live Reload Support
 * ============================================================================
 */

/*
 * Callback for live reload notification
 */
typedef void (*E9BinaryenReloadCallback)(const char *function_name,
                                          uint64_t old_addr,
                                          uint64_t new_addr,
                                          void *userdata);

/*
 * Set callback for live reload events
 */
void e9_binaryen_set_reload_callback(E9BinaryenReloadCallback callback,
                                      void *userdata);

/*
 * Process source change and generate patches
 *
 * old_obj: Old object file
 * new_obj: New object file (recompiled)
 * out_patches: Output array of patch descriptors
 * out_num_patches: Output number of patches
 *
 * Returns 0 on success, -1 on error
 */
typedef struct {
    uint64_t address;        /* Target address in binary */
    uint8_t *old_bytes;      /* Original bytes */
    uint8_t *new_bytes;      /* Replacement bytes */
    size_t size;             /* Patch size */
    const char *function;    /* Function name (may be NULL) */
} E9BinaryenPatch;

int e9_binaryen_diff_objects(const uint8_t *old_obj, size_t old_size,
                              const uint8_t *new_obj, size_t new_size,
                              E9BinaryenPatch **out_patches,
                              int *out_num_patches);

/*
 * Free patches returned by e9_binaryen_diff_objects
 */
void e9_binaryen_free_patches(E9BinaryenPatch *patches, int num_patches);

/*
 * ============================================================================
 * Error Handling
 * ============================================================================
 */

/*
 * Get last error message
 */
const char *e9_binaryen_get_error(void);

/*
 * Clear error state
 */
void e9_binaryen_clear_error(void);

#ifdef __cplusplus
}
#endif

#endif /* E9BINARYEN_H */
