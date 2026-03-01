/*
 * e9binaryen.c
 * Binaryen WASM Optimizer Integration Implementation
 *
 * This file implements the Binaryen API by calling into binaryen.wasm
 * through WAMR (WebAssembly Micro Runtime).
 *
 * The binaryen.wasm module is loaded from ZipOS and provides:
 *   - BinaryenModuleCreate, BinaryenModuleDispose
 *   - BinaryenModuleRead, BinaryenModuleWrite
 *   - BinaryenModuleOptimize, BinaryenModuleValidate
 *   - BinaryenSetOptimizeLevel, BinaryenSetShrinkLevel
 *   - And many more Binaryen C API functions
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9binaryen.h"
#include "e9wasm_host.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* WAMR headers */
#ifdef BUILD_PLATFORM_COSMOPOLITAN
#include "wasm_export.h"
#else
/* Stub for non-WAMR builds */
typedef void *wasm_module_t;
typedef void *wasm_module_inst_t;
typedef void *wasm_exec_env_t;
typedef void *wasm_function_inst_t;
#endif

/*
 * ============================================================================
 * Runtime State
 * ============================================================================
 */

static struct {
    bool initialized;
    E9BinaryenBackend backend;

    /* WAMR module for binaryen.wasm */
    void *binaryen_module;          /* wasm_module_t */
    void *binaryen_inst;            /* wasm_module_inst_t */
    void *exec_env;                 /* wasm_exec_env_t */

    /* Cached function pointers (WASM) */
    void *fn_module_create;
    void *fn_module_dispose;
    void *fn_module_read;
    void *fn_module_write;
    void *fn_module_optimize;
    void *fn_module_validate;
    void *fn_set_opt_level;
    void *fn_set_shrink_level;
    void *fn_malloc;
    void *fn_free;

    /* Current optimization settings */
    E9BinaryenOptLevel opt_level;
    int shrink_level;

    /* Error message */
    char error_msg[512];

    /* Reload callback */
    E9BinaryenReloadCallback reload_callback;
    void *reload_userdata;

} g_binaryen = {0};

/*
 * ============================================================================
 * Error Handling
 * ============================================================================
 */

static void set_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_binaryen.error_msg, sizeof(g_binaryen.error_msg), fmt, args);
    va_end(args);
}

const char *e9_binaryen_get_error(void)
{
    return g_binaryen.error_msg[0] ? g_binaryen.error_msg : NULL;
}

void e9_binaryen_clear_error(void)
{
    g_binaryen.error_msg[0] = '\0';
}

/*
 * ============================================================================
 * WASM Function Lookup
 * ============================================================================
 */

#ifdef BUILD_PLATFORM_COSMOPOLITAN

static void *lookup_function(const char *name)
{
    if (!g_binaryen.binaryen_inst) return NULL;

    wasm_function_inst_t func = wasm_runtime_lookup_function(
        (wasm_module_inst_t)g_binaryen.binaryen_inst, name);

    if (!func) {
        /* Try with underscore prefix (Emscripten convention) */
        char prefixed[256];
        snprintf(prefixed, sizeof(prefixed), "_%s", name);
        func = wasm_runtime_lookup_function(
            (wasm_module_inst_t)g_binaryen.binaryen_inst, prefixed);
    }

    return (void *)func;
}

static int call_void_func(void *func)
{
    if (!func || !g_binaryen.exec_env) return -1;

    uint32_t argv[1] = {0};
    if (!wasm_runtime_call_wasm((wasm_exec_env_t)g_binaryen.exec_env,
                                 (wasm_function_inst_t)func, 0, argv)) {
        set_error("WASM call failed: %s",
                  wasm_runtime_get_exception((wasm_module_inst_t)g_binaryen.binaryen_inst));
        return -1;
    }
    return 0;
}

static int32_t call_i32_func(void *func)
{
    if (!func || !g_binaryen.exec_env) return 0;

    uint32_t argv[1] = {0};
    if (!wasm_runtime_call_wasm((wasm_exec_env_t)g_binaryen.exec_env,
                                 (wasm_function_inst_t)func, 0, argv)) {
        set_error("WASM call failed: %s",
                  wasm_runtime_get_exception((wasm_module_inst_t)g_binaryen.binaryen_inst));
        return 0;
    }
    return (int32_t)argv[0];
}

static int32_t call_i32_func_i32(void *func, int32_t arg)
{
    if (!func || !g_binaryen.exec_env) return 0;

    uint32_t argv[1] = {(uint32_t)arg};
    if (!wasm_runtime_call_wasm((wasm_exec_env_t)g_binaryen.exec_env,
                                 (wasm_function_inst_t)func, 1, argv)) {
        set_error("WASM call failed: %s",
                  wasm_runtime_get_exception((wasm_module_inst_t)g_binaryen.binaryen_inst));
        return 0;
    }
    return (int32_t)argv[0];
}

static int32_t call_i32_func_i32_i32(void *func, int32_t arg1, int32_t arg2)
{
    if (!func || !g_binaryen.exec_env) return 0;

    uint32_t argv[2] = {(uint32_t)arg1, (uint32_t)arg2};
    if (!wasm_runtime_call_wasm((wasm_exec_env_t)g_binaryen.exec_env,
                                 (wasm_function_inst_t)func, 2, argv)) {
        set_error("WASM call failed: %s",
                  wasm_runtime_get_exception((wasm_module_inst_t)g_binaryen.binaryen_inst));
        return 0;
    }
    return (int32_t)argv[0];
}

static void call_void_func_i32(void *func, int32_t arg)
{
    if (!func || !g_binaryen.exec_env) return;

    uint32_t argv[1] = {(uint32_t)arg};
    if (!wasm_runtime_call_wasm((wasm_exec_env_t)g_binaryen.exec_env,
                                 (wasm_function_inst_t)func, 1, argv)) {
        set_error("WASM call failed: %s",
                  wasm_runtime_get_exception((wasm_module_inst_t)g_binaryen.binaryen_inst));
    }
}

/*
 * Allocate memory in WASM linear memory
 * Returns WASM pointer, or 0 on failure
 */
static int32_t wasm_malloc(size_t size)
{
    return call_i32_func_i32(g_binaryen.fn_malloc, (int32_t)size);
}

/*
 * Free memory in WASM linear memory
 */
static void wasm_free(int32_t ptr)
{
    call_void_func_i32(g_binaryen.fn_free, ptr);
}

/*
 * Copy data to WASM memory
 */
static int copy_to_wasm(int32_t wasm_ptr, const void *data, size_t size)
{
    if (!g_binaryen.binaryen_inst) return -1;

    if (!wasm_runtime_validate_app_addr((wasm_module_inst_t)g_binaryen.binaryen_inst,
                                         wasm_ptr, size)) {
        set_error("Invalid WASM memory access");
        return -1;
    }

    void *native_ptr = wasm_runtime_addr_app_to_native(
        (wasm_module_inst_t)g_binaryen.binaryen_inst, wasm_ptr);
    memcpy(native_ptr, data, size);
    return 0;
}

/*
 * Copy data from WASM memory
 */
static int copy_from_wasm(void *out, int32_t wasm_ptr, size_t size)
{
    if (!g_binaryen.binaryen_inst) return -1;

    if (!wasm_runtime_validate_app_addr((wasm_module_inst_t)g_binaryen.binaryen_inst,
                                         wasm_ptr, size)) {
        set_error("Invalid WASM memory access");
        return -1;
    }

    void *native_ptr = wasm_runtime_addr_app_to_native(
        (wasm_module_inst_t)g_binaryen.binaryen_inst, wasm_ptr);
    memcpy(out, native_ptr, size);
    return 0;
}

#endif /* BUILD_PLATFORM_COSMOPOLITAN */

/*
 * ============================================================================
 * Initialization
 * ============================================================================
 */

int e9_binaryen_init(E9BinaryenBackend backend)
{
    if (g_binaryen.initialized) {
        return 0;  /* Already initialized */
    }

    g_binaryen.backend = backend;
    g_binaryen.opt_level = E9_BINARYEN_OPT_O2;
    g_binaryen.shrink_level = 1;

#ifdef BUILD_PLATFORM_COSMOPOLITAN
    if (backend == E9_BINARYEN_WASM) {
        /* Load binaryen.wasm from ZipOS */
        g_binaryen.binaryen_module = e9wasm_load_module("/zip/lib/binaryen.wasm");
        if (!g_binaryen.binaryen_module) {
            /* Try alternate location */
            g_binaryen.binaryen_module = e9wasm_load_module("/zip/binaryen.wasm");
        }

        if (!g_binaryen.binaryen_module) {
            set_error("Failed to load binaryen.wasm from ZipOS");
            return -1;
        }

        /* Get module instance */
        g_binaryen.binaryen_inst = g_binaryen.binaryen_module;  /* WAMR simplification */

        /* Create execution environment */
        g_binaryen.exec_env = wasm_runtime_create_exec_env(
            (wasm_module_inst_t)g_binaryen.binaryen_inst, 64 * 1024);
        if (!g_binaryen.exec_env) {
            set_error("Failed to create WASM exec environment");
            return -1;
        }

        /* Cache frequently used function pointers */
        g_binaryen.fn_module_create = lookup_function("BinaryenModuleCreate");
        g_binaryen.fn_module_dispose = lookup_function("BinaryenModuleDispose");
        g_binaryen.fn_module_read = lookup_function("BinaryenModuleRead");
        g_binaryen.fn_module_write = lookup_function("BinaryenModuleWrite");
        g_binaryen.fn_module_optimize = lookup_function("BinaryenModuleOptimize");
        g_binaryen.fn_module_validate = lookup_function("BinaryenModuleValidate");
        g_binaryen.fn_set_opt_level = lookup_function("BinaryenSetOptimizeLevel");
        g_binaryen.fn_set_shrink_level = lookup_function("BinaryenSetShrinkLevel");
        g_binaryen.fn_malloc = lookup_function("malloc");
        g_binaryen.fn_free = lookup_function("free");

        if (!g_binaryen.fn_malloc || !g_binaryen.fn_free) {
            set_error("binaryen.wasm missing required functions (malloc/free)");
            return -1;
        }
    } else {
        /* Native backend - not implemented in portable build */
        set_error("Native Binaryen backend not available in this build");
        return -1;
    }
#else
    /* Non-Cosmopolitan build - stub implementation */
    set_error("Binaryen WASM backend requires Cosmopolitan build");
    return -1;
#endif

    g_binaryen.initialized = true;
    return 0;
}

void e9_binaryen_shutdown(void)
{
    if (!g_binaryen.initialized) return;

#ifdef BUILD_PLATFORM_COSMOPOLITAN
    if (g_binaryen.exec_env) {
        wasm_runtime_destroy_exec_env((wasm_exec_env_t)g_binaryen.exec_env);
        g_binaryen.exec_env = NULL;
    }
    /* Module cleanup handled by e9wasm_shutdown */
    g_binaryen.binaryen_module = NULL;
    g_binaryen.binaryen_inst = NULL;
#endif

    memset(&g_binaryen, 0, sizeof(g_binaryen));
}

bool e9_binaryen_is_ready(void)
{
    return g_binaryen.initialized;
}

const char *e9_binaryen_version(void)
{
    /* TODO: Call BinaryenGetVersion from WASM */
    return "binaryen (version unknown)";
}

/*
 * ============================================================================
 * Module Operations
 * ============================================================================
 */

E9BinaryenModuleRef e9_binaryen_module_create(void)
{
    if (!g_binaryen.initialized) {
        set_error("Binaryen not initialized");
        return NULL;
    }

#ifdef BUILD_PLATFORM_COSMOPOLITAN
    if (!g_binaryen.fn_module_create) {
        set_error("BinaryenModuleCreate not available");
        return NULL;
    }

    int32_t module = call_i32_func(g_binaryen.fn_module_create);
    return (E9BinaryenModuleRef)(intptr_t)module;
#else
    return NULL;
#endif
}

E9BinaryenModuleRef e9_binaryen_module_read(const uint8_t *data, size_t size)
{
    if (!g_binaryen.initialized || !data || size == 0) {
        set_error("Invalid arguments to module_read");
        return NULL;
    }

#ifdef BUILD_PLATFORM_COSMOPOLITAN
    if (!g_binaryen.fn_module_read) {
        set_error("BinaryenModuleRead not available");
        return NULL;
    }

    /* Allocate WASM memory for input */
    int32_t wasm_buf = wasm_malloc(size);
    if (!wasm_buf) {
        set_error("Failed to allocate WASM memory");
        return NULL;
    }

    /* Copy data to WASM */
    if (copy_to_wasm(wasm_buf, data, size) != 0) {
        wasm_free(wasm_buf);
        return NULL;
    }

    /* Call BinaryenModuleRead(input, inputSize) */
    int32_t module = call_i32_func_i32_i32(g_binaryen.fn_module_read,
                                            wasm_buf, (int32_t)size);

    wasm_free(wasm_buf);

    if (!module) {
        set_error("BinaryenModuleRead failed");
        return NULL;
    }

    return (E9BinaryenModuleRef)(intptr_t)module;
#else
    return NULL;
#endif
}

size_t e9_binaryen_module_write(E9BinaryenModuleRef module,
                                 uint8_t *out, size_t out_size)
{
    if (!g_binaryen.initialized || !module) {
        set_error("Invalid arguments to module_write");
        return 0;
    }

#ifdef BUILD_PLATFORM_COSMOPOLITAN
    /* TODO: Implement proper BinaryenModuleWrite call */
    /* This requires handling the output buffer allocation in WASM */
    set_error("module_write not fully implemented");
    return 0;
#else
    return 0;
#endif
}

void e9_binaryen_module_dispose(E9BinaryenModuleRef module)
{
    if (!g_binaryen.initialized || !module) return;

#ifdef BUILD_PLATFORM_COSMOPOLITAN
    if (g_binaryen.fn_module_dispose) {
        call_void_func_i32(g_binaryen.fn_module_dispose, (int32_t)(intptr_t)module);
    }
#endif
}

bool e9_binaryen_module_validate(E9BinaryenModuleRef module)
{
    if (!g_binaryen.initialized || !module) return false;

#ifdef BUILD_PLATFORM_COSMOPOLITAN
    if (!g_binaryen.fn_module_validate) {
        set_error("BinaryenModuleValidate not available");
        return false;
    }

    int32_t result = call_i32_func_i32(g_binaryen.fn_module_validate,
                                        (int32_t)(intptr_t)module);
    return result != 0;
#else
    return false;
#endif
}

char *e9_binaryen_module_print(E9BinaryenModuleRef module)
{
    if (!g_binaryen.initialized || !module) return NULL;

    /* TODO: Call BinaryenModulePrint and capture output */
    set_error("module_print not implemented");
    return NULL;
}

/*
 * ============================================================================
 * Optimization
 * ============================================================================
 */

void e9_binaryen_set_opt_level(E9BinaryenOptLevel level)
{
    g_binaryen.opt_level = level;

#ifdef BUILD_PLATFORM_COSMOPOLITAN
    if (g_binaryen.initialized && g_binaryen.fn_set_opt_level) {
        int binaryen_level;
        switch (level) {
            case E9_BINARYEN_OPT_NONE: binaryen_level = 0; break;
            case E9_BINARYEN_OPT_O1:   binaryen_level = 1; break;
            case E9_BINARYEN_OPT_O2:   binaryen_level = 2; break;
            case E9_BINARYEN_OPT_O3:   binaryen_level = 3; break;
            case E9_BINARYEN_OPT_OS:   binaryen_level = 2; break;
            case E9_BINARYEN_OPT_OZ:   binaryen_level = 2; break;
            default:                    binaryen_level = 2; break;
        }
        call_void_func_i32(g_binaryen.fn_set_opt_level, binaryen_level);
    }
#endif
}

void e9_binaryen_set_shrink_level(int level)
{
    g_binaryen.shrink_level = level;

#ifdef BUILD_PLATFORM_COSMOPOLITAN
    if (g_binaryen.initialized && g_binaryen.fn_set_shrink_level) {
        call_void_func_i32(g_binaryen.fn_set_shrink_level, level);
    }
#endif
}

int e9_binaryen_optimize(E9BinaryenModuleRef module)
{
    if (!g_binaryen.initialized || !module) {
        set_error("Invalid arguments to optimize");
        return -1;
    }

#ifdef BUILD_PLATFORM_COSMOPOLITAN
    if (!g_binaryen.fn_module_optimize) {
        set_error("BinaryenModuleOptimize not available");
        return -1;
    }

    call_void_func_i32(g_binaryen.fn_module_optimize, (int32_t)(intptr_t)module);
    return 0;
#else
    return -1;
#endif
}

int e9_binaryen_run_pass(E9BinaryenModuleRef module, const char *pass_name)
{
    /* TODO: Call BinaryenModuleRunPasses */
    set_error("run_pass not implemented");
    return -1;
}

int e9_binaryen_run_passes(E9BinaryenModuleRef module,
                            const char **pass_names, int num_passes)
{
    /* TODO: Call BinaryenModuleRunPasses with multiple passes */
    set_error("run_passes not implemented");
    return -1;
}

/*
 * ============================================================================
 * Code Generation
 * ============================================================================
 */

uint8_t *e9_binaryen_wat_to_wasm(const char *wat, size_t *out_size)
{
    /* TODO: Implement WAT parsing */
    set_error("wat_to_wasm not implemented");
    return NULL;
}

char *e9_binaryen_wasm_to_wat(const uint8_t *wasm, size_t size)
{
    /* TODO: Implement WASM disassembly */
    set_error("wasm_to_wat not implemented");
    return NULL;
}

/*
 * ============================================================================
 * Binary Patching Support
 * ============================================================================
 */

size_t e9_binaryen_optimize_patch(int arch,
                                   const uint8_t *code, size_t size,
                                   uint8_t *out, size_t out_size)
{
    /* TODO: Convert machine code to WASM, optimize, convert back */
    /* This is complex and requires architecture-specific handling */
    set_error("optimize_patch not implemented");
    return 0;
}

E9BinaryenModuleRef e9_binaryen_merge_modules(E9BinaryenModuleRef *modules,
                                               int num_modules)
{
    /* TODO: Call wasm-merge functionality */
    set_error("merge_modules not implemented");
    return NULL;
}

/*
 * ============================================================================
 * Live Reload Support
 * ============================================================================
 */

void e9_binaryen_set_reload_callback(E9BinaryenReloadCallback callback,
                                      void *userdata)
{
    g_binaryen.reload_callback = callback;
    g_binaryen.reload_userdata = userdata;
}

int e9_binaryen_diff_objects(const uint8_t *old_obj, size_t old_size,
                              const uint8_t *new_obj, size_t new_size,
                              E9BinaryenPatch **out_patches,
                              int *out_num_patches)
{
    /* TODO: Implement object diffing
     *
     * Algorithm:
     * 1. Parse both object files (ELF .o or COFF .obj)
     * 2. Extract function symbols and code
     * 3. Compare function bodies
     * 4. Generate patch descriptors for changed functions
     * 5. Use Binaryen to optimize patches if they're WASM
     */
    set_error("diff_objects not implemented");
    return -1;
}

void e9_binaryen_free_patches(E9BinaryenPatch *patches, int num_patches)
{
    if (!patches) return;

    for (int i = 0; i < num_patches; i++) {
        free(patches[i].old_bytes);
        free(patches[i].new_bytes);
    }
    free(patches);
}
