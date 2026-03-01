/*
 * e9livereload.c
 * Live Reload Integration for APE Binary Hot-Patching
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Wires together the following components:
 *   - e9ape.h: APE parsing and PE-based patching (no ELF for x86-64!)
 *   - e9binaryen.h: Object file diffing and patch generation
 *   - e9wasm_host.h: Memory mapping and icache flush
 *
 * Workflow:
 *   1. File change detected (inotify/kqueue/polling)
 *   2. Invoke cosmocc to recompile changed .c to .o
 *   3. Use Binaryen to diff old .o vs new .o
 *   4. Convert Binaryen patches to APE file offsets via PE sections
 *   5. Apply patches to mmap'd binary (or self)
 *   6. Flush instruction cache
 *   7. Execution continues with new code
 *
 * For self-patching: the running APE maps itself, patches in place.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#ifdef __linux__
#include <sys/inotify.h>
#endif

#include "e9livereload.h"
#include "e9ape.h"
#include "wasm/e9binaryen.h"
#include "wasm/e9wasm_host.h"

/* ═══════════════════════════════════════════════════════════════════════
 * Internal State
 * ═══════════════════════════════════════════════════════════════════════ */

#define MAX_PATCHES 256
#define MAX_PATH_LEN 256
#define ERROR_BUF_SIZE 512

typedef struct {
    uint32_t id;
    char source_file[MAX_PATH_LEN];
    char function_name[128];

    E9PatchTargetType target_type;
    uint64_t target_address;
    off_t file_offset;              /* Resolved file offset */

    uint8_t *old_bytes;
    size_t old_size;
    uint8_t *new_bytes;
    size_t new_size;

    E9PatchStatus status;
    char error_msg[256];
    uint64_t timestamp;
} InternalPatch;

typedef struct {
    bool initialized;
    bool watching;

    /* Configuration */
    E9LiveReloadConfig config;
    char source_dir[MAX_PATH_LEN];
    char compiler[MAX_PATH_LEN];
    char cache_dir[MAX_PATH_LEN];

    /* Target binary */
    char target_path[MAX_PATH_LEN];
    bool is_self_patch;
    int target_fd;
    uint8_t *target_mapped;
    size_t target_size;

    /* APE info (from e9ape.h) */
    E9_APEInfo ape_info;

    /* File watcher */
#ifdef __linux__
    int inotify_fd;
    int watch_fd;
#endif

    /* Patches */
    InternalPatch patches[MAX_PATCHES];
    size_t num_patches;
    uint32_t next_patch_id;

    /* Object cache (for diffing) */
    /* Maps source path -> last object file content */

    /* Callback */
    E9LiveReloadCallback callback;
    void *callback_userdata;

    /* Statistics */
    E9LiveReloadStats stats;

    /* Error state */
    char error_msg[ERROR_BUF_SIZE];
} LiveReloadState;

static LiveReloadState g_state = {0};

/* ═══════════════════════════════════════════════════════════════════════
 * Error Handling
 * ═══════════════════════════════════════════════════════════════════════ */

static void set_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_state.error_msg, ERROR_BUF_SIZE, fmt, args);
    va_end(args);
}

const char *e9_livereload_get_error(void)
{
    return g_state.error_msg[0] ? g_state.error_msg : NULL;
}

void e9_livereload_clear_error(void)
{
    g_state.error_msg[0] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════
 * Event Dispatch
 * ═══════════════════════════════════════════════════════════════════════ */

static void dispatch_event(E9LiveReloadEventType type, const char *file,
                            uint32_t patch_id, const char *func,
                            uint64_t addr, size_t size,
                            int err_code, const char *err_msg)
{
    if (!g_state.callback)
        return;

    E9LiveReloadEvent event = {
        .type = type,
        .timestamp = (uint64_t)time(NULL),
        .file_path = file,
        .patch_id = patch_id,
        .function_name = func,
        .patch_address = addr,
        .patch_size = size,
        .error_code = err_code,
        .error_msg = err_msg,
    };

    g_state.callback(&event, g_state.callback_userdata);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Object Cache
 * ═══════════════════════════════════════════════════════════════════════ */

static void ensure_cache_dir(void)
{
    struct stat st;
    if (stat(g_state.cache_dir, &st) != 0)
    {
        mkdir(g_state.cache_dir, 0755);
    }
}

static void get_cached_object_path(const char *source, char *out, size_t out_size)
{
    /* source: /path/to/foo.c -> cache_dir/foo.c.o */
    const char *basename = strrchr(source, '/');
    basename = basename ? basename + 1 : source;

    snprintf(out, out_size, "%s/%s.o", g_state.cache_dir, basename);
}

static void get_new_object_path(const char *source, char *out, size_t out_size)
{
    /* source: /path/to/foo.c -> cache_dir/foo.c.new.o */
    const char *basename = strrchr(source, '/');
    basename = basename ? basename + 1 : source;

    snprintf(out, out_size, "%s/%s.new.o", g_state.cache_dir, basename);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Compilation
 * ═══════════════════════════════════════════════════════════════════════ */

static int compile_source(const char *source_path, const char *output_path)
{
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "%s %s -c %s -o %s 2>&1",
             g_state.compiler,
             g_state.config.compiler_flags ? g_state.config.compiler_flags : "",
             source_path,
             output_path);

    dispatch_event(E9_LR_EVENT_COMPILE_START, source_path, 0, NULL, 0, 0, 0, NULL);

    if (g_state.config.verbose)
        fprintf(stderr, "[livereload] Compiling: %s\n", cmd);

    int ret = system(cmd);

    if (ret != 0)
    {
        set_error("Compilation failed with exit code %d", ret);
        dispatch_event(E9_LR_EVENT_COMPILE_ERROR, source_path, 0, NULL,
                       0, 0, ret, "Compilation failed");
        return -1;
    }

    dispatch_event(E9_LR_EVENT_COMPILE_DONE, source_path, 0, NULL, 0, 0, 0, NULL);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Binary Diffing and Patch Generation
 * ═══════════════════════════════════════════════════════════════════════ */

static uint8_t *read_file(const char *path, size_t *out_size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        return NULL;
    }

    uint8_t *data = malloc(st.st_size);
    if (!data)
    {
        close(fd);
        return NULL;
    }

    if (read(fd, data, st.st_size) != st.st_size)
    {
        free(data);
        close(fd);
        return NULL;
    }

    close(fd);
    *out_size = st.st_size;
    return data;
}

static int generate_patches(const char *source_path,
                             const char *old_object,
                             const char *new_object)
{
    /* Read both object files */
    size_t old_size, new_size;
    uint8_t *old_data = read_file(old_object, &old_size);
    uint8_t *new_data = read_file(new_object, &new_size);

    if (!old_data || !new_data)
    {
        free(old_data);
        free(new_data);
        set_error("Failed to read object files for diffing");
        return -1;
    }

    /* Use Binaryen to diff the objects */
    E9BinaryenPatch *binaryen_patches = NULL;
    int num_binaryen_patches = 0;

    int ret = e9_binaryen_diff_objects(old_data, old_size,
                                        new_data, new_size,
                                        &binaryen_patches,
                                        &num_binaryen_patches);

    free(old_data);
    free(new_data);

    if (ret != 0)
    {
        set_error("Binaryen diff failed");
        return -1;
    }

    if (num_binaryen_patches == 0)
    {
        if (g_state.config.verbose)
            fprintf(stderr, "[livereload] No changes detected in %s\n", source_path);
        return 0;
    }

    /* Convert Binaryen patches to our internal format */
    int patches_created = 0;

    for (int i = 0; i < num_binaryen_patches; i++)
    {
        E9BinaryenPatch *bp = &binaryen_patches[i];

        if (g_state.num_patches >= MAX_PATCHES)
        {
            set_error("Maximum patch count exceeded");
            break;
        }

        InternalPatch *patch = &g_state.patches[g_state.num_patches];
        memset(patch, 0, sizeof(*patch));

        patch->id = ++g_state.next_patch_id;
        strncpy(patch->source_file, source_path, MAX_PATH_LEN - 1);
        if (bp->function)
            strncpy(patch->function_name, bp->function, sizeof(patch->function_name) - 1);

        /* Binaryen gives us addresses - need to convert via APE PE sections */
        patch->target_type = E9_PATCH_TARGET_PE_RVA;
        patch->target_address = bp->address;

        /* Convert RVA to file offset using e9ape */
        uint32_t rva = (uint32_t)bp->address;
        patch->file_offset = e9_ape_rva_to_offset(&g_state.ape_info, rva);

        if (patch->file_offset < 0)
        {
            if (g_state.config.verbose)
                fprintf(stderr, "[livereload] Cannot translate RVA 0x%lx to file offset\n",
                        (unsigned long)bp->address);
            continue;
        }

        /* Copy old and new bytes */
        patch->old_size = bp->size;
        patch->new_size = bp->size;  /* Binaryen patches are same-size replacements */

        patch->old_bytes = malloc(bp->size);
        patch->new_bytes = malloc(bp->size);

        if (!patch->old_bytes || !patch->new_bytes)
        {
            free(patch->old_bytes);
            free(patch->new_bytes);
            continue;
        }

        memcpy(patch->old_bytes, bp->old_bytes, bp->size);
        memcpy(patch->new_bytes, bp->new_bytes, bp->size);

        patch->status = E9_PATCH_STATUS_PENDING;
        patch->timestamp = (uint64_t)time(NULL);

        g_state.num_patches++;
        g_state.stats.patches_generated++;
        patches_created++;

        dispatch_event(E9_LR_EVENT_PATCH_GENERATED, source_path, patch->id,
                       patch->function_name, bp->address, bp->size, 0, NULL);
    }

    e9_binaryen_free_patches(binaryen_patches, num_binaryen_patches);

    return patches_created;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Patch Application
 * ═══════════════════════════════════════════════════════════════════════ */

static int apply_patch_internal(InternalPatch *patch)
{
    if (!g_state.target_mapped)
    {
        snprintf(patch->error_msg, sizeof(patch->error_msg),
                 "Target not mapped");
        patch->status = E9_PATCH_STATUS_FAILED;
        return -1;
    }

    if (patch->file_offset < 0 ||
        (size_t)(patch->file_offset + patch->new_size) > g_state.target_size)
    {
        snprintf(patch->error_msg, sizeof(patch->error_msg),
                 "Patch offset 0x%lx out of bounds", (unsigned long)patch->file_offset);
        patch->status = E9_PATCH_STATUS_FAILED;
        g_state.stats.patches_failed++;
        dispatch_event(E9_LR_EVENT_PATCH_FAILED, patch->source_file, patch->id,
                       patch->function_name, patch->target_address, patch->new_size,
                       -1, patch->error_msg);
        return -1;
    }

    /* Apply patch using e9ape */
    int ret = e9_ape_patch_offset(g_state.target_mapped, g_state.target_size,
                                   &g_state.ape_info,
                                   patch->file_offset,
                                   patch->new_bytes, patch->new_size);

    if (ret != 0)
    {
        snprintf(patch->error_msg, sizeof(patch->error_msg),
                 "e9_ape_patch_offset failed");
        patch->status = E9_PATCH_STATUS_FAILED;
        g_state.stats.patches_failed++;
        dispatch_event(E9_LR_EVENT_PATCH_FAILED, patch->source_file, patch->id,
                       patch->function_name, patch->target_address, patch->new_size,
                       -1, patch->error_msg);
        return -1;
    }

    /* Flush instruction cache */
    void *patch_addr = g_state.target_mapped + patch->file_offset;
    e9wasm_flush_icache(patch_addr, patch->new_size);

    patch->status = E9_PATCH_STATUS_APPLIED;
    g_state.stats.patches_applied++;
    g_state.stats.total_bytes_patched += patch->new_size;
    g_state.stats.last_patch_time = (uint64_t)time(NULL);

    dispatch_event(E9_LR_EVENT_PATCH_APPLIED, patch->source_file, patch->id,
                   patch->function_name, patch->target_address, patch->new_size,
                   0, NULL);

    if (g_state.config.verbose)
        fprintf(stderr, "[livereload] Applied patch #%u at 0x%lx (%zu bytes) [%s]\n",
                patch->id, (unsigned long)patch->file_offset, patch->new_size,
                patch->function_name[0] ? patch->function_name : "unknown");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * File Change Handling
 * ═══════════════════════════════════════════════════════════════════════ */

static int handle_file_change(const char *source_path)
{
    g_state.stats.changes_detected++;
    g_state.stats.last_change_time = (uint64_t)time(NULL);

    dispatch_event(E9_LR_EVENT_FILE_CHANGE, source_path, 0, NULL, 0, 0, 0, NULL);

    if (g_state.config.verbose)
        fprintf(stderr, "[livereload] File changed: %s\n", source_path);

    ensure_cache_dir();

    /* Paths for old and new objects */
    char old_obj[MAX_PATH_LEN], new_obj[MAX_PATH_LEN];
    get_cached_object_path(source_path, old_obj, sizeof(old_obj));
    get_new_object_path(source_path, new_obj, sizeof(new_obj));

    /* Compile to new object */
    if (compile_source(source_path, new_obj) != 0)
        return -1;

    /* Check if we have a previous object to diff against */
    struct stat st;
    if (stat(old_obj, &st) != 0)
    {
        /* First compilation - just cache it */
        rename(new_obj, old_obj);
        if (g_state.config.verbose)
            fprintf(stderr, "[livereload] First compilation cached for %s\n", source_path);
        return 0;
    }

    /* Generate patches by diffing old vs new */
    int num_patches = generate_patches(source_path, old_obj, new_obj);

    /* Update cache */
    rename(new_obj, old_obj);

    if (num_patches <= 0)
        return num_patches;

    /* Apply patches if hot-patching is enabled */
    if (g_state.config.enable_hot_patch)
    {
        int applied = 0;
        for (size_t i = 0; i < g_state.num_patches; i++)
        {
            if (g_state.patches[i].status == E9_PATCH_STATUS_PENDING)
            {
                if (apply_patch_internal(&g_state.patches[i]) == 0)
                    applied++;
            }
        }
        return applied;
    }

    return num_patches;
}

/* ═══════════════════════════════════════════════════════════════════════
 * File Watcher
 * ═══════════════════════════════════════════════════════════════════════ */

#ifdef __linux__
static int init_inotify(void)
{
    g_state.inotify_fd = inotify_init1(IN_NONBLOCK);
    if (g_state.inotify_fd < 0)
    {
        set_error("inotify_init1 failed: %s", strerror(errno));
        return -1;
    }

    g_state.watch_fd = inotify_add_watch(g_state.inotify_fd,
                                          g_state.source_dir,
                                          IN_MODIFY | IN_CLOSE_WRITE);
    if (g_state.watch_fd < 0)
    {
        set_error("inotify_add_watch failed: %s", strerror(errno));
        close(g_state.inotify_fd);
        g_state.inotify_fd = -1;
        return -1;
    }

    return 0;
}

static void cleanup_inotify(void)
{
    if (g_state.watch_fd >= 0)
    {
        inotify_rm_watch(g_state.inotify_fd, g_state.watch_fd);
        g_state.watch_fd = -1;
    }
    if (g_state.inotify_fd >= 0)
    {
        close(g_state.inotify_fd);
        g_state.inotify_fd = -1;
    }
}

static int poll_inotify(void)
{
    char buf[4096];
    ssize_t len = read(g_state.inotify_fd, buf, sizeof(buf));

    if (len <= 0)
        return 0;

    int events_processed = 0;
    size_t offset = 0;

    while (offset < (size_t)len)
    {
        struct inotify_event *event = (struct inotify_event *)(buf + offset);

        if (event->len > 0)
        {
            const char *name = event->name;
            size_t name_len = strlen(name);

            /* Check for .c or .h files */
            if ((name_len > 2 && strcmp(name + name_len - 2, ".c") == 0) ||
                (name_len > 2 && strcmp(name + name_len - 2, ".h") == 0))
            {
                char full_path[MAX_PATH_LEN];
                snprintf(full_path, sizeof(full_path), "%s/%s",
                         g_state.source_dir, name);

                handle_file_change(full_path);
                events_processed++;
            }
        }

        offset += sizeof(struct inotify_event) + event->len;
    }

    return events_processed;
}
#else
/* Fallback for non-Linux platforms - use polling */
static int init_inotify(void) { return 0; }
static void cleanup_inotify(void) {}
static int poll_inotify(void) { return 0; }
#endif

/* ═══════════════════════════════════════════════════════════════════════
 * Public API - Lifecycle
 * ═══════════════════════════════════════════════════════════════════════ */

int e9_livereload_init(const char *target_path,
                        const E9LiveReloadConfig *config)
{
    if (g_state.initialized)
    {
        set_error("Live reload already initialized");
        return -1;
    }

    memset(&g_state, 0, sizeof(g_state));

    /* Copy config */
    if (config)
        g_state.config = *config;
    else
    {
        E9LiveReloadConfig default_config = E9_LIVERELOAD_CONFIG_DEFAULT;
        g_state.config = default_config;
    }

    /* Set source directory */
    strncpy(g_state.source_dir,
            g_state.config.source_dir ? g_state.config.source_dir : ".",
            MAX_PATH_LEN - 1);

    /* Set compiler */
    strncpy(g_state.compiler,
            g_state.config.compiler ? g_state.config.compiler : "cosmocc",
            MAX_PATH_LEN - 1);

    /* Set cache directory */
    strncpy(g_state.cache_dir,
            g_state.config.cache_dir ? g_state.config.cache_dir : ".e9cache",
            MAX_PATH_LEN - 1);

    /* Determine target path */
    if (target_path)
    {
        strncpy(g_state.target_path, target_path, MAX_PATH_LEN - 1);
        g_state.is_self_patch = false;
    }
    else
    {
        /* Self-patching mode */
        const char *self = e9_ape_get_self_path();
        if (!self)
        {
            set_error("Cannot determine self executable path");
            return -1;
        }
        strncpy(g_state.target_path, self, MAX_PATH_LEN - 1);
        g_state.is_self_patch = true;
    }

    /* Open and map target binary */
    g_state.target_fd = open(g_state.target_path, O_RDWR);
    if (g_state.target_fd < 0)
    {
        set_error("Cannot open target: %s: %s", g_state.target_path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(g_state.target_fd, &st) != 0)
    {
        set_error("Cannot stat target: %s", strerror(errno));
        close(g_state.target_fd);
        return -1;
    }
    g_state.target_size = st.st_size;

    /* Memory map with write access */
    g_state.target_mapped = mmap(NULL, g_state.target_size,
                                  PROT_READ | PROT_WRITE,
                                  MAP_SHARED,
                                  g_state.target_fd, 0);

    if (g_state.target_mapped == MAP_FAILED)
    {
        set_error("Cannot mmap target: %s", strerror(errno));
        close(g_state.target_fd);
        g_state.target_mapped = NULL;
        return -1;
    }

    /* Parse APE structure */
    if (e9_ape_parse(g_state.target_mapped, g_state.target_size, &g_state.ape_info) != 0)
    {
        set_error("Target is not a valid APE binary");
        munmap(g_state.target_mapped, g_state.target_size);
        close(g_state.target_fd);
        g_state.target_mapped = NULL;
        return -1;
    }

    /* Initialize Binaryen for object diffing */
    if (e9_binaryen_init(E9_BINARYEN_WASM) != 0)
    {
        /* Try native fallback */
        if (e9_binaryen_init(E9_BINARYEN_NATIVE) != 0)
        {
            if (g_state.config.verbose)
                fprintf(stderr, "[livereload] Warning: Binaryen not available, diff disabled\n");
        }
    }

#ifdef __linux__
    g_state.inotify_fd = -1;
    g_state.watch_fd = -1;
#endif

    g_state.next_patch_id = 0;
    g_state.initialized = true;

    if (g_state.config.verbose)
    {
        fprintf(stderr, "[livereload] Initialized for %s (%s)\n",
                g_state.target_path,
                g_state.is_self_patch ? "self-patching" : "external target");
        e9_ape_dump_info(&g_state.ape_info, stderr);
    }

    return 0;
}

void e9_livereload_shutdown(void)
{
    if (!g_state.initialized)
        return;

    e9_livereload_unwatch();

    /* Free patches */
    for (size_t i = 0; i < g_state.num_patches; i++)
    {
        free(g_state.patches[i].old_bytes);
        free(g_state.patches[i].new_bytes);
    }

    /* Unmap target */
    if (g_state.target_mapped)
    {
        munmap(g_state.target_mapped, g_state.target_size);
        g_state.target_mapped = NULL;
    }

    if (g_state.target_fd >= 0)
    {
        close(g_state.target_fd);
        g_state.target_fd = -1;
    }

    e9_binaryen_shutdown();

    memset(&g_state, 0, sizeof(g_state));
}

bool e9_livereload_is_ready(void)
{
    return g_state.initialized && g_state.target_mapped != NULL;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Public API - Watch Control
 * ═══════════════════════════════════════════════════════════════════════ */

int e9_livereload_watch(void)
{
    if (!g_state.initialized)
    {
        set_error("Live reload not initialized");
        return -1;
    }

    if (g_state.watching)
        return 0;

    if (init_inotify() != 0)
        return -1;

    g_state.watching = true;

    if (g_state.config.verbose)
        fprintf(stderr, "[livereload] Watching: %s\n", g_state.source_dir);

    return 0;
}

void e9_livereload_unwatch(void)
{
    if (!g_state.watching)
        return;

    cleanup_inotify();
    g_state.watching = false;
}

int e9_livereload_poll(void)
{
    if (!g_state.initialized)
        return -1;

    if (!g_state.watching)
        return 0;

    return poll_inotify();
}

void e9_livereload_set_callback(E9LiveReloadCallback callback, void *userdata)
{
    g_state.callback = callback;
    g_state.callback_userdata = userdata;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Public API - Manual Operations
 * ═══════════════════════════════════════════════════════════════════════ */

int e9_livereload_reload_file(const char *source_path)
{
    if (!g_state.initialized)
    {
        set_error("Live reload not initialized");
        return -1;
    }

    return handle_file_change(source_path);
}

uint32_t e9_livereload_apply_patch(E9PatchTargetType target_type,
                                    uint64_t address,
                                    const uint8_t *patch,
                                    size_t patch_size)
{
    if (!g_state.initialized || !g_state.target_mapped)
    {
        set_error("Live reload not ready");
        return 0;
    }

    if (g_state.num_patches >= MAX_PATCHES)
    {
        set_error("Maximum patch count exceeded");
        return 0;
    }

    InternalPatch *p = &g_state.patches[g_state.num_patches];
    memset(p, 0, sizeof(*p));

    p->id = ++g_state.next_patch_id;
    p->target_type = target_type;
    p->target_address = address;

    /* Resolve file offset */
    switch (target_type)
    {
        case E9_PATCH_TARGET_FILE_OFFSET:
            p->file_offset = (off_t)address;
            break;

        case E9_PATCH_TARGET_PE_RVA:
            p->file_offset = e9_ape_rva_to_offset(&g_state.ape_info, (uint32_t)address);
            break;

        case E9_PATCH_TARGET_VA:
            /* VA to RVA: typically VA = 0x400000 + RVA */
            if (address >= 0x400000)
                p->file_offset = e9_ape_rva_to_offset(&g_state.ape_info,
                                                       (uint32_t)(address - 0x400000));
            else
                p->file_offset = (off_t)address;
            break;
    }

    if (p->file_offset < 0)
    {
        set_error("Cannot resolve patch address 0x%lx", (unsigned long)address);
        return 0;
    }

    /* Store old bytes for potential revert */
    p->old_size = patch_size;
    p->old_bytes = malloc(patch_size);
    if (p->old_bytes)
        memcpy(p->old_bytes, g_state.target_mapped + p->file_offset, patch_size);

    /* Store new bytes */
    p->new_size = patch_size;
    p->new_bytes = malloc(patch_size);
    if (p->new_bytes)
        memcpy(p->new_bytes, patch, patch_size);

    p->timestamp = (uint64_t)time(NULL);
    p->status = E9_PATCH_STATUS_PENDING;

    g_state.num_patches++;

    /* Apply immediately */
    if (apply_patch_internal(p) != 0)
        return 0;

    return p->id;
}

int e9_livereload_revert_patch(uint32_t patch_id)
{
    if (!g_state.initialized || !g_state.target_mapped)
        return -1;

    for (size_t i = 0; i < g_state.num_patches; i++)
    {
        InternalPatch *p = &g_state.patches[i];
        if (p->id == patch_id && p->status == E9_PATCH_STATUS_APPLIED)
        {
            /* Restore old bytes */
            if (p->old_bytes)
            {
                memcpy(g_state.target_mapped + p->file_offset,
                       p->old_bytes, p->old_size);

                e9wasm_flush_icache(g_state.target_mapped + p->file_offset,
                                     p->old_size);

                p->status = E9_PATCH_STATUS_REVERTED;
                g_state.stats.patches_reverted++;

                dispatch_event(E9_LR_EVENT_PATCH_REVERTED, p->source_file, p->id,
                               p->function_name, p->target_address, p->old_size,
                               0, NULL);

                return 0;
            }
        }
    }

    set_error("Patch %u not found or not applied", patch_id);
    return -1;
}

void e9_livereload_flush_icache(void *addr, size_t size)
{
    e9wasm_flush_icache(addr, size);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Public API - Query
 * ═══════════════════════════════════════════════════════════════════════ */

size_t e9_livereload_pending_count(void)
{
    size_t count = 0;
    for (size_t i = 0; i < g_state.num_patches; i++)
    {
        if (g_state.patches[i].status == E9_PATCH_STATUS_PENDING)
            count++;
    }
    return count;
}

size_t e9_livereload_get_pending(E9PatchInfo *patches, size_t max_patches)
{
    size_t count = 0;
    for (size_t i = 0; i < g_state.num_patches && count < max_patches; i++)
    {
        InternalPatch *p = &g_state.patches[i];
        if (p->status == E9_PATCH_STATUS_PENDING)
        {
            patches[count].id = p->id;
            patches[count].source_file = p->source_file;
            patches[count].function_name = p->function_name;
            patches[count].target_type = p->target_type;
            patches[count].target_address = p->target_address;
            patches[count].old_bytes = p->old_bytes;
            patches[count].old_size = p->old_size;
            patches[count].new_bytes = p->new_bytes;
            patches[count].new_size = p->new_size;
            patches[count].status = p->status;
            patches[count].error_msg = p->error_msg;
            patches[count].timestamp = p->timestamp;
            count++;
        }
    }
    return count;
}

size_t e9_livereload_applied_count(void)
{
    size_t count = 0;
    for (size_t i = 0; i < g_state.num_patches; i++)
    {
        if (g_state.patches[i].status == E9_PATCH_STATUS_APPLIED)
            count++;
    }
    return count;
}

void e9_livereload_get_stats(E9LiveReloadStats *stats)
{
    if (stats)
        *stats = g_state.stats;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Public API - Utilities
 * ═══════════════════════════════════════════════════════════════════════ */

bool e9_livereload_compiler_available(void)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "which %s >/dev/null 2>&1", g_state.compiler);
    return system(cmd) == 0;
}

const char *e9_livereload_compiler_version(void)
{
    static char version[256];
    char cmd[512];

    snprintf(cmd, sizeof(cmd), "%s --version 2>&1 | head -1", g_state.compiler);

    FILE *fp = popen(cmd, "r");
    if (!fp)
        return NULL;

    if (fgets(version, sizeof(version), fp) == NULL)
    {
        pclose(fp);
        return NULL;
    }

    pclose(fp);

    /* Remove newline */
    size_t len = strlen(version);
    if (len > 0 && version[len - 1] == '\n')
        version[len - 1] = '\0';

    return version;
}
