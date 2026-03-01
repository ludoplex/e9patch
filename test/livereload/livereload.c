/*
 * livereload.c - APE Live Reload Implementation
 *
 * Real-time C source -> binary patching for APE executables.
 * Uses ptrace for memory modification and direct icache flush.
 *
 * Generated types from: specs/domain/livereload.schema
 * Workflow: make regen → use gen/domain/livereload_types.h
 *
 * Workflow:
 *   1. Watch source files (inotify)
 *   2. Recompile on change (cosmocc -c)
 *   3. Extract function addresses (objdump/nm)
 *   4. Diff object files
 *   5. Patch target process (ptrace)
 *   6. Flush instruction cache
 *
 * Copyright (C) 2024 E9Studio Contributors
 * License: GPLv3+
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/inotify.h>
#include <stdarg.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Generated Types (from cosmicringforge)
 * ═══════════════════════════════════════════════════════════════════════════ */

#include "livereload_types.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_PATH        256
#define MAX_PATCH_SIZE  4096
#define CACHE_DIR       ".e9cache"
#define COMPILER        "cosmocc"

/* Runtime patch data (extends generated PatchInfo with actual bytes) */
typedef struct {
    PatchInfo info;
    uint8_t old_bytes[MAX_PATCH_SIZE];
    uint8_t new_bytes[MAX_PATCH_SIZE];
    size_t patch_size;  /* Actual patch size in bytes */
} PatchData;

/* Runtime state (local struct, not in schema - ephemeral runtime data) */
typedef struct {
    int target_pid;
    char source_file[MAX_PATH];
    char cache_dir[MAX_PATH];
    int changes_detected;
    int patches_applied;
    int patches_failed;
} LiveReloadState;

static volatile int g_running = 1;
static LiveReloadState g_state = {0};

/* ═══════════════════════════════════════════════════════════════════════════
 * Signal Handling
 * ═══════════════════════════════════════════════════════════════════════════ */

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Utility Functions
 * ═══════════════════════════════════════════════════════════════════════════ */

static void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("\033[36m[livereload]\033[0m ");
    vprintf(fmt, args);
    printf("\n");
    fflush(stdout);
    va_end(args);
}

static void log_success(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("\033[32m[SUCCESS]\033[0m ");
    vprintf(fmt, args);
    printf("\n");
    fflush(stdout);
    va_end(args);
}

static void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "\033[31m[ERROR]\033[0m ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(args);
}

static int run_command(const char *cmd, char *output, size_t output_size) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    if (output && output_size > 0) {
        output[0] = '\0';
        size_t total = 0;
        while (fgets(output + total, output_size - total, fp)) {
            total = strlen(output);
            if (total >= output_size - 1) break;
        }
    } else {
        char buf[256];
        while (fgets(buf, sizeof(buf), fp)) {}
    }

    return pclose(fp);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Compilation
 * ═══════════════════════════════════════════════════════════════════════════ */

static int compile_source(const char *source, const char *output) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "%s -c -O2 -g -ffunction-sections -o '%s' '%s' 2>&1",
             COMPILER, output, source);

    log_info("Compiling: %s", source);

    char compile_output[4096];
    int ret = run_command(cmd, compile_output, sizeof(compile_output));

    if (WEXITSTATUS(ret) != 0) {
        log_error("Compilation failed:\n%s", compile_output);
        return -1;
    }

    log_success("Compiled: %s", output);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Symbol Extraction
 * ═══════════════════════════════════════════════════════════════════════════ */

static int get_function_info(const char *object_file, const char *func_name,
                              FunctionInfo *info) {
    char cmd[512];
    char output[4096];

    /* Use nm to get symbol address */
    snprintf(cmd, sizeof(cmd), "nm '%s' 2>/dev/null | grep ' T %s$'",
             object_file, func_name);

    if (run_command(cmd, output, sizeof(output)) != 0 || strlen(output) == 0) {
        return -1;
    }

    /* Parse: "0000000000000000 T function_name" */
    if (sscanf(output, "%lx", &info->address) != 1) {
        return -1;
    }

    strncpy(info->name, func_name, sizeof(info->name) - 1);

    /* Get function size using objdump */
    snprintf(cmd, sizeof(cmd),
             "objdump -d '%s' 2>/dev/null | grep -A100 '<%s>:' | "
             "grep -E '^[[:space:]]*[0-9a-f]+:' | wc -l",
             object_file, func_name);

    if (run_command(cmd, output, sizeof(output)) == 0) {
        int lines = atoi(output);
        info->size = lines * 4;  /* Rough estimate */
    } else {
        info->size = 64;  /* Default */
    }

    return 0;
}

/* Get function address in running process */
static uint64_t get_runtime_address(int pid, const char *func_name) {
    char cmd[512];
    char output[4096];

    /* Get base address from /proc/pid/maps */
    snprintf(cmd, sizeof(cmd),
             "head -1 /proc/%d/maps | cut -d'-' -f1", pid);

    if (run_command(cmd, output, sizeof(output)) != 0) {
        return 0;
    }

    uint64_t base = 0;
    sscanf(output, "%lx", &base);

    /* Get function offset from executable */
    snprintf(cmd, sizeof(cmd),
             "nm /proc/%d/exe 2>/dev/null | grep ' T %s$' | cut -d' ' -f1",
             pid, func_name);

    if (run_command(cmd, output, sizeof(output)) != 0 || strlen(output) == 0) {
        return 0;
    }

    uint64_t offset = 0;
    sscanf(output, "%lx", &offset);

    return base + offset;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Object File Diffing
 * ═══════════════════════════════════════════════════════════════════════════ */

static int extract_function_bytes(const char *object_file, const char *func_name,
                                   uint8_t *bytes, size_t *size) {
    char cmd[512];
    char output[16384];

    /* Use objdump to get function bytes */
    snprintf(cmd, sizeof(cmd),
             "objdump -d '%s' 2>/dev/null | "
             "sed -n '/<%s>:/,/^$/p' | "
             "grep -E '^[[:space:]]*[0-9a-f]+:' | "
             "awk '{for(i=2;i<=NF && $i~/^[0-9a-f][0-9a-f]$/;i++) print $i}'",
             object_file, func_name);

    if (run_command(cmd, output, sizeof(output)) != 0) {
        return -1;
    }

    /* Parse hex bytes */
    *size = 0;
    char *line = strtok(output, "\n");
    while (line && *size < MAX_PATCH_SIZE) {
        unsigned int byte;
        if (sscanf(line, "%x", &byte) == 1) {
            bytes[(*size)++] = (uint8_t)byte;
        }
        line = strtok(NULL, "\n");
    }

    return (*size > 0) ? 0 : -1;
}

static int diff_functions(const char *old_obj, const char *new_obj,
                          const char *func_name, PatchData *patch) {
    size_t old_size = 0, new_size = 0;

    if (extract_function_bytes(old_obj, func_name, patch->old_bytes, &old_size) != 0) {
        log_error("Cannot extract old function bytes");
        return -1;
    }

    if (extract_function_bytes(new_obj, func_name, patch->new_bytes, &new_size) != 0) {
        log_error("Cannot extract new function bytes");
        return -1;
    }

    /* Compare */
    if (old_size == new_size && memcmp(patch->old_bytes, patch->new_bytes, old_size) == 0) {
        return 0;  /* No difference */
    }

    /* Create patch using generated PatchInfo struct */
    strncpy(patch->info.function_name, func_name, sizeof(patch->info.function_name) - 1);
    patch->info.old_size = old_size;
    patch->info.new_size = new_size;
    patch->patch_size = new_size;

    log_info("Function '%s' changed: %zu -> %zu bytes", func_name, old_size, new_size);

    return 1;  /* Difference found */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Process Patching (ptrace)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int attach_process(int pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        log_error("Cannot attach to PID %d: %s", pid, strerror(errno));
        return -1;
    }

    int status;
    waitpid(pid, &status, 0);

    if (!WIFSTOPPED(status)) {
        log_error("Process did not stop");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    return 0;
}

static int detach_process(int pid) {
    return ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

static int read_memory(int pid, uint64_t addr, void *buf, size_t len) {
    size_t i;
    long *dst = (long *)buf;

    for (i = 0; i < len; i += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (errno != 0) {
            return -1;
        }
        dst[i / sizeof(long)] = word;
    }

    return 0;
}

static int write_memory(int pid, uint64_t addr, const void *buf, size_t len) {
    size_t i;
    const long *src = (const long *)buf;

    for (i = 0; i < len; i += sizeof(long)) {
        if (ptrace(PTRACE_POKEDATA, pid, addr + i, src[i / sizeof(long)]) < 0) {
            return -1;
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ICache Flush
 * ═══════════════════════════════════════════════════════════════════════════ */

static void flush_icache(uint64_t addr, size_t size) {
    /*
     * On x86-64, instruction cache is coherent with data cache,
     * so no explicit flush is needed for self-modifying code.
     *
     * However, the CPU may still have stale instructions in the
     * pipeline. We use a serializing instruction to ensure
     * the new code is visible.
     */
#if defined(__x86_64__) || defined(_M_X64)
    /* x86-64: CPUID serializes instruction stream */
    __asm__ volatile("cpuid" ::: "eax", "ebx", "ecx", "edx", "memory");
#elif defined(__aarch64__)
    /* AArch64: explicit cache maintenance */
    __asm__ volatile(
        "dc cvau, %0\n"
        "dsb ish\n"
        "ic ivau, %0\n"
        "dsb ish\n"
        "isb\n"
        :: "r"(addr)
    );
#endif
    (void)addr;
    (void)size;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Live Reload Core
 * ═══════════════════════════════════════════════════════════════════════════ */

static int apply_patch(int pid, PatchData *patch) {
    uint64_t addr = get_runtime_address(pid, patch->info.function_name);
    if (addr == 0) {
        log_error("Cannot find runtime address for '%s'", patch->info.function_name);
        return -1;
    }

    patch->info.target_address = addr;

    log_info("Patching '%s' at 0x%lx (%zu bytes)",
             patch->info.function_name, addr, patch->patch_size);

    /* Attach to process */
    if (attach_process(pid) != 0) {
        return -1;
    }

    /* Read current bytes (for verification/revert) */
    uint8_t current[MAX_PATCH_SIZE];
    if (read_memory(pid, addr, current, patch->patch_size) != 0) {
        log_error("Cannot read memory at 0x%lx", addr);
        detach_process(pid);
        return -1;
    }

    /* Write new bytes */
    if (write_memory(pid, addr, patch->new_bytes, patch->patch_size) != 0) {
        log_error("Cannot write memory at 0x%lx: %s", addr, strerror(errno));
        detach_process(pid);
        return -1;
    }

    /* Flush instruction cache */
    flush_icache(addr, patch->patch_size);

    /* Detach and continue */
    detach_process(pid);

    log_success("Patch applied: %s @ 0x%lx", patch->info.function_name, addr);
    g_state.patches_applied++;

    return 0;
}

static int handle_file_change(const char *source_file) {
    char old_obj[MAX_PATH], new_obj[MAX_PATH];
    char basename[64];

    /* Extract basename */
    const char *slash = strrchr(source_file, '/');
    const char *name = slash ? slash + 1 : source_file;
    strncpy(basename, name, sizeof(basename) - 1);
    char *dot = strrchr(basename, '.');
    if (dot) *dot = '\0';

    snprintf(old_obj, sizeof(old_obj), "%s/%s.o", g_state.cache_dir, basename);
    snprintf(new_obj, sizeof(new_obj), "%s/%s.new.o", g_state.cache_dir, basename);

    g_state.changes_detected++;

    /* Compile new version */
    if (compile_source(source_file, new_obj) != 0) {
        g_state.patches_failed++;
        return -1;
    }

    /* Check if old object exists */
    struct stat st;
    if (stat(old_obj, &st) != 0) {
        log_info("No baseline, creating initial object");
        rename(new_obj, old_obj);
        return 0;
    }

    /* Diff and patch each function */
    /* For this demo, we focus on the get_message function */
    PatchData patch = {0};
    int diff = diff_functions(old_obj, new_obj, "get_message", &patch);

    if (diff > 0) {
        if (apply_patch(g_state.target_pid, &patch) != 0) {
            g_state.patches_failed++;
        }
    } else if (diff == 0) {
        log_info("No changes to get_message()");
    }

    /* Update baseline */
    rename(new_obj, old_obj);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * File Watching
 * ═══════════════════════════════════════════════════════════════════════════ */

static int setup_watch(const char *dir) {
    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        log_error("inotify_init failed: %s", strerror(errno));
        return -1;
    }

    int wd = inotify_add_watch(fd, dir, IN_CLOSE_WRITE | IN_MODIFY);
    if (wd < 0) {
        log_error("inotify_add_watch failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

static int poll_events(int fd) {
    char buffer[4096];

    ssize_t len = read(fd, buffer, sizeof(buffer));
    if (len < 0) {
        if (errno == EAGAIN) return 0;
        return -1;
    }

    int events = 0;
    ssize_t i = 0;
    while (i < len) {
        struct inotify_event *event = (struct inotify_event *)&buffer[i];

        if (event->len > 0) {
            const char *name = event->name;
            size_t nlen = strlen(name);

            /* Check for .c file */
            if (nlen > 2 && strcmp(name + nlen - 2, ".c") == 0) {
                /* Debounce: small delay */
                usleep(50000);

                char path[MAX_PATH];
                snprintf(path, sizeof(path), "%s", name);

                log_info("File changed: %s", name);
                handle_file_change(path);
                events++;
            }
        }

        i += sizeof(struct inotify_event) + event->len;
    }

    return events;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_usage(const char *prog) {
    printf("Usage: %s <target_pid> [source_file]\n", prog);
    printf("\n");
    printf("Live reload for APE binaries - hot-patch running processes.\n");
    printf("\n");
    printf("Arguments:\n");
    printf("  target_pid   PID of the process to patch\n");
    printf("  source_file  Source file to watch (default: target.c)\n");
    printf("\n");
    printf("Example:\n");
    printf("  # Terminal 1: Run target\n");
    printf("  ./target &\n");
    printf("\n");
    printf("  # Terminal 2: Run live reload\n");
    printf("  sudo %s $(pgrep target) target.c\n", prog);
    printf("\n");
    printf("  # Terminal 3: Edit target.c\n");
    printf("  # Change get_message() return value and save\n");
    printf("  # Watch terminal 1 - message changes in real-time!\n");
}

static void print_banner(void) {
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf(" APE Live Reload - Real-time Binary Patching\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("\n");
}

static void print_stats(void) {
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf(" Session Statistics\n");
    printf("═══════════════════════════════════════════════════════════════════════\n");
    printf("  Changes detected:  %d\n", g_state.changes_detected);
    printf("  Patches applied:   %d\n", g_state.patches_applied);
    printf("  Patches failed:    %d\n", g_state.patches_failed);
    printf("═══════════════════════════════════════════════════════════════════════\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    /* Parse arguments */
    g_state.target_pid = atoi(argv[1]);
    const char *source_file = (argc > 2) ? argv[2] : "target.c";

    if (g_state.target_pid <= 0) {
        log_error("Invalid PID: %s", argv[1]);
        return 1;
    }

    /* Check if process exists */
    if (kill(g_state.target_pid, 0) != 0) {
        log_error("Process %d not found: %s", g_state.target_pid, strerror(errno));
        return 1;
    }

    /* Check for root (needed for ptrace) */
    if (geteuid() != 0) {
        log_error("Root privileges required for ptrace");
        log_info("Try: sudo %s %d %s", argv[0], g_state.target_pid, source_file);
        return 1;
    }

    strncpy(g_state.source_file, source_file, MAX_PATH - 1);
    snprintf(g_state.cache_dir, MAX_PATH, "%s", CACHE_DIR);

    /* Create cache directory */
    mkdir(g_state.cache_dir, 0755);

    /* Setup */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    print_banner();
    printf("  Target PID:    %d\n", g_state.target_pid);
    printf("  Source file:   %s\n", g_state.source_file);
    printf("  Cache dir:     %s\n", g_state.cache_dir);
    printf("  Compiler:      %s\n", COMPILER);
    printf("\n");
    printf("  Watching for changes...\n");
    printf("  Edit %s and save to trigger hot-patching.\n", source_file);
    printf("  Press Ctrl+C to stop.\n");
    printf("\n");
    printf("───────────────────────────────────────────────────────────────────────\n");

    /* Setup file watch */
    int watch_fd = setup_watch(".");
    if (watch_fd < 0) {
        return 1;
    }

    /* Initial compilation */
    char initial_obj[MAX_PATH];
    snprintf(initial_obj, sizeof(initial_obj), "%s/target.o", g_state.cache_dir);
    if (compile_source(source_file, initial_obj) == 0) {
        log_info("Baseline established");
    }

    /* Main loop */
    while (g_running) {
        poll_events(watch_fd);
        usleep(100000);  /* 100ms */
    }

    close(watch_fd);
    print_stats();

    return 0;
}
