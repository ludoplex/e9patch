/* Live Reload Test Driver
 *
 * Demonstrates the e9livereload API:
 *   1. Watch source file for changes (inotify)
 *   2. Recompile on change (cosmocc)
 *   3. Diff objects (binaryen)
 *   4. Patch running binary (e9patch)
 *   5. Flush icache
 *
 * Usage: ./test_livereload [source_dir]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "../../src/e9patch/e9livereload.h"

static volatile int running = 1;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

/* Callback for live reload events */
static void livereload_callback(const E9LiveReloadEvent *event, void *user_data) {
    (void)user_data;

    switch (event->type) {
        case E9_LR_EVENT_FILE_CHANGE:
            printf("[livereload] File changed: %s\n", event->file_path);
            break;
        case E9_LR_EVENT_COMPILE_START:
            printf("[livereload] Compiling: %s\n", event->file_path);
            break;
        case E9_LR_EVENT_COMPILE_DONE:
            printf("[livereload] Compile done\n");
            break;
        case E9_LR_EVENT_COMPILE_ERROR:
            printf("[livereload] Compile ERROR: %s\n", event->error_msg);
            break;
        case E9_LR_EVENT_PATCH_GENERATED:
            printf("[livereload] Patch generated: %s @ 0x%lx (%zu bytes)\n",
                   event->function_name,
                   (unsigned long)event->patch_address,
                   event->patch_size);
            break;
        case E9_LR_EVENT_PATCH_APPLIED:
            printf("[livereload] PATCH APPLIED: %s @ 0x%lx\n",
                   event->function_name, (unsigned long)event->patch_address);
            break;
        case E9_LR_EVENT_PATCH_FAILED:
            printf("[livereload] Patch FAILED: %s\n", event->error_msg);
            break;
        case E9_LR_EVENT_PATCH_REVERTED:
            printf("[livereload] Patch reverted: %s\n", event->function_name);
            break;
        default:
            printf("[livereload] Event: %d\n", event->type);
            break;
    }
    fflush(stdout);
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [source_dir]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Watches source_dir for .c file changes and hot-patches\n");
    fprintf(stderr, "the running binary in real-time.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Default source_dir: current directory\n");
}

int main(int argc, char **argv) {
    const char *source_dir = ".";

    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        source_dir = argv[1];
    }

    printf("=========================================================================\n");
    printf(" e9livereload - Real-time Binary Patching for APE\n");
    printf("=========================================================================\n");
    printf("\n");
    printf("  Source dir:  %s\n", source_dir);
    printf("  Compiler:    cosmocc (APE-aware)\n");
    printf("  Mode:        Self-patching (hot-patch running binary)\n");
    printf("\n");
    printf("  Watching for .c file changes...\n");
    printf("  Edit and save source files to trigger hot-patching.\n");
    printf("  Press Ctrl+C to stop.\n");
    printf("\n");
    printf("-------------------------------------------------------------------------\n");
    fflush(stdout);

    /* Set up signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Configure live reload */
    E9LiveReloadConfig config = E9_LIVERELOAD_CONFIG_DEFAULT;
    config.source_dir = source_dir;
    config.compiler = "cosmocc";
    config.compiler_flags = "-O2 -g";
    config.enable_hot_patch = true;
    config.enable_file_patch = false;
    config.verbose = true;

    /* Initialize live reload (NULL = self-patching) */
    int result = e9_livereload_init(NULL, &config);
    if (result != 0) {
        fprintf(stderr, "Failed to initialize live reload: %s\n",
                e9_livereload_get_error());
        return 1;
    }

    /* Set up event callback */
    e9_livereload_set_callback(livereload_callback, NULL);

    /* Start watching */
    result = e9_livereload_watch();
    if (result != 0) {
        fprintf(stderr, "Failed to start file watcher: %s\n",
                e9_livereload_get_error());
        e9_livereload_shutdown();
        return 1;
    }

    printf("[livereload] Watching %s for changes...\n", source_dir);
    printf("[livereload] Ready for hot-patching\n\n");

    /* Main loop - poll for changes */
    while (running) {
        result = e9_livereload_poll();
        if (result < 0) {
            fprintf(stderr, "Poll error: %s\n", e9_livereload_get_error());
            break;
        }
        usleep(config.watch_interval_ms * 1000);
    }

    printf("\n[livereload] Shutting down...\n");

    /* Get stats before shutdown */
    E9LiveReloadStats stats;
    e9_livereload_get_stats(&stats);

    printf("\n");
    printf("=========================================================================\n");
    printf(" Session Statistics\n");
    printf("=========================================================================\n");
    printf("  Changes detected:  %lu\n", (unsigned long)stats.changes_detected);
    printf("  Patches generated: %lu\n", (unsigned long)stats.patches_generated);
    printf("  Patches applied:   %lu\n", (unsigned long)stats.patches_applied);
    printf("  Patches failed:    %lu\n", (unsigned long)stats.patches_failed);
    printf("  Bytes patched:     %lu\n", (unsigned long)stats.total_bytes_patched);
    printf("=========================================================================\n");

    /* Cleanup */
    e9_livereload_shutdown();

    return 0;
}
