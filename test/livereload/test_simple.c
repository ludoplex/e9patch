/* Simple Live Reload Test
 *
 * Demonstrates the core workflow without WAMR dependency:
 *   1. Watch source file for changes (inotify)
 *   2. Recompile on change (cosmocc)
 *   3. Compare object files
 *
 * This is a minimal proof of concept.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <errno.h>
#include <time.h>

#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + 16))

static volatile int running = 1;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

/* Get file modification time */
static time_t get_mtime(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return st.st_mtime;
}

/* Compile a C file */
static int compile_file(const char *source, const char *output) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "cosmocc -c -O2 -g -o %s %s 2>&1", output, source);

    printf("[compile] %s\n", cmd);
    int ret = system(cmd);
    return WEXITSTATUS(ret);
}

/* Compare two object files */
static int compare_objects(const char *old_obj, const char *new_obj) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cmp -s %s %s", old_obj, new_obj);
    return system(cmd);  /* 0 if same, non-0 if different */
}

/* Get object file size */
static size_t get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return st.st_size;
}

int main(int argc, char **argv) {
    const char *source_file = "target.c";
    const char *watch_dir = ".";

    if (argc > 1) source_file = argv[1];
    if (argc > 2) watch_dir = argv[2];

    printf("=========================================================================\n");
    printf(" e9livereload - Simple Live Reload Test\n");
    printf("=========================================================================\n");
    printf("\n");
    printf("  Source file:  %s\n", source_file);
    printf("  Watch dir:    %s\n", watch_dir);
    printf("  Compiler:     cosmocc\n");
    printf("\n");
    printf("  Edit %s and save to see compilation triggered.\n", source_file);
    printf("  Press Ctrl+C to stop.\n");
    printf("\n");
    printf("-------------------------------------------------------------------------\n");
    fflush(stdout);

    /* Set up signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Set up inotify */
    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        return 1;
    }

    int wd = inotify_add_watch(fd, watch_dir, IN_MODIFY | IN_CLOSE_WRITE);
    if (wd < 0) {
        perror("inotify_add_watch");
        close(fd);
        return 1;
    }

    /* Create cache directory */
    system("mkdir -p .e9cache");

    /* Initial compilation */
    char old_obj[256], new_obj[256];
    snprintf(old_obj, sizeof(old_obj), ".e9cache/%s.o", source_file);
    snprintf(new_obj, sizeof(new_obj), ".e9cache/%s.new.o", source_file);

    printf("[init] Initial compilation...\n");
    if (compile_file(source_file, old_obj) != 0) {
        printf("[init] Initial compilation failed, waiting for valid source...\n");
    } else {
        printf("[init] Baseline object: %s (%zu bytes)\n", old_obj, get_file_size(old_obj));
    }
    printf("\n");

    /* Stats */
    int changes_detected = 0;
    int recompiles = 0;
    int patches_would_apply = 0;

    /* Main loop */
    char buffer[BUF_LEN];

    while (running) {
        fd_set fds;
        struct timeval tv;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;  /* 100ms */

        int ret = select(fd + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        if (ret == 0) continue;  /* Timeout */

        int length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];

            if (event->len > 0) {
                /* Check if it's a .c file */
                const char *name = event->name;
                size_t len = strlen(name);

                if (len > 2 && strcmp(name + len - 2, ".c") == 0) {
                    if (event->mask & (IN_MODIFY | IN_CLOSE_WRITE)) {
                        changes_detected++;
                        printf("\n[watch] File modified: %s\n", name);

                        /* Small delay to ensure file is fully written */
                        usleep(50000);

                        /* Check if source_file matches */
                        if (strstr(source_file, name) != NULL ||
                            strcmp(name, source_file) == 0) {

                            /* Compile new version */
                            printf("[compile] Recompiling %s...\n", source_file);
                            int comp_ret = compile_file(source_file, new_obj);
                            recompiles++;

                            if (comp_ret != 0) {
                                printf("[compile] FAILED (exit %d)\n", comp_ret);
                            } else {
                                printf("[compile] SUCCESS\n");

                                /* Compare objects */
                                if (compare_objects(old_obj, new_obj) != 0) {
                                    size_t old_size = get_file_size(old_obj);
                                    size_t new_size = get_file_size(new_obj);

                                    printf("[diff] Objects DIFFER\n");
                                    printf("[diff]   Old: %zu bytes\n", old_size);
                                    printf("[diff]   New: %zu bytes\n", new_size);
                                    printf("[diff]   Delta: %+ld bytes\n",
                                           (long)new_size - (long)old_size);

                                    /* This is where we would apply the patch */
                                    printf("[patch] WOULD APPLY PATCH HERE\n");
                                    printf("[patch] (full implementation uses e9ape + binaryen)\n");
                                    patches_would_apply++;

                                    /* Update baseline */
                                    rename(new_obj, old_obj);
                                    printf("[cache] Updated baseline\n");
                                } else {
                                    printf("[diff] Objects identical (no patch needed)\n");
                                }
                            }
                        }
                    }
                }
            }

            i += EVENT_SIZE + event->len;
        }
    }

    printf("\n");
    printf("=========================================================================\n");
    printf(" Session Statistics\n");
    printf("=========================================================================\n");
    printf("  Changes detected:      %d\n", changes_detected);
    printf("  Recompilations:        %d\n", recompiles);
    printf("  Patches would apply:   %d\n", patches_would_apply);
    printf("=========================================================================\n");

    /* Cleanup */
    inotify_rm_watch(fd, wd);
    close(fd);

    return 0;
}
