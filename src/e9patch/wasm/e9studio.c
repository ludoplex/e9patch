/*
 * e9studio.c
 * Self-contained e9patch studio
 *
 * A single APE file that provides:
 * - Native binary analysis and decompilation
 * - Embedded WASM VM for sandboxed execution (optional)
 * - Terminal UI for interactive binary exploration
 * - File watcher for hot-reload patching
 * - Self-modification capability (save patches to own ZipOS)
 *
 * No browser or external tools required.
 *
 * Usage:
 *   ./e9studio.com target.elf          # Analyze and patch target.elf
 *   ./e9studio.com --daemon            # Run as background service
 *   ./e9studio.com --self-test         # Run internal tests
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

/* Central config must be included first for feature test macros */
#include "e9studio_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <errno.h>

/* Platform-specific includes for terminal handling */
#ifdef __COSMOPOLITAN__
#include <cosmo.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#elif defined(_WIN32)
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#endif

#include "e9wasm_host.h"
#include "../analysis/e9studio_analysis.h"
#include "../e9livereload.h"

#ifdef __linux__
#include <sys/inotify.h>
#endif

/*
 * Platform detection helpers for Cosmopolitan
 */
#ifdef __COSMOPOLITAN__
static inline bool is_windows(void) { return IsWindows(); }
static inline bool is_linux(void) { return IsLinux(); }
#else
static inline bool is_windows(void) {
#ifdef _WIN32
    return true;
#else
    return false;
#endif
}
static inline bool is_linux(void) {
#ifdef __linux__
    return true;
#else
    return false;
#endif
}
#endif

/*
 * View modes for TUI
 */
typedef enum {
    VIEW_DISASM = 0,     /* Disassembly view */
    VIEW_DECOMPILE = 1,  /* Decompiled C view */
    VIEW_HEX = 2,        /* Hex dump view */
    VIEW_INFO = 3,       /* Binary info view */
    VIEW_MAX
} ViewMode;

static const char *view_mode_names[] = {
    "Disassembly",
    "Decompiled C",
    "Hex Dump",
    "Binary Info"
};

/*
 * Execution mode for WASM runtime
 */
typedef enum {
    EXEC_MODE_DEFAULT = 0,   /* Use best available (Fast JIT if supported) */
    EXEC_MODE_INTERP = 1,    /* Fast interpreter */
    EXEC_MODE_JIT = 2,       /* Fast JIT compilation */
    EXEC_MODE_AOT = 3        /* Ahead-of-time compiled modules */
} ExecMode;

/*
 * Studio Configuration
 */
typedef struct {
    const char *target_path;        /* Path to target binary */
    const char *source_dir;         /* Directory containing source files */
    int port;                       /* Port for remote connections (0 = disabled) */
    bool daemon_mode;               /* Run as background service */
    bool verbose;                   /* Verbose output */
    bool tui_mode;                  /* Terminal UI mode */
    bool self_test;                 /* Run self-tests */
    ExecMode exec_mode;             /* WASM execution mode */
} StudioConfig;

static StudioConfig g_config = {
    .target_path = NULL,
    .source_dir = ".",
    .port = 0,
    .daemon_mode = false,
    .verbose = false,
    .tui_mode = true,
    .self_test = false,
    .exec_mode = EXEC_MODE_DEFAULT,
};

/*
 * TUI State
 */
typedef struct {
    ViewMode view_mode;             /* Current view mode */
    uint64_t view_addr;             /* Current address being viewed */
    int scroll_offset;              /* Scroll position in view */
    char status_msg[256];           /* Status message to display */
    time_t status_time;             /* When status was set */
    bool binary_loaded;             /* Whether a binary is loaded */
    bool needs_redraw;              /* Flag to force redraw */
    int term_rows;                  /* Terminal rows */
    int term_cols;                  /* Terminal columns */
} TUIState;

static TUIState g_tui = {
    .view_mode = VIEW_DISASM,
    .view_addr = 0,
    .scroll_offset = 0,
    .status_msg = "",
    .status_time = 0,
    .binary_loaded = false,
    .needs_redraw = true,
    .term_rows = 24,
    .term_cols = 80,
};

/*
 * Global State
 */
static volatile bool g_running = true;
static bool g_raw_mode = false;

/* Platform-specific terminal state */
#if defined(_WIN32) && !defined(__COSMOPOLITAN__)
static DWORD g_orig_console_mode = 0;
#else
static struct termios g_orig_termios;
#endif

/* View buffer for rendering */
#define VIEW_BUF_SIZE (64 * 1024)
static char g_view_buffer[VIEW_BUF_SIZE];

/*
 * Signal handler
 */
static void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

/*
 * Terminal handling - cross-platform implementation
 */
static void disable_raw_mode(void) {
    if (!g_raw_mode) return;

#if defined(_WIN32) && !defined(__COSMOPOLITAN__)
    /* Windows native: restore console mode */
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin != INVALID_HANDLE_VALUE) {
        SetConsoleMode(hStdin, g_orig_console_mode);
    }
#else
    /* POSIX or Cosmopolitan: restore termios */
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
#endif

    g_raw_mode = false;
}

static void enable_raw_mode(void) {
#if defined(_WIN32) && !defined(__COSMOPOLITAN__)
    /* Windows native: enable virtual terminal processing */
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

    if (hStdin == INVALID_HANDLE_VALUE) return;

    /* Query current console mode for stdin; bail if it fails (e.g. redirected input) */
    if (!GetConsoleMode(hStdin, &g_orig_console_mode))
        return;

    DWORD mode = g_orig_console_mode;
    mode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
    mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;

    /* Enable raw-ish input mode; if this fails, don't register atexit or mark raw mode */
    if (!SetConsoleMode(hStdin, mode))
        return;

    /* Enable ANSI escape sequences for output; if stdout is a console, require success */
    if (hStdout != INVALID_HANDLE_VALUE) {
        DWORD out_mode;
        if (!GetConsoleMode(hStdout, &out_mode))
            return;
        out_mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        if (!SetConsoleMode(hStdout, out_mode))
            return;
    }

    atexit(disable_raw_mode);
    g_raw_mode = true;
#else
    /* POSIX or Cosmopolitan: use termios */
    if (!isatty(STDIN_FILENO)) return;

    tcgetattr(STDIN_FILENO, &g_orig_termios);
    atexit(disable_raw_mode);

    struct termios raw = g_orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 1;

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    g_raw_mode = true;
#endif
}

static void get_terminal_size(void) {
#if defined(_WIN32) && !defined(__COSMOPOLITAN__)
    /* Windows native: use console API */
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdout != INVALID_HANDLE_VALUE && 
        GetConsoleScreenBufferInfo(hStdout, &csbi)) {
        g_tui.term_cols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        g_tui.term_rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    }
#else
    /* POSIX or Cosmopolitan: use ioctl */
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        g_tui.term_rows = ws.ws_row;
        g_tui.term_cols = ws.ws_col;
    }
#endif
}

/*
 * Set status message
 */
static void set_status(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_tui.status_msg, sizeof(g_tui.status_msg), fmt, args);
    va_end(args);
    g_tui.status_time = time(NULL);
    g_tui.needs_redraw = true;
}

/*
 * Print usage
 */
static void print_usage(const char *prog) {
    printf("E9Patch Studio - Self-contained binary analysis and rewriting\n\n");
    printf("Usage: %s [options] [target.elf]\n\n", prog);
    printf("Options:\n");
    printf("  --source-dir DIR     Source files directory (default: .)\n");
    printf("  --port PORT          Enable remote connections on PORT\n");
    printf("  --daemon             Run as background service\n");
    printf("  --no-tui             Disable terminal UI\n");
    printf("  --verbose, -v        Verbose output\n");
    printf("  --self-test          Run internal tests\n");
    printf("  --help, -h           Show this help\n");
    printf("\n");
    printf("Interactive commands:\n");
    printf("  TAB / v      Cycle view: Disasm -> Decompile -> Hex -> Info\n");
    printf("  j / DOWN     Scroll down / Next instruction\n");
    printf("  k / UP       Scroll up / Previous instruction\n");
    printf("  n            Next function\n");
    printf("  p            Previous function\n");
    printf("  g            Go to address (prompts for input)\n");
    printf("  f            Find function by name\n");
    printf("  d            Decompile current function\n");
    printf("  x            Show cross-references to current address\n");
    printf("  i            Show binary info\n");
    printf("  l            Show live reload stats\n");
    printf("  s            Save patched binary\n");
    printf("  r            Reload and reanalyze\n");
    printf("  q            Quit\n");
    printf("\n");
    printf("Native analysis features (no WASM required):\n");
    printf("  - Disassembly (Zydis)\n");
    printf("  - Decompilation to Cosmopolitan C\n");
    printf("  - Control flow graph analysis\n");
    printf("  - Symbol resolution\n");
    printf("  - Cross-reference analysis\n");
}

/*
 * Parse command line arguments
 */
static int parse_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "--source-dir") == 0 && i + 1 < argc) {
            g_config.source_dir = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            g_config.port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--daemon") == 0) {
            g_config.daemon_mode = true;
            g_config.tui_mode = false;
        } else if (strcmp(argv[i], "--no-tui") == 0) {
            g_config.tui_mode = false;
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            g_config.verbose = true;
        } else if (strcmp(argv[i], "--self-test") == 0) {
            g_config.self_test = true;
        } else if (strcmp(argv[i], "--jit") == 0) {
            g_config.exec_mode = EXEC_MODE_JIT;
        } else if (strcmp(argv[i], "--interp") == 0) {
            g_config.exec_mode = EXEC_MODE_INTERP;
        } else if (strcmp(argv[i], "--aot") == 0) {
            g_config.exec_mode = EXEC_MODE_AOT;
        } else if (argv[i][0] != '-') {
            g_config.target_path = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return -1;
        }
    }

    return 0;
}

/*
 * Load target binary using analysis engine
 */
static int load_target(void) {
    const char *path = g_config.target_path;
    if (!path) {
        /* Try loading from ZipOS */
        if (access("/zip/target.elf", F_OK) == 0) {
            path = "/zip/target.elf";
        } else {
            return -1;
        }
    }

    set_status("Loading: %s", path);

    if (e9studio_load_binary(path) < 0) {
        set_status("Failed to load: %s", path);
        return -1;
    }

    g_tui.binary_loaded = true;
    set_status("Loaded and analyzed: %s", path);

    return 0;
}

/*
 * Initialize WASM runtime (optional, for sandboxed execution)
 */
static int init_wasm(void) {
    if (g_config.verbose) {
        fprintf(stderr, "Initializing WASM runtime...\n");
    }

    /* Check if ZipOS is available before trying to use WASM modules */
    int zipos_ok = e9wasm_zipos_available();
    int wasm_exists = zipos_ok && e9wasm_zipos_file_exists("/zip/e9patch.wasm");

    if (!wasm_exists) {
        /* Log in verbose mode or when ZipOS is explicitly disabled */
        const char *disable_env = getenv("COSMOPOLITAN_DISABLE_ZIPOS");
        if (g_config.verbose || (disable_env && strcmp(disable_env, "1") == 0)) {
            fprintf(stderr, "Note: e9patch.wasm not found in ZipOS, running in native mode\n");
        }
        /* Native mode is fully functional for analysis and decompilation */
        return 0;
    }

    E9WasmConfig config = {
        .stack_size = 64 * 1024,
        .heap_size = 32 * 1024 * 1024,
        .shared_buffer_size = 128 * 1024 * 1024,
        .enable_wasi = true,
        .enable_debug = g_config.verbose,
        .module_path = "/zip/e9patch.wasm",
    };

    if (e9wasm_init(&config) < 0) {
        /* Not fatal - native mode works fine */
        if (g_config.verbose) {
            fprintf(stderr, "WASM init failed, using native mode only\n");
        }
        return 0;
    }

    /* Try to load WASM modules (optional) */
    void *module = e9wasm_load_module("/zip/e9patch.wasm");
    if (module) {
        if (g_config.verbose) {
            fprintf(stderr, "Loaded e9patch.wasm for sandboxed execution\n");
        }
    } else {
        /* Module load failed - continue in native mode */
        if (g_config.verbose) {
            fprintf(stderr, "WASM module load failed, continuing in native mode\n");
        }
    }

    return 0;
}

/*
 * Live Reload Integration
 * Uses e9livereload.h for hot-patching APE binaries in real-time.
 */
static bool g_livereload_initialized = false;

/*
 * Live reload event callback - updates TUI status
 */
static void livereload_callback(const E9LiveReloadEvent *event, void *userdata) {
    (void)userdata;

    switch (event->type) {
        case E9_LR_EVENT_FILE_CHANGE:
            set_status("Source changed: %s - recompiling...",
                       event->file_path ? event->file_path : "unknown");
            break;

        case E9_LR_EVENT_COMPILE_START:
            set_status("Compiling: %s",
                       event->file_path ? event->file_path : "unknown");
            break;

        case E9_LR_EVENT_COMPILE_DONE:
            set_status("Compiled: %s",
                       event->file_path ? event->file_path : "unknown");
            break;

        case E9_LR_EVENT_COMPILE_ERROR:
            set_status("Compile failed: %s - %s",
                       event->file_path ? event->file_path : "unknown",
                       event->error_msg ? event->error_msg : "unknown error");
            break;

        case E9_LR_EVENT_PATCH_GENERATED:
            set_status("Patch #%u generated for %s (%zu bytes)",
                       event->patch_id,
                       event->function_name ? event->function_name : "code",
                       event->patch_size);
            break;

        case E9_LR_EVENT_PATCH_APPLIED:
            set_status("Patch #%u applied at 0x%lx (%zu bytes) [%s]",
                       event->patch_id,
                       (unsigned long)event->patch_address,
                       event->patch_size,
                       event->function_name ? event->function_name : "unknown");
            break;

        case E9_LR_EVENT_PATCH_FAILED:
            set_status("Patch #%u failed: %s",
                       event->patch_id,
                       event->error_msg ? event->error_msg : "unknown error");
            break;

        case E9_LR_EVENT_PATCH_REVERTED:
            set_status("Patch #%u reverted", event->patch_id);
            break;

        default:
            break;
    }

    g_tui.needs_redraw = true;
}

/*
 * Initialize live reload with target binary
 */
static int init_file_watcher(void) {
    /* Use target binary for live reload, or self if analyzing self */
    const char *target = g_config.target_path;

    E9LiveReloadConfig lr_config = E9_LIVERELOAD_CONFIG_DEFAULT;
    lr_config.source_dir = g_config.source_dir;
    lr_config.verbose = g_config.verbose;
    lr_config.enable_hot_patch = true;

    if (e9_livereload_init(target, &lr_config) != 0) {
        if (g_config.verbose) {
            fprintf(stderr, "Live reload init failed: %s\n",
                    e9_livereload_get_error());
        }
        return -1;
    }

    e9_livereload_set_callback(livereload_callback, NULL);

    if (e9_livereload_watch() != 0) {
        if (g_config.verbose) {
            fprintf(stderr, "File watch start failed: %s\n",
                    e9_livereload_get_error());
        }
        e9_livereload_shutdown();
        return -1;
    }

    g_livereload_initialized = true;

    if (g_config.verbose) {
        fprintf(stderr, "Live reload active: watching %s\n", g_config.source_dir);
        if (e9_livereload_compiler_available()) {
            fprintf(stderr, "Compiler: %s\n", e9_livereload_compiler_version());
        }
    }

    return 0;
}

/*
 * Poll for file changes and process live reload events
 */
static void check_file_changes(void) {
    if (!g_livereload_initialized) return;

    int events = e9_livereload_poll();
    if (events > 0 && g_config.verbose) {
        fprintf(stderr, "Processed %d live reload events\n", events);
    }
}

/*
 * Cleanup live reload resources
 */
static void cleanup_file_watcher(void) {
    if (g_livereload_initialized) {
        e9_livereload_shutdown();
        g_livereload_initialized = false;
    }
}

/*
 * ANSI escape sequences for TUI
 */
#define ANSI_CLEAR      "\033[2J"
#define ANSI_HOME       "\033[H"
#define ANSI_BOLD       "\033[1m"
#define ANSI_DIM        "\033[2m"
#define ANSI_RESET      "\033[0m"
#define ANSI_REVERSE    "\033[7m"
#define ANSI_FG_GREEN   "\033[32m"
#define ANSI_FG_YELLOW  "\033[33m"
#define ANSI_FG_BLUE    "\033[34m"
#define ANSI_FG_CYAN    "\033[36m"
#define ANSI_FG_WHITE   "\033[37m"

/*
 * TUI rendering
 */
static void render_tui(void) {
    get_terminal_size();

    /* Clear screen and move to home */
    printf(ANSI_CLEAR ANSI_HOME);

    /* Header bar */
    printf(ANSI_REVERSE ANSI_BOLD);
    printf(" E9Studio");
    printf(ANSI_RESET ANSI_REVERSE);
    printf(" | View: %s | ", view_mode_names[g_tui.view_mode]);

    if (g_tui.binary_loaded) {
        printf("Addr: 0x%lx", g_tui.view_addr);
    } else {
        printf("No binary loaded");
    }

    /* Pad to terminal width */
    int header_len = 50;  /* approximate */
    for (int i = header_len; i < g_tui.term_cols; i++) {
        putchar(' ');
    }
    printf(ANSI_RESET "\n");

    /* Separator */
    for (int i = 0; i < g_tui.term_cols; i++) putchar('-');
    putchar('\n');

    /* Main content area */
    int content_lines = g_tui.term_rows - 5;  /* header + separator + status + help */

    if (!g_tui.binary_loaded) {
        printf("\n  No binary loaded.\n");
        printf("  Usage: e9studio <binary.elf>\n\n");
        printf("  Or press 'o' to open a file.\n");
    } else {
        /* Get content based on view mode */
        switch (g_tui.view_mode) {
            case VIEW_DISASM:
                e9studio_get_disassembly(g_tui.view_addr, content_lines,
                                         g_view_buffer, VIEW_BUF_SIZE);
                break;

            case VIEW_DECOMPILE:
                e9studio_get_decompiled(NULL, g_view_buffer, VIEW_BUF_SIZE);
                break;

            case VIEW_HEX:
                e9studio_get_hex_view(g_tui.view_addr, content_lines,
                                      g_view_buffer, VIEW_BUF_SIZE);
                break;

            case VIEW_INFO:
                /* Redirect stdout to capture print_info */
                snprintf(g_view_buffer, VIEW_BUF_SIZE,
                    "Binary Information\n"
                    "------------------\n"
                    "Use 'i' for full info (prints to terminal)\n");
                break;

            default:
                g_view_buffer[0] = '\0';
                break;
        }

        /* Print content with line limit */
        char *line = g_view_buffer;
        int lines_printed = 0;

        while (*line && lines_printed < content_lines) {
            char *next = strchr(line, '\n');
            if (next) {
                *next = '\0';
                printf("%s\n", line);
                line = next + 1;
            } else {
                printf("%s\n", line);
                break;
            }
            lines_printed++;
        }

        /* Fill remaining lines */
        while (lines_printed < content_lines) {
            printf("~\n");
            lines_printed++;
        }
    }

    /* Separator */
    for (int i = 0; i < g_tui.term_cols; i++) putchar('-');
    putchar('\n');

    /* Status bar */
    printf(ANSI_REVERSE);
    if (g_tui.status_msg[0] && (time(NULL) - g_tui.status_time) < 5) {
        printf(" %s", g_tui.status_msg);
    } else {
        printf(" Ready");
    }
    /* Pad status bar */
    int status_len = strlen(g_tui.status_msg) + 2;
    for (int i = status_len; i < g_tui.term_cols; i++) putchar(' ');
    printf(ANSI_RESET "\n");

    /* Help line */
    printf(ANSI_DIM);
    printf(" TAB:view  j/k:scroll  n/p:func  g:goto  d:decompile  l:live  s:save  q:quit");
    printf(ANSI_RESET);

    fflush(stdout);
    g_tui.needs_redraw = false;
}

/*
 * Handle TUI input
 */
static void handle_input(void) {
    char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return;

    switch (c) {
        case 'q':
        case 'Q':
            g_running = false;
            break;

        case '\t':  /* Tab - cycle view */
        case 'v':
        case 'V':
            g_tui.view_mode = (g_tui.view_mode + 1) % VIEW_MAX;
            set_status("View: %s", view_mode_names[g_tui.view_mode]);
            break;

        case 'j':   /* Scroll down / next line */
        case 'J':
            g_tui.view_addr += 16;
            g_tui.needs_redraw = true;
            break;

        case 'k':   /* Scroll up / previous line */
        case 'K':
            if (g_tui.view_addr >= 16) {
                g_tui.view_addr -= 16;
            }
            g_tui.needs_redraw = true;
            break;

        case 'n':   /* Next function */
        case 'N':
            if (g_tui.binary_loaded) {
                if (e9studio_next_function() == 0) {
                    set_status("Next function");
                } else {
                    set_status("No more functions");
                }
            }
            break;

        case 'p':   /* Previous function */
        case 'P':
            if (g_tui.binary_loaded) {
                if (e9studio_prev_function() == 0) {
                    set_status("Previous function");
                } else {
                    set_status("No previous function");
                }
            }
            break;

        case 'g':   /* Go to address */
        case 'G':
            if (g_tui.binary_loaded) {
                /* Simple address input - read hex */
                printf("\n" ANSI_BOLD "Go to address: 0x" ANSI_RESET);
                fflush(stdout);

                disable_raw_mode();
                char addr_buf[32];
                if (fgets(addr_buf, sizeof(addr_buf), stdin)) {
                    uint64_t addr = strtoull(addr_buf, NULL, 16);
                    e9studio_goto_address(addr);
                    g_tui.view_addr = addr;
                    set_status("Jumped to 0x%lx", addr);
                }
                enable_raw_mode();
            }
            break;

        case 'f':   /* Find function */
        case 'F':
            if (g_tui.binary_loaded) {
                printf("\n" ANSI_BOLD "Function name: " ANSI_RESET);
                fflush(stdout);

                disable_raw_mode();
                char name_buf[128];
                if (fgets(name_buf, sizeof(name_buf), stdin)) {
                    /* Remove newline */
                    name_buf[strcspn(name_buf, "\n")] = '\0';
                    if (e9studio_goto_function(name_buf) == 0) {
                        set_status("Found function: %s", name_buf);
                    } else {
                        set_status("Function not found: %s", name_buf);
                    }
                }
                enable_raw_mode();
            }
            break;

        case 'd':   /* Decompile current function */
        case 'D':
            if (g_tui.binary_loaded) {
                g_tui.view_mode = VIEW_DECOMPILE;
                set_status("Decompiling...");
            }
            break;

        case 'x':   /* Show cross-references */
        case 'X':
            if (g_tui.binary_loaded) {
                uint64_t xrefs[16];
                int count = e9studio_find_xrefs_to(g_tui.view_addr, xrefs, 16);
                if (count > 0) {
                    set_status("Found %d xrefs to 0x%lx", count, g_tui.view_addr);
                    /* Could show a list, for now just report count */
                } else {
                    set_status("No xrefs to 0x%lx", g_tui.view_addr);
                }
            }
            break;

        case 'i':   /* Show info */
        case 'I':
            if (g_tui.binary_loaded) {
                printf(ANSI_CLEAR ANSI_HOME);
                e9studio_print_info();
                printf("\nPress any key to continue...");
                fflush(stdout);
                read(STDIN_FILENO, &c, 1);
                g_tui.needs_redraw = true;
            }
            break;

        case 's':   /* Save patched binary */
        case 'S':
            if (g_tui.binary_loaded) {
                char outpath[256];
                snprintf(outpath, sizeof(outpath), "%s.patched",
                         g_config.target_path ? g_config.target_path : "output.elf");

                if (e9studio_save_patched_binary(outpath) == 0) {
                    set_status("Saved to: %s", outpath);
                } else {
                    set_status("Save failed");
                }
            }
            break;

        case 'a':   /* Apply pending patches */
        case 'A':
            if (g_tui.binary_loaded) {
                int applied = e9studio_apply_pending_patches();
                if (applied > 0) {
                    set_status("Applied %d patches", applied);
                } else if (applied == 0) {
                    set_status("No patches to apply");
                } else {
                    set_status("Patch application failed");
                }
            }
            break;

        case 'r':   /* Reload binary */
        case 'R':
            if (g_config.target_path) {
                set_status("Reloading...");
                if (load_target() == 0) {
                    set_status("Reloaded: %s", g_config.target_path);
                }
            }
            break;

        case 'e':   /* Export CFG as DOT */
        case 'E':
            if (g_tui.binary_loaded) {
                if (e9studio_export_cfg(NULL, "cfg.dot") == 0) {
                    set_status("Exported CFG to cfg.dot");
                } else {
                    set_status("CFG export failed");
                }
            }
            break;

        case 'l':   /* Show live reload stats */
        case 'L':
            if (g_livereload_initialized) {
                E9LiveReloadStats stats;
                e9_livereload_get_stats(&stats);

                printf(ANSI_CLEAR ANSI_HOME);
                printf(ANSI_BOLD "Live Reload Statistics" ANSI_RESET "\n");
                printf("────────────────────────────────────────\n");
                printf("  Changes detected:     %lu\n", (unsigned long)stats.changes_detected);
                printf("  Patches generated:    %lu\n", (unsigned long)stats.patches_generated);
                printf("  Patches applied:      %lu\n", (unsigned long)stats.patches_applied);
                printf("  Patches failed:       %lu\n", (unsigned long)stats.patches_failed);
                printf("  Patches reverted:     %lu\n", (unsigned long)stats.patches_reverted);
                printf("  Total bytes patched:  %lu\n", (unsigned long)stats.total_bytes_patched);
                printf("  Pending patches:      %zu\n", e9_livereload_pending_count());
                printf("  Applied patches:      %zu\n", e9_livereload_applied_count());
                printf("────────────────────────────────────────\n");
                printf("  Compiler available:   %s\n",
                       e9_livereload_compiler_available() ? "yes" : "no");
                if (e9_livereload_compiler_available()) {
                    printf("  Compiler version:     %s\n",
                           e9_livereload_compiler_version());
                }
                printf("\nPress any key to continue...");
                fflush(stdout);
                read(STDIN_FILENO, &c, 1);
                g_tui.needs_redraw = true;
            } else {
                set_status("Live reload not active");
            }
            break;

        case '?':   /* Help */
            print_usage("e9studio");
            printf("\nPress any key to continue...");
            fflush(stdout);
            read(STDIN_FILENO, &c, 1);
            g_tui.needs_redraw = true;
            break;

        default:
            /* Arrow keys come as escape sequences */
            if (c == '\033') {
                char seq[2];
                if (read(STDIN_FILENO, &seq[0], 1) == 1 &&
                    read(STDIN_FILENO, &seq[1], 1) == 1) {
                    if (seq[0] == '[') {
                        switch (seq[1]) {
                            case 'A': /* Up */
                                if (g_tui.view_addr >= 16) {
                                    g_tui.view_addr -= 16;
                                    g_tui.needs_redraw = true;
                                }
                                break;
                            case 'B': /* Down */
                                g_tui.view_addr += 16;
                                g_tui.needs_redraw = true;
                                break;
                        }
                    }
                }
            }
            break;
    }
}

/*
 * Run self-tests
 */
static int run_self_tests(void) {
    printf("Running e9studio self-tests...\n\n");

    int passed = 0, failed = 0;

    #define TEST(name, cond) do { \
        printf("  %-40s ", name); \
        if (cond) { printf("[PASS]\n"); passed++; } \
        else { printf("[FAIL]\n"); failed++; } \
    } while(0)

    #define WARN(name, cond) do { \
        printf("  %-40s ", name); \
        if (cond) { printf("[PASS]\n"); passed++; } \
        else { printf("[WARN]\n"); } \
    } while(0)

    /* Test analysis initialization */
    TEST("Analysis engine initialization", e9studio_analysis_init() == 0);

    /* Test WASM runtime (optional) */
    E9WasmConfig config = {
        .stack_size = 64 * 1024,
        .heap_size = 16 * 1024 * 1024,
        .shared_buffer_size = 64 * 1024 * 1024,
        .enable_wasi = true,
        .enable_debug = true,
    };
    WARN("WASM runtime initialization", e9wasm_init(&config) == 0);

    /* Test shared buffer */
    size_t buf_size;
    uint8_t *buf = e9wasm_get_shared_buffer(&buf_size);
    TEST("Shared buffer allocation", buf != NULL && buf_size > 0);

    /* Test ZipOS access (optional) */
    int zipos_ok = e9wasm_zipos_available();
    WARN("Embedded ZipOS available", zipos_ok);

    if (zipos_ok) {
        size_t size;
        uint8_t *data = e9wasm_zipos_read(".cosmo/VERSION", &size);
        TEST("ZipOS file read", data != NULL && size > 0);
        if (data) free(data);
    } else {
        TEST("ZipOS file read (skipped)", true);
    }

    /* Test mmap */
    void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST("Anonymous mmap", mem != MAP_FAILED);
    if (mem != MAP_FAILED) munmap(mem, 4096);

    /* Test executable path */
    const char *exe = e9wasm_get_exe_path();
    TEST("Executable path detection", exe != NULL && strlen(exe) > 0);

    /* Test live reload initialization */
    E9LiveReloadConfig lr_config = E9_LIVERELOAD_CONFIG_DEFAULT;
    lr_config.source_dir = ".";
    lr_config.verbose = true;

    /* Live reload init on self (optional - may fail if not APE) */
    int lr_init = e9_livereload_init(NULL, &lr_config);
    WARN("Live reload initialization", lr_init == 0);

    if (lr_init == 0) {
        TEST("Live reload ready", e9_livereload_is_ready());
        WARN("Compiler available", e9_livereload_compiler_available());

        /* Get initial stats */
        E9LiveReloadStats stats;
        e9_livereload_get_stats(&stats);
        TEST("Live reload stats", stats.changes_detected == 0);

        e9_livereload_shutdown();
    }

    /* Cleanup */
    e9studio_analysis_shutdown();
    e9wasm_shutdown();

    printf("\n  Results: %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}

/*
 * Main entry point
 */
int main(int argc, char **argv) {
    /* Parse arguments */
    if (parse_args(argc, argv) < 0) {
        print_usage(argv[0]);
        return 1;
    }

    /* Run self-tests if requested */
    if (g_config.self_test) {
        return run_self_tests();
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize analysis engine */
    if (e9studio_analysis_init() < 0) {
        fprintf(stderr, "Failed to initialize analysis engine\n");
        return 1;
    }

    /* Initialize WASM runtime (optional) */
    init_wasm();

    /* Load target binary if specified */
    if (g_config.target_path || access("/zip/target.elf", F_OK) == 0) {
        load_target();
    }

    /* Initialize file watcher */
    if (g_config.source_dir) {
        init_file_watcher();
    }

    /* Run TUI or daemon mode */
    if (g_config.tui_mode) {
        enable_raw_mode();
        render_tui();

        /* Main loop */
        while (g_running) {
            /* Check for file changes */
            check_file_changes();

            /* Handle input */
            handle_input();

            /* Redraw if needed */
            if (g_tui.needs_redraw) {
                render_tui();
            }

            /* Small sleep to avoid busy-waiting */
            usleep(10000);  /* 10ms */
        }

        disable_raw_mode();
        printf(ANSI_CLEAR ANSI_HOME);
    } else if (g_config.daemon_mode) {
        fprintf(stderr, "Running in daemon mode on port %d...\n", g_config.port);
        while (g_running) {
            check_file_changes();
            usleep(100000);  /* 100ms */
        }
    } else {
        /* Non-interactive mode - just analyze and print info */
        if (g_tui.binary_loaded) {
            e9studio_print_info();
        }
    }

    /* Cleanup */
    cleanup_file_watcher();
    e9studio_analysis_shutdown();
    e9wasm_shutdown();

    return 0;
}
