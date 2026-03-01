# e9studio Architecture

> **LLM Reference Document** - Binary patching architecture for APE polyglots.
>
> Part of cosmo-bde. See also: `../docs/ARCHITECTURE.md`

---

## 1. System Overview

e9studio provides live reload (hot-patching) for APE (Actually Portable Executable) binaries.
It enables real-time C source code changes to appear in running applications without restart.

```
+===========================================================================+
|                              e9studio                                      |
|              Live Reload / Hot-Patching for APE Binaries                   |
+===========================================================================+

   WORKFLOW:
   +--------+     +---------+     +----------+     +-------+     +-------+
   | File   |---->| cosmocc |---->| Binaryen |---->| APE   |---->|ICache |
   | Watch  |     | Compile |     | Diff     |     | Patch |     | Flush |
   +--------+     +---------+     +----------+     +-------+     +-------+
   inotify/       .c -> .o        old.o vs        PE RVA      clear_cache
   stat()                         new.o           -> offset

   RESULT: Edit C source -> See changes in running app in ~200-500ms

+===========================================================================+
```

---

## 2. Component Architecture

```
+===========================================================================+
|                         e9studio COMPONENTS                                |
+===========================================================================+

  +-----------------------------------------------------------------------+
  |                         PUBLIC API LAYER                               |
  +-----------------------------------------------------------------------+
  |                                                                        |
  |   e9livereload.h                                                       |
  |   +-----------------------------------------------------------------+  |
  |   | Lifecycle:          | Watch Control:      | Manual Operations:  |  |
  |   | - init()            | - watch()           | - reload_file()     |  |
  |   | - shutdown()        | - unwatch()         | - apply_patch()     |  |
  |   | - is_ready()        | - poll()            | - revert_patch()    |  |
  |   |                     | - set_callback()    | - flush_icache()    |  |
  |   +-----------------------------------------------------------------+  |
  |                                                                        |
  |   e9ape.h                           e9procmem.h                        |
  |   +-----------------------------+   +-----------------------------+    |
  |   | - parse()                   |   | - open() / close()          |    |
  |   | - rva_to_offset()           |   | - read() / write()          |    |
  |   | - patch_offset()            |   | - flush_icache()            |    |
  |   | - get_section()             |   | - get_platform()            |    |
  |   | - dump_info()               |   | - error()                   |    |
  |   | - get_self_path()           |   |                             |    |
  |   +-----------------------------+   +-----------------------------+    |
  |                                                                        |
  +-----------------------------------------------------------------------+
                                    |
                                    v
  +-----------------------------------------------------------------------+
  |                       INTERNAL COMPONENTS                              |
  +-----------------------------------------------------------------------+
  |                                                                        |
  |   +------------------+    +------------------+    +------------------+ |
  |   |   e9ape.c        |    |  e9binaryen.c    |    |  e9wasm_host.c   | |
  |   |                  |    |                  |    |                  | |
  |   |  PE PARSER       |    |  OBJECT DIFFER   |    |  WASM RUNTIME    | |
  |   |                  |    |                  |    |                  | |
  |   |  +-- DOS Header  |    |  +-- Load .o     |    |  +-- wasm3/WAMR  | |
  |   |  +-- PE Header   |    |  +-- Symbol diff |    |  +-- Host funcs  | |
  |   |  +-- Sections    |    |  +-- Byte diff   |    |  +-- Memory map  | |
  |   |  +-- RVA xlate   |    |  +-- Gen patches |    |  +-- ICache      | |
  |   +------------------+    +------------------+    +------------------+ |
  |                                                                        |
  +-----------------------------------------------------------------------+
                                    |
                                    v
  +-----------------------------------------------------------------------+
  |                     X-MACRO DEFINITIONS                                |
  +-----------------------------------------------------------------------+
  |                                                                        |
  |   e9procmem.h (single source of truth for constants)                   |
  |                                                                        |
  |   #define PROCMEM_OS_XMACRO(X) \                                       |
  |       X(PROCMEM_OS_UNKNOWN, 0, "unknown") \                            |
  |       X(PROCMEM_OS_LINUX,   1, "linux")   \                            |
  |       X(PROCMEM_OS_WINDOWS, 2, "windows") \                            |
  |       X(PROCMEM_OS_MACOS,   3, "macos")   \                            |
  |       X(PROCMEM_OS_BSD,     4, "bsd")                                  |
  |                                                                        |
  |   #define PROCMEM_STATUS_XMACRO(X) \                                   |
  |       X(PROCMEM_OK,         0, "success")         \                    |
  |       X(PROCMEM_ERR_OPEN,  -1, "open failed")     \                    |
  |       X(PROCMEM_ERR_READ,  -2, "read failed")     \                    |
  |       X(PROCMEM_ERR_WRITE, -3, "write failed")    \                    |
  |       X(PROCMEM_ERR_PERM,  -4, "permission denied")                    |
  |                                                                        |
  +-----------------------------------------------------------------------+
```

---

## 3. APE Patching Flow

```
+===========================================================================+
|                         APE PATCHING FLOW                                  |
+===========================================================================+

   STEP 1: FILE CHANGE DETECTION
   +--------------------------------------------------------------------+
   |                                                                     |
   |   Linux:   inotify_add_watch(fd, path, IN_MODIFY | IN_CLOSE_WRITE) |
   |   macOS:   kqueue + EVFILT_VNODE                                   |
   |   Windows: ReadDirectoryChangesW()                                  |
   |   Fallback: stat() polling every 100ms                             |
   |                                                                     |
   +--------------------------------------------------------------------+
                                    |
                                    v
   STEP 2: COMPILATION
   +--------------------------------------------------------------------+
   |                                                                     |
   |   cosmocc -c -O2 -g -ffunction-sections src/app.c -o .e9cache/app.o|
   |                                                                     |
   |   -ffunction-sections: Each function in separate section           |
   |                        (enables per-function patching)             |
   |                                                                     |
   +--------------------------------------------------------------------+
                                    |
                                    v
   STEP 3: OBJECT DIFFING (Binaryen)
   +--------------------------------------------------------------------+
   |                                                                     |
   |   e9_binaryen_diff_objects(old.o, new.o, &patches, &count)         |
   |                                                                     |
   |   For each function:                                               |
   |     - Compare symbol addresses                                      |
   |     - Compare instruction bytes                                     |
   |     - Generate patch if different                                   |
   |                                                                     |
   |   Output: Array of (function_name, rva, old_bytes, new_bytes)      |
   |                                                                     |
   +--------------------------------------------------------------------+
                                    |
                                    v
   STEP 4: ADDRESS TRANSLATION
   +--------------------------------------------------------------------+
   |                                                                     |
   |   e9_ape_rva_to_offset(&ape_info, rva) -> file_offset              |
   |                                                                     |
   |   PE Section Table Lookup:                                          |
   |   +-- .text  VA=0x1000 Raw=0x400  Size=0x5000                      |
   |   +-- .data  VA=0x6000 Raw=0x5400 Size=0x1000                      |
   |                                                                     |
   |   Example: RVA 0x2500 (in .text)                                   |
   |     -> offset_in_section = 0x2500 - 0x1000 = 0x1500                |
   |     -> file_offset = 0x400 + 0x1500 = 0x1900                       |
   |                                                                     |
   +--------------------------------------------------------------------+
                                    |
                                    v
   STEP 5: MEMORY PATCHING
   +--------------------------------------------------------------------+
   |                                                                     |
   |   Linux:   process_vm_writev(pid, local_iov, remote_iov)           |
   |   Windows: WriteProcessMemory(hProcess, addr, buf, size)           |
   |   macOS:   vm_write(task, addr, data, size)                        |
   |                                                                     |
   |   NO PTRACE NEEDED on Linux! process_vm_writev works without       |
   |   stopping the target process (if same user or CAP_SYS_PTRACE).    |
   |                                                                     |
   +--------------------------------------------------------------------+
                                    |
                                    v
   STEP 6: ICACHE FLUSH
   +--------------------------------------------------------------------+
   |                                                                     |
   |   __builtin___clear_cache(addr, addr + size)  [GCC/Clang]          |
   |   FlushInstructionCache(hProcess, addr, size) [Windows]            |
   |                                                                     |
   |   Required because CPU may have cached old instructions.           |
   |   On x86-64 this is usually a no-op but needed for correctness.    |
   |                                                                     |
   +--------------------------------------------------------------------+
                                    |
                                    v
   STEP 7: CONTINUE EXECUTION
   +--------------------------------------------------------------------+
   |                                                                     |
   |   Target process continues with new code.                           |
   |   No restart, no reload, no state loss.                             |
   |                                                                     |
   |   Total latency: ~200-500ms (dominated by compilation)             |
   |                                                                     |
   +--------------------------------------------------------------------+
```

---

## 4. State Machine: Live Reload Session

```
+===========================================================================+
|                    LIVE RELOAD STATE MACHINE                               |
+===========================================================================+

                         +-------------+
                         |             |
                         |    INIT     |
                         |             |
                         +------+------+
                                |
                    e9_livereload_init()
                                |
                                v
                         +-------------+
          +------------->|             |<-------------+
          |              |    IDLE     |              |
          |              |             |              |
          |              +------+------+              |
          |                     |                     |
          |         e9_livereload_watch()             |
          |                     |                     |
          |                     v                     |
          |              +-------------+              |
          |              |             |              |
          |              |  WATCHING   |<---------+   |
          |              |             |          |   |
          |              +------+------+          |   |
          |                     |                 |   |
          |              file change              |   |
          |                     |                 |   |
          |                     v                 |   |
          |              +-------------+          |   |
          |              |             |          |   |
          |              | COMPILING   |          |   |
          |              |             |          |   |
          |              +------+------+          |   |
          |                     |                 |   |
          |               success/fail            |   |
          |                     |                 |   |
          |          +----------+----------+      |   |
          |          |                     |      |   |
          |          v                     v      |   |
          |   +-------------+       +-------------+   |
          |   |             |       |             |   |
          |   |  DIFFING    |       | COMP_ERROR  |---+
          |   |             |       |             |
          |   +------+------+       +-------------+
          |          |
          |     patches found
          |          |
          |          v
          |   +-------------+
          |   |             |
          |   |  PATCHING   |
          |   |             |
          |   +------+------+
          |          |
          |    success/fail
          |          |
          |   +------+------+
          |   |             |
          |   v             v
          |  +-------------+  +-------------+
          |  |             |  |             |
          |  |  PATCHED    |  | PATCH_ERROR |
          |  |             |  |             |
          |  +------+------+  +------+------+
          |         |                |
          |         +--------+-------+
          |                  |
          +------------------+
               (continue watching)

   EVENTS:
   +-------------------+----------------------------------------+
   | Event             | Callback Type                          |
   +-------------------+----------------------------------------+
   | E9_LR_EVENT_FILE_CHANGE    | File modified                 |
   | E9_LR_EVENT_COMPILE_START  | Compilation starting          |
   | E9_LR_EVENT_COMPILE_DONE   | Compilation succeeded         |
   | E9_LR_EVENT_COMPILE_ERROR  | Compilation failed            |
   | E9_LR_EVENT_PATCH_GENERATED| Diff found changes            |
   | E9_LR_EVENT_PATCH_APPLIED  | Patch written to memory       |
   | E9_LR_EVENT_PATCH_FAILED   | Patch application failed      |
   | E9_LR_EVENT_PATCH_REVERTED | Patch was reverted            |
   +-------------------+----------------------------------------+
```

---

## 5. Patch Lifecycle

```
+===========================================================================+
|                         PATCH LIFECYCLE                                    |
+===========================================================================+

   +-------------+
   |             |
   |   PENDING   |  <- Patch generated, not yet applied
   |             |
   +------+------+
          |
          | apply_patch_internal()
          |
   +------v------+
   |             |
   |   APPLIED   |  <- Patch written to process memory
   |             |
   +------+------+
          |
          | revert_patch()
          |
   +------v------+
   |             |
   |  REVERTED   |  <- Original bytes restored
   |             |
   +-------------+

          OR

   +------+------+
   |             |
   |   PENDING   |
   |             |
   +------+------+
          |
          | apply fails
          |
   +------v------+
   |             |
   |   FAILED    |  <- Error recorded in patch->error_msg
   |             |
   +-------------+

   PATCH DATA STRUCTURE:
   +------------------------------------------------------------------+
   |  InternalPatch                                                    |
   |  +--------------------+----------------------------------------+ |
   |  | id                 | uint32_t - unique patch identifier     | |
   |  | source_file        | char[256] - originating source path    | |
   |  | function_name      | char[128] - function being patched     | |
   |  | target_type        | E9_PATCH_TARGET_PE_RVA / FILE_OFFSET   | |
   |  | target_address     | uint64_t - RVA or VA                   | |
   |  | file_offset        | off_t - resolved file offset           | |
   |  | old_bytes          | uint8_t* - original instruction bytes  | |
   |  | old_size           | size_t                                 | |
   |  | new_bytes          | uint8_t* - replacement instruction     | |
   |  | new_size           | size_t                                 | |
   |  | status             | E9_PATCH_STATUS_*                      | |
   |  | error_msg          | char[256]                              | |
   |  | timestamp          | uint64_t - when patch was created      | |
   |  +--------------------+----------------------------------------+ |
   +------------------------------------------------------------------+
```

---

## 6. File Organization

```
upstream/e9studio/
+-- src/
|   +-- e9patch/
|   |   +-- e9livereload.h    <- Public API: watch, patch, revert
|   |   +-- e9livereload.c    <- Full implementation with Binaryen
|   |   +-- e9ape.h           <- APE parsing and PE section handling
|   |   +-- e9ape.c
|   |   +-- e9procmem.h       <- Cross-platform memory access (X-macros)
|   |   +-- wasm/
|   |       +-- e9binaryen.h  <- Binaryen integration for object diff
|   |       +-- e9binaryen.c
|   |       +-- e9wasm_host.h <- WASM runtime host functions
|   |       +-- e9wasm_host.c
|   |
|   +-- e9studio/             <- GUI components (future)
|       +-- gui/
|
+-- test/
|   +-- livereload/
|       +-- livereload.c      <- Standalone test tool (simpler impl)
|       +-- target.c          <- Test target program
|       +-- Makefile
|
+-- specs/
|   +-- e9livereload.schema   <- Type definitions for schemagen
|   +-- e9ape.schema
|   +-- features/
|       +-- e9livereload.feature  <- BDD scenarios
|       +-- ape_detection.feature
|       +-- ape_patching.feature
|
+-- gen/
|   +-- domain/
|       +-- e9livereload_types.h  <- Generated from schema
|       +-- e9livereload_types.c
|       +-- e9ape_types.h
|       +-- e9ape_types.c
|
+-- doc/
|   +-- ape-anatomy-analysis.md   <- Detailed APE RE notes
|   +-- e9patch-programming-guide.md
|   +-- cosmopolitan-port.md
|
+-- .claude/
    +-- CLAUDE.md             <- LLM context (symlink to AGENTS.md)
```

---

## 7. Integration with cosmo-bde

e9studio is integrated as a submodule in cosmo-bde and follows the same patterns:

```
cosmo-bde (mbse-stacks)
+-- upstream/
|   +-- e9studio/              <- This repository as submodule
|
+-- specs/
|   +-- domain/
|       +-- livereload.schema  <- Shared type definitions
|       +-- e9livereload.schema
|
+-- gen/
|   +-- domain/
|       +-- livereload_types.h <- Generated, used by both
|
+-- Makefile
    e9studio:
        $(MAKE) -C upstream/e9studio
```

### Build Integration

```bash
# From cosmo-bde root:
make tools          # Build schemagen, etc.
make regen          # Regenerate including e9studio types
make e9studio       # Build livereload tool

# Result:
build/livereload    # APE binary, runs everywhere
```

### CI Integration

See `.github/workflows/repo-ci.yml`:
- `e9studio` job builds and tests livereload
- Integration test attaches to running process
- Verifies patch application works

---

## 8. Future: IR-Based Patching

Current workflow compiles to object code then diffs bytes. A lower-latency approach
would use intermediate representation (IR) diffing:

```
CURRENT:
  .c -> cosmocc -> .o (full compile) -> byte diff -> patch
  Latency: ~200-500ms (dominated by full compilation)

FUTURE (IR-based):
  .c -> parse -> IR (AST/SSA) -> IR diff -> codegen only changed -> patch
  Latency: ~50-100ms (skip redundant compilation)

OPTIONS:
  1. Ring 0 AST: Lemon + lexgen for C parsing, AST-level diff (RECOMMENDED)
  2. LLVM IR: Use clang -emit-llvm, diff at IR level
  3. Binaryen IR: ludoplex/binaryen WASM diffing (.com + .wasm)
  4. Incremental: ccache + -ffunction-sections, compile only changed

NOTE: TinyCC is NOT compatible with Cosmopolitan (relocation errors)

BINARYEN ADVANTAGE:
  Already integrated for object diffing. Could extend to:
  .c -> clang -> WASM -> Binaryen optimize -> diff -> native codegen
```

---

## 9. Quick Reference

### API Usage

```c
#include "e9livereload.h"

// Initialize for self-patching
E9LiveReloadConfig config = E9_LIVERELOAD_CONFIG_DEFAULT;
config.source_dir = "src";
config.verbose = true;

if (e9_livereload_init(NULL, &config) != 0) {
    fprintf(stderr, "Init failed: %s\n", e9_livereload_get_error());
    return 1;
}

// Set callback for events
e9_livereload_set_callback(my_callback, NULL);

// Start watching
e9_livereload_watch();

// Main loop
while (running) {
    e9_livereload_poll();
    // ... application logic ...
    usleep(10000);  // 10ms
}

// Cleanup
e9_livereload_shutdown();
```

### Command Line

```bash
# Build
make -C upstream/e9studio

# Run target in background
./build/app &
APP_PID=$!

# Attach live reload
sudo ./build/livereload $APP_PID src/main.c

# Edit source - changes appear in running app!
vim src/main.c

# Stop
kill $APP_PID
```

---

*Generated for LLM reference. Part of cosmo-bde.*
