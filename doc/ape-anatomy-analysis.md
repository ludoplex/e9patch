# APE (Actually Portable Executable) Anatomy Analysis

## Executive Summary

Cosmopolitan's .com files are APE (Actually Portable Executables) - polyglot binaries that
are simultaneously valid as:
- DOS/Windows PE executables
- Unix shell scripts
- ELF binaries (Linux/BSD/etc.)
- Mach-O binaries (macOS)
- ZIP archives (ZipOS filesystem)

This document analyzes how these features can be leveraged for self-contained dynamic
binary rewriting without requiring a browser.

---

## 1. APE File Structure (Byte-Level Anatomy)

```
┌────────────────────────────────────────────────────────────────────┐
│ Offset 0x00-0x01: MZ Header (0x4D 0x5A)                            │
│   - Required for Windows PE recognition                            │
│   - Also begins valid shell script: "MZ" is harmless in shell      │
├────────────────────────────────────────────────────────────────────┤
│ Offset 0x02-0x3B: DOS Stub + Shell Script Polyglot                 │
│   - Contains: #!/bin/sh or similar                                 │
│   - Encoded to be valid DOS stub AND shell script                  │
│   - Shell interprets this; DOS/Windows skip to PE header           │
├────────────────────────────────────────────────────────────────────┤
│ Offset 0x3C-0x3F: PE Header Offset (e_lfanew)                      │
│   - Points to PE signature for Windows loader                      │
├────────────────────────────────────────────────────────────────────┤
│ Offset 0x40-0x7F: Extended Shell Script                            │
│   - More shell commands                                            │
│   - Typically: exec or dd commands to extract/run                  │
├────────────────────────────────────────────────────────────────────┤
│ Offset 0x80+: PE Header (if Windows)                               │
│   - PE\0\0 signature                                               │
│   - COFF header                                                    │
│   - Optional header (PE32+)                                        │
│   - Section headers                                                │
├────────────────────────────────────────────────────────────────────┤
│ ELF Header (embedded in shell script region)                       │
│   - 0x7F ELF magic                                                 │
│   - Placed where shell treats it as comment/string                 │
│   - Program headers point to actual code sections                  │
├────────────────────────────────────────────────────────────────────┤
│ Mach-O Header (for macOS)                                          │
│   - 0xFEEDFACF magic (64-bit)                                      │
│   - Load commands                                                  │
│   - Segment definitions                                            │
├────────────────────────────────────────────────────────────────────┤
│ .text Section                                                      │
│   - Actual x86-64 machine code                                     │
│   - Position-independent (PIC)                                     │
│   - Cosmopolitan runtime startup code                              │
├────────────────────────────────────────────────────────────────────┤
│ .data / .rodata / .bss Sections                                    │
│   - Initialized and uninitialized data                             │
│   - String constants, global variables                             │
├────────────────────────────────────────────────────────────────────┤
│ ZIP Central Directory Entries                                      │  ← ZipOS
│   - File metadata (names, sizes, offsets)                          │
│   - CRC checksums                                                  │
│   - Compression method (usually STORE for mmap)                    │
├────────────────────────────────────────────────────────────────────┤
│ ZIP Local File Headers + Data                                      │  ← ZipOS
│   - Actual embedded files                                          │
│   - Can include: assets, libraries, models (llamafile)             │
│   - Memory-mappable when uncompressed                              │
├────────────────────────────────────────────────────────────────────┤
│ ZIP End of Central Directory (EOCD)                                │  ← ZipOS
│   - Points back to central directory                               │
│   - This is what makes the whole file a valid ZIP                  │
└────────────────────────────────────────────────────────────────────┘
```

## 2. The Shell Script Bootstrap (How Unix Execution Works)

When you run `./program.com` on Unix:

```bash
# The first ~60 bytes decode to something like:
MZqFpD='
temporary storage for APE binary
'
exec 7<> "$0"                    # Open self as fd 7
exec 6<&0                        # Save stdin
exec 5<&1                        # Save stdout
# ... determine OS, extract appropriate header ...
dd bs=1 skip=$OFFSET count=$SIZE <&7 2>/dev/null | /lib64/ld-linux-x86-64.so.2 /dev/stdin "$@"
```

The key techniques:
1. **Self-reading**: The script opens itself (`$0`) to read binary sections
2. **memfd_create**: On Linux, creates anonymous file in memory
3. **Header patching**: Writes correct ELF/Mach-O header to temp file
4. **Exec chain**: Replaces itself with the native binary

## 3. ZipOS: The Virtual Filesystem

### How ZipOS Works

```c
// In Cosmopolitan libc:
// When you open("/zip/myfile.txt", O_RDONLY):

1. Cosmopolitan intercepts the open() call
2. Checks if path starts with "/zip/"
3. Locates the ZIP central directory (from EOCD at EOF)
4. Binary searches for the file entry
5. Returns a special fd that:
   - For STORE'd files: mmap's directly from executable
   - For DEFLATE'd files: decompresses on read

// Memory mapping (zero-copy for uncompressed):
void *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, exe_fd, zip_offset);
```

### ZipOS in llamafile

```
llamafile.com (4.2 GB example)
├── [0x000000 - 0x100000]  APE headers + bootstrap (~1MB)
├── [0x100000 - 0x200000]  Executable code (~1MB)
├── [0x200000 - 0x300000]  Cosmopolitan runtime (~1MB)
└── [0x300000 - 0xFFFFFFFF] ZIP containing:
    └── weights.gguf (4GB, STORED uncompressed)
        ↓
        Accessed via: open("/zip/weights.gguf")
        Memory-mapped directly from offset 0x300000
        No copy, no extraction, just mmap()
```

### Key ZipOS Characteristics

| Feature | Behavior | Implication for e9patch |
|---------|----------|------------------------|
| **STORE compression** | Zero-copy mmap | Target binaries can be mmap'd directly |
| **DEFLATE compression** | Streamed decompression | Source files can be compressed |
| **Append-only** | Can add files to running exe | Hot-add patches without restart |
| **Central directory at EOF** | Easy to update | Can modify ZIP without rewriting whole file |

## 4. Memory Management Deep-Dive

### APE Loader Memory Layout (Linux example)

```
Virtual Address Space After APE Bootstrap:
────────────────────────────────────────────────────────────────
0x00000000_00400000  ┌─────────────────────────────────────────┐
                     │ ELF .text (executable code)             │
                     │ - Cosmopolitan startup                  │
                     │ - Main program code                     │
0x00000000_00600000  ├─────────────────────────────────────────┤
                     │ ELF .data (initialized data)            │
                     │ ELF .bss  (zero-initialized)            │
0x00000000_00800000  ├─────────────────────────────────────────┤
                     │ Heap (grows up via sbrk/mmap)           │
                     │                                         │
                     │           ↓ grows down                  │
                     │                                         │
0x00007FFF_FFFFF000  ├─────────────────────────────────────────┤
                     │ Stack                                   │
0x00007FFF_FFFFFFFF  └─────────────────────────────────────────┘

ZipOS mmap regions (placed by Cosmopolitan):
────────────────────────────────────────────────────────────────
0x00000XXX_XXXXXXXX  ┌─────────────────────────────────────────┐
                     │ mmap of /zip/file1 → exe offset 0xNNNN  │
                     ├─────────────────────────────────────────┤
                     │ mmap of /zip/file2 → exe offset 0xMMMM  │
                     └─────────────────────────────────────────┘
```

### llamafile Memory Strategy

```c
// llamafile uses Cosmopolitan's __maps facility:

// 1. Open model from ZipOS
int fd = open("/zip/model.gguf", O_RDONLY);

// 2. Get file size
struct stat st;
fstat(fd, &st);

// 3. Memory-map (this is the magic)
void *model = mmap(NULL, st.st_size,
                   PROT_READ,           // Read-only
                   MAP_PRIVATE,         // Copy-on-write if modified
                   fd, 0);

// What actually happens:
// - Kernel creates page table entries pointing to exe file
// - No physical memory allocated yet
// - First access triggers page fault
// - Kernel reads page from disk into page cache
// - Same physical page shared across processes

// 4. Access model weights
float weight = ((float*)model)[index];  // Page fault → disk read → cache
```

### Copy-on-Write for Hot Patching

```c
// For dynamic patching, we can use MAP_PRIVATE:

void *binary = mmap(NULL, size,
                    PROT_READ | PROT_WRITE,  // Want to modify
                    MAP_PRIVATE,              // Copy-on-write
                    fd, offset);

// Initial state: points to original pages in exe
// After write: kernel copies page, we get private modified copy
// Original exe file: unchanged

binary[0x1234] = 0x90;  // NOP instruction
// → Triggers COW, only this page is copied
// → Original file untouched
// → Other processes see original
```

## 5. Self-Contained WASM VM Architecture

### Replacing Chrome with Embedded wasm3

Instead of using Chrome as the WASM runtime, we can embed wasm3 directly in the APE:

```
┌─────────────────────────────────────────────────────────────────┐
│                    e9patch-studio.com                           │
├─────────────────────────────────────────────────────────────────┤
│ APE Bootstrap (shell script polyglot)                           │
├─────────────────────────────────────────────────────────────────┤
│ Native Code:                                                    │
│   ├── Minimal C runtime (Cosmopolitan)                          │
│   ├── wasm3 interpreter (~200KB)                                │
│   ├── WASI implementation                                       │
│   ├── ZipOS interface                                           │
│   └── Platform abstraction (mmap, signals, etc.)                │
├─────────────────────────────────────────────────────────────────┤
│ /zip/ (ZipOS filesystem):                                       │
│   ├── e9patch-core.wasm      (~500KB)  ← Patching engine        │
│   ├── binaryen.wasm          (~2MB)    ← WASM IR diffing        │
│   ├── ui.wasm                (~300KB)  ← TUI framework          │
│   ├── target.elf             (varies)  ← Binary to patch        │
│   └── src/                             ← Source files           │
│       ├── main.c                                                │
│       └── utils.c                                               │
└─────────────────────────────────────────────────────────────────┘
```

### Memory Architecture with Embedded WASM

```
┌─────────────────────────────────────────────────────────────────┐
│ Native Host Process (APE)                                       │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ wasm3 Runtime                                             │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────────┐ │  │
│  │  │ WASM Linear Memory (e9patch-core.wasm)              │ │  │
│  │  │                                                     │ │  │
│  │  │  0x00000 ┌──────────────────────────────────────┐  │ │  │
│  │  │          │ WASM Stack                           │  │ │  │
│  │  │  0x10000 ├──────────────────────────────────────┤  │ │  │
│  │  │          │ WASM Heap                            │  │ │  │
│  │  │  0x80000 ├──────────────────────────────────────┤  │ │  │
│  │  │          │ Shared Buffer (for binary data)      │←─┼─┼──┼── mmap'd from ZipOS
│  │  │  0xFFFFF └──────────────────────────────────────┘  │ │  │
│  │  └─────────────────────────────────────────────────────┘ │  │
│  │                                                           │  │
│  │  Host Functions (WASI + Custom):                          │  │
│  │    ├── fd_read, fd_write (→ ZipOS)                        │  │
│  │    ├── mmap_binary (→ direct ZipOS mmap)                  │  │
│  │    ├── apply_patch (→ native mprotect + write)            │  │
│  │    └── notify_change (→ trigger recompile)                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Native Services:                                               │
│    ├── File watcher (inotify/kqueue/ReadDirectoryChanges)      │
│    ├── Terminal UI (ncurses or raw ANSI)                       │
│    └── Network (optional: for remote editing)                  │
└─────────────────────────────────────────────────────────────────┘
```

### Advantages Over Chrome

| Aspect | Chrome | Embedded wasm3 |
|--------|--------|----------------|
| **Distribution** | Requires Chrome installed | Single .com file |
| **Startup time** | 2-5 seconds | <100ms |
| **Memory overhead** | ~500MB base | ~5MB |
| **Headless operation** | Complex setup | Native |
| **ZipOS access** | Via JS bridge | Direct mmap |
| **Binary modification** | ArrayBuffer copy | Direct mprotect |
| **Platform support** | Chrome platforms | Anywhere APE runs |

## 6. Dynamic Binary Editing Workflow

### In-Place Patching Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      e9patch-studio.com                         │
│                                                                 │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐   │
│  │ Source Files  │    │   Compiler    │    │   e9patch     │   │
│  │ (/zip/src/)   │───>│   (WASM)      │───>│   (WASM)      │   │
│  └───────────────┘    └───────────────┘    └───────────────┘   │
│         ↑                    │                    │             │
│         │                    │                    ↓             │
│  ┌──────┴──────┐      ┌──────▼──────┐    ┌───────────────┐     │
│  │   Editor    │      │  Relocations │    │ Target Binary │     │
│  │   (TUI)     │      │  + Patches   │    │ (/zip/target) │     │
│  └─────────────┘      └─────────────┘    └───────────────┘     │
│                                                 │               │
│                                                 ↓               │
│                                          ┌───────────────┐     │
│                                          │ Patched View  │     │
│                                          │ (mmap + COW)  │     │
│                                          └───────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

### Edit-Compile-Patch Cycle

```
1. USER EDITS SOURCE
   └─→ /zip/src/main.c modified (or extracted to tmpfs)

2. FILE WATCHER DETECTS CHANGE
   └─→ inotify/kqueue triggers callback

3. COMPILER RUNS (in WASM sandbox)
   ├─→ Parse modified file
   ├─→ Generate object code
   └─→ Produce relocation info

4. E9PATCH ANALYZES (in WASM sandbox)
   ├─→ Compare old vs new object code
   ├─→ Identify changed functions
   ├─→ Calculate trampoline addresses
   └─→ Generate patch instructions

5. NATIVE HOST APPLIES PATCHES
   ├─→ mmap target binary (MAP_PRIVATE for COW)
   ├─→ mprotect to allow writes
   ├─→ Write patch bytes
   ├─→ mprotect to restore exec
   └─→ Flush instruction cache (if needed)

6. VERIFICATION
   ├─→ Disassemble patched region
   ├─→ Run integrity checks
   └─→ Update UI with status
```

## 7. Implementation Strategy

### Phase 1: Native Host Skeleton

```c
// e9host.c - Minimal native host for WASM runtime

#include "cosmopolitan.h"
#include "wasm3.h"

// ZipOS-backed memory for WASM
static struct {
    uint8_t *base;
    size_t size;
    int fd;
} g_binary;

// Host function: map binary from ZipOS into WASM-accessible memory
m3ApiRawFunction(host_mmap_binary) {
    m3ApiGetArg(uint32_t, path_ptr);
    m3ApiGetArg(uint32_t, path_len);

    // Get path string from WASM memory
    char path[256];
    memcpy(path, m3_GetMemory(runtime) + path_ptr, path_len);
    path[path_len] = '\0';

    // Open from ZipOS
    g_binary.fd = open(path, O_RDONLY);
    struct stat st;
    fstat(g_binary.fd, &st);
    g_binary.size = st.st_size;

    // mmap directly (zero-copy from ZipOS)
    g_binary.base = mmap(NULL, g_binary.size,
                         PROT_READ | PROT_WRITE, MAP_PRIVATE,
                         g_binary.fd, 0);

    m3ApiReturn(g_binary.size);
}

// Host function: apply patch to mapped binary
m3ApiRawFunction(host_apply_patch) {
    m3ApiGetArg(uint32_t, offset);
    m3ApiGetArg(uint32_t, data_ptr);
    m3ApiGetArg(uint32_t, data_len);

    uint8_t *wasm_mem = m3_GetMemory(runtime);

    // Write patch bytes
    memcpy(g_binary.base + offset, wasm_mem + data_ptr, data_len);

    m3ApiSuccess();
}
```

### Phase 2: WASM Patching Engine

```c
// e9core.c - Compiled to WASM

#include <stdint.h>

// Imported from host
extern uint32_t host_mmap_binary(const char *path, uint32_t len);
extern void host_apply_patch(uint32_t offset, const uint8_t *data, uint32_t len);
extern void host_log(const char *msg, uint32_t len);

// Binary analysis (runs in WASM sandbox)
typedef struct {
    uint32_t offset;
    uint32_t old_size;
    uint32_t new_size;
    uint8_t *trampoline;
} Patch;

Patch *analyze_changes(const uint8_t *old_obj, uint32_t old_size,
                       const uint8_t *new_obj, uint32_t new_size) {
    // ... e9patch core logic here ...
    // All the trampoline generation, tactic selection, etc.
    // Runs safely in WASM sandbox
}

void apply_patches(Patch *patches, uint32_t count) {
    for (uint32_t i = 0; i < count; i++) {
        host_apply_patch(patches[i].offset,
                        patches[i].trampoline,
                        patches[i].new_size);
    }
}
```

### Phase 3: Self-Modifying APE

The most powerful feature: the APE can modify its own ZipOS contents:

```c
// Append new patched binary to ZipOS
void save_patched_binary(const char *name, uint8_t *data, size_t size) {
    // The APE file is still open (we executed from it)
    // We can append to the ZIP portion

    int exe_fd = open("/proc/self/exe", O_RDWR | O_APPEND);

    // Write new ZIP local file header
    struct zip_local_header lh = {
        .signature = 0x04034b50,
        .version = 20,
        .flags = 0,
        .compression = 0,  // STORE (for mmap)
        .filename_len = strlen(name),
        .uncompressed_size = size,
        // ...
    };

    write(exe_fd, &lh, sizeof(lh));
    write(exe_fd, name, strlen(name));
    write(exe_fd, data, size);

    // Update central directory
    // ...

    close(exe_fd);

    // Now /zip/patched_binary is accessible!
}
```

## 8. Comparison: Browser vs Embedded WASM

### Workflow Comparison

```
BROWSER-BASED (Original Design):
─────────────────────────────────
User ─→ CLion ─→ WebSocket ─→ Browser ─→ e9patch.wasm
                     │              │
                     │              └─→ JavaScript bridge
                     │                       │
                     └───────────────────────┘
                              ↓
                       Patched binary
                       (download or push)

EMBEDDED WASM (Proposed):
─────────────────────────────────
User ─→ Editor ─→ e9patch-studio.com
           │              │
           │    ┌─────────┴─────────┐
           │    │    Native Host    │
           │    │   ┌───────────┐   │
           │    │   │  wasm3    │   │
           │    │   │ ┌───────┐ │   │
           │    │   │ │e9patch│ │   │
           │    │   │ │.wasm  │ │   │
           │    │   │ └───────┘ │   │
           │    │   └───────────┘   │
           │    │         ↓         │
           │    │   ZipOS mmap      │
           │    └─────────┬─────────┘
           │              │
           └──────────────┘
                  ↓
           Modified binary
           (in-place or saved to ZipOS)
```

### Capability Matrix

| Capability | Browser | Embedded wasm3 |
|------------|---------|----------------|
| Direct mmap to ZipOS | No (copy required) | Yes (zero-copy) |
| Modify running binary | No | Yes (COW) |
| Offline operation | No | Yes |
| Single-file distribution | No | Yes |
| Startup latency | High | Low |
| Memory efficiency | Low | High |
| Signal handling for B0 tactic | No | Yes (native host) |
| Debug with GDB | No | Yes |
| Embed in CI/CD | Complex | Simple |

## 9. Conclusion

The APE format with ZipOS provides an ideal platform for self-contained dynamic binary
rewriting:

1. **ZipOS enables zero-copy access** to embedded binaries and source files
2. **wasm3 can replace Chrome** as the WASM runtime with significant advantages
3. **Self-modification** allows the tool to update its own embedded content
4. **COW mmap** enables safe in-place patching without corrupting originals
5. **Single-file distribution** simplifies deployment enormously

The recommended architecture is:
- Native Cosmopolitan host (~500KB) with wasm3/WAMR
- e9patch core compiled to WASM (~500KB) for sandboxed execution
- Ring 0 AST-based compilation (Lemon + lexgen) for live reload
- Optional ludoplex/binaryen (.wasm) for IR-level diffing
- All stored in ZipOS for single-file distribution

> **Note:** TinyCC is NOT compatible with Cosmopolitan (produces "Invalid relocation
> entry" errors). Use Ring 0 AST-based parsing (Lemon + lexgen) or cosmocc for
> compilation. See docs/IR_PATCHING.md for the full architecture.
