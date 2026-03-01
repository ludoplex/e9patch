# IR-Based Patching for Lower Latency

> **Future Enhancement** - Using Intermediate Representation to reduce patch latency.

---

## Problem Statement

Current live reload latency is **200-500ms**, dominated by full recompilation:

```
CURRENT WORKFLOW:
  .c -> [cosmocc full compile] -> .o -> [byte diff] -> patch
        ^^^^^^^^^^^^^^^^^^^^
        ~150-400ms (bottleneck)
```

---

## IR-Based Solution

Use Intermediate Representation to skip redundant work:

```
IR-BASED WORKFLOW:
  .c -> [parse to IR] -> [IR diff] -> [codegen changed only] -> patch
        ^^^^^^^^^^^^     ^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^
        ~10-20ms         ~5-10ms      ~20-50ms

  Total: ~50-100ms (4-5x faster)
```

---

## IR Options

### Option 1: LLVM IR

Use Clang to emit LLVM IR, diff at IR level, codegen only changed functions.

```
.c -> clang -emit-llvm -> .ll (text IR) or .bc (bitcode)
                             |
                             v
                      [IR-level diff]
                             |
               +-------------+-------------+
               |                           |
        [unchanged funcs]          [changed funcs]
               |                           |
               v                           v
         (skip codegen)              llc -> .o
                                           |
                                           v
                                      [patch]
```

**Advantages:**
- Mature tooling (LLVM/Clang)
- Rich optimization passes
- Can diff at multiple levels (AST, IR, MIR)

**Disadvantages:**
- LLVM is large (~100MB)
- Not Ring 0 compatible (C++ toolchain)

### Option 2: Binaryen/WASM IR

Use WASM as the intermediate representation. Already integrated for object diffing.

```
.c -> clang --target=wasm32 -> .wasm -> [Binaryen optimize]
                                              |
                                              v
                                       [WASM-level diff]
                                              |
                                +-------------+-------------+
                                |                           |
                         [unchanged]                 [changed funcs]
                                |                           |
                                v                           v
                          (skip)                   wasm2c -> .c
                                                           |
                                                           v
                                                      cosmocc -> patch
```

**Advantages:**
- Binaryen already in project
- WASM is platform-neutral IR
- wasm2c produces portable C

**Disadvantages:**
- Extra compile step (C -> WASM -> C)
- Some semantic loss

### Option 3: TinyCC (tcc)

Use TinyCC for near-instant compilation. ~10ms compile times.

```
.c -> [tcc -c] -> .o -> [byte diff] -> patch
      ^^^^^^^^
      ~10-20ms (vs 200ms for gcc/clang)
```

**Advantages:**
- Extremely fast compilation
- Pure C, Ring 0 compatible
- Simple integration

**Disadvantages:**
- Less optimization (-O0 equivalent)
- Some C99/C11 features missing
- May produce different code layout than cosmocc

### Option 4: Incremental Compilation

Use ccache + function sections for incremental builds.

```
.c -> [ccache check] -> cache hit? -> skip compile
                             |
                             no
                             |
                             v
      [cosmocc -ffunction-sections] -> .o
                             |
                             v
                    [per-function diff]
                             |
                    [patch only changed]
```

**Advantages:**
- Works with existing toolchain
- No new dependencies
- Gradual improvement

**Disadvantages:**
- Still full compile on cache miss
- Requires ccache setup

### Option 5: AST-Level Diffing

Parse to AST, diff AST, regenerate only changed subtrees.

```
old.c -> [parse] -> AST_old --+
                              |
                              v
new.c -> [parse] -> AST_new --+--> [AST diff]
                                        |
                          +-------------+-------------+
                          |                           |
                   [unchanged subtrees]        [changed subtrees]
                          |                           |
                          v                           v
                    (reuse .o)               [codegen] -> patch
```

**Advantages:**
- Minimal recompilation
- Semantic awareness

**Disadvantages:**
- Requires C parser (Lemon + lexgen could help)
- Complex implementation

---

## Recommended Approach

**Phase 1: TinyCC Integration (Quick Win)**

```c
// In e9livereload.c
#ifdef USE_TCC
  #include <libtcc.h>

  // Compile in-memory, no disk I/O
  TCCState *s = tcc_new();
  tcc_set_output_type(s, TCC_OUTPUT_OBJ);
  tcc_compile_string(s, source_code);
  int size = tcc_relocate(s, NULL);
  void *code = malloc(size);
  tcc_relocate(s, code);
  // code now contains compiled function
#endif
```

Latency: **~20-50ms** (10x improvement)

**Phase 2: Binaryen IR Diff (Medium Term)**

Extend existing Binaryen integration:

```c
// Already have:
e9_binaryen_diff_objects(old.o, new.o, &patches, &count);

// Add:
e9_binaryen_diff_wasm(old.wasm, new.wasm, &ir_patches, &count);
// Works at IR level, more precise diff
```

Latency: **~50-80ms** (with WASM as IR)

**Phase 3: Incremental AST (Long Term)**

Build incremental C parser using Ring 0 tools:

```
specs/parsing/c11.grammar  -> Lemon -> c11_parse.c
specs/parsing/c11.lex      -> lexgen -> c11_lex.c

// Then:
AST old_ast = parse_file("old.c");
AST new_ast = parse_file("new.c");
Diff diff = ast_diff(old_ast, new_ast);
for_each_changed_function(diff, recompile_and_patch);
```

Latency: **~30-50ms** (AST diff + selective codegen)

---

## Implementation Sketch: TinyCC

```c
/* e9tcc.h - TinyCC integration for fast recompilation */

#ifndef E9TCC_H
#define E9TCC_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    void *code;
    size_t size;
    const char *function_name;
    uint64_t address;
} E9TCCPatch;

/*
 * Compile source to machine code in memory.
 * Returns array of patches for changed functions.
 */
int e9_tcc_compile(const char *source,
                   E9TCCPatch **patches,
                   int *num_patches);

/*
 * Free patches returned by e9_tcc_compile.
 */
void e9_tcc_free_patches(E9TCCPatch *patches, int count);

/*
 * Check if TCC is available.
 */
int e9_tcc_available(void);

#endif /* E9TCC_H */
```

```c
/* e9tcc.c */

#ifdef USE_TCC
#include <libtcc.h>

int e9_tcc_compile(const char *source,
                   E9TCCPatch **patches,
                   int *num_patches) {
    TCCState *s = tcc_new();
    if (!s) return -1;

    tcc_set_output_type(s, TCC_OUTPUT_MEMORY);
    tcc_set_options(s, "-nostdlib -fPIC");

    if (tcc_compile_string(s, source) < 0) {
        tcc_delete(s);
        return -1;
    }

    int size = tcc_relocate(s, NULL);
    if (size < 0) {
        tcc_delete(s);
        return -1;
    }

    void *code = malloc(size);
    tcc_relocate(s, code);

    // Extract function addresses from TCC symbol table
    // ... implementation ...

    tcc_delete(s);
    return 0;
}
#endif
```

---

## Latency Comparison

| Approach | Compile | Diff | Patch | Total |
|----------|---------|------|-------|-------|
| **Current (cosmocc)** | 200-400ms | 10ms | 5ms | **~200-500ms** |
| **TinyCC** | 10-20ms | 10ms | 5ms | **~30-50ms** |
| **Binaryen IR** | 50ms | 5ms | 5ms | **~60-80ms** |
| **Incremental AST** | 10ms | 10ms | 5ms | **~30-50ms** |
| **ccache hit** | 0ms | 10ms | 5ms | **~15-20ms** |

---

## Ring Classification

| Approach | Ring | Notes |
|----------|------|-------|
| TinyCC (libtcc) | **Ring 0** | Pure C, can vendor |
| Binaryen | Ring 1/2 | C++, but WASM module Ring 0 |
| LLVM IR | Ring 2 | C++ toolchain required |
| Incremental AST | **Ring 0** | Use Lemon + lexgen |
| ccache | Ring 1 | System tool |

**Recommendation:** Start with TinyCC (Ring 0) for immediate gains, then add AST-based incremental compilation using Ring 0 tools.

---

## Integration with Live Reload

```c
// In e9livereload.c, add fast-path option:

static int compile_source_fast(const char *source_path,
                               E9TCCPatch **patches,
                               int *num_patches) {
#ifdef USE_TCC
    if (g_state.config.use_tcc && e9_tcc_available()) {
        // Fast path: TCC in-memory compilation
        char *source = read_file(source_path);
        int ret = e9_tcc_compile(source, patches, num_patches);
        free(source);
        return ret;
    }
#endif
    // Fallback: cosmocc + Binaryen diff
    return compile_source_slow(source_path, patches, num_patches);
}
```

---

*Future enhancement for CosmicRingForge/e9studio. Last updated: 2024*
