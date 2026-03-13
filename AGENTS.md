# E9Studio - Agent Context

> Universal context for LLM coding assistants (Claude, Copilot, Cursor, Aider, Continue, etc.)

## 🚨 MANDATORY: Read Upstream Docs FIRST

**STOP. Before writing ANY code, you MUST read these repositories:**

| Priority | Repository | What to Read | Why |
|----------|------------|--------------|-----|
| **1** | [jart/cosmopolitan](https://github.com/jart/cosmopolitan) | README, tool/cosmocc/README.md, ape/ | ALL e9studio code uses cosmocc |
| **2** | [jart/cosmopolitan/ape](https://github.com/jart/cosmopolitan/tree/master/ape) | loader.c, ape.h | APE binary format internals |
| **3** | ludoplex/binaryen | README | WASM IR for object diffing |

**You cannot effectively work on e9studio without understanding:**
- APE polyglot structure (contains BOTH ELF and PE views of shared sections)
- cosmocc toolchain (GCC 14.1.0 default, Clang 19 via -mclang)
- ZipOS virtual filesystem (/zip/ paths, mmap)
- Cross-platform process memory APIs

**Failure to read upstream docs will result in:**
- Wrong APE patching (not syncing both ELF and PE views)
- Using incompatible tools (TinyCC, libclang library)
- Broken cross-platform code

**Full vendor documentation:** [VENDORS.md](../../../VENDORS.md)

---

## Overview

Binary patching tool for APE (Actually Portable Executable) polyglot binaries.
Part of cosmo-bde, demonstrating spec-driven C code generation.

## Critical Constraints

| Constraint | Rationale |
|------------|-----------|
| Pure C only | Dogfooding with C generators |
| APE-native | Patch ELF+PE+Mach-O+shell+ZipOS simultaneously |
| Spec-driven | Types from `.schema`, FSMs from `.sm` |
| Cosmopolitan | Builds with cosmocc for portability |

## ⚠️ CRITICAL: Tool Compatibility

**READ THIS FIRST** - Know which tools work with Cosmopolitan:

| Tool | Status | Notes |
|------|--------|-------|
| **TinyCC (libtcc)** | ❌ BANNED | "Invalid relocation entry" with cosmopolitan.a |
| **Binaryen** | ✅ OK | Use ludoplex/binaryen (.com + .wasm outputs) |
| **Clang (cosmocc)** | ✅ OK | cosmocc bundles Clang 19, use `-mclang` flag |
| **libclang (library)** | ⚠️ Avoid | Programmatic AST access has relocation issues |

**Why TinyCC is banned:**
- TinyCC seems attractive for fast in-memory compilation
- Produces "Invalid relocation entry" errors when linking with cosmopolitan.a
- This is a fundamental incompatibility - do NOT attempt to use TinyCC

**Compiler notes:**
- cosmocc bundles **GCC 14.1.0** (default) and **Clang 19** (`-mclang`)
- Clang mode compiles C++ 3x faster
- **libclang** (library for AST parsing) ≠ **clang** (compiler)

**IR patching approaches (ordered by preference):**

| Approach | Ring | Latency | Notes |
|----------|------|---------|-------|
| Ring 0 AST (Lemon+lexgen) | 0 | ~30-50ms | Pure C, fully dogfooded |
| Binaryen WASM (ludoplex) | 1 | ~60-80ms | .wasm in ZipOS |
| ccache (warm) | 1 | ~15-20ms | Requires cache hits |

See [docs/IR_PATCHING.md](docs/IR_PATCHING.md) for full Ring 0 composable architecture.

## File Map

```
specs/
├── e9ape.schema          # Type definitions (schemagen)
├── e9ape.sm              # State machines (smgen)
├── e9livereload.schema   # Live reload protocol
├── domain/               # Domain specs (c11_ast.schema, etc.)
├── parsing/              # Parser specs (c11.lex, c11.grammar)
├── behavior/             # State machines (livereload.sm, patch.sm)
└── features/             # BDD Gherkin specs

gen/
└── domain/               # Generated types (DO NOT HAND-EDIT)

src/e9patch/
├── e9ape.c,h             # APE patching (ELF+PE polyglot) - PURE C
├── e9livereload.c,h      # Live reload integration - PURE C
├── e9procmem.c,h         # Cross-platform process memory - PURE C
├── wasm/                 # Binaryen WASM integration
├── *.cpp                 # Legacy C++ (being migrated to C)
└── vendor/               # Third-party code
```

**Note:** Legacy `.cpp` files exist but new code MUST be pure C.

## Naming

```
e9_{module}_{action}()   # Functions
e9_{name}_t              # Types
E9_{TYPE}_{VALUE}        # Enums
```

## Workflow

1. Edit specs (`*.schema`, `*.sm`, `*.feature`)
2. `make regen` → updates `gen/`
3. Update `src/` to use generated code
4. `git diff --exit-code gen/` must pass

## Quick Reference

- Return `0` on success, `-1` on error
- Use `e9_livereload_get_error()` for error strings
- APE contains both ELF and PE views of shared sections
- ZipOS contains embedded assets (e.g., `binaryen.wasm`)

## Live Reload (Hot Patching)

Real-time C source → APE binary updates:

```
File Watch → cosmocc Recompile → Binaryen Diff → APE Patch → ICache Flush
```

Key files:
- `src/e9patch/e9livereload.h` - Live reload API
- `src/e9patch/e9livereload.c` - Integration layer
- `src/e9patch/e9ape.h` - APE patching (ELF+PE polyglot)
- `src/e9patch/wasm/e9binaryen.h` - Object diff via Binaryen
- `specs/e9livereload.schema` - Protocol spec

## Architecture Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - Component architecture and data flow
- [doc/ape-anatomy-analysis.md](doc/ape-anatomy-analysis.md) - APE binary RE notes

## State Machines

- `specs/behavior/livereload.sm` - Live reload session lifecycle
- `specs/behavior/patch.sm` - Individual patch lifecycle

```
LiveReload States:
  UNINIT -> IDLE -> WATCHING -> COMPILING -> DIFFING -> PATCHING -> WATCHING

Patch States:
  PENDING -> APPLYING -> VERIFYING -> APPLIED <-> REVERTED
                                  \-> FAILED
```

## See Also

- [VENDORS.md](../../../VENDORS.md) - **Vendor repos (READ FIRST)**
- [CONVENTIONS.md](CONVENTIONS.md) - Full style guide
- [specs/E9APE_DOGFOODING.md](specs/E9APE_DOGFOODING.md) - Dogfooding details
- [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) - cosmo-bde architecture
- [../docs/APE_LIVERELOAD.md](../docs/APE_LIVERELOAD.md) - APE live reload reference
