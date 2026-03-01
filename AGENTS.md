# E9Studio - Agent Context

> Universal context for LLM coding assistants (Claude, Copilot, Cursor, Aider, Continue, etc.)

## Overview

Binary patching tool for APE (Actually Portable Executable) polyglot binaries.
Part of cosmicringforge, demonstrating spec-driven C code generation.

## Critical Constraints

| Constraint | Rationale |
|------------|-----------|
| Pure C only | Dogfooding with C generators |
| APE-native | Patch ELF+PE+shell+ZipOS simultaneously |
| Spec-driven | Types from `.schema`, FSMs from `.sm` |
| Cosmopolitan | Builds with cosmocc for portability |

## File Map

```
specs/
├── e9ape.schema        # Type definitions (schemagen input)
├── e9ape.sm            # State machines (smgen input)
└── features/           # BDD Gherkin specs
    ├── ape_detection.feature
    ├── ape_patching.feature
    └── zipos_access.feature

gen/                    # Generated (DO NOT HAND-EDIT)
├── e9ape_types.h
├── e9ape_types.c
├── e9ape_fsm.h
└── e9ape_fsm.c

src/e9patch/
├── e9ape.h             # Public API
└── e9ape.c             # Implementation (uses gen/)
```

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
- PE sections are ground truth for APE (no x86-64 ELF!)
- ZipOS contains embedded assets (e.g., `binaryen.wasm`)

## Live Reload (Hot Patching)

Real-time C source → APE binary updates:

```
File Watch → cosmocc Recompile → Binaryen Diff → APE Patch → ICache Flush
```

Key files:
- `src/e9patch/e9livereload.h` - Live reload API
- `src/e9patch/e9livereload.c` - Integration layer
- `src/e9patch/e9ape.h` - APE patching (PE-based)
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

- [CONVENTIONS.md](CONVENTIONS.md) - Full style guide
- [specs/E9APE_DOGFOODING.md](specs/E9APE_DOGFOODING.md) - Dogfooding details
- [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) - CosmicRingForge architecture
- [../docs/APE_LIVERELOAD.md](../docs/APE_LIVERELOAD.md) - APE live reload reference
