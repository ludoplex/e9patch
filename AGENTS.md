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
- Use `e9_ape_get_error()` for error strings
- Sync patches to both ELF and PE views by default
- ZipOS contains embedded assets (e.g., `binaryen.wasm`)

## See Also

- [CONVENTIONS.md](CONVENTIONS.md) - Full style guide
- [specs/E9APE_DOGFOODING.md](specs/E9APE_DOGFOODING.md) - Dogfooding details
