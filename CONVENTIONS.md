# E9Studio Universal Conventions

> For Humans and LLMs alike

This document defines the **single source of truth** for all e9studio development conventions. It is designed to be:

1. **Human-readable**: Clear, concise, example-driven
2. **LLM-parseable**: Structured, unambiguous, searchable
3. **Enforceable**: Can be validated by tools and regen-and-diff

---

## 1. Language: Pure C

**Rule**: All e9studio code is portable C, not C++.

```c
/* YES - Pure C */
typedef struct {
    int64_t offset;
    size_t size;
} e9_range_t;

/* NO - C++ */
class E9Range {  // FORBIDDEN
    int64_t offset;
    size_t size;
};
```

**Why**: cosmicringforge generates C. Using C++ would break dogfooding.

---

## 2. Naming Conventions

### Types

```c
/* Pattern: {prefix}_{name}_t */
e9_ape_info_t        /* APE info structure */
e9_pe_section_t      /* PE section header */
e9_zipos_entry_t     /* ZipOS file entry */
```

### Functions

```c
/* Pattern: {prefix}_{module}_{action}() */
e9_ape_parse()       /* Parse APE binary */
e9_ape_patch()       /* Apply patch to APE */
e9_zipos_read()      /* Read from ZipOS */
```

### Constants and Enums

```c
/* Pattern: {PREFIX}_{NAME} */
#define E9_APE_MAGIC_MZ "MZqFpD"

/* Pattern: {PREFIX}_{TYPE}_{VALUE} */
typedef enum {
    E9_FORMAT_UNKNOWN,
    E9_FORMAT_ELF,
    E9_FORMAT_PE,
    E9_FORMAT_APE,
} e9_format_t;
```

### Files

```
{module}.c           /* Implementation */
{module}.h           /* Public API */
{module}_internal.h  /* Internal helpers (if needed) */
```

---

## 3. Code Structure

### Section Separators

Use box-drawing characters for visual structure:

```c
/* ── Detection ─────────────────────────────────────────────────── */

bool e9_ape_detect(const uint8_t *data, size_t size);

/* ── Parsing ───────────────────────────────────────────────────── */

int e9_ape_parse(const uint8_t *data, size_t size, e9_ape_info_t *info);

/* ── Patching ──────────────────────────────────────────────────── */

int e9_ape_patch(uint8_t *data, size_t size, const e9_ape_info_t *info,
                 uint64_t vaddr, const uint8_t *patch, size_t patch_size);
```

### Header Guards

```c
#ifndef E9APE_H
#define E9APE_H
/* ... */
#endif /* E9APE_H */
```

### Include Order

```c
/* 1. Corresponding header (if .c file) */
#include "e9ape.h"

/* 2. Standard library */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* 3. System headers (if needed) */
#include <elf.h>

/* 4. Project headers */
#include "e9patch.h"
```

---

## 4. Error Handling

### Return Conventions

```c
/* Success: 0, Failure: -1 */
int e9_ape_parse(...);  /* Returns 0 on success, -1 on error */

/* Pointer return: NULL on failure */
uint8_t *e9_ape_zipos_read(...);  /* Returns NULL on error */

/* Boolean queries */
bool e9_ape_detect(...);  /* true if APE, false otherwise */
```

### Error Messages

```c
/* Thread-local error string */
const char *e9_ape_get_error(void);
void e9_ape_clear_error(void);

/* Usage */
if (e9_ape_parse(data, size, &info) < 0) {
    fprintf(stderr, "APE parse failed: %s\n", e9_ape_get_error());
}
```

---

## 5. Spec-Driven Development

### File Types

| Extension | Generator | Purpose |
|-----------|-----------|---------|
| `.schema` | schemagen | Data structures, types |
| `.sm` | smgen | State machines, FSMs |
| `.feature` | (BDD) | Behavior specifications |

### Directory Structure

```
e9studio/
├── specs/
│   ├── e9ape.schema          # Type definitions
│   ├── e9ape.sm              # State machines
│   ├── features/
│   │   ├── ape_detection.feature
│   │   ├── ape_patching.feature
│   │   └── zipos_access.feature
│   └── E9APE_DOGFOODING.md   # Integration guide
├── gen/                       # Generated code (DO NOT EDIT)
│   ├── e9ape_types.h
│   ├── e9ape_types.c
│   ├── e9ape_fsm.h
│   └── e9ape_fsm.c
└── src/
    └── e9patch/
        ├── e9ape.h           # Hand-written API (uses gen/)
        └── e9ape.c           # Hand-written impl (uses gen/)
```

### Regen-and-Diff Gate

```bash
# MUST pass before any commit
make regen
git diff --exit-code gen/
```

---

## 6. APE-Specific Conventions

### Polyglot Awareness

APE binaries are valid as multiple formats. Code must respect all layers:

```c
/* When patching, consider all views */
typedef struct {
    int32_t sync_elf_pe;      /* Patch both ELF and PE? */
    int32_t preserve_zipos;   /* Keep ZipOS intact? */
} e9_ape_info_t;
```

### Address Spaces

```c
/* ELF uses virtual addresses */
uint64_t elf_vaddr;   /* e.g., 0x401000 */

/* PE uses RVA (Relative Virtual Address) */
uint32_t pe_rva;      /* e.g., 0x1000 */

/* Both map to file offsets */
off_t file_offset;    /* e.g., 0x400 */
```

### ZipOS Paths

```c
/* ZipOS paths are Unix-style, starting with / */
const char *path = "/lib/binaryen.wasm";

/* NOT Windows-style */
/* const char *path = "lib\\binaryen.wasm";  WRONG */
```

---

## 7. Build Profiles

### Portable (Default)

```bash
make PROFILE=portable
# Uses system cc, links dynamically
```

### APE (Cosmopolitan)

```bash
make PROFILE=ape
# Uses cosmocc, produces .com APE binary
```

### Generated Code Must Work With Both

```c
/* gen/ code must be portable */
#include <stdint.h>   /* Standard types */
/* No platform-specific headers */
```

---

## 8. Documentation Style

### Literate Comments

```c
/*
 * e9_ape_parse - Parse APE binary structure
 *
 * Analyzes an APE polyglot binary and extracts the offsets of all
 * format layers: shell script, MZ/DOS header, ELF, PE, and ZipOS.
 *
 * The APE format (Actually Portable Executable) is a polyglot that
 * is simultaneously valid as:
 *   - DOS/MZ executable (Windows)
 *   - ELF executable (Linux/BSD)
 *   - Shell script (Unix bootstrap)
 *   - ZIP archive (ZipOS embedded filesystem)
 *
 * Parameters:
 *   data - Pointer to APE binary data
 *   size - Size of data in bytes
 *   info - Output structure to populate
 *
 * Returns:
 *   0 on success, -1 on error (call e9_ape_get_error for details)
 */
int e9_ape_parse(const uint8_t *data, size_t size, e9_ape_info_t *info);
```

### ASCII Art for Complex Structures

```c
/*
 * APE Binary Layout:
 *
 * ┌────────────────────────────────────────────┐
 * │ Shell Script Header (optional)             │
 * │ "#!/bin/sh\n..."                           │
 * ├────────────────────────────────────────────┤
 * │ MZ Header ("MZqFpD...")                    │
 * │ ├─ DOS stub                                │
 * │ └─ PE signature at e_lfanew                │
 * ├────────────────────────────────────────────┤
 * │ ELF Header (at offset 64 typically)        │
 * │ ├─ Program headers                         │
 * │ └─ Sections                                │
 * ├────────────────────────────────────────────┤
 * │ PE Headers                                 │
 * │ ├─ COFF file header                        │
 * │ ├─ Optional header                         │
 * │ └─ Section headers                         │
 * ├────────────────────────────────────────────┤
 * │ Code/Data (shared by ELF and PE)           │
 * ├────────────────────────────────────────────┤
 * │ ZipOS (embedded filesystem)                │
 * │ ├─ Local file headers                      │
 * │ ├─ File data                               │
 * │ ├─ Central directory                       │
 * │ └─ End of central directory                │
 * └────────────────────────────────────────────┘
 */
```

---

## 9. LLM Instruction Set

When working with e9studio code, LLMs should:

### DO

- Generate C code, not C++
- Use `e9_` prefix for all symbols
- Follow `{prefix}_{module}_{action}` naming
- Add section separators between logical groups
- Write literate comments explaining "why"
- Create/update `.schema` and `.sm` specs first
- Run `make regen` after spec changes

### DO NOT

- Use C++ features (classes, templates, exceptions, `new`)
- Hand-edit files in `gen/` directory
- Skip the regen-and-diff gate
- Use platform-specific headers
- Ignore APE's polyglot nature (always consider all views)
- Create new files without updating specs

### VERIFY

- [ ] Is it pure C? (`grep -r 'class\|template\|new\s' src/`)
- [ ] Are names correct? (`grep -r '^[a-z]' src/*.h | grep -v e9_`)
- [ ] Is gen/ clean? (`make regen && git diff --exit-code gen/`)
- [ ] Do features pass? (`make test-features`)

---

## 10. Quick Reference

| What | Convention |
|------|------------|
| Type | `e9_{name}_t` |
| Function | `e9_{module}_{action}()` |
| Constant | `E9_{NAME}` |
| Enum value | `E9_{TYPE}_{VALUE}` |
| Success | `return 0` |
| Failure | `return -1` |
| Specs | `specs/*.schema`, `specs/*.sm` |
| Generated | `gen/*` (DO NOT EDIT) |
| BDD | `specs/features/*.feature` |

---

*This document is the single source of truth. When in doubt, refer here.*
