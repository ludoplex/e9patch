# IR-Based Patching: Ring 0/1/2 Composable Architecture

> **LLM Reference Document** - Full Ring composability for IR-based live reload.
>
> Dogfooded using CosmicRingForge generators. C version abstracted (base: C11/Cosmopolitan).

---

## 1. Problem Statement

Current live reload latency: **200-500ms**, dominated by full recompilation.

```
CURRENT:
  .c -> [cosmocc full compile] -> .o -> [byte diff] -> patch
        ^^^^^^^^^^^^^^^^^^^^
        ~150-400ms (bottleneck)
```

**Goal:** Reduce to **30-80ms** using IR-level diffing and selective codegen.

---

## 2. Solution: Ring 0 AST-Based IR

Use CosmicRingForge generators to build a C parser for AST-level diffing:

```
IR-BASED (Ring 0 Dogfooded):
  .c -> [c11_lex + c11_parse] -> AST -> [ast_diff] -> [codegen changed] -> patch
        ^^^^^^^^^^^^^^^^^^^^^^^^^^     ^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^
        Ring 0 generators              Ring 0 SM     Selective compile

  Total: ~30-80ms (4-8x faster)
```

---

## 3. C Version Abstraction

**Base target:** C11 (Cosmopolitan libc compatibility)

**Abstraction strategy:** Version-specific features via feature flags:

```c
/* In c11_tokens.def */
#if C_STANDARD >= 11
    TOK(_STATIC_ASSERT, "_Static_assert", KEYWORD, "C11 static assert")
    TOK(_ALIGNAS,       "_Alignas",       KEYWORD, "C11 alignment")
    TOK(_ALIGNOF,       "_Alignof",       KEYWORD, "C11 alignment query")
    TOK(_NORETURN,      "_Noreturn",      KEYWORD, "C11 noreturn")
    TOK(_GENERIC,       "_Generic",       KEYWORD, "C11 generic selection")
#endif

#if C_STANDARD >= 23
    TOK(TRUE,           "true",           KEYWORD, "C23 true literal")
    TOK(FALSE,          "false",          KEYWORD, "C23 false literal")
    TOK(NULLPTR,        "nullptr",        KEYWORD, "C23 null pointer")
#endif
```

**Configuration in schema:**

```
# In c11_ast.schema
@c_standard 11          # Base: C11 (Cosmopolitan)
@c_standard_min 89      # Minimum supported
@c_standard_max 23      # Maximum supported
```

---

## 4. Ring Classification

```
+===========================================================================+
|                    IR PATCHING RING CLASSIFICATION                         |
+===========================================================================+

+=== RING 0: Bootstrap (C + sh + make) =====================================+
|                                                                            |
| SPECS (Human-authored, Single Source of Truth):                            |
|   specs/domain/c11_ast.schema      <- AST node types                       |
|   specs/domain/ir_patch.schema     <- Patch data structures                |
|   specs/parsing/c11_tokens.def     <- Token X-macros                       |
|   specs/parsing/c11.lex            <- Lexer rules                          |
|   specs/parsing/c11.grammar        <- Lemon grammar                        |
|   specs/behavior/ast_diff.sm       <- Diff algorithm state machine         |
|   specs/behavior/ir_compile.sm     <- Selective compile state machine      |
|   specs/testing/ir_patch.feature   <- BDD scenarios                        |
|                                                                            |
| GENERATORS (Ring 0 tools):                                                 |
|   schemagen   <- c11_ast.schema  -> c11_ast_types.c,h                      |
|   defgen      <- c11_tokens.def  -> c11_tokens.h (X-macros)                |
|   lexgen      <- c11.lex         -> c11_lex.c,h                            |
|   lemon       <- c11.grammar     -> c11_parse.c,h                          |
|   smgen       <- ast_diff.sm     -> ast_diff_sm.c,h                        |
|   bddgen      <- ir_patch.feature -> ir_patch_bdd.c                        |
|                                                                            |
| GENERATED (Committed, drift-gated):                                        |
|   gen/domain/c11_ast_types.c,h                                             |
|   gen/domain/ir_patch_types.c,h                                            |
|   gen/parsing/c11_tokens.h                                                 |
|   gen/parsing/c11_lex.c,h                                                  |
|   gen/parsing/c11_parse.c,h                                                |
|   gen/behavior/ast_diff_sm.c,h                                             |
|   gen/behavior/ir_compile_sm.c,h                                           |
|   gen/testing/ir_patch_bdd.c                                               |
|                                                                            |
+============================================================================+
                                   |
                                   | optional enhancements
                                   v
+=== RING 1: Velocity Tools (C utilities) ==================================+
|                                                                            |
| OPTIONAL (Not required for build):                                         |
|   cppcheck       <- Static analysis of generated parser                    |
|   ASan/UBSan     <- Runtime validation of AST operations                   |
|   ccache         <- Cache compiled objects for faster rebuilds             |
|   makeheaders    <- Auto-generate headers from implementations             |
|                                                                            |
| RING 1 OUTPUTS (enhance development):                                      |
|   - Static analysis reports                                                |
|   - Sanitizer-instrumented binaries                                        |
|   - Cached object files                                                    |
|                                                                            |
+============================================================================+
                                   |
                                   | external tool outputs (committed)
                                   v
+=== RING 1: Binaryen (ludoplex fork) =====================================+
|                                                                            |
| COMPATIBLE TOOLING:                                                        |
|   ludoplex/binaryen  <- WASM-based IR diffing (.com + .wasm outputs)      |
|                         Cosmopolitan-compatible, embeddable in ZipOS       |
|                                                                            |
+============================================================================+
                                   |
                                   v
+=== RING 2: External Toolchains ==========================================+
|                                                                            |
| COMPILER NOTES:                                                            |
|   cosmocc bundles GCC 14.1.0 (default) + Clang 19 (-mclang flag)          |
|   Clang mode compiles C++ 3x faster                                        |
|                                                                            |
| ALTERNATIVE FRONTENDS (outputs committed, NOT required for build):         |
|   libclang (library) <- Programmatic AST access (has relocation issues)   |
|                         Note: libclang ≠ clang compiler                    |
|                                                                            |
| ⚠️ INCOMPATIBLE (do NOT use):                                              |
|   TinyCC (libtcc)    <- "Invalid relocation entry" with cosmopolitan.a    |
|                                                                            |
| VALIDATION TOOLS (development only):                                       |
|   gcc -fsyntax-only  <- Validate parser correctness                        |
|   clang -ast-dump    <- Compare AST structure (via cosmocc -mclang)        |
|                                                                            |
| RING 2 RULE: Outputs committed, builds succeed with Ring 0 only            |
|                                                                            |
+============================================================================+
```

---

## 5. File Structure

```
upstream/e9studio/
+-- specs/
|   +-- domain/
|   |   +-- c11_ast.schema        # AST node types (schemagen)
|   |   +-- ir_patch.schema       # Patch structures (schemagen)
|   |   +-- ir_codegen.schema     # Codegen config (schemagen)
|   |
|   +-- parsing/
|   |   +-- c11_tokens.def        # Token X-macros (defgen)
|   |   +-- c11.lex               # Lexer rules (lexgen)
|   |   +-- c11.grammar           # Lemon grammar
|   |
|   +-- behavior/
|   |   +-- ast_diff.sm           # Diff state machine (smgen)
|   |   +-- ir_compile.sm         # Selective compile SM (smgen)
|   |   +-- livereload.sm         # Session lifecycle (smgen)
|   |   +-- patch.sm              # Patch lifecycle (smgen)
|   |
|   +-- testing/
|       +-- ir_patch.feature      # BDD scenarios (bddgen)
|       +-- ast_diff.feature
|
+-- gen/
|   +-- domain/
|   |   +-- c11_ast_types.c,h
|   |   +-- ir_patch_types.c,h
|   |   +-- ir_codegen_types.c,h
|   |
|   +-- parsing/
|   |   +-- c11_tokens.h          # X-macro expanded
|   |   +-- c11_lex.c,h           # Generated lexer
|   |   +-- c11_parse.c,h         # Generated parser
|   |
|   +-- behavior/
|   |   +-- ast_diff_sm.c,h
|   |   +-- ir_compile_sm.c,h
|   |   +-- livereload_sm.c,h
|   |   +-- patch_sm.c,h
|   |
|   +-- testing/
|       +-- ir_patch_bdd.c
|       +-- ast_diff_bdd.c
|
+-- src/e9patch/
    +-- ir/
        +-- c11_parser.c          # Parser integration
        +-- ast_diff.c            # AST comparison
        +-- ir_codegen.c          # Selective code generation
        +-- ir_patch.c            # IR-based patching
```

---

## 6. Data Flow Diagram

```
+===========================================================================+
|                         IR-BASED PATCHING FLOW                             |
+===========================================================================+

   OLD SOURCE                                 NEW SOURCE
   +----------+                               +----------+
   | old.c    |                               | new.c    |
   +----+-----+                               +-----+----+
        |                                           |
        v                                           v
   +----+-----+                               +-----+----+
   | c11_lex  |  <- gen/parsing/c11_lex.c     | c11_lex  |
   +----+-----+                               +-----+----+
        |                                           |
        v                                           v
   +----+-----+                               +-----+----+
   | c11_parse|  <- gen/parsing/c11_parse.c   | c11_parse|
   +----+-----+                               +-----+----+
        |                                           |
        v                                           v
   +----+-----+                               +-----+----+
   | old_ast  |  <- gen/domain/c11_ast_types  | new_ast  |
   +----+-----+                               +-----+----+
        |                                           |
        +-------------------+   +-------------------+
                            |   |
                            v   v
                      +-----+---+-----+
                      |   ast_diff    |  <- gen/behavior/ast_diff_sm.c
                      +-------+-------+
                              |
                              v
                      +-------+-------+
                      | FuncChange[]  |  <- gen/domain/ir_patch_types
                      | - name        |
                      | - change_type |
                      | - old_hash    |
                      | - new_hash    |
                      +-------+-------+
                              |
          +-------------------+-------------------+
          |                   |                   |
          v                   v                   v
    +-----+-----+       +-----+-----+       +-----+-----+
    | ADDED     |       | MODIFIED  |       | REMOVED   |
    +-----+-----+       +-----+-----+       +-----+-----+
          |                   |                   |
          v                   v                   v
    +-----+-----+       +-----+-----+       +-----+-----+
    | codegen   |       | codegen   |       | nop-fill  |
    | new func  |       | new body  |       | old addr  |
    +-----+-----+       +-----+-----+       +-----+-----+
          |                   |                   |
          +-------------------+-------------------+
                              |
                              v
                      +-------+-------+
                      | ir_compile_sm |  <- gen/behavior/ir_compile_sm.c
                      +-------+-------+
                              |
                              v
                      +-------+-------+
                      | process_vm_  |  <- src/e9patch/e9procmem.h
                      | writev()     |
                      +-------+-------+
                              |
                              v
                      +-------+-------+
                      | icache_flush |
                      +-------+-------+
                              |
                              v
                      +-------+-------+
                      | PATCHED!     |
                      +---------------+
```

---

## 7. State Machines

### AST Diff State Machine

```
specs/behavior/ast_diff.sm:

  INIT -> PARSE_OLD -> PARSE_NEW -> HASH_FUNCS -> COMPARE -> DONE
              |             |            |           |
              v             v            v           v
          PARSE_ERR    PARSE_ERR    [func hashes] [FuncChange[]]

States:
  INIT        - Initialize diff context
  PARSE_OLD   - Parse old source to AST
  PARSE_NEW   - Parse new source to AST
  HASH_FUNCS  - Compute content hashes for all functions
  COMPARE     - Compare function hashes, detect changes
  DONE        - Return list of changed functions
  PARSE_ERR   - Handle parse errors gracefully
```

### IR Compile State Machine

```
specs/behavior/ir_compile.sm:

  INIT -> SELECT_CHANGED -> CODEGEN -> LINK -> EXTRACT -> DONE
              |                |         |        |
              v                v         v        v
         [FuncChange[]]    [obj code] [linked] [patch bytes]

States:
  INIT           - Initialize compile context
  SELECT_CHANGED - Filter to only changed functions
  CODEGEN        - Compile only changed function bodies
  LINK           - Link to resolve symbols
  EXTRACT        - Extract machine code bytes
  DONE           - Return patch data
```

---

## 8. X-Macro Usage

### Token Definition (defgen input)

```c
/* specs/parsing/c11_tokens.def */

#define C11_KEYWORDS(TOK) \
    TOK(IF,     "if",     KEYWORD, "if statement") \
    TOK(ELSE,   "else",   KEYWORD, "else branch") \
    TOK(WHILE,  "while",  KEYWORD, "while loop") \
    TOK(FOR,    "for",    KEYWORD, "for loop") \
    TOK(RETURN, "return", KEYWORD, "return statement") \
    /* ... */

#define C11_TOKENS(TOK) \
    C11_KEYWORDS(TOK) \
    C11_OPERATORS(TOK) \
    C11_PUNCTUATION(TOK) \
    C11_LITERALS(TOK)
```

### Generated Expansion (gen/parsing/c11_tokens.h)

```c
/* AUTO-GENERATED by defgen - DO NOT EDIT */

typedef enum {
    #define TOK(name, lex, kind, doc) C11_TOK_##name,
    C11_TOKENS(TOK)
    #undef TOK
    C11_TOK_COUNT
} C11TokenType;

static inline const char* c11_token_str(C11TokenType t) {
    switch(t) {
        #define TOK(name, lex, kind, doc) case C11_TOK_##name: return lex;
        C11_TOKENS(TOK)
        #undef TOK
    }
    return "<unknown>";
}

static inline const char* c11_token_doc(C11TokenType t) {
    switch(t) {
        #define TOK(name, lex, kind, doc) case C11_TOK_##name: return doc;
        C11_TOKENS(TOK)
        #undef TOK
    }
    return "";
}
```

---

## 9. Latency Comparison

| Approach | Ring | Compile | Diff | Total | Notes |
|----------|------|---------|------|-------|-------|
| Current (cosmocc full) | 0 | 200-400ms | 10ms | **~200-500ms** | Baseline |
| **Ring 0 AST (Lemon+lexgen)** | **0** | 10-20ms | 10-20ms | **~30-50ms** | **Recommended** |
| ccache hit | 1 | 0ms | 10ms | **~15-20ms** | Cache warm |
| Binaryen WASM (ludoplex) | 1 | 50ms | 5ms | **~60-80ms** | .com + .wasm |
| LLVM IR (clang) | 2 | 50ms | 10ms | **~70-100ms** | C++ dependency |
| ~~TinyCC (libtcc)~~ | ❌ | — | — | **N/A** | Incompatible |

> **Why no TinyCC?** TinyCC produces "Invalid relocation entry" errors when linking
> with `cosmopolitan.a`. This is a fundamental incompatibility - do not attempt.

> **Binaryen is OK:** Use `ludoplex/binaryen` fork which provides Cosmopolitan-
> compatible outputs (.com and .wasm). The WASM module can be embedded in ZipOS.

---

## 10. Build Integration

### Makefile Targets

```makefile
# Ring 0 generators for IR parsing
ir-gen: build/schemagen build/defgen build/lexgen build/lemon build/smgen
    ./build/schemagen specs/domain/c11_ast.schema gen/domain c11_ast
    ./build/defgen specs/parsing/c11_tokens.def gen/parsing c11
    ./build/lexgen specs/parsing/c11.lex gen/parsing c11
    ./build/lemon specs/parsing/c11.grammar
    mv c11_parse.c c11_parse.h gen/parsing/
    ./build/smgen specs/behavior/ast_diff.sm gen/behavior ast_diff
    ./build/smgen specs/behavior/ir_compile.sm gen/behavior ir_compile

# Build IR-based patching
ir-patch: ir-gen
    $(CC) -c gen/parsing/c11_lex.c -o build/c11_lex.o
    $(CC) -c gen/parsing/c11_parse.c -o build/c11_parse.o
    $(CC) -c gen/behavior/ast_diff_sm.c -o build/ast_diff_sm.o
    $(CC) -c src/e9patch/ir/ast_diff.c -o build/ast_diff.o
    $(CC) -c src/e9patch/ir/ir_codegen.c -o build/ir_codegen.o
    # Link into livereload

# Verify no drift
ir-verify: ir-gen
    git diff --exit-code gen/parsing/ gen/behavior/
```

### CI Integration

```yaml
# .github/workflows/repo-ci.yml
ir-parsing:
  name: IR Parsing (Ring 0)
  steps:
    - uses: actions/checkout@v4
    - name: Build generators
      run: make tools
    - name: Generate IR parsing code
      run: make ir-gen
    - name: Verify no drift
      run: make ir-verify
    - name: Build IR patching
      run: make ir-patch
    - name: Test AST diff
      run: ./build/test_ast_diff
```

---

## 11. C Version Configuration

### Runtime Selection

```c
/* In c11_parser.c */

typedef struct {
    int c_standard;  /* 89, 99, 11, 23 */

    /* Version-specific features */
    bool allow_inline;           /* C99+ */
    bool allow_restrict;         /* C99+ */
    bool allow_variadic_macros;  /* C99+ */
    bool allow_static_assert;    /* C11+ */
    bool allow_generic;          /* C11+ */
    bool allow_alignas;          /* C11+ */
    bool allow_nullptr;          /* C23+ */
    bool allow_true_false;       /* C23+ */
} C11ParserConfig;

/* Default: C11 for Cosmopolitan compatibility */
#define C11_PARSER_CONFIG_DEFAULT { \
    .c_standard = 11, \
    .allow_inline = true, \
    .allow_restrict = true, \
    .allow_variadic_macros = true, \
    .allow_static_assert = true, \
    .allow_generic = true, \
    .allow_alignas = true, \
    .allow_nullptr = false, \
    .allow_true_false = false, \
}

/* Initialize parser with C standard */
int c11_parser_init(C11ParseContext *ctx, int c_standard) {
    ctx->c_standard = c_standard;

    /* Configure lexer for this standard */
    c11_lex_set_standard(ctx->lexer, c_standard);

    return 0;
}
```

### Schema Version Directive

```
# In c11_ast.schema
@c_standard 11
@c_standard_features {
    "inline": 99,
    "restrict": 99,
    "_Static_assert": 11,
    "_Generic": 11,
    "_Alignas": 11,
    "_Alignof": 11,
    "nullptr": 23,
    "true": 23,
    "false": 23
}
```

---

## 12. Summary

**Full Ring 0 Dogfooding (Pure C, No C++ Required):**

| Component | Spec File | Generator | Output |
|-----------|-----------|-----------|--------|
| AST Types | c11_ast.schema | schemagen | c11_ast_types.c,h |
| Tokens | c11_tokens.def | defgen | c11_tokens.h |
| Lexer | c11.lex | lexgen | c11_lex.c,h |
| Parser | c11.grammar | lemon | c11_parse.c,h |
| Diff SM | ast_diff.sm | smgen | ast_diff_sm.c,h |
| Compile SM | ir_compile.sm | smgen | ir_compile_sm.c,h |
| Tests | ir_patch.feature | bddgen | ir_patch_bdd.c |

**Benefits:**
- **4-8x faster** than current approach (~30-50ms vs ~200-500ms)
- **Ring 0 only** - no external toolchains required
- **Pure C** - no C++ dependencies (Binaryen, libclang not needed)
- **Cosmopolitan compatible** - builds with cosmocc to APE
- **C version abstracted** - supports C89 through C23
- **Fully dogfooded** - uses CosmicRingForge generators
- **Drift-gated** - CI verifies generated code matches specs

**Tool Status:**
- ✅ **Binaryen** - OK via ludoplex/binaryen (.com + .wasm, embeddable in ZipOS)
- ✅ **Clang** - OK, cosmocc bundles Clang 19 (`-mclang` for 3x faster C++ compile)
- ❌ ~~TinyCC~~ - BANNED, incompatible with Cosmopolitan (relocation errors)
- ⚠️ ~~libclang~~ - Avoid, programmatic AST access has relocation issues (note: libclang ≠ clang)

---

*Generated for LLM reference. Part of CosmicRingForge/e9studio.*
