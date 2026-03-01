/*
 * e9analysis.h
 * Comprehensive Binary Analysis Engine for E9Studio
 *
 * Provides:
 * - Multi-architecture disassembly (x86-64, AArch64)
 * - Automatic symbol detection and injection
 * - Control Flow Graph (CFG) generation
 * - DWARF debug info parsing
 * - Decompilation to pseudo-C
 * - Source-to-binary mapping for live patching
 *
 * Inspired by Ghidra's analysis capabilities, designed for
 * embedded use in the e9studio APE with ZipOS integration.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9ANALYSIS_H
#define E9ANALYSIS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Supported architectures
 */
typedef enum {
    E9_ARCH_UNKNOWN = 0,
    E9_ARCH_X86_64,
    E9_ARCH_AARCH64,
    E9_ARCH_RISCV64,    /* Future */
} E9Arch;

/*
 * Binary format
 */
typedef enum {
    E9_FORMAT_UNKNOWN = 0,
    E9_FORMAT_ELF,
    E9_FORMAT_PE,
    E9_FORMAT_MACHO,
    E9_FORMAT_APE,      /* Actually Portable Executable (polyglot ELF+PE+shell) */
    E9_FORMAT_RAW,
} E9Format;

/*
 * Symbol types
 */
typedef enum {
    E9_SYM_UNKNOWN = 0,
    E9_SYM_FUNCTION,
    E9_SYM_GLOBAL_VAR,
    E9_SYM_LOCAL_VAR,
    E9_SYM_PARAMETER,
    E9_SYM_LABEL,
    E9_SYM_STRING,
    E9_SYM_VTABLE,
    E9_SYM_THUNK,
} E9SymbolType;

/*
 * Data types for decompilation
 */
typedef enum {
    E9_TYPE_VOID = 0,
    E9_TYPE_INT8,
    E9_TYPE_INT16,
    E9_TYPE_INT32,
    E9_TYPE_INT64,
    E9_TYPE_UINT8,
    E9_TYPE_UINT16,
    E9_TYPE_UINT32,
    E9_TYPE_UINT64,
    E9_TYPE_FLOAT,
    E9_TYPE_DOUBLE,
    E9_TYPE_POINTER,
    E9_TYPE_ARRAY,
    E9_TYPE_STRUCT,
    E9_TYPE_UNION,
    E9_TYPE_FUNCTION,
    E9_TYPE_UNKNOWN,
} E9DataType;

/*
 * Instruction categories for analysis
 */
typedef enum {
    E9_INSN_OTHER = 0,
    E9_INSN_CALL,
    E9_INSN_JUMP,
    E9_INSN_COND_JUMP,
    E9_INSN_RET,
    E9_INSN_SYSCALL,
    E9_INSN_NOP,
    E9_INSN_PUSH,
    E9_INSN_POP,
    E9_INSN_MOV,
    E9_INSN_LEA,
    E9_INSN_ARITHMETIC,
    E9_INSN_COMPARE,
    E9_INSN_SHIFT,
    E9_INSN_LOGICAL,
    E9_INSN_LOAD,
    E9_INSN_STORE,
    E9_INSN_SIMD,
} E9InsnCategory;

/*
 * Forward declarations
 */
typedef struct E9Binary E9Binary;
typedef struct E9Symbol E9Symbol;
typedef struct E9Function E9Function;
typedef struct E9BasicBlock E9BasicBlock;
typedef struct E9Instruction E9Instruction;
typedef struct E9CFG E9CFG;
typedef struct E9Type E9Type;
typedef struct E9Variable E9Variable;
typedef struct E9SourceMapping E9SourceMapping;

/*
 * Decoded instruction
 */
struct E9Instruction {
    uint64_t address;           /* Virtual address */
    uint32_t size;              /* Instruction size in bytes */
    uint8_t bytes[16];          /* Raw instruction bytes */

    E9InsnCategory category;    /* Instruction category */
    char mnemonic[16];          /* Mnemonic string */
    char operands[128];         /* Operand string */

    /* Control flow targets */
    uint64_t target;            /* Direct target (if applicable) */
    bool target_is_indirect;    /* Is target computed? */
    bool is_conditional;        /* Conditional execution? */

    /* Register usage (bitmap) */
    uint32_t regs_read;
    uint32_t regs_written;

    /* Memory access */
    bool reads_memory;
    bool writes_memory;
    int64_t mem_displacement;

    /* Links */
    E9Instruction *next;        /* Next instruction in sequence */
    E9BasicBlock *block;        /* Containing basic block */
};

/*
 * Basic block in CFG
 */
struct E9BasicBlock {
    uint32_t id;                /* Block ID */
    uint64_t start_addr;        /* Start address */
    uint64_t end_addr;          /* End address (exclusive) */

    E9Instruction *first;       /* First instruction */
    E9Instruction *last;        /* Last instruction */
    uint32_t num_insns;         /* Number of instructions */

    /* CFG edges */
    E9BasicBlock **predecessors;
    uint32_t num_preds;
    E9BasicBlock **successors;
    uint32_t num_succs;

    /* Analysis results */
    uint32_t dominates;         /* Dominator tree info */
    uint32_t post_dominates;
    uint32_t loop_depth;        /* Nesting depth in loops */
    bool is_loop_header;

    /* Decompilation */
    char *pseudo_c;             /* Generated C code for block */
    E9Variable **live_in;       /* Variables live at entry */
    E9Variable **live_out;      /* Variables live at exit */

    E9Function *function;       /* Containing function */
};

/*
 * Control Flow Graph
 */
struct E9CFG {
    E9BasicBlock **blocks;      /* All basic blocks */
    uint32_t num_blocks;

    E9BasicBlock *entry;        /* Entry block */
    E9BasicBlock **exits;       /* Exit blocks */
    uint32_t num_exits;

    /* Computed properties */
    bool is_reducible;          /* Reducible CFG? */
    uint32_t cyclomatic_complexity;
};

/*
 * Function representation
 */
struct E9Function {
    char *name;                 /* Function name (may be auto-generated) */
    uint64_t address;           /* Entry point address */
    uint64_t end_address;       /* End address (heuristic) */
    uint32_t size;              /* Size in bytes */

    E9CFG *cfg;                 /* Control flow graph */
    E9Type *return_type;        /* Return type */
    E9Type **param_types;       /* Parameter types */
    char **param_names;         /* Parameter names */
    uint32_t num_params;

    /* Stack frame */
    int32_t stack_size;         /* Stack frame size */
    E9Variable **locals;        /* Local variables */
    uint32_t num_locals;

    /* Calling convention */
    enum {
        E9_CC_UNKNOWN,
        E9_CC_SYSV_AMD64,       /* System V AMD64 ABI */
        E9_CC_MS_X64,           /* Microsoft x64 */
        E9_CC_AAPCS64,          /* ARM64 AAPCS */
    } calling_convention;

    /* Analysis flags */
    bool is_leaf;               /* No calls to other functions? */
    bool is_recursive;          /* Calls itself? */
    bool is_variadic;           /* Variable arguments? */
    bool is_noreturn;           /* Never returns? */
    bool is_thunk;              /* Simple jump wrapper? */

    /* Decompilation output */
    char *decompiled_c;         /* Full C code */
    char *signature;            /* Function signature */

    /* Source mapping (if DWARF available) */
    char *source_file;
    uint32_t source_line;

    E9Symbol *symbol;           /* Associated symbol */
    E9Function *next;           /* Linked list */
};

/*
 * Symbol information
 */
struct E9Symbol {
    char *name;                 /* Symbol name */
    char *demangled;            /* Demangled name (C++) */
    uint64_t address;           /* Address */
    uint64_t size;              /* Size (if known) */
    E9SymbolType type;          /* Symbol type */

    /* Source info (from DWARF) */
    char *source_file;
    uint32_t source_line;
    uint32_t source_column;

    /* Type info */
    E9Type *data_type;

    /* Flags */
    bool is_external;           /* Defined externally? */
    bool is_weak;               /* Weak symbol? */
    bool is_static;             /* Static/local? */

    E9Symbol *next;
};

/*
 * Type representation
 */
struct E9Type {
    E9DataType kind;
    char *name;                 /* Type name */
    uint32_t size;              /* Size in bytes */
    uint32_t alignment;         /* Alignment */

    union {
        struct {                /* Pointer */
            E9Type *pointee;
        } ptr;
        struct {                /* Array */
            E9Type *element;
            uint32_t count;
        } array;
        struct {                /* Struct/Union */
            char **field_names;
            E9Type **field_types;
            uint32_t *field_offsets;
            uint32_t num_fields;
        } composite;
        struct {                /* Function */
            E9Type *return_type;
            E9Type **param_types;
            uint32_t num_params;
            bool is_variadic;
        } func;
    };
};

/*
 * Variable (local or global)
 */
struct E9Variable {
    char *name;
    E9Type *type;
    int32_t stack_offset;       /* For locals: offset from frame base */
    uint64_t address;           /* For globals: address */
    int reg;                    /* If in register: register number */

    /* Liveness */
    uint64_t def_addr;          /* Where defined */
    uint64_t last_use_addr;     /* Where last used */
};

/*
 * Source-to-binary mapping
 */
struct E9SourceMapping {
    char *source_file;
    uint32_t line;
    uint32_t column;
    uint64_t address;
    uint32_t size;              /* Size of code for this line */

    E9SourceMapping *next;
};

/*
 * Binary analysis context
 */
struct E9Binary {
    /* Input */
    const uint8_t *data;        /* Binary data */
    size_t size;                /* Size */
    uint64_t base_address;      /* Load address */

    /* Detected properties */
    E9Arch arch;
    E9Format format;
    bool is_pie;                /* Position independent? */
    bool has_debug_info;        /* DWARF present? */

    /* Entry points */
    uint64_t entry_point;       /* Main entry */
    uint64_t *init_array;       /* Constructors */
    uint32_t num_init;
    uint64_t *fini_array;       /* Destructors */
    uint32_t num_fini;

    /* Sections */
    struct {
        uint64_t addr;
        uint64_t size;
        uint32_t flags;
        char name[32];
    } *sections;
    uint32_t num_sections;

    /* Analysis results */
    E9Symbol *symbols;          /* Symbol table */
    uint32_t num_symbols;

    E9Function *functions;      /* Discovered functions */
    uint32_t num_functions;

    E9SourceMapping *mappings;  /* Source mappings */
    uint32_t num_mappings;

    /* String table */
    struct {
        uint64_t addr;
        char *value;
    } *strings;
    uint32_t num_strings;

    /* Cross-references */
    struct {
        uint64_t from;
        uint64_t to;
        enum { XREF_CALL, XREF_JUMP, XREF_DATA } type;
    } *xrefs;
    uint32_t num_xrefs;

    /* APE-specific layout (for E9_FORMAT_APE) */
    struct {
        uint64_t shell_offset;      /* Shell script shebang location */
        uint64_t shell_size;
        uint64_t elf_offset;        /* ELF header offset */
        uint64_t elf_size;
        uint64_t pe_offset;         /* PE header offset */
        uint64_t pe_size;
        uint64_t macho_offset;      /* Mach-O offset (if present) */
        uint64_t macho_size;
        uint64_t zipos_start;       /* ZipOS local file headers */
        uint64_t zipos_central_dir; /* ZipOS central directory */
        uint64_t zipos_end;         /* ZipOS end of central directory */
        uint32_t zipos_num_entries;
    } ape;
};

/*
 * ============================================================================
 * Analysis API
 * ============================================================================
 */

/*
 * Create binary analysis context from data in memory
 */
E9Binary *e9_binary_create(const uint8_t *data, size_t size);

/*
 * Open binary from file path
 */
E9Binary *e9_binary_open(const char *path);

/*
 * Free binary analysis context
 */
void e9_binary_free(E9Binary *bin);

/*
 * Detect architecture and format
 */
int e9_binary_detect(E9Binary *bin);

/*
 * Run full analysis pipeline
 */
int e9_binary_analyze(E9Binary *bin);

/*
 * ============================================================================
 * Disassembly
 * ============================================================================
 */

/*
 * Disassemble single instruction (allocates)
 * Note: Named differently from e9vendor's e9_disasm_one to avoid conflict
 */
E9Instruction *e9_disasm_instruction(E9Binary *bin, uint64_t addr);

/*
 * Disassemble single instruction into provided struct
 * Returns 0 on success, -1 on error
 */
int e9_disasm(E9Binary *bin, uint64_t addr, E9Instruction *insn);

/*
 * Disassemble range of addresses
 */
E9Instruction *e9_disasm_range(E9Binary *bin, uint64_t start, uint64_t end);

/*
 * Get disassembly string for instruction
 */
const char *e9_disasm_str(E9Binary *bin, E9Instruction *insn, char *buf, size_t bufsize);

/*
 * ============================================================================
 * Symbol Analysis
 * ============================================================================
 */

/*
 * Parse symbols from binary (ELF symtab, DWARF, etc.)
 */
int e9_symbols_parse(E9Binary *bin);

/*
 * Add custom symbol
 */
E9Symbol *e9_symbol_add(E9Binary *bin, const char *name, uint64_t addr,
                        E9SymbolType type);

/*
 * Find symbol by address
 */
E9Symbol *e9_symbol_at(E9Binary *bin, uint64_t addr);

/*
 * Find symbol by name
 */
E9Symbol *e9_symbol_by_name(E9Binary *bin, const char *name);

/*
 * Auto-generate symbols for discovered functions
 */
int e9_symbols_auto(E9Binary *bin);

/*
 * Export symbols to file (for injection into other tools)
 */
int e9_symbols_export(E9Binary *bin, const char *path, const char *format);

/*
 * Import symbols from file
 */
int e9_symbols_import(E9Binary *bin, const char *path);

/*
 * ============================================================================
 * Function Discovery
 * ============================================================================
 */

/*
 * Discover functions using multiple heuristics
 */
int e9_functions_discover(E9Binary *bin);

/*
 * Add function manually
 */
E9Function *e9_function_add(E9Binary *bin, uint64_t addr, const char *name);

/*
 * Find function containing address
 */
E9Function *e9_function_at(E9Binary *bin, uint64_t addr);

/*
 * Get function by name
 */
E9Function *e9_function_by_name(E9Binary *bin, const char *name);

/*
 * ============================================================================
 * CFG Construction
 * ============================================================================
 */

/*
 * Build CFG for function
 */
E9CFG *e9_cfg_build(E9Binary *bin, E9Function *func);

/*
 * Free CFG
 */
void e9_cfg_free(E9CFG *cfg);

/*
 * Export CFG to DOT format (for visualization)
 */
int e9_cfg_to_dot(E9CFG *cfg, const char *path);

/*
 * ============================================================================
 * Decompilation
 * ============================================================================
 */

/*
 * Decompile function to C
 */
char *e9_decompile_function(E9Binary *bin, E9Function *func);

/*
 * Decompile basic block to C
 */
char *e9_decompile_block(E9Binary *bin, E9BasicBlock *block);

/*
 * Generate C header for binary (types, function prototypes)
 */
char *e9_generate_header(E9Binary *bin);

/*
 * Generate complete C source approximation
 */
char *e9_generate_source(E9Binary *bin);

/*
 * ============================================================================
 * DWARF Debug Info
 * ============================================================================
 */

/*
 * Parse DWARF debug info
 */
int e9_dwarf_parse(E9Binary *bin);

/*
 * Get source location for address
 */
int e9_dwarf_addr_to_line(E9Binary *bin, uint64_t addr,
                          char *file, size_t file_size,
                          uint32_t *line, uint32_t *column);

/*
 * Get address for source location
 */
int e9_dwarf_line_to_addr(E9Binary *bin, const char *file, uint32_t line,
                          uint64_t *addr, uint32_t *size);

/*
 * Get variable info at address
 */
E9Variable *e9_dwarf_get_variable(E9Binary *bin, uint64_t addr,
                                   const char *name);

/*
 * ============================================================================
 * Source Mapping & Live Patching
 * ============================================================================
 */

/*
 * Build source-to-binary mapping
 */
int e9_mapping_build(E9Binary *bin);

/*
 * Find binary range for source line
 */
int e9_mapping_line_to_range(E9Binary *bin, const char *file, uint32_t line,
                              uint64_t *start, uint64_t *end);

/*
 * Compare old and new object files, generate patch list
 */
typedef struct {
    uint64_t address;           /* Address to patch */
    uint8_t *old_bytes;         /* Original bytes */
    uint8_t *new_bytes;         /* Replacement bytes */
    uint32_t size;              /* Size of patch */
    char *description;          /* Human-readable description */
} E9Patch;

typedef struct {
    E9Patch *patches;
    uint32_t num_patches;
    char *error;                /* Error message if failed */
} E9PatchSet;

E9PatchSet *e9_diff_objects(const uint8_t *old_obj, size_t old_size,
                            const uint8_t *new_obj, size_t new_size);

void e9_patchset_free(E9PatchSet *ps);

/*
 * ============================================================================
 * Architecture-Specific
 * ============================================================================
 */

/* x86-64 specific */
typedef enum {
    E9_REG_X64_RAX, E9_REG_X64_RBX, E9_REG_X64_RCX, E9_REG_X64_RDX,
    E9_REG_X64_RSI, E9_REG_X64_RDI, E9_REG_X64_RBP, E9_REG_X64_RSP,
    E9_REG_X64_R8,  E9_REG_X64_R9,  E9_REG_X64_R10, E9_REG_X64_R11,
    E9_REG_X64_R12, E9_REG_X64_R13, E9_REG_X64_R14, E9_REG_X64_R15,
    E9_REG_X64_RIP, E9_REG_X64_RFLAGS,
    E9_REG_X64_COUNT
} E9RegX64;

/* AArch64 specific */
typedef enum {
    E9_REG_A64_X0,  E9_REG_A64_X1,  E9_REG_A64_X2,  E9_REG_A64_X3,
    E9_REG_A64_X4,  E9_REG_A64_X5,  E9_REG_A64_X6,  E9_REG_A64_X7,
    E9_REG_A64_X8,  E9_REG_A64_X9,  E9_REG_A64_X10, E9_REG_A64_X11,
    E9_REG_A64_X12, E9_REG_A64_X13, E9_REG_A64_X14, E9_REG_A64_X15,
    E9_REG_A64_X16, E9_REG_A64_X17, E9_REG_A64_X18, E9_REG_A64_X19,
    E9_REG_A64_X20, E9_REG_A64_X21, E9_REG_A64_X22, E9_REG_A64_X23,
    E9_REG_A64_X24, E9_REG_A64_X25, E9_REG_A64_X26, E9_REG_A64_X27,
    E9_REG_A64_X28, E9_REG_A64_X29, E9_REG_A64_X30, E9_REG_A64_SP,
    E9_REG_A64_PC,  E9_REG_A64_NZCV,
    E9_REG_A64_COUNT
} E9RegA64;

/*
 * Get register name string
 */
const char *e9_reg_name(E9Arch arch, int reg);

/*
 * Get calling convention argument registers
 */
const int *e9_cc_arg_regs(E9Arch arch, int calling_convention, int *count);

/*
 * Get calling convention return register
 */
int e9_cc_ret_reg(E9Arch arch, int calling_convention);

/*
 * ============================================================================
 * APE (Actually Portable Executable) Support
 * ============================================================================
 */

/*
 * Detect if binary is APE format
 */
bool e9_binary_is_ape(const uint8_t *data, size_t size);

/*
 * Parse APE layout into E9Binary.ape struct
 */
int e9_binary_parse_ape(E9Binary *bin);

/*
 * Get the ELF view of an APE binary (for ELF-specific operations)
 * Returns a temporary E9Binary pointing into the APE's ELF section
 */
E9Binary *e9_ape_get_elf_view(E9Binary *bin);

/*
 * Get the PE view of an APE binary (for PE-specific operations)
 * Returns a temporary E9Binary pointing into the APE's PE section
 */
E9Binary *e9_ape_get_pe_view(E9Binary *bin);

/*
 * Free an APE view obtained from e9_ape_get_*_view()
 */
void e9_ape_free_view(E9Binary *view);

/*
 * Apply a patch to APE binary, updating both ELF and PE views
 * This ensures cross-platform consistency of patches
 */
int e9_ape_patch_sync(E9Binary *bin, uint64_t vaddr,
                      const uint8_t *bytes, size_t size);

/*
 * Extract ZipOS contents from APE
 */
int e9_ape_zipos_list(E9Binary *bin, char ***entries, uint32_t *count);

/*
 * Extract a specific file from APE's ZipOS
 */
uint8_t *e9_ape_zipos_extract(E9Binary *bin, const char *path, size_t *size);

/*
 * Update a file in APE's ZipOS (for in-place ZipOS editing)
 */
int e9_ape_zipos_update(E9Binary *bin, const char *path,
                        const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* E9ANALYSIS_H */
