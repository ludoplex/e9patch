/*
 * e9analysis.c
 * Comprehensive Binary Analysis Engine for E9Studio
 *
 * Implementation of multi-arch disassembly, symbol detection,
 * CFG generation, DWARF parsing, and decompilation.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include "e9analysis.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* Note: When building with cosmocc, cosmopolitan libc is automatically provided.
 * No need to include cosmopolitan.h - it's only for amalgamation builds. */

/*
 * ============================================================================
 * Internal Structures and Constants
 * ============================================================================
 */

/* ELF magic numbers and constants */
#define ELF_MAGIC       "\x7f" "ELF"
#define ELF_CLASS_64    2
#define ELF_DATA_LSB    1
#define ELF_MACHINE_X64 0x3E
#define ELF_MACHINE_AARCH64 0xB7

/* PE magic numbers */
#define PE_DOS_MAGIC    0x5A4D  /* MZ */
#define PE_NT_MAGIC     0x00004550  /* PE\0\0 */
#define PE_MACHINE_AMD64 0x8664
#define PE_MACHINE_ARM64 0xAA64

/* Mach-O magic numbers */
#define MACHO_MAGIC_64  0xFEEDFACF
#define MACHO_CIGAM_64  0xCFFAEDFE
#define MACHO_CPU_X64   0x01000007
#define MACHO_CPU_ARM64 0x0100000C

/* Analysis limits */
#define MAX_FUNCTIONS       65536
#define MAX_SYMBOLS         262144
#define MAX_BASIC_BLOCKS    1048576
#define MAX_INSN_SIZE       16
#define MAX_STRING_LEN      4096

/* x86-64 instruction prefixes */
#define X64_PREFIX_REX      0x40
#define X64_PREFIX_REX_W    0x48

/* x86-64 opcodes */
#define X64_OP_CALL_REL     0xE8
#define X64_OP_JMP_REL      0xE9
#define X64_OP_JMP_SHORT    0xEB
#define X64_OP_RET          0xC3
#define X64_OP_RET_IMM      0xC2
#define X64_OP_NOP          0x90
#define X64_OP_INT3         0xCC
#define X64_OP_PUSH_RBP     0x55
#define X64_OP_MOV_RBP_RSP  0x89  /* 48 89 E5 */
#define X64_OP_TWO_BYTE     0x0F

/* x86-64 conditional jumps (0F 8x) */
#define X64_OP_JCC_BASE     0x80

/* AArch64 instruction masks */
#define A64_MASK_BL         0xFC000000
#define A64_OP_BL           0x94000000
#define A64_MASK_B          0xFC000000
#define A64_OP_B            0x14000000
#define A64_MASK_RET        0xFFFFFC1F
#define A64_OP_RET          0xD65F0000
#define A64_MASK_CBZ        0x7F000000
#define A64_OP_CBZ          0x34000000
#define A64_MASK_TBZ        0x7F000000
#define A64_OP_TBZ          0x36000000
#define A64_MASK_BCOND      0xFF000010
#define A64_OP_BCOND        0x54000000

/*
 * ============================================================================
 * Internal Helper Prototypes
 * ============================================================================
 */

static int detect_elf(E9Binary *bin);
static int detect_pe(E9Binary *bin);
static int detect_macho(E9Binary *bin);
static int detect_ape(E9Binary *bin);

static int parse_elf_symbols(E9Binary *bin);
static int parse_pe_symbols(E9Binary *bin);
static int parse_macho_symbols(E9Binary *bin);

static E9Instruction *disasm_x64(E9Binary *bin, uint64_t addr);
static E9Instruction *disasm_aarch64(E9Binary *bin, uint64_t addr);

static int discover_functions_linear(E9Binary *bin);
static int discover_functions_recursive(E9Binary *bin, uint64_t start);
static int discover_functions_heuristic(E9Binary *bin);

static void analyze_function_bounds(E9Binary *bin, E9Function *func);
static void analyze_calling_convention(E9Binary *bin, E9Function *func);

/*
 * ============================================================================
 * Memory Management
 * ============================================================================
 */

static void *e9_alloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "e9analysis: allocation failed (%zu bytes)\n", size);
    }
    return p;
}

static void e9_free(void *ptr)
{
    free(ptr);
}

static void *e9_realloc(void *ptr, size_t size)
{
    void *p = realloc(ptr, size);
    if (!p && size > 0) {
        fprintf(stderr, "e9analysis: reallocation failed (%zu bytes)\n", size);
    }
    return p;
}

static char *e9_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *p = (char *)e9_alloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

/*
 * ============================================================================
 * Binary Context Creation/Destruction
 * ============================================================================
 */

E9Binary *e9_binary_create(const uint8_t *data, size_t size)
{
    if (!data || size < 16) {
        return NULL;
    }

    E9Binary *bin = (E9Binary *)e9_alloc(sizeof(E9Binary));
    if (!bin) return NULL;

    bin->data = data;
    bin->size = size;
    bin->arch = E9_ARCH_UNKNOWN;
    bin->format = E9_FORMAT_UNKNOWN;

    return bin;
}

void e9_binary_free(E9Binary *bin)
{
    if (!bin) return;

    /* Free symbols */
    E9Symbol *sym = bin->symbols;
    while (sym) {
        E9Symbol *next = sym->next;
        free(sym->name);
        free(sym->demangled);
        free(sym->source_file);
        free(sym);
        sym = next;
    }

    /* Free functions */
    E9Function *func = bin->functions;
    while (func) {
        E9Function *next = func->next;
        free(func->name);
        free(func->signature);
        free(func->decompiled_c);
        free(func->source_file);
        if (func->cfg) {
            e9_cfg_free(func->cfg);
        }
        free(func);
        func = next;
    }

    /* Free source mappings */
    E9SourceMapping *map = bin->mappings;
    while (map) {
        E9SourceMapping *next = map->next;
        free(map->source_file);
        free(map);
        map = next;
    }

    /* Free sections */
    free(bin->sections);

    /* Free strings */
    if (bin->strings) {
        for (uint32_t i = 0; i < bin->num_strings; i++) {
            free(bin->strings[i].value);
        }
        free(bin->strings);
    }

    /* Free xrefs */
    free(bin->xrefs);

    /* Free init/fini arrays */
    free(bin->init_array);
    free(bin->fini_array);

    free(bin);
}

E9Binary *e9_binary_open(const char *path)
{
    if (!path) return NULL;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "e9analysis: cannot open '%s'\n", path);
        return NULL;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0 || size > 1024 * 1024 * 1024) {  /* 1GB limit */
        fprintf(stderr, "e9analysis: invalid file size\n");
        fclose(fp);
        return NULL;
    }

    /* Allocate buffer */
    uint8_t *data = (uint8_t *)malloc((size_t)size);
    if (!data) {
        fprintf(stderr, "e9analysis: allocation failed\n");
        fclose(fp);
        return NULL;
    }

    /* Read file */
    if (fread(data, 1, (size_t)size, fp) != (size_t)size) {
        fprintf(stderr, "e9analysis: read error\n");
        free(data);
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    /* Create binary context */
    E9Binary *bin = e9_binary_create(data, (size_t)size);
    if (!bin) {
        free(data);
        return NULL;
    }

    /* Auto-detect format */
    e9_binary_detect(bin);

    return bin;
}

/*
 * ============================================================================
 * Format and Architecture Detection
 * ============================================================================
 */

int e9_binary_detect(E9Binary *bin)
{
    if (!bin || !bin->data || bin->size < 16) {
        return -1;
    }

    const uint8_t *data = bin->data;

    /* Check APE first - APE binaries are polyglot MZ+ELF+PE+shell */
    if (e9_binary_is_ape(data, bin->size)) {
        return detect_ape(bin);
    }

    /* Check ELF */
    if (memcmp(data, ELF_MAGIC, 4) == 0) {
        return detect_elf(bin);
    }

    /* Check PE (DOS header) */
    if (data[0] == 'M' && data[1] == 'Z') {
        return detect_pe(bin);
    }

    /* Check Mach-O */
    uint32_t magic = *(uint32_t *)data;
    if (magic == MACHO_MAGIC_64 || magic == MACHO_CIGAM_64) {
        return detect_macho(bin);
    }

    /* Raw binary - try heuristics */
    bin->format = E9_FORMAT_RAW;

    /* Check for x86-64 prolog pattern */
    if (data[0] == 0x55 && data[1] == 0x48 && data[2] == 0x89) {
        bin->arch = E9_ARCH_X86_64;
        return 0;
    }

    /* Check for AArch64 pattern */
    uint32_t insn = *(uint32_t *)data;
    if ((insn & 0x7F800000) == 0x29000000 ||  /* STP */
        (insn & 0xFFE00000) == 0xD1000000) {  /* SUB SP */
        bin->arch = E9_ARCH_AARCH64;
        return 0;
    }

    bin->arch = E9_ARCH_UNKNOWN;
    return 0;
}

static int detect_elf(E9Binary *bin)
{
    const uint8_t *data = bin->data;

    if (bin->size < 64) return -1;

    /* Verify 64-bit */
    if (data[4] != ELF_CLASS_64) {
        fprintf(stderr, "e9analysis: only 64-bit ELF supported\n");
        return -1;
    }

    bin->format = E9_FORMAT_ELF;

    /* Get machine type */
    uint16_t machine = *(uint16_t *)(data + 18);
    switch (machine) {
        case ELF_MACHINE_X64:
            bin->arch = E9_ARCH_X86_64;
            break;
        case ELF_MACHINE_AARCH64:
            bin->arch = E9_ARCH_AARCH64;
            break;
        default:
            bin->arch = E9_ARCH_UNKNOWN;
            break;
    }

    /* Get entry point */
    bin->entry_point = *(uint64_t *)(data + 24);

    /* Check for PIE (ET_DYN = 3) */
    uint16_t e_type = *(uint16_t *)(data + 16);
    bin->is_pie = (e_type == 3);

    /* Parse section headers for .debug* presence */
    uint64_t shoff = *(uint64_t *)(data + 40);
    uint16_t shentsize = *(uint16_t *)(data + 58);
    uint16_t shnum = *(uint16_t *)(data + 60);
    uint16_t shstrndx = *(uint16_t *)(data + 62);

    if (shoff && shnum && shstrndx < shnum && shoff + shnum * shentsize <= bin->size) {
        /* Get string table */
        const uint8_t *shstrtab_hdr = data + shoff + shstrndx * shentsize;
        uint64_t strtab_off = *(uint64_t *)(shstrtab_hdr + 24);
        uint64_t strtab_size = *(uint64_t *)(shstrtab_hdr + 32);

        if (strtab_off + strtab_size <= bin->size) {
            const char *strtab = (const char *)(data + strtab_off);

            /* Count sections and look for debug info */
            bin->sections = e9_alloc(shnum * sizeof(*bin->sections));
            bin->num_sections = 0;

            for (uint16_t i = 0; i < shnum; i++) {
                const uint8_t *shdr = data + shoff + i * shentsize;
                uint32_t name_off = *(uint32_t *)shdr;
                uint64_t addr = *(uint64_t *)(shdr + 16);
                uint64_t size = *(uint64_t *)(shdr + 32);
                uint64_t flags = *(uint64_t *)(shdr + 8);

                if (name_off < strtab_size) {
                    const char *name = strtab + name_off;
                    if (strncmp(name, ".debug", 6) == 0) {
                        bin->has_debug_info = true;
                    }

                    if (bin->sections && bin->num_sections < shnum) {
                        bin->sections[bin->num_sections].addr = addr;
                        bin->sections[bin->num_sections].size = size;
                        bin->sections[bin->num_sections].flags = (uint32_t)flags;
                        strncpy(bin->sections[bin->num_sections].name, name, 31);
                        bin->num_sections++;
                    }
                }
            }
        }
    }

    return 0;
}

static int detect_pe(E9Binary *bin)
{
    const uint8_t *data = bin->data;

    if (bin->size < 64) return -1;

    /* Get PE header offset from DOS header */
    uint32_t pe_off = *(uint32_t *)(data + 0x3C);
    if (pe_off + 24 > bin->size) return -1;

    /* Verify PE signature */
    if (memcmp(data + pe_off, "PE\0\0", 4) != 0) {
        return -1;
    }

    bin->format = E9_FORMAT_PE;

    /* Get machine type */
    uint16_t machine = *(uint16_t *)(data + pe_off + 4);
    switch (machine) {
        case PE_MACHINE_AMD64:
            bin->arch = E9_ARCH_X86_64;
            break;
        case PE_MACHINE_ARM64:
            bin->arch = E9_ARCH_AARCH64;
            break;
        default:
            bin->arch = E9_ARCH_UNKNOWN;
            break;
    }

    /* Get optional header to find entry point */
    uint16_t opt_hdr_size = *(uint16_t *)(data + pe_off + 20);
    if (pe_off + 24 + opt_hdr_size <= bin->size) {
        const uint8_t *opt_hdr = data + pe_off + 24;
        uint16_t magic = *(uint16_t *)opt_hdr;

        if (magic == 0x20B) {  /* PE32+ */
            bin->entry_point = *(uint32_t *)(opt_hdr + 16);
            bin->base_address = *(uint64_t *)(opt_hdr + 24);
        }
    }

    return 0;
}

static int detect_macho(E9Binary *bin)
{
    const uint8_t *data = bin->data;
    uint32_t magic = *(uint32_t *)data;
    bool swap = (magic == MACHO_CIGAM_64);

    bin->format = E9_FORMAT_MACHO;

    /* Read header (64-bit only) */
    uint32_t cputype = *(uint32_t *)(data + 4);
    if (swap) cputype = __builtin_bswap32(cputype);

    switch (cputype) {
        case MACHO_CPU_X64:
            bin->arch = E9_ARCH_X86_64;
            break;
        case MACHO_CPU_ARM64:
            bin->arch = E9_ARCH_AARCH64;
            break;
        default:
            bin->arch = E9_ARCH_UNKNOWN;
            break;
    }

    /* Get number of load commands */
    uint32_t ncmds = *(uint32_t *)(data + 16);
    if (swap) ncmds = __builtin_bswap32(ncmds);

    /* Parse load commands for entry point and segments */
    uint64_t offset = 32;  /* After mach_header_64 */
    for (uint32_t i = 0; i < ncmds && offset + 8 <= bin->size; i++) {
        uint32_t cmd = *(uint32_t *)(data + offset);
        uint32_t cmdsize = *(uint32_t *)(data + offset + 4);
        if (swap) {
            cmd = __builtin_bswap32(cmd);
            cmdsize = __builtin_bswap32(cmdsize);
        }

        /* LC_MAIN = 0x28 | LC_REQ_DYLD */
        if ((cmd & 0xFF) == 0x28 && offset + 24 <= bin->size) {
            bin->entry_point = *(uint64_t *)(data + offset + 8);
            if (swap) bin->entry_point = __builtin_bswap64(bin->entry_point);
        }

        /* LC_SEGMENT_64 = 0x19 */
        if (cmd == 0x19 && offset + 72 <= bin->size) {
            const char *segname = (const char *)(data + offset + 8);
            if (strcmp(segname, "__TEXT") == 0) {
                bin->base_address = *(uint64_t *)(data + offset + 24);
                if (swap) bin->base_address = __builtin_bswap64(bin->base_address);
            }
        }

        offset += cmdsize;
    }

    return 0;
}

/*
 * ============================================================================
 * APE (Actually Portable Executable) Detection and Parsing
 * ============================================================================
 */

/*
 * APE magic: starts with 'MZqFpD' (DOS MZ header with special signature)
 * or 'jartsr' shell script prefix followed by binary bootstrap
 */
#define APE_MAGIC_MZ    "MZqFpD"
#define APE_MAGIC_SHELL "jartsr"

bool e9_binary_is_ape(const uint8_t *data, size_t size)
{
    if (!data || size < 64) return false;

    /* Check for APE MZ signature (most common) */
    if (memcmp(data, APE_MAGIC_MZ, 6) == 0) {
        return true;
    }

    /* Check for shell script APE variant */
    if (data[0] == '#' && data[1] == '!') {
        /* Look for embedded ELF and PE in first 64KB */
        size_t scan_limit = (size < 65536) ? size : 65536;
        bool has_elf = false, has_pe = false;

        for (size_t i = 0; i < scan_limit - 4; i++) {
            if (!has_elf && memcmp(data + i, "\x7fELF", 4) == 0) {
                has_elf = true;
            }
            if (!has_pe && data[i] == 'M' && data[i+1] == 'Z') {
                /* Check if there's a PE signature */
                if (i + 64 < size) {
                    uint32_t pe_off = *(uint32_t *)(data + i + 0x3C);
                    if (i + pe_off + 4 < size &&
                        memcmp(data + i + pe_off, "PE\0\0", 4) == 0) {
                        has_pe = true;
                    }
                }
            }
            if (has_elf && has_pe) return true;
        }
    }

    /* Check for standard MZ that also contains ELF (APE polyglot) */
    if (data[0] == 'M' && data[1] == 'Z') {
        /* Look for ELF header within first 4KB */
        for (size_t i = 64; i < 4096 && i + 4 < size; i++) {
            if (memcmp(data + i, "\x7fELF", 4) == 0) {
                return true;  /* MZ + ELF = APE */
            }
        }
    }

    return false;
}

static int detect_ape(E9Binary *bin)
{
    const uint8_t *data = bin->data;
    size_t size = bin->size;

    bin->format = E9_FORMAT_APE;

    /* Parse APE layout */
    memset(&bin->ape, 0, sizeof(bin->ape));

    /* Find shell script offset */
    if (data[0] == '#' && data[1] == '!') {
        bin->ape.shell_offset = 0;
        /* Find end of shell portion (look for binary data) */
        for (size_t i = 0; i < size && i < 4096; i++) {
            if (data[i] == 0x7f && i + 4 < size &&
                memcmp(data + i, "\x7fELF", 4) == 0) {
                bin->ape.shell_size = i;
                break;
            }
        }
    }

    /* Find ELF header */
    for (size_t i = 0; i < size - 4 && i < 65536; i++) {
        if (memcmp(data + i, "\x7fELF", 4) == 0) {
            bin->ape.elf_offset = i;

            /* Parse ELF to get size and entry point */
            if (i + 64 < size && data[i + 4] == 2) {  /* 64-bit */
                uint64_t entry = *(uint64_t *)(data + i + 24);
                bin->entry_point = entry;

                uint64_t phoff = *(uint64_t *)(data + i + 32);
                uint16_t phnum = *(uint16_t *)(data + i + 56);

                /* Calculate ELF size from program headers */
                uint64_t max_end = 0;
                for (uint16_t j = 0; j < phnum && i + phoff + 56 <= size; j++) {
                    uint64_t p_offset = *(uint64_t *)(data + i + phoff + j * 56 + 8);
                    uint64_t p_filesz = *(uint64_t *)(data + i + phoff + j * 56 + 32);
                    if (p_offset + p_filesz > max_end) {
                        max_end = p_offset + p_filesz;
                    }
                }
                bin->ape.elf_size = max_end;

                /* Get architecture from ELF */
                uint16_t machine = *(uint16_t *)(data + i + 18);
                switch (machine) {
                    case ELF_MACHINE_X64:
                        bin->arch = E9_ARCH_X86_64;
                        break;
                    case ELF_MACHINE_AARCH64:
                        bin->arch = E9_ARCH_AARCH64;
                        break;
                    default:
                        bin->arch = E9_ARCH_UNKNOWN;
                }
            }
            break;
        }
    }

    /* Find PE header */
    for (size_t i = 0; i < size - 64; i++) {
        if (data[i] == 'M' && data[i+1] == 'Z') {
            uint32_t pe_off = *(uint32_t *)(data + i + 0x3C);
            if (i + pe_off + 4 < size &&
                memcmp(data + i + pe_off, "PE\0\0", 4) == 0) {
                bin->ape.pe_offset = i;

                /* Calculate PE size from section table */
                uint16_t num_sections = *(uint16_t *)(data + i + pe_off + 6);
                uint16_t opt_hdr_size = *(uint16_t *)(data + i + pe_off + 20);
                size_t sec_table = i + pe_off + 24 + opt_hdr_size;

                uint32_t max_end = 0;
                for (uint16_t j = 0; j < num_sections && sec_table + 40 <= size; j++) {
                    uint32_t raw_ptr = *(uint32_t *)(data + sec_table + 20);
                    uint32_t raw_size = *(uint32_t *)(data + sec_table + 16);
                    if (raw_ptr + raw_size > max_end) {
                        max_end = raw_ptr + raw_size;
                    }
                    sec_table += 40;
                }
                bin->ape.pe_size = max_end;
                break;
            }
        }
    }

    /* Find ZipOS (ZIP central directory at end) */
    for (size_t i = size - 22; i > 0 && i > size - 65536; i--) {
        if (data[i] == 'P' && data[i+1] == 'K' &&
            data[i+2] == 0x05 && data[i+3] == 0x06) {
            bin->ape.zipos_end = i + 22;
            bin->ape.zipos_num_entries = *(uint16_t *)(data + i + 10);
            bin->ape.zipos_central_dir = *(uint32_t *)(data + i + 16);

            /* Find first local file header */
            for (size_t j = 0; j < bin->ape.zipos_central_dir && j + 4 < size; j++) {
                if (data[j] == 'P' && data[j+1] == 'K' &&
                    data[j+2] == 0x03 && data[j+3] == 0x04) {
                    bin->ape.zipos_start = j;
                    break;
                }
            }
            break;
        }
    }

    /* If no entry point from ELF, use base address heuristic */
    if (bin->entry_point == 0) {
        bin->entry_point = 0x400000;  /* Common Linux base */
    }
    if (bin->base_address == 0) {
        bin->base_address = 0x400000;
    }

    return 0;
}

int e9_binary_parse_ape(E9Binary *bin)
{
    if (!bin || bin->format != E9_FORMAT_APE) {
        return -1;
    }
    /* Layout already parsed in detect_ape */
    return 0;
}

E9Binary *e9_ape_get_elf_view(E9Binary *bin)
{
    if (!bin || bin->format != E9_FORMAT_APE || bin->ape.elf_offset == 0) {
        return NULL;
    }

    E9Binary *view = e9_alloc(sizeof(E9Binary));
    if (!view) return NULL;

    view->data = bin->data + bin->ape.elf_offset;
    view->size = bin->ape.elf_size;
    view->base_address = bin->base_address;
    view->arch = bin->arch;
    view->format = E9_FORMAT_ELF;

    /* Re-detect to populate sections etc. */
    detect_elf(view);

    return view;
}

E9Binary *e9_ape_get_pe_view(E9Binary *bin)
{
    if (!bin || bin->format != E9_FORMAT_APE || bin->ape.pe_offset == 0) {
        return NULL;
    }

    E9Binary *view = e9_alloc(sizeof(E9Binary));
    if (!view) return NULL;

    view->data = bin->data + bin->ape.pe_offset;
    view->size = bin->ape.pe_size;
    view->base_address = bin->base_address;
    view->arch = bin->arch;
    view->format = E9_FORMAT_PE;

    /* Re-detect to populate sections etc. */
    detect_pe(view);

    return view;
}

void e9_ape_free_view(E9Binary *view)
{
    if (view) {
        /* Don't free data - it's a pointer into parent APE */
        e9_free(view);
    }
}

int e9_ape_patch_sync(E9Binary *bin, uint64_t vaddr,
                      const uint8_t *bytes, size_t size)
{
    if (!bin || bin->format != E9_FORMAT_APE || !bytes) {
        return -1;
    }

    /* Convert vaddr to file offsets in both ELF and PE sections */
    /* For APE, the same virtual address appears at different file offsets
     * in the ELF and PE views. We need to patch both. */

    /* TODO: Implement proper vaddr to offset translation for both views */
    /* For now, we patch at the raw offset in the ELF view only */

    /* This is a placeholder - full implementation requires understanding
     * the relationship between ELF and PE virtual address spaces in APE */

    return -1;  /* Not fully implemented yet */
}

/*
 * ============================================================================
 * Full Analysis Pipeline
 * ============================================================================
 */

int e9_binary_analyze(E9Binary *bin)
{
    if (!bin) return -1;

    /* Step 1: Detect format and architecture */
    if (e9_binary_detect(bin) != 0) {
        return -1;
    }

    if (bin->arch == E9_ARCH_UNKNOWN) {
        fprintf(stderr, "e9analysis: unknown architecture\n");
        return -1;
    }

    /* Step 2: Parse symbols */
    e9_symbols_parse(bin);

    /* Step 3: Discover functions */
    e9_functions_discover(bin);

    /* Step 4: Build CFGs for each function */
    E9Function *func = bin->functions;
    while (func) {
        func->cfg = e9_cfg_build(bin, func);
        analyze_calling_convention(bin, func);
        func = func->next;
    }

    /* Step 5: Parse DWARF if available */
    if (bin->has_debug_info) {
        e9_dwarf_parse(bin);
    }

    /* Step 6: Auto-generate missing symbols */
    e9_symbols_auto(bin);

    /* Step 7: Build source mappings */
    e9_mapping_build(bin);

    return 0;
}

/*
 * ============================================================================
 * Disassembly - x86-64
 * ============================================================================
 */

/* Simple x86-64 length decoder */
static int x64_insn_length(const uint8_t *code, size_t max_len)
{
    if (max_len == 0) return 0;

    size_t pos = 0;
    bool has_rex = false;
    bool has_modrm = false;

    /* Skip prefixes */
    while (pos < max_len) {
        uint8_t b = code[pos];
        if (b == 0x66 || b == 0x67 || b == 0xF0 ||
            b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E ||
            b == 0x26 || b == 0x64 || b == 0x65) {
            pos++;
        } else if ((b & 0xF0) == 0x40) {  /* REX prefix */
            has_rex = true;
            pos++;
        } else {
            break;
        }
    }

    if (pos >= max_len) return (int)pos;

    uint8_t opcode = code[pos++];

    /* Two-byte opcode */
    if (opcode == 0x0F) {
        if (pos >= max_len) return (int)pos;
        opcode = code[pos++];

        /* Three-byte opcodes */
        if (opcode == 0x38 || opcode == 0x3A) {
            if (pos >= max_len) return (int)pos;
            pos++;
            has_modrm = true;
        } else {
            /* Most 0F xx opcodes have ModR/M */
            has_modrm = true;
        }
    } else {
        /* Single-byte opcode analysis */
        switch (opcode) {
            /* No operands */
            case 0x90: case 0xC3: case 0xCB: case 0xCC:
            case 0xF4: case 0xF5: case 0xFC: case 0xFD:
                return (int)pos;

            /* imm8 */
            case 0x04: case 0x0C: case 0x14: case 0x1C:
            case 0x24: case 0x2C: case 0x34: case 0x3C:
            case 0x6A: case 0xA8: case 0xB0: case 0xB1:
            case 0xB2: case 0xB3: case 0xB4: case 0xB5:
            case 0xB6: case 0xB7: case 0xCD: case 0xD4:
            case 0xD5: case 0xE4: case 0xE5: case 0xE6:
            case 0xE7: case 0xEB:
                return (int)(pos + 1);

            /* imm16/32 */
            case 0x05: case 0x0D: case 0x15: case 0x1D:
            case 0x25: case 0x2D: case 0x35: case 0x3D:
            case 0x68: case 0xA9: case 0xE8: case 0xE9:
                return (int)(pos + 4);

            /* imm64 (with REX.W) */
            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                return has_rex ? (int)(pos + 8) : (int)(pos + 4);

            /* ret imm16 */
            case 0xC2: case 0xCA:
                return (int)(pos + 2);

            /* Conditional jumps (short) */
            case 0x70: case 0x71: case 0x72: case 0x73:
            case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x78: case 0x79: case 0x7A: case 0x7B:
            case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            case 0xE0: case 0xE1: case 0xE2: case 0xE3:
                return (int)(pos + 1);

            default:
                has_modrm = true;
                break;
        }
    }

    /* Parse ModR/M if needed */
    if (has_modrm && pos < max_len) {
        uint8_t modrm = code[pos++];
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t rm = modrm & 7;

        /* SIB byte */
        if (mod != 3 && rm == 4 && pos < max_len) {
            pos++;  /* SIB */
        }

        /* Displacement */
        if (mod == 1) {
            pos += 1;  /* disp8 */
        } else if (mod == 2 || (mod == 0 && rm == 5)) {
            pos += 4;  /* disp32 */
        }

        /* Immediate (estimate based on opcode) */
        if (opcode >= 0x80 && opcode <= 0x83) {
            pos += (opcode == 0x81) ? 4 : 1;
        }
    }

    return (int)pos;
}

static E9Instruction *disasm_x64(E9Binary *bin, uint64_t addr)
{
    /* Convert address to offset */
    uint64_t offset;
    if (bin->base_address && addr >= bin->base_address) {
        offset = addr - bin->base_address;
    } else {
        offset = addr;
    }

    if (offset >= bin->size) return NULL;

    const uint8_t *code = bin->data + offset;
    size_t max_len = bin->size - offset;
    if (max_len > MAX_INSN_SIZE) max_len = MAX_INSN_SIZE;

    int len = x64_insn_length(code, max_len);
    if (len <= 0 || (size_t)len > max_len) return NULL;

    E9Instruction *insn = (E9Instruction *)e9_alloc(sizeof(E9Instruction));
    if (!insn) return NULL;

    insn->address = addr;
    insn->size = len;
    memcpy(insn->bytes, code, len);

    /* Decode instruction category and operands */
    size_t pos = 0;

    /* Skip prefixes */
    while (pos < (size_t)len && ((code[pos] & 0xF0) == 0x40 ||
           code[pos] == 0x66 || code[pos] == 0x67 ||
           code[pos] == 0xF2 || code[pos] == 0xF3 ||
           code[pos] == 0x2E || code[pos] == 0x36)) {
        pos++;
    }

    if (pos >= (size_t)len) {
        insn->category = E9_INSN_OTHER;
        strcpy(insn->mnemonic, "???");
        return insn;
    }

    uint8_t opcode = code[pos];

    /* Categorize and decode */
    switch (opcode) {
        case 0xC3:
        case 0xCB:
            insn->category = E9_INSN_RET;
            strcpy(insn->mnemonic, "ret");
            break;

        case 0xC2:
        case 0xCA:
            insn->category = E9_INSN_RET;
            strcpy(insn->mnemonic, "ret");
            if (pos + 3 <= (size_t)len) {
                uint16_t imm = *(uint16_t *)(code + pos + 1);
                snprintf(insn->operands, sizeof(insn->operands), "0x%x", imm);
            }
            break;

        case 0xE8:  /* call rel32 */
            insn->category = E9_INSN_CALL;
            strcpy(insn->mnemonic, "call");
            if (pos + 5 <= (size_t)len) {
                int32_t rel = *(int32_t *)(code + pos + 1);
                insn->target = addr + len + rel;
                snprintf(insn->operands, sizeof(insn->operands), "0x%lx", insn->target);
            }
            break;

        case 0xE9:  /* jmp rel32 */
            insn->category = E9_INSN_JUMP;
            strcpy(insn->mnemonic, "jmp");
            if (pos + 5 <= (size_t)len) {
                int32_t rel = *(int32_t *)(code + pos + 1);
                insn->target = addr + len + rel;
                snprintf(insn->operands, sizeof(insn->operands), "0x%lx", insn->target);
            }
            break;

        case 0xEB:  /* jmp rel8 */
            insn->category = E9_INSN_JUMP;
            strcpy(insn->mnemonic, "jmp");
            if (pos + 2 <= (size_t)len) {
                int8_t rel = (int8_t)code[pos + 1];
                insn->target = addr + len + rel;
                snprintf(insn->operands, sizeof(insn->operands), "0x%lx", insn->target);
            }
            break;

        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            {
                static const char *jcc_names[] = {
                    "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
                    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
                };
                insn->category = E9_INSN_COND_JUMP;
                insn->is_conditional = true;
                strcpy(insn->mnemonic, jcc_names[opcode - 0x70]);
                if (pos + 2 <= (size_t)len) {
                    int8_t rel = (int8_t)code[pos + 1];
                    insn->target = addr + len + rel;
                    snprintf(insn->operands, sizeof(insn->operands), "0x%lx", insn->target);
                }
            }
            break;

        case 0x90:
            insn->category = E9_INSN_NOP;
            strcpy(insn->mnemonic, "nop");
            break;

        case 0xCC:
            insn->category = E9_INSN_OTHER;
            strcpy(insn->mnemonic, "int3");
            break;

        case 0x0F:
            if (pos + 1 < (size_t)len) {
                uint8_t op2 = code[pos + 1];
                if (op2 >= 0x80 && op2 <= 0x8F) {
                    /* Conditional jump (near) */
                    static const char *jcc_names[] = {
                        "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
                        "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
                    };
                    insn->category = E9_INSN_COND_JUMP;
                    insn->is_conditional = true;
                    strcpy(insn->mnemonic, jcc_names[op2 - 0x80]);
                    if (pos + 6 <= (size_t)len) {
                        int32_t rel = *(int32_t *)(code + pos + 2);
                        insn->target = addr + len + rel;
                        snprintf(insn->operands, sizeof(insn->operands), "0x%lx", insn->target);
                    }
                } else if (op2 == 0x05) {
                    insn->category = E9_INSN_SYSCALL;
                    strcpy(insn->mnemonic, "syscall");
                } else {
                    insn->category = E9_INSN_OTHER;
                    snprintf(insn->mnemonic, sizeof(insn->mnemonic), "0f%02x", op2);
                }
            }
            break;

        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
            insn->category = E9_INSN_PUSH;
            strcpy(insn->mnemonic, "push");
            {
                static const char *regs[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};
                strcpy(insn->operands, regs[opcode - 0x50]);
            }
            break;

        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            insn->category = E9_INSN_POP;
            strcpy(insn->mnemonic, "pop");
            {
                static const char *regs[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};
                strcpy(insn->operands, regs[opcode - 0x58]);
            }
            break;

        default:
            insn->category = E9_INSN_OTHER;
            snprintf(insn->mnemonic, sizeof(insn->mnemonic), "op%02x", opcode);
            break;
    }

    return insn;
}

/*
 * ============================================================================
 * Disassembly - AArch64
 * ============================================================================
 */

static E9Instruction *disasm_aarch64(E9Binary *bin, uint64_t addr)
{
    /* Convert address to offset */
    uint64_t offset;
    if (bin->base_address && addr >= bin->base_address) {
        offset = addr - bin->base_address;
    } else {
        offset = addr;
    }

    if (offset + 4 > bin->size) return NULL;

    const uint8_t *code = bin->data + offset;
    uint32_t insn_word = *(uint32_t *)code;

    E9Instruction *insn = (E9Instruction *)e9_alloc(sizeof(E9Instruction));
    if (!insn) return NULL;

    insn->address = addr;
    insn->size = 4;  /* All AArch64 instructions are 4 bytes */
    memcpy(insn->bytes, code, 4);

    /* Decode instruction category */
    if ((insn_word & A64_MASK_BL) == A64_OP_BL) {
        /* BL - branch with link (call) */
        insn->category = E9_INSN_CALL;
        strcpy(insn->mnemonic, "bl");
        int32_t imm = (insn_word & 0x03FFFFFF);
        if (imm & 0x02000000) imm |= 0xFC000000;  /* Sign extend */
        insn->target = addr + (imm << 2);
        snprintf(insn->operands, sizeof(insn->operands), "0x%lx", insn->target);
    }
    else if ((insn_word & A64_MASK_B) == A64_OP_B) {
        /* B - unconditional branch */
        insn->category = E9_INSN_JUMP;
        strcpy(insn->mnemonic, "b");
        int32_t imm = (insn_word & 0x03FFFFFF);
        if (imm & 0x02000000) imm |= 0xFC000000;
        insn->target = addr + (imm << 2);
        snprintf(insn->operands, sizeof(insn->operands), "0x%lx", insn->target);
    }
    else if ((insn_word & A64_MASK_RET) == A64_OP_RET) {
        /* RET */
        insn->category = E9_INSN_RET;
        strcpy(insn->mnemonic, "ret");
    }
    else if ((insn_word & A64_MASK_BCOND) == A64_OP_BCOND) {
        /* B.cond - conditional branch */
        static const char *cond_names[] = {
            "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
            "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
        };
        insn->category = E9_INSN_COND_JUMP;
        insn->is_conditional = true;
        uint8_t cond = insn_word & 0xF;
        snprintf(insn->mnemonic, sizeof(insn->mnemonic), "b.%s", cond_names[cond]);
        int32_t imm = (insn_word >> 5) & 0x7FFFF;
        if (imm & 0x40000) imm |= 0xFFF80000;
        insn->target = addr + (imm << 2);
        snprintf(insn->operands, sizeof(insn->operands), "0x%lx", insn->target);
    }
    else if ((insn_word & A64_MASK_CBZ) == A64_OP_CBZ) {
        /* CBZ/CBNZ */
        insn->category = E9_INSN_COND_JUMP;
        insn->is_conditional = true;
        bool is_cbnz = (insn_word >> 24) & 1;
        strcpy(insn->mnemonic, is_cbnz ? "cbnz" : "cbz");
        int32_t imm = (insn_word >> 5) & 0x7FFFF;
        if (imm & 0x40000) imm |= 0xFFF80000;
        insn->target = addr + (imm << 2);
        uint8_t rt = insn_word & 0x1F;
        bool is_64 = (insn_word >> 31) & 1;
        snprintf(insn->operands, sizeof(insn->operands), "%c%d, 0x%lx",
                 is_64 ? 'x' : 'w', rt, insn->target);
    }
    else if ((insn_word & A64_MASK_TBZ) == A64_OP_TBZ) {
        /* TBZ/TBNZ */
        insn->category = E9_INSN_COND_JUMP;
        insn->is_conditional = true;
        bool is_tbnz = (insn_word >> 24) & 1;
        strcpy(insn->mnemonic, is_tbnz ? "tbnz" : "tbz");
        int32_t imm = (insn_word >> 5) & 0x3FFF;
        if (imm & 0x2000) imm |= 0xFFFFC000;
        insn->target = addr + (imm << 2);
        snprintf(insn->operands, sizeof(insn->operands), "0x%lx", insn->target);
    }
    else if ((insn_word & 0xFC000000) == 0xD4000000) {
        /* SVC - supervisor call */
        insn->category = E9_INSN_SYSCALL;
        strcpy(insn->mnemonic, "svc");
        uint16_t imm = (insn_word >> 5) & 0xFFFF;
        snprintf(insn->operands, sizeof(insn->operands), "#0x%x", imm);
    }
    else if ((insn_word & 0x1F000000) == 0x10000000) {
        /* ADR/ADRP */
        insn->category = E9_INSN_LEA;
        bool is_adrp = (insn_word >> 31) & 1;
        strcpy(insn->mnemonic, is_adrp ? "adrp" : "adr");
    }
    else if ((insn_word & 0x3B000000) == 0x39000000) {
        /* LDR/STR (immediate) */
        bool is_load = (insn_word >> 22) & 1;
        insn->category = is_load ? E9_INSN_LOAD : E9_INSN_STORE;
        strcpy(insn->mnemonic, is_load ? "ldr" : "str");
        insn->reads_memory = is_load;
        insn->writes_memory = !is_load;
    }
    else if ((insn_word & 0x7F800000) == 0x29000000 ||
             (insn_word & 0x7F800000) == 0x28000000) {
        /* STP/LDP */
        bool is_load = (insn_word >> 22) & 1;
        insn->category = is_load ? E9_INSN_LOAD : E9_INSN_STORE;
        strcpy(insn->mnemonic, is_load ? "ldp" : "stp");
    }
    else if ((insn_word & 0xFF000000) == 0xD1000000 ||
             (insn_word & 0xFF000000) == 0x91000000) {
        /* SUB/ADD (immediate) */
        insn->category = E9_INSN_ARITHMETIC;
        bool is_sub = (insn_word >> 30) & 1;
        strcpy(insn->mnemonic, is_sub ? "sub" : "add");
    }
    else if ((insn_word & 0xFFFFFFFF) == 0xD503201F) {
        /* NOP */
        insn->category = E9_INSN_NOP;
        strcpy(insn->mnemonic, "nop");
    }
    else {
        insn->category = E9_INSN_OTHER;
        snprintf(insn->mnemonic, sizeof(insn->mnemonic), "0x%08x", insn_word);
    }

    return insn;
}

/*
 * ============================================================================
 * Disassembly API
 * ============================================================================
 */

E9Instruction *e9_disasm_instruction(E9Binary *bin, uint64_t addr)
{
    if (!bin) return NULL;

    switch (bin->arch) {
        case E9_ARCH_X86_64:
            return disasm_x64(bin, addr);
        case E9_ARCH_AARCH64:
            return disasm_aarch64(bin, addr);
        default:
            return NULL;
    }
}

E9Instruction *e9_disasm_range(E9Binary *bin, uint64_t start, uint64_t end)
{
    if (!bin || start >= end) return NULL;

    E9Instruction *head = NULL;
    E9Instruction *tail = NULL;
    uint64_t addr = start;

    while (addr < end) {
        E9Instruction *insn = e9_disasm_instruction(bin, addr);
        if (!insn) break;

        if (!head) {
            head = insn;
        } else {
            tail->next = insn;
        }
        tail = insn;

        addr += insn->size;
    }

    return head;
}

int e9_disasm(E9Binary *bin, uint64_t addr, E9Instruction *insn)
{
    if (!bin || !insn) return -1;

    E9Instruction *tmp = e9_disasm_instruction(bin, addr);
    if (!tmp) return -1;

    /* Copy to provided struct */
    *insn = *tmp;
    insn->next = NULL;  /* Don't copy linked list pointer */
    insn->block = NULL;

    /* Free the temporary allocation */
    free(tmp);

    return 0;
}

const char *e9_disasm_str(E9Binary *bin, E9Instruction *insn, char *buf, size_t bufsize)
{
    if (!insn || !buf || bufsize == 0) return "";

    /* Format: address: bytes  mnemonic operands */
    char bytes_str[48];
    size_t pos = 0;
    for (uint32_t i = 0; i < insn->size && i < 8; i++) {
        pos += snprintf(bytes_str + pos, sizeof(bytes_str) - pos, "%02x ", insn->bytes[i]);
    }

    snprintf(buf, bufsize, "%016lx: %-24s %s %s",
             insn->address, bytes_str, insn->mnemonic, insn->operands);

    return buf;
}

/*
 * ============================================================================
 * Symbol Parsing
 * ============================================================================
 */

int e9_symbols_parse(E9Binary *bin)
{
    if (!bin) return -1;

    switch (bin->format) {
        case E9_FORMAT_ELF:
            return parse_elf_symbols(bin);
        case E9_FORMAT_PE:
            return parse_pe_symbols(bin);
        case E9_FORMAT_MACHO:
            return parse_macho_symbols(bin);
        default:
            return 0;  /* No symbols for raw */
    }
}

static int parse_elf_symbols(E9Binary *bin)
{
    const uint8_t *data = bin->data;

    /* Get section header info */
    uint64_t shoff = *(uint64_t *)(data + 40);
    uint16_t shentsize = *(uint16_t *)(data + 58);
    uint16_t shnum = *(uint16_t *)(data + 60);
    uint16_t shstrndx = *(uint16_t *)(data + 62);

    if (!shoff || !shnum || shoff + shnum * shentsize > bin->size) {
        return 0;
    }

    /* Get section name string table */
    const uint8_t *shstrtab_hdr = data + shoff + shstrndx * shentsize;
    uint64_t shstrtab_off = *(uint64_t *)(shstrtab_hdr + 24);
    const char *shstrtab = (const char *)(data + shstrtab_off);

    /* Find .symtab and .strtab (or .dynsym/.dynstr) */
    uint64_t symtab_off = 0, symtab_size = 0;
    uint64_t strtab_off = 0;
    uint32_t symtab_entsize = 24;  /* Elf64_Sym size */

    for (uint16_t i = 0; i < shnum; i++) {
        const uint8_t *shdr = data + shoff + i * shentsize;
        uint32_t sh_type = *(uint32_t *)(shdr + 4);
        uint32_t sh_name = *(uint32_t *)shdr;
        const char *name = shstrtab + sh_name;

        /* SHT_SYMTAB = 2, SHT_DYNSYM = 11 */
        if (sh_type == 2 || (sh_type == 11 && !symtab_off)) {
            symtab_off = *(uint64_t *)(shdr + 24);
            symtab_size = *(uint64_t *)(shdr + 32);
            symtab_entsize = *(uint32_t *)(shdr + 56);
            uint32_t link = *(uint32_t *)(shdr + 40);

            /* Get linked string table */
            if (link < shnum) {
                const uint8_t *strtab_hdr = data + shoff + link * shentsize;
                strtab_off = *(uint64_t *)(strtab_hdr + 24);
            }
        }
    }

    if (!symtab_off || !strtab_off) {
        return 0;  /* No symbol table */
    }

    const char *strtab = (const char *)(data + strtab_off);
    uint32_t num_syms = symtab_size / symtab_entsize;

    for (uint32_t i = 0; i < num_syms; i++) {
        const uint8_t *sym = data + symtab_off + i * symtab_entsize;
        uint32_t st_name = *(uint32_t *)sym;
        uint8_t st_info = sym[4];
        uint64_t st_value = *(uint64_t *)(sym + 8);
        uint64_t st_size = *(uint64_t *)(sym + 16);

        if (st_name == 0 || st_value == 0) continue;

        const char *name = strtab + st_name;
        if (!name[0]) continue;

        E9Symbol *symbol = (E9Symbol *)e9_alloc(sizeof(E9Symbol));
        if (!symbol) continue;

        symbol->name = e9_strdup(name);
        symbol->address = st_value;
        symbol->size = st_size;

        /* Determine symbol type from ELF st_info */
        uint8_t type = st_info & 0xF;
        uint8_t bind = st_info >> 4;

        switch (type) {
            case 2:  /* STT_FUNC */
                symbol->type = E9_SYM_FUNCTION;
                break;
            case 1:  /* STT_OBJECT */
                symbol->type = E9_SYM_GLOBAL_VAR;
                break;
            default:
                symbol->type = E9_SYM_UNKNOWN;
                break;
        }

        symbol->is_weak = (bind == 2);  /* STB_WEAK */
        symbol->is_external = (bind == 1);  /* STB_GLOBAL */

        /* Add to list */
        symbol->next = bin->symbols;
        bin->symbols = symbol;
        bin->num_symbols++;
    }

    return 0;
}

static int parse_pe_symbols(E9Binary *bin)
{
    /* PE export table parsing */
    const uint8_t *data = bin->data;
    uint32_t pe_off = *(uint32_t *)(data + 0x3C);

    /* Get optional header */
    uint16_t opt_magic = *(uint16_t *)(data + pe_off + 24);
    if (opt_magic != 0x20B) return 0;  /* Not PE32+ */

    /* Export directory RVA is at offset 112 in optional header */
    uint32_t export_rva = *(uint32_t *)(data + pe_off + 24 + 112);
    uint32_t export_size = *(uint32_t *)(data + pe_off + 24 + 116);

    if (!export_rva || !export_size) return 0;

    /* TODO: Parse export table */
    /* This requires RVA-to-file-offset conversion which needs section parsing */

    return 0;
}

static int parse_macho_symbols(E9Binary *bin)
{
    /* TODO: Parse Mach-O symbol table (LC_SYMTAB) */
    return 0;
}

E9Symbol *e9_symbol_add(E9Binary *bin, const char *name, uint64_t addr, E9SymbolType type)
{
    if (!bin || !name) return NULL;

    E9Symbol *sym = (E9Symbol *)e9_alloc(sizeof(E9Symbol));
    if (!sym) return NULL;

    sym->name = e9_strdup(name);
    sym->address = addr;
    sym->type = type;

    sym->next = bin->symbols;
    bin->symbols = sym;
    bin->num_symbols++;

    return sym;
}

E9Symbol *e9_symbol_at(E9Binary *bin, uint64_t addr)
{
    if (!bin) return NULL;

    E9Symbol *sym = bin->symbols;
    while (sym) {
        if (sym->address == addr) return sym;
        if (sym->size && addr >= sym->address && addr < sym->address + sym->size) {
            return sym;
        }
        sym = sym->next;
    }
    return NULL;
}

E9Symbol *e9_symbol_by_name(E9Binary *bin, const char *name)
{
    if (!bin || !name) return NULL;

    E9Symbol *sym = bin->symbols;
    while (sym) {
        if (sym->name && strcmp(sym->name, name) == 0) return sym;
        if (sym->demangled && strcmp(sym->demangled, name) == 0) return sym;
        sym = sym->next;
    }
    return NULL;
}

int e9_symbols_auto(E9Binary *bin)
{
    if (!bin) return -1;

    /* Generate symbols for functions without names */
    E9Function *func = bin->functions;
    while (func) {
        if (!func->symbol) {
            char name[64];
            snprintf(name, sizeof(name), "sub_%lx", func->address);
            E9Symbol *sym = e9_symbol_add(bin, name, func->address, E9_SYM_FUNCTION);
            if (sym) {
                sym->size = func->size;
                func->symbol = sym;
                func->name = e9_strdup(name);
            }
        }
        func = func->next;
    }

    return 0;
}

int e9_symbols_export(E9Binary *bin, const char *path, const char *format)
{
    if (!bin || !path) return -1;

    FILE *fp = fopen(path, "w");
    if (!fp) return -1;

    if (!format || strcmp(format, "ghidra") == 0) {
        /* Ghidra CSV format */
        fprintf(fp, "Name,Address,Size,Type\n");
        E9Symbol *sym = bin->symbols;
        while (sym) {
            fprintf(fp, "%s,0x%lx,%lu,%d\n",
                    sym->name ? sym->name : "",
                    sym->address, sym->size, sym->type);
            sym = sym->next;
        }
    } else if (strcmp(format, "ida") == 0) {
        /* IDA Pro script format */
        E9Symbol *sym = bin->symbols;
        while (sym) {
            fprintf(fp, "MakeName(0x%lx, \"%s\");\n",
                    sym->address, sym->name ? sym->name : "");
            sym = sym->next;
        }
    }

    fclose(fp);
    return 0;
}

int e9_symbols_import(E9Binary *bin, const char *path)
{
    if (!bin || !path) return -1;

    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char name[256];
        uint64_t addr;
        int type = E9_SYM_UNKNOWN;

        /* Try parsing as CSV */
        if (sscanf(line, "%255[^,],%lx,%*u,%d", name, &addr, &type) >= 2) {
            e9_symbol_add(bin, name, addr, (E9SymbolType)type);
        }
    }

    fclose(fp);
    return 0;
}

/*
 * ============================================================================
 * Function Discovery
 * ============================================================================
 */

int e9_functions_discover(E9Binary *bin)
{
    if (!bin) return -1;

    /* Method 1: From symbols */
    E9Symbol *sym = bin->symbols;
    while (sym) {
        if (sym->type == E9_SYM_FUNCTION) {
            E9Function *func = e9_function_add(bin, sym->address, sym->name);
            if (func) {
                func->symbol = sym;
                func->size = sym->size;
            }
        }
        sym = sym->next;
    }

    /* Method 2: From entry point */
    if (bin->entry_point) {
        discover_functions_recursive(bin, bin->entry_point);
    }

    /* Method 3: Heuristic scan for function prologues */
    discover_functions_heuristic(bin);

    return 0;
}

static int discover_functions_recursive(E9Binary *bin, uint64_t start)
{
    /* Check if already discovered */
    if (e9_function_at(bin, start)) {
        return 0;
    }

    E9Function *func = e9_function_add(bin, start, NULL);
    if (!func) return -1;

    /* Disassemble and follow calls */
    uint64_t addr = start;
    uint64_t max_addr = start + 0x10000;  /* Limit search */

    while (addr < max_addr) {
        E9Instruction *insn = e9_disasm_instruction(bin, addr);
        if (!insn) break;

        if (insn->category == E9_INSN_RET) {
            func->end_address = addr + insn->size;
            free(insn);
            break;
        }

        if (insn->category == E9_INSN_CALL && !insn->target_is_indirect) {
            /* Recursively discover called function */
            discover_functions_recursive(bin, insn->target);
        }

        if (insn->category == E9_INSN_JUMP && !insn->is_conditional) {
            /* Tail call or jump - may end function */
            if (insn->target < start || insn->target > start + 0x10000) {
                func->end_address = addr + insn->size;
                free(insn);
                break;
            }
        }

        addr += insn->size;
        free(insn);
    }

    if (!func->end_address) {
        func->end_address = addr;
    }
    func->size = func->end_address - func->address;

    return 0;
}

static int discover_functions_heuristic(E9Binary *bin)
{
    if (!bin || bin->format == E9_FORMAT_RAW) return 0;

    /* Scan .text section for function prologues */
    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (strcmp(bin->sections[i].name, ".text") != 0) continue;

        uint64_t addr = bin->sections[i].addr;
        uint64_t end = addr + bin->sections[i].size;

        while (addr < end) {
            /* Check if already have function here */
            if (e9_function_at(bin, addr)) {
                addr += 16;  /* Skip to next potential function */
                continue;
            }

            /* Convert to offset */
            uint64_t offset;
            if (bin->base_address) {
                offset = addr - bin->base_address;
            } else {
                offset = addr;
            }
            if (offset + 16 > bin->size) break;

            const uint8_t *code = bin->data + offset;

            bool is_prologue = false;

            if (bin->arch == E9_ARCH_X86_64) {
                /* Check for push rbp; mov rbp, rsp */
                if (code[0] == 0x55 &&
                    code[1] == 0x48 && code[2] == 0x89 && code[3] == 0xE5) {
                    is_prologue = true;
                }
                /* Check for sub rsp, imm */
                else if (code[0] == 0x48 && code[1] == 0x83 && code[2] == 0xEC) {
                    is_prologue = true;
                }
                /* Check for push r12-r15 (common in System V) */
                else if ((code[0] == 0x41 && (code[1] >= 0x54 && code[1] <= 0x57))) {
                    is_prologue = true;
                }
            }
            else if (bin->arch == E9_ARCH_AARCH64) {
                uint32_t insn_word = *(uint32_t *)code;
                /* Check for STP x29, x30, [sp, #-N]! */
                if ((insn_word & 0xFFE00000) == 0xA9800000) {
                    uint8_t rt = insn_word & 0x1F;
                    uint8_t rt2 = (insn_word >> 10) & 0x1F;
                    if (rt == 29 && rt2 == 30) {
                        is_prologue = true;
                    }
                }
            }

            if (is_prologue) {
                discover_functions_recursive(bin, addr);
            }

            addr += (bin->arch == E9_ARCH_AARCH64) ? 4 : 1;
        }
    }

    return 0;
}

E9Function *e9_function_add(E9Binary *bin, uint64_t addr, const char *name)
{
    if (!bin) return NULL;

    /* Check for duplicate */
    E9Function *existing = e9_function_at(bin, addr);
    if (existing && existing->address == addr) {
        return existing;
    }

    E9Function *func = (E9Function *)e9_alloc(sizeof(E9Function));
    if (!func) return NULL;

    func->address = addr;
    if (name) {
        func->name = e9_strdup(name);
    }

    func->next = bin->functions;
    bin->functions = func;
    bin->num_functions++;

    return func;
}

E9Function *e9_function_at(E9Binary *bin, uint64_t addr)
{
    if (!bin) return NULL;

    E9Function *func = bin->functions;
    while (func) {
        if (func->address == addr) return func;
        if (func->end_address &&
            addr >= func->address && addr < func->end_address) {
            return func;
        }
        func = func->next;
    }
    return NULL;
}

E9Function *e9_function_by_name(E9Binary *bin, const char *name)
{
    if (!bin || !name) return NULL;

    E9Function *func = bin->functions;
    while (func) {
        if (func->name && strcmp(func->name, name) == 0) return func;
        func = func->next;
    }
    return NULL;
}

/*
 * ============================================================================
 * CFG Construction
 * ============================================================================
 */

E9CFG *e9_cfg_build(E9Binary *bin, E9Function *func)
{
    if (!bin || !func) return NULL;

    E9CFG *cfg = (E9CFG *)e9_alloc(sizeof(E9CFG));
    if (!cfg) return NULL;

    /* Allocate block array */
    uint32_t max_blocks = 1024;
    cfg->blocks = (E9BasicBlock **)e9_alloc(max_blocks * sizeof(E9BasicBlock *));
    if (!cfg->blocks) {
        free(cfg);
        return NULL;
    }

    /* Track block leaders (addresses that start new blocks) */
    typedef struct { uint64_t addr; bool visited; } Leader;
    Leader *leaders = (Leader *)e9_alloc(max_blocks * sizeof(Leader));
    uint32_t num_leaders = 0;

    /* Entry point is always a leader */
    leaders[num_leaders++].addr = func->address;

    /* First pass: find all block leaders */
    uint64_t addr = func->address;
    uint64_t end_addr = func->end_address ? func->end_address : (func->address + 0x10000);

    while (addr < end_addr && num_leaders < max_blocks - 2) {
        E9Instruction *insn = e9_disasm_instruction(bin, addr);
        if (!insn) break;

        if (insn->category == E9_INSN_CALL ||
            insn->category == E9_INSN_JUMP ||
            insn->category == E9_INSN_COND_JUMP) {

            if (!insn->target_is_indirect && insn->target >= func->address &&
                insn->target < end_addr) {
                /* Target is a leader */
                bool found = false;
                for (uint32_t i = 0; i < num_leaders; i++) {
                    if (leaders[i].addr == insn->target) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    leaders[num_leaders++].addr = insn->target;
                }
            }

            /* Instruction after conditional/call is also a leader */
            if (insn->category != E9_INSN_JUMP) {
                uint64_t next = addr + insn->size;
                bool found = false;
                for (uint32_t i = 0; i < num_leaders; i++) {
                    if (leaders[i].addr == next) {
                        found = true;
                        break;
                    }
                }
                if (!found && next < end_addr) {
                    leaders[num_leaders++].addr = next;
                }
            }
        }

        if (insn->category == E9_INSN_RET) {
            addr += insn->size;
            free(insn);
            break;
        }

        addr += insn->size;
        free(insn);
    }

    /* Sort leaders by address */
    for (uint32_t i = 0; i < num_leaders - 1; i++) {
        for (uint32_t j = i + 1; j < num_leaders; j++) {
            if (leaders[j].addr < leaders[i].addr) {
                Leader tmp = leaders[i];
                leaders[i] = leaders[j];
                leaders[j] = tmp;
            }
        }
    }

    /* Second pass: create basic blocks */
    for (uint32_t i = 0; i < num_leaders && cfg->num_blocks < max_blocks; i++) {
        E9BasicBlock *block = (E9BasicBlock *)e9_alloc(sizeof(E9BasicBlock));
        if (!block) continue;

        block->id = cfg->num_blocks;
        block->start_addr = leaders[i].addr;
        block->function = func;

        /* Determine end address */
        if (i + 1 < num_leaders) {
            block->end_addr = leaders[i + 1].addr;
        } else {
            block->end_addr = end_addr;
        }

        /* Disassemble block */
        addr = block->start_addr;
        while (addr < block->end_addr) {
            E9Instruction *insn = e9_disasm_instruction(bin, addr);
            if (!insn) break;

            insn->block = block;

            if (!block->first) {
                block->first = insn;
            } else {
                block->last->next = insn;
            }
            block->last = insn;
            block->num_insns++;

            /* Stop at control flow instructions */
            if (insn->category == E9_INSN_RET ||
                insn->category == E9_INSN_JUMP) {
                block->end_addr = addr + insn->size;
                break;
            }
            if (insn->category == E9_INSN_COND_JUMP &&
                addr + insn->size >= block->end_addr) {
                break;
            }

            addr += insn->size;
        }

        cfg->blocks[cfg->num_blocks++] = block;

        /* Set entry block */
        if (block->start_addr == func->address) {
            cfg->entry = block;
        }
    }

    /* Third pass: connect edges */
    for (uint32_t i = 0; i < cfg->num_blocks; i++) {
        E9BasicBlock *block = cfg->blocks[i];
        if (!block->last) continue;

        E9Instruction *last = block->last;

        /* Allocate successor array */
        block->successors = (E9BasicBlock **)e9_alloc(2 * sizeof(E9BasicBlock *));
        block->num_succs = 0;

        if (last->category == E9_INSN_RET) {
            /* Exit block */
            cfg->exits = (E9BasicBlock **)e9_realloc(cfg->exits,
                (cfg->num_exits + 1) * sizeof(E9BasicBlock *));
            if (cfg->exits) {
                cfg->exits[cfg->num_exits++] = block;
            }
        }
        else if (last->category == E9_INSN_JUMP && !last->target_is_indirect) {
            /* Find target block */
            for (uint32_t j = 0; j < cfg->num_blocks; j++) {
                if (cfg->blocks[j]->start_addr == last->target) {
                    block->successors[block->num_succs++] = cfg->blocks[j];

                    /* Add predecessor */
                    E9BasicBlock *succ = cfg->blocks[j];
                    succ->predecessors = (E9BasicBlock **)e9_realloc(succ->predecessors,
                        (succ->num_preds + 1) * sizeof(E9BasicBlock *));
                    if (succ->predecessors) {
                        succ->predecessors[succ->num_preds++] = block;
                    }
                    break;
                }
            }
        }
        else if (last->category == E9_INSN_COND_JUMP) {
            /* Fall-through successor */
            if (i + 1 < cfg->num_blocks) {
                block->successors[block->num_succs++] = cfg->blocks[i + 1];

                E9BasicBlock *succ = cfg->blocks[i + 1];
                succ->predecessors = (E9BasicBlock **)e9_realloc(succ->predecessors,
                    (succ->num_preds + 1) * sizeof(E9BasicBlock *));
                if (succ->predecessors) {
                    succ->predecessors[succ->num_preds++] = block;
                }
            }

            /* Branch target successor */
            if (!last->target_is_indirect) {
                for (uint32_t j = 0; j < cfg->num_blocks; j++) {
                    if (cfg->blocks[j]->start_addr == last->target) {
                        block->successors[block->num_succs++] = cfg->blocks[j];

                        E9BasicBlock *succ = cfg->blocks[j];
                        succ->predecessors = (E9BasicBlock **)e9_realloc(succ->predecessors,
                            (succ->num_preds + 1) * sizeof(E9BasicBlock *));
                        if (succ->predecessors) {
                            succ->predecessors[succ->num_preds++] = block;
                        }
                        break;
                    }
                }
            }
        }
        else if (last->category == E9_INSN_CALL || last->category == E9_INSN_OTHER) {
            /* Fall through to next block */
            if (i + 1 < cfg->num_blocks) {
                block->successors[block->num_succs++] = cfg->blocks[i + 1];

                E9BasicBlock *succ = cfg->blocks[i + 1];
                succ->predecessors = (E9BasicBlock **)e9_realloc(succ->predecessors,
                    (succ->num_preds + 1) * sizeof(E9BasicBlock *));
                if (succ->predecessors) {
                    succ->predecessors[succ->num_preds++] = block;
                }
            }
        }
    }

    free(leaders);

    /* Compute cyclomatic complexity */
    uint32_t edges = 0;
    for (uint32_t i = 0; i < cfg->num_blocks; i++) {
        edges += cfg->blocks[i]->num_succs;
    }
    cfg->cyclomatic_complexity = edges - cfg->num_blocks + 2;

    return cfg;
}

void e9_cfg_free(E9CFG *cfg)
{
    if (!cfg) return;

    for (uint32_t i = 0; i < cfg->num_blocks; i++) {
        E9BasicBlock *block = cfg->blocks[i];
        if (!block) continue;

        /* Free instructions */
        E9Instruction *insn = block->first;
        while (insn) {
            E9Instruction *next = insn->next;
            free(insn);
            insn = next;
        }

        free(block->predecessors);
        free(block->successors);
        free(block->pseudo_c);
        free(block->live_in);
        free(block->live_out);
        free(block);
    }

    free(cfg->blocks);
    free(cfg->exits);
    free(cfg);
}

int e9_cfg_to_dot(E9CFG *cfg, const char *path)
{
    if (!cfg || !path) return -1;

    FILE *fp = fopen(path, "w");
    if (!fp) return -1;

    fprintf(fp, "digraph CFG {\n");
    fprintf(fp, "    node [shape=box, fontname=\"monospace\"];\n");
    fprintf(fp, "    rankdir=TB;\n\n");

    /* Nodes */
    for (uint32_t i = 0; i < cfg->num_blocks; i++) {
        E9BasicBlock *block = cfg->blocks[i];
        fprintf(fp, "    block_%u [label=\"BB%u\\n0x%lx - 0x%lx\\n%u insns\"];\n",
                block->id, block->id, block->start_addr, block->end_addr,
                block->num_insns);
    }

    fprintf(fp, "\n");

    /* Edges */
    for (uint32_t i = 0; i < cfg->num_blocks; i++) {
        E9BasicBlock *block = cfg->blocks[i];
        for (uint32_t j = 0; j < block->num_succs; j++) {
            fprintf(fp, "    block_%u -> block_%u;\n",
                    block->id, block->successors[j]->id);
        }
    }

    fprintf(fp, "}\n");
    fclose(fp);
    return 0;
}

/*
 * ============================================================================
 * Decompilation
 * ============================================================================
 */

/* Simple register tracking for decompilation */
typedef struct {
    int reg;
    char *expr;
} RegState;

static const char *x64_reg_names[] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "rflags"
};

static const char *a64_reg_names[] = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
    "pc", "nzcv"
};

char *e9_decompile_function(E9Binary *bin, E9Function *func)
{
    if (!bin || !func || !func->cfg) return NULL;

    /* Estimate output size */
    size_t buf_size = 4096 + func->cfg->num_blocks * 512;
    char *output = (char *)e9_alloc(buf_size);
    if (!output) return NULL;

    size_t pos = 0;

    /* Function signature */
    pos += snprintf(output + pos, buf_size - pos,
                    "// Function: %s\n// Address: 0x%lx\n// Size: %u bytes\n\n",
                    func->name ? func->name : "unknown",
                    func->address, func->size);

    /* Generate return type */
    const char *ret_type = "int64_t";  /* Default */
    if (func->is_noreturn) {
        ret_type = "void __attribute__((noreturn))";
    }

    /* Parameters based on calling convention */
    pos += snprintf(output + pos, buf_size - pos, "%s %s(",
                    ret_type, func->name ? func->name : "sub");

    if (func->num_params == 0) {
        pos += snprintf(output + pos, buf_size - pos, "void");
    } else {
        for (uint32_t i = 0; i < func->num_params; i++) {
            if (i > 0) pos += snprintf(output + pos, buf_size - pos, ", ");
            pos += snprintf(output + pos, buf_size - pos, "int64_t arg%u", i);
        }
    }
    pos += snprintf(output + pos, buf_size - pos, ")\n{\n");

    /* Local variable declarations */
    if (func->num_locals > 0) {
        for (uint32_t i = 0; i < func->num_locals; i++) {
            E9Variable *var = func->locals[i];
            if (var && var->name) {
                pos += snprintf(output + pos, buf_size - pos,
                                "    int64_t %s; // [rbp%+d]\n",
                                var->name, var->stack_offset);
            }
        }
        pos += snprintf(output + pos, buf_size - pos, "\n");
    }

    /* Decompile each basic block */
    for (uint32_t i = 0; i < func->cfg->num_blocks; i++) {
        E9BasicBlock *block = func->cfg->blocks[i];

        /* Block label */
        pos += snprintf(output + pos, buf_size - pos,
                        "block_%u:  // 0x%lx\n", block->id, block->start_addr);

        /* Decompile instructions */
        E9Instruction *insn = block->first;
        while (insn && pos < buf_size - 256) {
            switch (insn->category) {
                case E9_INSN_CALL:
                    if (insn->target) {
                        E9Symbol *target_sym = e9_symbol_at(bin, insn->target);
                        pos += snprintf(output + pos, buf_size - pos,
                                        "    result = %s(); // call 0x%lx\n",
                                        target_sym ? target_sym->name : "func",
                                        insn->target);
                    } else {
                        pos += snprintf(output + pos, buf_size - pos,
                                        "    result = (*ptr)(); // indirect call\n");
                    }
                    break;

                case E9_INSN_RET:
                    pos += snprintf(output + pos, buf_size - pos,
                                    "    return result;\n");
                    break;

                case E9_INSN_COND_JUMP:
                    {
                        const char *cond = "?";
                        if (strstr(insn->mnemonic, "z") || strstr(insn->mnemonic, "eq")) {
                            cond = "==";
                        } else if (strstr(insn->mnemonic, "nz") || strstr(insn->mnemonic, "ne")) {
                            cond = "!=";
                        } else if (strstr(insn->mnemonic, "l") || strstr(insn->mnemonic, "lt")) {
                            cond = "<";
                        } else if (strstr(insn->mnemonic, "g")) {
                            cond = ">";
                        } else if (strstr(insn->mnemonic, "le")) {
                            cond = "<=";
                        } else if (strstr(insn->mnemonic, "ge")) {
                            cond = ">=";
                        }

                        /* Find target block */
                        uint32_t target_block = 0;
                        for (uint32_t j = 0; j < func->cfg->num_blocks; j++) {
                            if (func->cfg->blocks[j]->start_addr == insn->target) {
                                target_block = j;
                                break;
                            }
                        }

                        pos += snprintf(output + pos, buf_size - pos,
                                        "    if (cmp %s 0) goto block_%u;\n",
                                        cond, target_block);
                    }
                    break;

                case E9_INSN_JUMP:
                    {
                        uint32_t target_block = 0;
                        for (uint32_t j = 0; j < func->cfg->num_blocks; j++) {
                            if (func->cfg->blocks[j]->start_addr == insn->target) {
                                target_block = j;
                                break;
                            }
                        }
                        pos += snprintf(output + pos, buf_size - pos,
                                        "    goto block_%u;\n", target_block);
                    }
                    break;

                default:
                    /* Comment out other instructions */
                    pos += snprintf(output + pos, buf_size - pos,
                                    "    // %s %s\n", insn->mnemonic, insn->operands);
                    break;
            }

            insn = insn->next;
        }

        pos += snprintf(output + pos, buf_size - pos, "\n");
    }

    pos += snprintf(output + pos, buf_size - pos, "}\n");

    func->decompiled_c = output;
    return output;
}

char *e9_decompile_block(E9Binary *bin, E9BasicBlock *block)
{
    if (!bin || !block) return NULL;

    size_t buf_size = 1024 + block->num_insns * 128;
    char *output = (char *)e9_alloc(buf_size);
    if (!output) return NULL;

    size_t pos = 0;

    E9Instruction *insn = block->first;
    while (insn && pos < buf_size - 128) {
        /* Simple instruction-to-C mapping */
        switch (insn->category) {
            case E9_INSN_MOV:
                pos += snprintf(output + pos, buf_size - pos,
                                "// mov: %s\n", insn->operands);
                break;
            case E9_INSN_ARITHMETIC:
                pos += snprintf(output + pos, buf_size - pos,
                                "// arith: %s %s\n", insn->mnemonic, insn->operands);
                break;
            default:
                pos += snprintf(output + pos, buf_size - pos,
                                "// %s %s\n", insn->mnemonic, insn->operands);
                break;
        }
        insn = insn->next;
    }

    block->pseudo_c = output;
    return output;
}

char *e9_generate_header(E9Binary *bin)
{
    if (!bin) return NULL;

    size_t buf_size = 4096 + bin->num_functions * 128;
    char *output = (char *)e9_alloc(buf_size);
    if (!output) return NULL;

    size_t pos = 0;

    pos += snprintf(output + pos, buf_size - pos,
                    "/*\n * Auto-generated header for binary at 0x%lx\n"
                    " * Architecture: %s\n * Format: %s\n */\n\n",
                    bin->base_address,
                    bin->arch == E9_ARCH_X86_64 ? "x86-64" :
                    bin->arch == E9_ARCH_AARCH64 ? "AArch64" : "unknown",
                    bin->format == E9_FORMAT_ELF ? "ELF" :
                    bin->format == E9_FORMAT_PE ? "PE" :
                    bin->format == E9_FORMAT_MACHO ? "Mach-O" : "raw");

    pos += snprintf(output + pos, buf_size - pos,
                    "#ifndef _BINARY_H\n#define _BINARY_H\n\n"
                    "#include <stdint.h>\n\n");

    /* Function prototypes */
    E9Function *func = bin->functions;
    while (func && pos < buf_size - 256) {
        pos += snprintf(output + pos, buf_size - pos,
                        "/* 0x%lx */ int64_t %s();\n",
                        func->address, func->name ? func->name : "sub");
        func = func->next;
    }

    pos += snprintf(output + pos, buf_size - pos, "\n#endif /* _BINARY_H */\n");

    return output;
}

char *e9_generate_source(E9Binary *bin)
{
    if (!bin) return NULL;

    /* Estimate size needed */
    size_t buf_size = 8192 + bin->num_functions * 2048;
    char *output = (char *)e9_alloc(buf_size);
    if (!output) return NULL;

    size_t pos = 0;

    /* File header */
    pos += snprintf(output + pos, buf_size - pos,
                    "/*\n * Decompiled source for binary\n"
                    " * Generated by E9Studio analysis engine\n"
                    " *\n * Architecture: %s\n * Entry point: 0x%lx\n */\n\n",
                    bin->arch == E9_ARCH_X86_64 ? "x86-64" : "AArch64",
                    bin->entry_point);

    pos += snprintf(output + pos, buf_size - pos,
                    "#include <stdint.h>\n#include <stddef.h>\n\n");

    /* Global variables */
    E9Symbol *sym = bin->symbols;
    while (sym && pos < buf_size - 256) {
        if (sym->type == E9_SYM_GLOBAL_VAR) {
            pos += snprintf(output + pos, buf_size - pos,
                            "/* 0x%lx */ int64_t %s;\n",
                            sym->address, sym->name ? sym->name : "var");
        }
        sym = sym->next;
    }
    pos += snprintf(output + pos, buf_size - pos, "\n");

    /* Function implementations */
    E9Function *func = bin->functions;
    while (func && pos < buf_size - 1024) {
        if (!func->decompiled_c) {
            e9_decompile_function(bin, func);
        }
        if (func->decompiled_c) {
            size_t len = strlen(func->decompiled_c);
            if (pos + len < buf_size) {
                memcpy(output + pos, func->decompiled_c, len);
                pos += len;
                pos += snprintf(output + pos, buf_size - pos, "\n");
            }
        }
        func = func->next;
    }

    return output;
}

/*
 * ============================================================================
 * DWARF Debug Info Parsing
 * ============================================================================
 */

int e9_dwarf_parse(E9Binary *bin)
{
    if (!bin || !bin->has_debug_info) return -1;
    if (bin->format != E9_FORMAT_ELF) return -1;

    /* Find .debug_info, .debug_line, .debug_str sections */
    uint64_t debug_info_off = 0, debug_info_size = 0;
    uint64_t debug_line_off = 0, debug_line_size = 0;
    uint64_t debug_str_off = 0;

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (strcmp(bin->sections[i].name, ".debug_info") == 0) {
            debug_info_off = bin->sections[i].addr;
            debug_info_size = bin->sections[i].size;
        } else if (strcmp(bin->sections[i].name, ".debug_line") == 0) {
            debug_line_off = bin->sections[i].addr;
            debug_line_size = bin->sections[i].size;
        } else if (strcmp(bin->sections[i].name, ".debug_str") == 0) {
            debug_str_off = bin->sections[i].addr;
        }
    }

    if (!debug_line_off) return -1;

    /* Parse .debug_line for source mappings */
    /* This is a simplified DWARF line program interpreter */

    /* TODO: Full DWARF line program state machine */
    /* For now, just mark that we have debug info available */

    return 0;
}

int e9_dwarf_addr_to_line(E9Binary *bin, uint64_t addr,
                          char *file, size_t file_size,
                          uint32_t *line, uint32_t *column)
{
    if (!bin || !bin->mappings) return -1;

    E9SourceMapping *map = bin->mappings;
    while (map) {
        if (addr >= map->address && addr < map->address + map->size) {
            if (file && file_size > 0 && map->source_file) {
                strncpy(file, map->source_file, file_size - 1);
                file[file_size - 1] = '\0';
            }
            if (line) *line = map->line;
            if (column) *column = map->column;
            return 0;
        }
        map = map->next;
    }
    return -1;
}

int e9_dwarf_line_to_addr(E9Binary *bin, const char *file, uint32_t line,
                          uint64_t *addr, uint32_t *size)
{
    if (!bin || !bin->mappings || !file) return -1;

    E9SourceMapping *map = bin->mappings;
    while (map) {
        if (map->line == line && map->source_file &&
            strcmp(map->source_file, file) == 0) {
            if (addr) *addr = map->address;
            if (size) *size = map->size;
            return 0;
        }
        map = map->next;
    }
    return -1;
}

E9Variable *e9_dwarf_get_variable(E9Binary *bin, uint64_t addr, const char *name)
{
    if (!bin || !name) return NULL;

    /* Find function containing address */
    E9Function *func = e9_function_at(bin, addr);
    if (!func) return NULL;

    /* Search function's local variables */
    for (uint32_t i = 0; i < func->num_locals; i++) {
        if (func->locals[i] && func->locals[i]->name &&
            strcmp(func->locals[i]->name, name) == 0) {
            return func->locals[i];
        }
    }

    return NULL;
}

/*
 * ============================================================================
 * Source Mapping & Live Patching
 * ============================================================================
 */

int e9_mapping_build(E9Binary *bin)
{
    if (!bin) return -1;

    /* If DWARF available, mappings come from there */
    if (bin->has_debug_info) {
        /* Already populated by e9_dwarf_parse */
        return 0;
    }

    /* Otherwise, create basic function-level mappings */
    E9Function *func = bin->functions;
    while (func) {
        E9SourceMapping *map = (E9SourceMapping *)e9_alloc(sizeof(E9SourceMapping));
        if (map) {
            map->address = func->address;
            map->size = func->size;
            if (func->source_file) {
                map->source_file = e9_strdup(func->source_file);
            }
            map->line = func->source_line;

            map->next = bin->mappings;
            bin->mappings = map;
            bin->num_mappings++;
        }
        func = func->next;
    }

    return 0;
}

int e9_mapping_line_to_range(E9Binary *bin, const char *file, uint32_t line,
                              uint64_t *start, uint64_t *end)
{
    if (!bin || !file || !start || !end) return -1;

    E9SourceMapping *map = bin->mappings;
    while (map) {
        if (map->line == line && map->source_file &&
            strcmp(map->source_file, file) == 0) {
            *start = map->address;
            *end = map->address + map->size;
            return 0;
        }
        map = map->next;
    }
    return -1;
}

/*
 * ============================================================================
 * Object File Diffing for Live Patching
 * ============================================================================
 */

E9PatchSet *e9_diff_objects(const uint8_t *old_obj, size_t old_size,
                            const uint8_t *new_obj, size_t new_size)
{
    if (!old_obj || !new_obj) return NULL;

    E9PatchSet *ps = (E9PatchSet *)e9_alloc(sizeof(E9PatchSet));
    if (!ps) return NULL;

    /* Create analysis contexts for both */
    E9Binary *old_bin = e9_binary_create(old_obj, old_size);
    E9Binary *new_bin = e9_binary_create(new_obj, new_size);

    if (!old_bin || !new_bin) {
        e9_binary_free(old_bin);
        e9_binary_free(new_bin);
        ps->error = e9_strdup("Failed to create binary contexts");
        return ps;
    }

    /* Analyze both */
    e9_binary_analyze(old_bin);
    e9_binary_analyze(new_bin);

    /* Compare functions */
    uint32_t max_patches = 1024;
    ps->patches = (E9Patch *)e9_alloc(max_patches * sizeof(E9Patch));

    E9Function *new_func = new_bin->functions;
    while (new_func && ps->num_patches < max_patches) {
        E9Function *old_func = e9_function_by_name(old_bin, new_func->name);

        if (!old_func) {
            /* New function - skip for now */
            new_func = new_func->next;
            continue;
        }

        /* Compare function contents */
        uint64_t old_off = old_func->address;
        uint64_t new_off = new_func->address;

        if (old_bin->base_address) old_off -= old_bin->base_address;
        if (new_bin->base_address) new_off -= new_bin->base_address;

        uint32_t min_size = old_func->size < new_func->size ?
                            old_func->size : new_func->size;

        /* Byte-by-byte comparison */
        for (uint32_t i = 0; i < min_size; i++) {
            if (old_obj[old_off + i] != new_obj[new_off + i]) {
                /* Found difference - create patch */
                E9Patch *patch = &ps->patches[ps->num_patches];
                patch->address = old_func->address + i;

                /* Find extent of change */
                uint32_t patch_size = 1;
                while (i + patch_size < min_size &&
                       old_obj[old_off + i + patch_size] != new_obj[new_off + i + patch_size]) {
                    patch_size++;
                }

                patch->size = patch_size;
                patch->old_bytes = (uint8_t *)e9_alloc(patch_size);
                patch->new_bytes = (uint8_t *)e9_alloc(patch_size);

                if (patch->old_bytes && patch->new_bytes) {
                    memcpy(patch->old_bytes, old_obj + old_off + i, patch_size);
                    memcpy(patch->new_bytes, new_obj + new_off + i, patch_size);

                    char desc[256];
                    snprintf(desc, sizeof(desc), "Patch %s+0x%x (%u bytes)",
                             new_func->name ? new_func->name : "func", i, patch_size);
                    patch->description = e9_strdup(desc);

                    ps->num_patches++;
                }

                i += patch_size - 1;  /* Skip past patched region */
            }
        }

        new_func = new_func->next;
    }

    e9_binary_free(old_bin);
    e9_binary_free(new_bin);

    return ps;
}

void e9_patchset_free(E9PatchSet *ps)
{
    if (!ps) return;

    for (uint32_t i = 0; i < ps->num_patches; i++) {
        free(ps->patches[i].old_bytes);
        free(ps->patches[i].new_bytes);
        free(ps->patches[i].description);
    }
    free(ps->patches);
    free(ps->error);
    free(ps);
}

/*
 * ============================================================================
 * Calling Convention Analysis
 * ============================================================================
 */

static void analyze_calling_convention(E9Binary *bin, E9Function *func)
{
    if (!bin || !func || !func->cfg || !func->cfg->entry) return;

    /* Analyze prolog to determine calling convention */
    E9Instruction *insn = func->cfg->entry->first;
    if (!insn) return;

    if (bin->arch == E9_ARCH_X86_64) {
        /* Default to System V AMD64 for ELF, MS x64 for PE */
        if (bin->format == E9_FORMAT_PE) {
            func->calling_convention = E9_CC_MS_X64;
        } else {
            func->calling_convention = E9_CC_SYSV_AMD64;
        }

        /* Check for leaf function (no calls) */
        func->is_leaf = true;
        E9Instruction *i = insn;
        while (i) {
            if (i->category == E9_INSN_CALL) {
                func->is_leaf = false;
                break;
            }
            i = i->next;
        }
    }
    else if (bin->arch == E9_ARCH_AARCH64) {
        func->calling_convention = E9_CC_AAPCS64;
        func->is_leaf = true;

        E9Instruction *i = insn;
        while (i) {
            if (i->category == E9_INSN_CALL) {
                func->is_leaf = false;
                break;
            }
            i = i->next;
        }
    }
}

/*
 * ============================================================================
 * Architecture Helpers
 * ============================================================================
 */

const char *e9_reg_name(E9Arch arch, int reg)
{
    switch (arch) {
        case E9_ARCH_X86_64:
            if (reg >= 0 && reg < E9_REG_X64_COUNT) {
                return x64_reg_names[reg];
            }
            break;
        case E9_ARCH_AARCH64:
            if (reg >= 0 && reg < E9_REG_A64_COUNT) {
                return a64_reg_names[reg];
            }
            break;
        default:
            break;
    }
    return "???";
}

const int *e9_cc_arg_regs(E9Arch arch, int calling_convention, int *count)
{
    static const int sysv_args[] = {
        E9_REG_X64_RDI, E9_REG_X64_RSI, E9_REG_X64_RDX,
        E9_REG_X64_RCX, E9_REG_X64_R8, E9_REG_X64_R9
    };
    static const int ms_args[] = {
        E9_REG_X64_RCX, E9_REG_X64_RDX, E9_REG_X64_R8, E9_REG_X64_R9
    };
    static const int aapcs_args[] = {
        E9_REG_A64_X0, E9_REG_A64_X1, E9_REG_A64_X2, E9_REG_A64_X3,
        E9_REG_A64_X4, E9_REG_A64_X5, E9_REG_A64_X6, E9_REG_A64_X7
    };

    if (arch == E9_ARCH_X86_64) {
        if (calling_convention == E9_CC_MS_X64) {
            if (count) *count = 4;
            return ms_args;
        } else {
            if (count) *count = 6;
            return sysv_args;
        }
    } else if (arch == E9_ARCH_AARCH64) {
        if (count) *count = 8;
        return aapcs_args;
    }

    if (count) *count = 0;
    return NULL;
}

int e9_cc_ret_reg(E9Arch arch, int calling_convention)
{
    if (arch == E9_ARCH_X86_64) {
        return E9_REG_X64_RAX;
    } else if (arch == E9_ARCH_AARCH64) {
        return E9_REG_A64_X0;
    }
    return -1;
}
