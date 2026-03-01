/*
 * e9ape.h
 * APE (Actually Portable Executable) Binary Rewriting Support
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Based on RE analysis of actual APE binary (cosmocc output).
 *
 * KEY INSIGHT: APE has NO x86-64 ELF header embedded!
 *
 * Structure discovered via RE:
 *   0x00000 - MZ header "MZqFpD" + shell script bootstrap
 *   0x10A58 - PE header (e_lfanew points here)
 *   0x11000 - .text section (file offset == RVA in APE)
 *   0x2F000 - .rdata section
 *   0x35000 - .data section
 *   0x3C000 - ARM64 ELF (for aarch64 only)
 *   EOF-256 - ZipOS (.cosmo, .symtab.*)
 *
 * For patching x86-64:
 *   - Use PE sections as ground truth
 *   - file_offset often equals RVA
 *   - No ELF program headers to parse
 *
 * Pure C implementation for cosmicringforge dogfooding.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9APE_H
#define E9APE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * APE Info structure (opaque, use accessors)
 */
typedef struct {
    /* File info */
    size_t file_size;
    bool is_cosmopolitan;

    /* PE location */
    off_t pe_offset;
    size_t pe_size;
    uint16_t pe_num_sections;

    /* Section cache (for fast patching) */
    off_t text_offset;
    uint32_t text_rva;
    size_t text_size;

    off_t rdata_offset;
    uint32_t rdata_rva;
    size_t rdata_size;

    off_t data_offset;
    uint32_t data_rva;
    size_t data_size;

    /* Embedded architectures */
    bool has_arm64_elf;
    off_t arm64_elf_offset;

    bool is_assimilated;   /* Has ELF header (--assimilate was run) */
    off_t x86_elf_offset;

    /* ZipOS */
    off_t zipos_start;
    off_t zipos_central_dir;
    off_t zipos_end;
    uint32_t zipos_num_entries;

    /* Config */
    bool preserve_zipos;
} E9_APEInfo;

/*
 * ZipOS entry
 */
typedef struct {
    char *name;
    off_t local_header_offset;
    size_t compressed_size;
    size_t uncompressed_size;
    uint16_t compression;
    uint32_t crc32;
    bool is_directory;
} E9_ZipOSEntry;

/* ═══════════════════════════════════════════════════════════════════════
 * Detection
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Check if data is APE format
 * Returns true if MZqFpD magic or MZ+PE with heredoc
 */
bool e9_ape_detect(const uint8_t *data, size_t size);

/*
 * Parse APE structure
 * Returns 0 on success, -1 on error
 */
int e9_ape_parse(const uint8_t *data, size_t size, E9_APEInfo *info);

/* ═══════════════════════════════════════════════════════════════════════
 * Address Translation
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Convert PE RVA to file offset
 * PRIMARY method for APE - uses PE section table
 * Returns -1 if RVA not found in any section
 */
off_t e9_ape_rva_to_offset(const E9_APEInfo *info, uint32_t rva);

/*
 * Convert file offset to PE RVA
 * Returns 0 if offset not in mapped section
 */
uint32_t e9_ape_offset_to_rva(const E9_APEInfo *info, off_t offset);

/* ═══════════════════════════════════════════════════════════════════════
 * Patching
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Apply patch at file offset (RECOMMENDED)
 * Directly patches bytes at specified offset
 * Returns 0 on success, -1 on error
 */
int e9_ape_patch_offset(uint8_t *data, size_t size, const E9_APEInfo *info,
                        off_t offset, const uint8_t *patch, size_t patch_size);

/*
 * Apply patch at PE RVA
 * Converts RVA to file offset, then patches
 * Returns 0 on success, -1 on error
 */
int e9_ape_patch_rva(uint8_t *data, size_t size, const E9_APEInfo *info,
                     uint32_t rva, const uint8_t *patch, size_t patch_size);

/*
 * Apply patch at virtual address (LEGACY)
 * For compatibility with ELF-style addresses
 * Assumes VA = 0x400000 + RVA (typical APE layout)
 * Returns 0 on success, -1 on error
 */
int e9_ape_patch(uint8_t *data, size_t size, const E9_APEInfo *info,
                 uint64_t vaddr, const uint8_t *patch, size_t patch_size);

/* ═══════════════════════════════════════════════════════════════════════
 * ZipOS
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * List ZipOS entries
 * Returns allocated array (caller must free with e9_ape_zipos_free_list)
 */
E9_ZipOSEntry *e9_ape_zipos_list(const uint8_t *data, size_t size,
                                  const E9_APEInfo *info, size_t *out_count);

/*
 * Free ZipOS entry list
 */
void e9_ape_zipos_free_list(E9_ZipOSEntry *entries, size_t count);

/*
 * Check if path exists in ZipOS
 */
bool e9_ape_zipos_exists(const uint8_t *data, size_t size,
                          const E9_APEInfo *info, const char *path);

/* ═══════════════════════════════════════════════════════════════════════
 * Utilities
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Get path to self executable (for hot-patching)
 */
const char *e9_ape_get_self_path(void);

/*
 * Debug: dump APE info to file
 */
void e9_ape_dump_info(const E9_APEInfo *info, FILE *out);

/* ═══════════════════════════════════════════════════════════════════════
 * Constants
 * ═══════════════════════════════════════════════════════════════════════ */

#define E9_APE_MAGIC_COSMO     "MZqFpD"
#define E9_APE_DEFAULT_BASE    0x400000

#ifdef __cplusplus
}
#endif

#endif /* E9APE_H */
