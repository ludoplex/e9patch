/*
 * e9ape.h
 * APE (Actually Portable Executable) Binary Rewriting Support
 *
 * APE binaries are polyglot executables that are simultaneously valid as:
 *   - DOS/MZ executable (for Windows)
 *   - ELF executable (for Linux/BSD)
 *   - Shell script (for Unix bootstrapping)
 *   - ZIP archive (ZipOS embedded filesystem)
 *
 * When patching an APE binary, we must:
 *   1. Parse and understand all format layers
 *   2. Apply patches consistently to both ELF and PE views
 *   3. Preserve the shell script header
 *   4. Preserve ZipOS content (or update it if requested)
 *   5. Maintain polyglot validity across all formats
 *
 * Pure C implementation for dogfooding with cosmicringforge C generators.
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9APE_H
#define E9APE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <elf.h>

/*
 * APE Magic signatures
 */
#define APE_MAGIC_MZ        "MZqFpD"
#define APE_MAGIC_SHELL     "#!/"

/*
 * PE structures (minimal, for parsing)
 */
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} E9_PE_FILE_HEADER;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOSVersion;
    uint16_t MinorOSVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
} E9_PE_OPTIONAL_HEADER64;

typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} E9_PE_SECTION_HEADER;

/*
 * APE Info structure
 */
typedef struct {
    /* ELF view */
    Elf64_Ehdr *elf_ehdr;
    off_t elf_offset;
    size_t elf_size;

    /* PE view */
    E9_PE_FILE_HEADER *pe_file_hdr;
    E9_PE_OPTIONAL_HEADER64 *pe_opt_hdr;
    E9_PE_SECTION_HEADER *pe_sections;
    uint16_t pe_num_sections;
    off_t pe_offset;
    size_t pe_size;

    /* Shell script */
    off_t shell_offset;
    size_t shell_size;

    /* ZipOS */
    off_t zipos_start;
    off_t zipos_central_dir;
    off_t zipos_end;
    uint32_t zipos_num_entries;

    /* Flags */
    bool sync_elf_pe;       /* Sync patches to both ELF and PE views */
    bool preserve_zipos;    /* Preserve ZipOS content on write */
} E9_APEInfo;

/*
 * ZipOS entry descriptor
 */
typedef struct {
    const char *name;
    off_t offset;
    size_t compressed_size;
    size_t uncompressed_size;
    uint16_t compression;
    uint32_t crc32;
    bool is_directory;
} E9_ZipOSEntry;

/* ── Detection ─────────────────────────────────────────────────────── */

/*
 * Check if data is APE format
 */
bool e9_ape_detect(const uint8_t *data, size_t size);

/*
 * Parse APE structure into info
 * Returns 0 on success, -1 on error
 */
int e9_ape_parse(const uint8_t *data, size_t size, E9_APEInfo *info);

/* ── Address Translation ───────────────────────────────────────────── */

/*
 * Convert ELF virtual address to file offset
 * Returns -1 on error
 */
off_t e9_ape_elf_vaddr_to_offset(const uint8_t *data, const E9_APEInfo *info,
                                  uint64_t vaddr);

/*
 * Convert PE virtual address to file offset
 * Returns -1 on error
 */
off_t e9_ape_pe_vaddr_to_offset(const E9_APEInfo *info, uint64_t vaddr);

/* ── Patching ──────────────────────────────────────────────────────── */

/*
 * Apply patch to APE binary
 * Patches at ELF virtual address; if sync_elf_pe is set, also syncs to PE
 * Returns 0 on success, -1 on error
 */
int e9_ape_patch(uint8_t *data, size_t size, const E9_APEInfo *info,
                  uint64_t elf_vaddr, const uint8_t *patch, size_t patch_size);

/* ── ZipOS ─────────────────────────────────────────────────────────── */

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
 * Read uncompressed file from ZipOS
 * Returns allocated buffer (caller must free) or NULL on error
 */
uint8_t *e9_ape_zipos_read(const uint8_t *data, size_t size,
                            const E9_APEInfo *info, const char *path,
                            size_t *out_size);

/*
 * Check if path exists in ZipOS
 */
bool e9_ape_zipos_exists(const uint8_t *data, size_t size,
                          const E9_APEInfo *info, const char *path);

/* ── Utilities ─────────────────────────────────────────────────────── */

/*
 * Get self executable path (for hot-patching)
 */
const char *e9_ape_get_self_path(void);

#endif /* E9APE_H */
