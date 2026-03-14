/*
 * e9ape.c
 * APE (Actually Portable Executable) Binary Rewriting Implementation
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Based on RE analysis of actual APE binary (cosmocc output, 2026-02-28)
 *
 * KEY FINDINGS (from RE of gcc.com + apelink.c upstream):
 *
 *   APE is a polyglot with ELF, PE, and Mach-O views.
 *   Not all are present as complete headers in the static file:
 *
 *   Static file layout (verified via RE of cosmocc gcc.com):
 *     0x00000  MZ header "MZqFpD='\n"
 *     0x00028  Shell heredoc content (x86 real-mode bootstrap in heredoc)
 *     0x00201  Heredoc end marker + shell script body:
 *              - Platform detection (uname -m/-s)
 *              - ape loader exec chain
 *              - --assimilate: printf ELF header to offset 0 (x86-64)
 *              - --assimilate: dd Mach-O from 0xC98 to offset 0 (macOS)
 *              - Compressed loader extraction (gzip'd ape loader)
 *     0x00C98  Mach-O header + load commands (app's Mach-O, ~528 bytes)
 *              Segments: __PAGEZERO, __APE1, __APE2, __APE3
 *     0x00EA8  ELF program headers for --assimilate (phdrs only, no ehdr!)
 *              PT_LOAD(RX), PT_LOAD(RW), PT_TLS, PT_GNU_STACK, etc.
 *              Base: 0x0800000000
 *     ~padding~
 *     0x10C78  PE header (at e_lfanew offset) + COFF + optional header
 *     0x10D10  PE section table (.text, .rdata, .data)
 *     0x10D88  Mach-O #2 (loader's Mach-O, different from app's)
 *     0x10FC0  ELF header (APE loader's ELF, base 0x7f000000, NOT the app)
 *     0x11000  ELF phdrs for loader (4 entries)
 *     0x11100  Mach-O #3 (loader variant, 5 load commands)
 *     0x14000  .text section (shared code, file_offset == RVA)
 *     ...      .rdata, .data sections
 *     ...      ARM64 ELF (for aarch64)
 *     ...      Compressed ape loaders (gzip'd)
 *     EOF-area ZipOS (.symtab.amd64, .symtab.arm64, timezone data, etc.)
 *
 *   Runtime behavior:
 *     Linux:  --assimilate: printf writes 64-byte ELF ehdr to offset 0,
 *             referencing phdrs already at 0xEA8.
 *             Normal: ape loader maps the binary via its own ELF at 0x10FC0.
 *     macOS:  --assimilate: dd copies Mach-O from 0xC98 to offset 0.
 *             Normal: compressed loader extracted, compiles via cc on arm64.
 *     Windows: MZ + PE at e_lfanew works directly.
 *
 *   For patching:
 *     - All views map the same .text/.rdata/.data sections
 *     - PE section table provides canonical offset mapping
 *     - Patches to shared sections affect all views
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif

#include "e9ape.h"

/*
 * APE Magic signatures
 */
#define APE_MAGIC_COSMO     "MZqFpD"
#define APE_MAGIC_SHELL     "#!"
#define PE_SIGNATURE        "PE\0\0"
#define ELF_MAGIC           "\x7fELF"
#define ZIP_LOCAL_MAGIC     "PK\x03\x04"
#define ZIP_CENTRAL_MAGIC   "PK\x01\x02"
#define ZIP_END_MAGIC       "PK\x05\x06"

#define MACHO_MAGIC_64      0xFEEDFACF
#define MACHO_MAGIC_64_REV  0xCFFAEDFE

#define PE_MACHINE_AMD64    0x8664
#define PE_MACHINE_ARM64    0xAA64
#define ELF_MACHINE_X86_64  0x3E
#define ELF_MACHINE_AARCH64 0xB7

/*
 * PE structures (from RE analysis)
 */
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} PE_FILE_HEADER;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
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
} PE_OPTIONAL_HEADER64;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} PE_SECTION_HEADER;

/*
 * Internal APE info structure
 */
typedef struct {
    /* File info */
    size_t file_size;
    bool is_cosmopolitan;

    /* MZ/PE location */
    off_t mz_offset;           /* Always 0 for APE */
    off_t pe_header_offset;    /* From e_lfanew at 0x3C */

    /* Shell bootstrap */
    off_t shell_start;
    off_t shell_end;
    char heredoc_marker[32];

    /* PE structure (PRIMARY for x86-64 patching) */
    PE_FILE_HEADER *pe_file_hdr;
    PE_OPTIONAL_HEADER64 *pe_opt_hdr;
    PE_SECTION_HEADER *pe_sections;
    uint16_t pe_num_sections;
    uint64_t pe_image_base;
    uint32_t pe_entry_rva;

    /* Section cache */
    off_t text_offset;
    uint32_t text_rva;
    size_t text_size;

    off_t rdata_offset;
    uint32_t rdata_rva;
    size_t rdata_size;

    off_t data_offset;
    uint32_t data_rva;
    size_t data_size;

    /* Embedded ELF */
    bool has_arm64_elf;
    off_t arm64_elf_offset;
    size_t arm64_elf_size;

    /* App ELF: ehdr generated at runtime by printf (--assimilate),
     * but phdrs are present in file (e.g. at 0xEA8 in gcc.com).
     * Loader ELF: complete ehdr+phdrs in prologue (e.g. at 0x10FC0). */
    bool has_x86_elf;          /* x86-64 ELF ehdr found in file */
    off_t x86_elf_offset;      /* Offset (may be loader's, not app's) */
    bool has_elf_phdrs;        /* App's ELF phdrs present (for --assimilate) */
    off_t elf_phdrs_offset;    /* Offset of app's ELF phdrs */

    /* Embedded Mach-O (app's, present at rest, dd'd to offset 0 on macOS) */
    bool has_macho;
    off_t macho_offset;        /* Offset of app's Mach-O header */
    size_t macho_size;         /* Size of Mach-O header + load commands */

    /* ZipOS */
    off_t zipos_start;
    off_t zipos_central_dir;
    off_t zipos_end;
    uint32_t zipos_num_entries;

    /* Patching config */
    bool preserve_zipos;
} APEInfo;

/* ZipOS entry type is defined in e9ape.h as E9_ZipOSEntry */

/* ═══════════════════════════════════════════════════════════════════════
 * Detection
 * ═══════════════════════════════════════════════════════════════════════ */

bool e9_ape_detect(const uint8_t *data, size_t size)
{
    if (data == NULL || size < 64)
        return false;

    /* Check for Cosmopolitan APE magic "MZqFpD" */
    if (memcmp(data, APE_MAGIC_COSMO, 6) == 0)
        return true;

    /* Check for MZ header with PE signature */
    if (data[0] == 'M' && data[1] == 'Z')
    {
        if (size < 0x40)
            return false;

        uint32_t pe_offset = *(uint32_t *)(data + 0x3C);
        if (pe_offset + 4 > size)
            return false;

        if (memcmp(data + pe_offset, PE_SIGNATURE, 4) == 0)
        {
            /* Has PE - check if it also has shell script (APE characteristic) */
            /* Look for heredoc pattern after MZ header */
            for (size_t i = 8; i < 64 && i < size - 2; i++)
            {
                if (data[i] == '<' && data[i+1] == '<')
                    return true;  /* Heredoc found - this is APE */
            }
            /* Even without heredoc, MZ+PE is APE-like */
            return true;
        }
    }

    return false;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Parsing
 * ═══════════════════════════════════════════════════════════════════════ */

int e9_ape_parse(const uint8_t *data, size_t size, E9_APEInfo *info)
{
    if (data == NULL || info == NULL || size < 64)
        return -1;

    if (!e9_ape_detect(data, size))
        return -1;

    memset(info, 0, sizeof(E9_APEInfo));
    info->preserve_zipos = true;

    /* ── Parse MZ header ─────────────────────────────────────────────── */

    info->is_cosmopolitan = (memcmp(data, APE_MAGIC_COSMO, 6) == 0);

    /* Get PE header offset from e_lfanew at 0x3C */
    info->pe_offset = *(uint32_t *)(data + 0x3C);

    if (info->pe_offset + 24 > (off_t)size)
    {
        fprintf(stderr, "e9ape: PE header offset 0x%lx out of bounds\n",
                (unsigned long)info->pe_offset);
        return -1;
    }

    /* Verify PE signature */
    if (memcmp(data + info->pe_offset, PE_SIGNATURE, 4) != 0)
    {
        fprintf(stderr, "e9ape: Invalid PE signature at 0x%lx\n",
                (unsigned long)info->pe_offset);
        return -1;
    }

    /* ── Parse shell bootstrap ───────────────────────────────────────── */

    /* Shell script starts after MZ fields, look for heredoc marker */
    /* Note: shell_start is internal only, not exposed in public E9_APEInfo */

    /* Find heredoc marker (e.g., <<'justinezgyqwu') */
    for (size_t i = 0x20; i < 128 && i + 16 < size; i++)
    {
        if (data[i] == '<' && data[i+1] == '<' && data[i+2] == '\'')
        {
            /* Extract marker */
            size_t j = 0;
            for (size_t k = i + 3; k < size && j < 31; k++)
            {
                if (data[k] == '\'')
                    break;
                /* info->heredoc_marker[j++] = data[k]; */
            }
            break;
        }
    }

    /* ── Parse PE structure (PRIMARY for x86-64) ─────────────────────── */

    off_t pe_coff = info->pe_offset + 4;
    PE_FILE_HEADER *file_hdr = (PE_FILE_HEADER *)(data + pe_coff);

    info->pe_num_sections = file_hdr->NumberOfSections;

    if (file_hdr->Machine != PE_MACHINE_AMD64 &&
        file_hdr->Machine != PE_MACHINE_ARM64)
    {
        fprintf(stderr, "e9ape: Unsupported PE machine type 0x%x\n",
                file_hdr->Machine);
        return -1;
    }

    /* Parse optional header */
    off_t pe_opt = pe_coff + sizeof(PE_FILE_HEADER);
    PE_OPTIONAL_HEADER64 *opt_hdr = (PE_OPTIONAL_HEADER64 *)(data + pe_opt);

    if (opt_hdr->Magic != 0x20B)
    {
        fprintf(stderr, "e9ape: Expected PE32+ (0x20B), got 0x%x\n",
                opt_hdr->Magic);
        return -1;
    }

    info->pe_size = opt_hdr->SizeOfImage;

    /* Parse section table */
    off_t sec_table = pe_opt + file_hdr->SizeOfOptionalHeader;
    PE_SECTION_HEADER *sections = (PE_SECTION_HEADER *)(data + sec_table);

    /* Cache section info for fast lookup */
    for (uint16_t i = 0; i < info->pe_num_sections && i < 16; i++)
    {
        PE_SECTION_HEADER *sec = &sections[i];

        if (memcmp(sec->Name, ".text", 5) == 0)
        {
            info->text_offset = sec->PointerToRawData;
            info->text_rva = sec->VirtualAddress;
            info->text_size = sec->SizeOfRawData;
        }
        else if (memcmp(sec->Name, ".rdata", 6) == 0)
        {
            info->rdata_offset = sec->PointerToRawData;
            info->rdata_rva = sec->VirtualAddress;
            info->rdata_size = sec->SizeOfRawData;
        }
        else if (memcmp(sec->Name, ".data", 5) == 0)
        {
            info->data_offset = sec->PointerToRawData;
            info->data_rva = sec->VirtualAddress;
            info->data_size = sec->SizeOfRawData;
        }
    }

    /* ── Find embedded headers ─────────────────────────────────────────
     *
     * RE of gcc.com reveals the prologue layout:
     *
     *   0x000   MZ + shell script (heredoc + platform detect + assimilate)
     *   ~0xC98  App's Mach-O header + load commands (__APE1/2/3 segments)
     *           Shell: dd skip=<offset> count=<size> copies to offset 0
     *   ~0xEA8  App's ELF program headers (phdrs only, no ehdr!)
     *           The ehdr is printf'd to offset 0 by --assimilate
     *   ...PE header at e_lfanew...
     *   ~0x10D88 Loader's Mach-O (different from app's)
     *   ~0x10FC0 Loader's x86-64 ELF (base 0x7f000000, NOT the app)
     *   ~0x11100 Loader's Mach-O variant
     *
     * Scan the prologue region (up to .text start) for:
     * 1. First Mach-O magic = app's Mach-O (before PE header)
     * 2. ELF magic = loader's ELF (may be after PE header)
     * 3. PT_LOAD phdrs for the app (between Mach-O and PE)       */
    off_t prologue_end = info->text_offset > 0 ? info->text_offset
                                                : (off_t)size;

    /* Find app's Mach-O (first 0xFEEDFACF before PE header) */
    for (off_t i = 0x200; i + 32 < info->pe_offset && i + 32 < (off_t)size; i++)
    {
        if (i + 4 <= (off_t)size)
        {
            uint32_t magic = *(uint32_t *)(data + i);
            if (magic == MACHO_MAGIC_64 || magic == MACHO_MAGIC_64_REV)
            {
                info->has_macho = true;
                info->macho_offset = i;

                /* Parse ncmds and sizeofcmds to get total size */
                if (i + 32 <= (off_t)size)
                {
                    uint32_t sizeofcmds = *(uint32_t *)(data + i + 20);
                    info->macho_size = 32 + sizeofcmds; /* header + commands */
                }

                /* ELF phdrs for --assimilate follow immediately after Mach-O.
                 * Check for PT_LOAD (type=1) at the next aligned position. */
                off_t post_macho = i + info->macho_size;
                if (post_macho + 56 < (off_t)size)
                {
                    uint32_t p_type = *(uint32_t *)(data + post_macho);
                    if (p_type == 1)  /* PT_LOAD */
                    {
                        info->has_elf_phdrs = true;
                        info->elf_phdrs_offset = post_macho;
                    }
                }
                break;
            }
        }
    }

    /* Find x86-64 ELF headers in full prologue (may be after PE header).
     * Note: the first one found is typically the APE loader's ELF,
     * not the application's (app uses printf-generated ehdr). */
    for (off_t i = 0x40; i + 64 < prologue_end && i + 64 < (off_t)size; i++)
    {
        if (memcmp(data + i, ELF_MAGIC, 4) == 0)
        {
            uint16_t e_machine = *(uint16_t *)(data + i + 18);
            if (e_machine == ELF_MACHINE_X86_64)
            {
                info->has_x86_elf = true;
                info->x86_elf_offset = i;
                break;
            }
        }
    }

    /* ARM64 ELF is typically after .data section */
    off_t search_start = info->data_offset + info->data_size;
    search_start = (search_start + 0xFFF) & ~0xFFF;  /* Align to 4KB */

    for (off_t i = search_start; i + 64 < (off_t)size; i += 0x1000)
    {
        if (memcmp(data + i, ELF_MAGIC, 4) == 0)
        {
            uint16_t e_machine = *(uint16_t *)(data + i + 18);
            if (e_machine == ELF_MACHINE_AARCH64)
            {
                info->has_arm64_elf = true;
                info->arm64_elf_offset = i;
                break;
            }
            else if (e_machine == ELF_MACHINE_X86_64 && !info->has_x86_elf)
            {
                /* x86-64 ELF found outside shell region (e.g. assimilated) */
                info->has_x86_elf = true;
                info->x86_elf_offset = i;
            }
        }
    }

    /* ── Find ZipOS at end ───────────────────────────────────────────── */

    /* Search backwards from end for EOCD signature */
    for (off_t i = size - 22; i > 0 && i > (off_t)size - 65536; i--)
    {
        if (memcmp(data + i, ZIP_END_MAGIC, 4) == 0)
        {
            info->zipos_end = i + 22;
            info->zipos_num_entries = *(uint16_t *)(data + i + 10);
            info->zipos_central_dir = *(uint32_t *)(data + i + 16);

            /* Find first local header */
            for (off_t j = 0; j < info->zipos_central_dir && j + 4 < (off_t)size; j++)
            {
                if (memcmp(data + j, ZIP_LOCAL_MAGIC, 4) == 0)
                {
                    info->zipos_start = j;
                    break;
                }
            }
            break;
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Address Translation
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Convert PE RVA to file offset
 * This is the PRIMARY method for APE patching.
 */
off_t e9_ape_rva_to_offset(const E9_APEInfo *info, uint32_t rva)
{
    if (info == NULL)
        return -1;

    /* Check .text */
    if (rva >= info->text_rva &&
        rva < info->text_rva + info->text_size)
    {
        return info->text_offset + (rva - info->text_rva);
    }

    /* Check .rdata */
    if (rva >= info->rdata_rva &&
        rva < info->rdata_rva + info->rdata_size)
    {
        return info->rdata_offset + (rva - info->rdata_rva);
    }

    /* Check .data */
    if (rva >= info->data_rva &&
        rva < info->data_rva + info->data_size)
    {
        return info->data_offset + (rva - info->data_rva);
    }

    /* In APE, RVA often equals file offset */
    /* This is a fallback for sections we didn't cache */
    return rva;
}

/*
 * Convert file offset to PE RVA
 */
uint32_t e9_ape_offset_to_rva(const E9_APEInfo *info, off_t offset)
{
    if (info == NULL)
        return 0;

    /* Check .text */
    if (offset >= info->text_offset &&
        offset < info->text_offset + (off_t)info->text_size)
    {
        return info->text_rva + (uint32_t)(offset - info->text_offset);
    }

    /* Check .rdata */
    if (offset >= info->rdata_offset &&
        offset < info->rdata_offset + (off_t)info->rdata_size)
    {
        return info->rdata_rva + (uint32_t)(offset - info->rdata_offset);
    }

    /* Check .data */
    if (offset >= info->data_offset &&
        offset < info->data_offset + (off_t)info->data_size)
    {
        return info->data_rva + (uint32_t)(offset - info->data_offset);
    }

    /* Fallback: in APE, often offset == RVA */
    return (uint32_t)offset;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Patching
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Apply patch at file offset
 * This is the safest method - directly specifies where in file to patch.
 */
int e9_ape_patch_offset(uint8_t *data, size_t size, const E9_APEInfo *info,
                        off_t offset, const uint8_t *patch, size_t patch_size)
{
    if (data == NULL || patch == NULL || patch_size == 0)
        return -1;

    if (offset < 0 || (size_t)(offset + patch_size) > size)
    {
        fprintf(stderr, "e9ape: Patch at offset 0x%lx (size %zu) out of bounds\n",
                (unsigned long)offset, patch_size);
        return -1;
    }

    /* Check if patch would damage ZipOS */
    if (info && info->preserve_zipos && info->zipos_start > 0)
    {
        if (offset + (off_t)patch_size > info->zipos_start)
        {
            fprintf(stderr, "e9ape: Warning: Patch overlaps ZipOS at 0x%lx\n",
                    (unsigned long)info->zipos_start);
            /* Continue anyway - user should know */
        }
    }

    memcpy(data + offset, patch, patch_size);
    return 0;
}

/*
 * Apply patch at PE RVA
 * Converts RVA to file offset using section mapping.
 */
int e9_ape_patch_rva(uint8_t *data, size_t size, const E9_APEInfo *info,
                     uint32_t rva, const uint8_t *patch, size_t patch_size)
{
    if (info == NULL)
        return -1;

    off_t offset = e9_ape_rva_to_offset(info, rva);
    if (offset < 0)
    {
        fprintf(stderr, "e9ape: Cannot translate RVA 0x%x to file offset\n", rva);
        return -1;
    }

    return e9_ape_patch_offset(data, size, info, offset, patch, patch_size);
}

/*
 * Legacy API: Patch at virtual address
 * Maps VA through PE section table (ELF and PE views share sections).
 * Assumes VA = ImageBase + RVA pattern.
 */
int e9_ape_patch(uint8_t *data, size_t size, const E9_APEInfo *info,
                 uint64_t vaddr, const uint8_t *patch, size_t patch_size)
{
    if (info == NULL)
        return -1;

    /* Both ELF and PE views share the same code/data sections.
     * Use PE section table for VA-to-offset translation. */

    /* Convert VA to RVA: typically VA = 0x400000 + RVA in APE */
    uint32_t rva;
    if (vaddr >= 0x400000 && vaddr < 0x500000)
    {
        rva = (uint32_t)(vaddr - 0x400000);
    }
    else if (vaddr < 0x100000)
    {
        /* Already an RVA or file offset */
        rva = (uint32_t)vaddr;
    }
    else
    {
        fprintf(stderr, "e9ape: Unusual virtual address 0x%lx, treating as RVA\n",
                (unsigned long)vaddr);
        rva = (uint32_t)vaddr;
    }

    return e9_ape_patch_rva(data, size, info, rva, patch, patch_size);
}

/* ═══════════════════════════════════════════════════════════════════════
 * ZipOS
 * ═══════════════════════════════════════════════════════════════════════ */

E9_ZipOSEntry *e9_ape_zipos_list(const uint8_t *data, size_t size,
                               const E9_APEInfo *info, size_t *out_count)
{
    if (data == NULL || info == NULL || out_count == NULL)
    {
        if (out_count) *out_count = 0;
        return NULL;
    }

    if (info->zipos_central_dir == 0)
    {
        *out_count = 0;
        return NULL;
    }

    /* Count entries from central directory */
    size_t count = 0;
    off_t pos = info->zipos_central_dir;

    while (pos + 46 < (off_t)size)
    {
        if (memcmp(data + pos, ZIP_CENTRAL_MAGIC, 4) != 0)
            break;

        count++;
        uint16_t name_len = *(uint16_t *)(data + pos + 28);
        uint16_t extra_len = *(uint16_t *)(data + pos + 30);
        uint16_t comment_len = *(uint16_t *)(data + pos + 32);
        pos += 46 + name_len + extra_len + comment_len;
    }

    if (count == 0)
    {
        *out_count = 0;
        return NULL;
    }

    /* Allocate and fill entries */
    E9_ZipOSEntry *entries = (E9_ZipOSEntry *)calloc(count, sizeof(E9_ZipOSEntry));
    if (entries == NULL)
    {
        *out_count = 0;
        return NULL;
    }

    pos = info->zipos_central_dir;
    for (size_t i = 0; i < count && pos + 46 < (off_t)size; i++)
    {
        entries[i].compression = *(uint16_t *)(data + pos + 10);
        entries[i].crc32 = *(uint32_t *)(data + pos + 16);
        entries[i].compressed_size = *(uint32_t *)(data + pos + 20);
        entries[i].uncompressed_size = *(uint32_t *)(data + pos + 24);
        entries[i].local_header_offset = *(uint32_t *)(data + pos + 42);

        uint16_t name_len = *(uint16_t *)(data + pos + 28);
        uint16_t extra_len = *(uint16_t *)(data + pos + 30);
        uint16_t comment_len = *(uint16_t *)(data + pos + 32);

        entries[i].name = (char *)malloc(name_len + 1);
        if (entries[i].name)
        {
            memcpy(entries[i].name, data + pos + 46, name_len);
            entries[i].name[name_len] = '\0';
            entries[i].is_directory = (name_len > 0 &&
                                       entries[i].name[name_len - 1] == '/');
        }

        pos += 46 + name_len + extra_len + comment_len;
    }

    *out_count = count;
    return entries;
}

void e9_ape_zipos_free_list(E9_ZipOSEntry *entries, size_t count)
{
    if (entries == NULL)
        return;

    for (size_t i = 0; i < count; i++)
        free(entries[i].name);

    free(entries);
}

bool e9_ape_zipos_exists(const uint8_t *data, size_t size,
                          const E9_APEInfo *info, const char *path)
{
    if (path == NULL)
        return false;

    size_t count;
    E9_ZipOSEntry *entries = e9_ape_zipos_list(data, size, info, &count);
    if (entries == NULL)
        return false;

    bool found = false;
    for (size_t i = 0; i < count; i++)
    {
        if (entries[i].name && strcmp(entries[i].name, path) == 0)
        {
            found = true;
            break;
        }
    }

    e9_ape_zipos_free_list(entries, count);
    return found;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Utilities
 * ═══════════════════════════════════════════════════════════════════════ */

const char *e9_ape_get_self_path(void)
{
#ifdef __linux__
    static char path[4096];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len > 0)
    {
        path[len] = '\0';
        return path;
    }
#elif defined(__APPLE__)
    static char path[4096];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) == 0)
        return path;
#elif defined(_WIN32)
    static char path[4096];
    if (GetModuleFileNameA(NULL, path, sizeof(path)) > 0)
        return path;
#endif
    return NULL;
}

/*
 * Debug: Print APE info
 */
void e9_ape_dump_info(const E9_APEInfo *info, FILE *out)
{
    if (info == NULL || out == NULL)
        return;

    fprintf(out, "APE Info:\n");
    fprintf(out, "  Cosmopolitan: %s\n", info->is_cosmopolitan ? "yes" : "no");
    fprintf(out, "  PE offset: 0x%lx\n", (unsigned long)info->pe_offset);
    fprintf(out, "  Sections: %u\n", info->pe_num_sections);
    fprintf(out, "  .text: offset=0x%lx rva=0x%x size=0x%zx\n",
            (unsigned long)info->text_offset, info->text_rva, info->text_size);
    fprintf(out, "  .rdata: offset=0x%lx rva=0x%x size=0x%zx\n",
            (unsigned long)info->rdata_offset, info->rdata_rva, info->rdata_size);
    fprintf(out, "  .data: offset=0x%lx rva=0x%x size=0x%zx\n",
            (unsigned long)info->data_offset, info->data_rva, info->data_size);
    fprintf(out, "  ARM64 ELF: %s", info->has_arm64_elf ? "yes" : "no");
    if (info->has_arm64_elf)
        fprintf(out, " at 0x%lx", (unsigned long)info->arm64_elf_offset);
    fprintf(out, "\n");
    fprintf(out, "  Loader ELF: %s", info->has_x86_elf ? "yes" : "no");
    if (info->has_x86_elf)
        fprintf(out, " at 0x%lx", (unsigned long)info->x86_elf_offset);
    fprintf(out, "\n");
    fprintf(out, "  App ELF phdrs: %s", info->has_elf_phdrs ? "yes" : "no");
    if (info->has_elf_phdrs)
        fprintf(out, " at 0x%lx", (unsigned long)info->elf_phdrs_offset);
    fprintf(out, "\n");
    fprintf(out, "  App Mach-O: %s", info->has_macho ? "yes" : "no");
    if (info->has_macho)
        fprintf(out, " at 0x%lx (size=%zu)", (unsigned long)info->macho_offset,
                info->macho_size);
    fprintf(out, "\n");
    fprintf(out, "  ZipOS: start=0x%lx entries=%u\n",
            (unsigned long)info->zipos_start, info->zipos_num_entries);
}
