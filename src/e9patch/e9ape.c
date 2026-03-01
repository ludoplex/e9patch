/*
 * e9ape.c
 * APE (Actually Portable Executable) Binary Rewriting Implementation
 *
 * Cosmopolitan APE binaries are polyglot executables that work on
 * Linux, macOS, Windows, FreeBSD, OpenBSD, and NetBSD from a single
 * file. This module enables e9patch to work directly with APE binaries.
 *
 * APE Structure (typical):
 *   [0x0000] DOS MZ header (first 64 bytes)
 *   [0x0040] Shell script bootstrap (#!/bin/sh or similar)
 *   [0x0XXX] ELF header and program headers
 *   [0x0XXX] PE header and sections
 *   [0x0XXX] Executable code (shared between ELF/PE views)
 *   [0xXXXX] ZipOS (ZIP central directory at end)
 *
 * Key insight: ELF and PE share the same code bytes but at different
 * virtual addresses. When patching, we must update both views.
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

#include <elf.h>

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
} PE_FILE_HEADER;

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
    /* ... more fields ... */
} PE_OPTIONAL_HEADER64;

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
} PE_SECTION_HEADER;

/*
 * APE Magic signatures
 */
#define APE_MAGIC_MZ        "MZqFpD"
#define APE_MAGIC_SHELL     "#!/"

/*
 * APE Info structure (standalone, not depending on e9patch.h)
 */
typedef struct {
    /* ELF view */
    Elf64_Ehdr *elf_ehdr;
    off_t elf_offset;
    size_t elf_size;

    /* PE view */
    PE_FILE_HEADER *pe_file_hdr;
    PE_OPTIONAL_HEADER64 *pe_opt_hdr;
    PE_SECTION_HEADER *pe_sections;
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
    bool sync_elf_pe;
    bool preserve_zipos;
} APEInfo;

/*
 * ZipOS entry
 */
typedef struct {
    const char *name;
    off_t offset;
    size_t compressed_size;
    size_t uncompressed_size;
    uint16_t compression;
    uint32_t crc32;
    bool is_directory;
} ZipOSEntry;

/*
 * Check if data is APE format
 */
bool e9_ape_detect(const uint8_t *data, size_t size)
{
    if (data == NULL || size < 64)
        return false;

    /* Check for Cosmopolitan APE magic "MZqFpD" */
    if (memcmp(data, APE_MAGIC_MZ, 6) == 0)
        return true;

    /* Check for MZ + embedded ELF (generic APE pattern) */
    if (data[0] == 'M' && data[1] == 'Z')
    {
        /* Look for ELF magic in first 8KB */
        size_t scan_limit = (size < 8192) ? size : 8192;
        for (size_t i = 64; i < scan_limit - 4; i++)
        {
            if (data[i] == 0x7f && data[i+1] == 'E' &&
                data[i+2] == 'L' && data[i+3] == 'F')
            {
                return true;
            }
        }
    }

    /* Check for shell script APE variant */
    if (data[0] == '#' && data[1] == '!')
    {
        size_t scan_limit = (size < 65536) ? size : 65536;
        bool has_elf = false, has_mz = false;

        for (size_t i = 0; i < scan_limit - 4; i++)
        {
            if (!has_elf && memcmp(data + i, "\x7fELF", 4) == 0)
                has_elf = true;
            if (!has_mz && data[i] == 'M' && data[i+1] == 'Z')
                has_mz = true;
            if (has_elf && has_mz)
                return true;
        }
    }

    return false;
}

/*
 * Parse APE structure
 */
int e9_ape_parse(const uint8_t *data, size_t size, APEInfo *info)
{
    if (data == NULL || info == NULL || size < 64)
        return -1;

    if (!e9_ape_detect(data, size))
        return -1;

    memset(info, 0, sizeof(APEInfo));
    info->sync_elf_pe = true;
    info->preserve_zipos = true;

    /* Find shell script offset */
    if (data[0] == '#' && data[1] == '!')
    {
        info->shell_offset = 0;
        for (size_t i = 0; i < size && i < 4096; i++)
        {
            if (data[i] == 0x7f && i + 4 < size &&
                memcmp(data + i, "\x7fELF", 4) == 0)
            {
                info->shell_size = i;
                break;
            }
            if (data[i] == 0x00)
            {
                info->shell_size = i;
                break;
            }
        }
    }

    /* Find ELF header */
    for (size_t i = 0; i < size - 4 && i < 65536; i++)
    {
        if (memcmp(data + i, "\x7fELF", 4) == 0)
        {
            info->elf_offset = (off_t)i;
            info->elf_ehdr = (Elf64_Ehdr *)(data + i);

            if (i + 64 <= size && data[i + 4] == 2)  /* 64-bit */
            {
                Elf64_Ehdr *ehdr = info->elf_ehdr;
                uint64_t phoff = ehdr->e_phoff;
                uint16_t phnum = ehdr->e_phnum;
                uint16_t phentsize = ehdr->e_phentsize;

                /* Calculate ELF size */
                uint64_t max_end = 64;
                for (uint16_t j = 0; j < phnum; j++)
                {
                    size_t ph_off = i + phoff + j * phentsize;
                    if (ph_off + 56 > size) break;

                    Elf64_Phdr *phdr = (Elf64_Phdr *)(data + ph_off);
                    if (phdr->p_offset + phdr->p_filesz > max_end)
                        max_end = phdr->p_offset + phdr->p_filesz;
                }
                info->elf_size = max_end;
            }
            break;
        }
    }

    /* Find PE/DOS header */
    for (size_t i = 0; i < size - 64; i++)
    {
        if (data[i] == 'M' && data[i+1] == 'Z')
        {
            if (i + 0x3C + 4 > size) continue;

            uint32_t pe_off = *(uint32_t *)(data + i + 0x3C);
            if (i + pe_off + 4 > size) continue;

            if (memcmp(data + i + pe_off, "PE\0\0", 4) == 0)
            {
                info->pe_offset = (off_t)i;
                info->pe_file_hdr = (PE_FILE_HEADER *)(data + i + pe_off + 4);

                uint16_t opt_hdr_size = info->pe_file_hdr->SizeOfOptionalHeader;
                if (i + pe_off + 24 + opt_hdr_size <= size)
                {
                    info->pe_opt_hdr = (PE_OPTIONAL_HEADER64 *)(data + i + pe_off + 24);
                }

                info->pe_num_sections = info->pe_file_hdr->NumberOfSections;
                size_t sec_table = pe_off + 24 + opt_hdr_size;
                info->pe_sections = (PE_SECTION_HEADER *)(data + i + sec_table);

                /* Calculate PE size */
                uint32_t max_end = 0;
                for (uint16_t j = 0; j < info->pe_num_sections; j++)
                {
                    PE_SECTION_HEADER *sec = &info->pe_sections[j];
                    if (sec->PointerToRawData + sec->SizeOfRawData > max_end)
                        max_end = sec->PointerToRawData + sec->SizeOfRawData;
                }
                info->pe_size = max_end;
                break;
            }
        }
    }

    /* Find ZipOS */
    for (size_t i = size - 22; i > 0 && i > size - 65536; i--)
    {
        if (data[i] == 'P' && data[i+1] == 'K' &&
            data[i+2] == 0x05 && data[i+3] == 0x06)
        {
            info->zipos_end = (off_t)(i + 22);
            info->zipos_num_entries = *(uint16_t *)(data + i + 10);
            info->zipos_central_dir = (off_t)(*(uint32_t *)(data + i + 16));

            for (size_t j = 0; j < (size_t)info->zipos_central_dir && j + 4 < size; j++)
            {
                if (data[j] == 'P' && data[j+1] == 'K' &&
                    data[j+2] == 0x03 && data[j+3] == 0x04)
                {
                    info->zipos_start = (off_t)j;
                    break;
                }
            }
            break;
        }
    }

    return 0;
}

/*
 * Convert ELF virtual address to file offset within APE
 */
off_t e9_ape_elf_vaddr_to_offset(const uint8_t *data, const APEInfo *info,
                                  uint64_t vaddr)
{
    if (data == NULL || info == NULL || info->elf_ehdr == NULL)
        return -1;

    Elf64_Ehdr *ehdr = info->elf_ehdr;
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(data + info->elf_offset + ehdr->e_phoff);

    for (uint16_t i = 0; i < ehdr->e_phnum; i++)
    {
        if (phdrs[i].p_type == PT_LOAD)
        {
            uint64_t seg_start = phdrs[i].p_vaddr;
            uint64_t seg_end = seg_start + phdrs[i].p_memsz;

            if (vaddr >= seg_start && vaddr < seg_end)
            {
                uint64_t offset_in_seg = vaddr - seg_start;
                return info->elf_offset + phdrs[i].p_offset + offset_in_seg;
            }
        }
    }

    return -1;
}

/*
 * Convert PE virtual address to file offset within APE
 */
off_t e9_ape_pe_vaddr_to_offset(const APEInfo *info, uint64_t vaddr)
{
    if (info == NULL || info->pe_opt_hdr == NULL || info->pe_sections == NULL)
        return -1;

    uint64_t image_base = info->pe_opt_hdr->ImageBase;
    if (vaddr < image_base)
        return -1;

    uint64_t rva = vaddr - image_base;

    for (uint16_t i = 0; i < info->pe_num_sections; i++)
    {
        PE_SECTION_HEADER *sec = &info->pe_sections[i];
        uint32_t sec_start = sec->VirtualAddress;
        uint32_t sec_end = sec_start + sec->VirtualSize;

        if (rva >= sec_start && rva < sec_end)
        {
            uint32_t offset_in_sec = (uint32_t)(rva - sec_start);
            return info->pe_offset + sec->PointerToRawData + offset_in_sec;
        }
    }

    return -1;
}

/*
 * Apply patch to APE binary (both ELF and PE views if sync enabled)
 */
int e9_ape_patch(uint8_t *data, size_t size, const APEInfo *info,
                  uint64_t elf_vaddr, const uint8_t *patch, size_t patch_size)
{
    if (data == NULL || info == NULL || patch == NULL || patch_size == 0)
        return -1;

    /* Get ELF file offset */
    off_t elf_off = e9_ape_elf_vaddr_to_offset(data, info, elf_vaddr);
    if (elf_off < 0 || (size_t)(elf_off + patch_size) > size)
    {
        fprintf(stderr, "e9ape: ELF patch at 0x%lx out of bounds\n",
                (unsigned long)elf_vaddr);
        return -1;
    }

    /* Apply patch at ELF location */
    memcpy(data + elf_off, patch, patch_size);

    /* If sync enabled and PE view exists, try to patch PE view too */
    if (info->sync_elf_pe && info->pe_offset != 0)
    {
        /* In APE, ELF and PE often share code at same file offsets
         * but with different virtual addresses. We've already patched
         * the file offset, so PE view gets it automatically if they share. */

        /* If they don't share (different mappings), we'd need the
         * corresponding PE virtual address to patch. For now, we assume
         * shared code sections. */
    }

    return 0;
}

/*
 * List ZipOS entries
 */
ZipOSEntry *e9_ape_zipos_list(const uint8_t *data, size_t size,
                               const APEInfo *info, size_t *out_count)
{
    if (data == NULL || info == NULL || out_count == NULL)
    {
        if (out_count) *out_count = 0;
        return NULL;
    }

    if (info->zipos_start == 0 || info->zipos_central_dir == 0)
    {
        *out_count = 0;
        return NULL;
    }

    /* Count entries */
    size_t count = 0;
    off_t pos = info->zipos_central_dir;
    while (pos + 46 < (off_t)size)
    {
        if (memcmp(data + pos, "PK\x01\x02", 4) != 0)
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

    /* Allocate and parse entries */
    ZipOSEntry *entries = (ZipOSEntry *)calloc(count, sizeof(ZipOSEntry));
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

        uint16_t name_len = *(uint16_t *)(data + pos + 28);
        uint16_t extra_len = *(uint16_t *)(data + pos + 30);
        uint16_t comment_len = *(uint16_t *)(data + pos + 32);
        entries[i].offset = *(uint32_t *)(data + pos + 42);

        char *name = (char *)malloc(name_len + 1);
        if (name)
        {
            memcpy(name, data + pos + 46, name_len);
            name[name_len] = '\0';
            entries[i].name = name;
            entries[i].is_directory = (name_len > 0 && name[name_len-1] == '/');
        }

        pos += 46 + name_len + extra_len + comment_len;
    }

    *out_count = count;
    return entries;
}

/*
 * Free ZipOS entry list
 */
void e9_ape_zipos_free_list(ZipOSEntry *entries, size_t count)
{
    if (entries == NULL)
        return;

    for (size_t i = 0; i < count; i++)
        free((void *)entries[i].name);

    free(entries);
}

/*
 * Read uncompressed file from ZipOS
 */
uint8_t *e9_ape_zipos_read(const uint8_t *data, size_t size,
                            const APEInfo *info, const char *path,
                            size_t *out_size)
{
    if (data == NULL || info == NULL || path == NULL || out_size == NULL)
        return NULL;

    size_t count;
    ZipOSEntry *entries = e9_ape_zipos_list(data, size, info, &count);
    if (entries == NULL)
        return NULL;

    uint8_t *result = NULL;
    for (size_t i = 0; i < count; i++)
    {
        if (entries[i].name && strcmp(entries[i].name, path) == 0)
        {
            if (entries[i].compression == 0)  /* Stored */
            {
                off_t local_hdr = entries[i].offset;
                if (local_hdr + 30 > (off_t)size)
                    break;

                uint16_t name_len = *(uint16_t *)(data + local_hdr + 26);
                uint16_t extra_len = *(uint16_t *)(data + local_hdr + 28);
                off_t data_off = local_hdr + 30 + name_len + extra_len;

                if (data_off + entries[i].compressed_size > (off_t)size)
                    break;

                result = (uint8_t *)malloc(entries[i].uncompressed_size);
                if (result)
                {
                    memcpy(result, data + data_off, entries[i].uncompressed_size);
                    *out_size = entries[i].uncompressed_size;
                }
            }
            break;
        }
    }

    e9_ape_zipos_free_list(entries, count);
    return result;
}

/*
 * Get self executable path (Linux)
 */
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
#endif
    return NULL;
}
