#pragma once

#include <cstdint>

// Prefer the system ELF definitions on platforms that ship them. On Windows
// (MSVC) <elf.h> is unavailable, so provide the small subset Relay needs.
#if !defined(_WIN32)
#include <elf.h>
#define RELAY_HAVE_SYSTEM_ELF_H 1
#endif

#ifndef RELAY_HAVE_SYSTEM_ELF_H

typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t Elf64_Sxword;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;

typedef struct {
    unsigned char e_ident[16];
    Elf64_Half    e_type;
    Elf64_Half    e_machine;
    Elf64_Word    e_version;
    Elf64_Addr    e_entry;
    Elf64_Off     e_phoff;
    Elf64_Off     e_shoff;
    Elf64_Word    e_flags;
    Elf64_Half    e_ehsize;
    Elf64_Half    e_phentsize;
    Elf64_Half    e_phnum;
    Elf64_Half    e_shentsize;
    Elf64_Half    e_shnum;
    Elf64_Half    e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    Elf64_Word   p_type;
    Elf64_Word   p_flags;
    Elf64_Off    p_offset;
    Elf64_Addr   p_vaddr;
    Elf64_Addr   p_paddr;
    Elf64_Xword  p_filesz;
    Elf64_Xword  p_memsz;
    Elf64_Xword  p_align;
} Elf64_Phdr;

#define PT_LOAD 1
#define PF_X    1

static_assert(sizeof(Elf64_Ehdr) == 64, "Unexpected Elf64_Ehdr layout");
static_assert(sizeof(Elf64_Phdr) == 56, "Unexpected Elf64_Phdr layout");

#endif // !RELAY_HAVE_SYSTEM_ELF_H
