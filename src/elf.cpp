#include "elf/elf.h"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <utility>

#include <Zydis/Zydis.h>

namespace {
using namespace quant::codegen::mc;

struct DecodedInsn {
    uint64_t offset = 0; // relative to the p_offset of the executable segment
    ZydisDecodedInstruction ins{};
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
};

bool is_nr_register(ZydisRegister r) {
    return r == ZYDIS_REGISTER_RAX ||
           r == ZYDIS_REGISTER_EAX ||
           r == ZYDIS_REGISTER_AX  ||
           r == ZYDIS_REGISTER_AL;
}

bool is_block_boundary(const ZydisDecodedInstruction& ins) {
    switch (ins.mnemonic) {
        case ZYDIS_MNEMONIC_SYSCALL:
        case ZYDIS_MNEMONIC_SYSENTER:
        case ZYDIS_MNEMONIC_SYSEXIT:
        case ZYDIS_MNEMONIC_INT:
        case ZYDIS_MNEMONIC_INTO:
        case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_CALL:
        case ZYDIS_MNEMONIC_RET:
        case ZYDIS_MNEMONIC_JMP:
            return true;
        default:
            break;
    }

    return ins.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE;
}

// looking for the last write of immediates to EAX/RAX that occurs before a syscall.
int64_t extract_nr(const std::vector<DecodedInsn>& decs, size_t idx) {

    for (size_t n = 0; n < 16 && idx > n; ++n) {
        const DecodedInsn& d = decs[idx - 1 - n];

        if (is_block_boundary(d.ins))
            break;

        const bool dst_is_rax =
            d.ins.operand_count_visible >= 2 &&
            d.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            is_nr_register(d.ops[0].reg.value);

        // mov eax/rax, imm
        if (dst_is_rax &&
            (d.ins.mnemonic == ZYDIS_MNEMONIC_MOV ||
             d.ins.mnemonic == ZYDIS_MNEMONIC_MOVZX) &&
            d.ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            return static_cast<int64_t>(d.ops[1].imm.value.u & 0xFFFFFFFFull);
        }

        // xor eax, eax -> nr = 0 (read)
        if (d.ins.mnemonic == ZYDIS_MNEMONIC_XOR &&
            dst_is_rax &&
            d.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            is_nr_register(d.ops[1].reg.value)) {
            return 0;
        }
    }
    return -1;
}

const char* syscall_name(TargetArch arch, int64_t nr) {
    if (arch == TargetArch::AARCH64) {
        switch (nr) {
            case 56:  return "openat";
            case 63:  return "read";
            case 64:  return "write";
            case 93:  return "exit";
            case 94:  return "exit_group";
            case 172: return "getpid";
            case 215: return "munmap";
            case 222: return "mmap";
            default:  return "?";
        }
    }

    switch (nr) {
        case 0:   return "read";
        case 1:   return "write";
        case 2:   return "open";
        case 3:   return "close";
        case 5:   return "fstat";
        case 8:   return "lseek";
        case 9:   return "mmap";
        case 11:  return "munmap";
        case 12:  return "brk";
        case 14:  return "rt_sigprocmask";
        case 20:  return "writev";
        case 28:  return "madvise";
        case 39:  return "getpid";
        case 57:  return "fork";
        case 59:  return "execve";
        case 60:  return "exit";
        case 72:  return "fcntl";
        case 74:  return "fsync";
        case 79:  return "getcwd";
        case 99:  return "sysinfo";
        case 158: return "arch_prctl";
        case 186: return "gettid";
        case 202: return "futex";
        case 231: return "exit_group";
        case 234: return "tgkill";
        case 257: return "openat";
        case 267: return "readlinkat";
        case 302: return "prlimit64";
        case 318: return "getrandom";
        case 334: return "rseq";
        default:  return "?";
    }
}

// func name from .symtab, within which a virtual address resides
std::string function_for(uint64_t va, const uint8_t* data, uint64_t file_size) {
    if (!data || file_size < sizeof(Elf64_Ehdr))
        return {};

    const auto* eh = reinterpret_cast<const Elf64_Ehdr*>(data);

    if (eh->e_shoff == 0 || eh->e_shnum == 0)
        return {}; // remove .symtab
    if (eh->e_shoff + eh->e_shnum * sizeof(Elf64_Shdr) > file_size)
        return {};

    const auto* shdrs = reinterpret_cast<const Elf64_Shdr*>(data + eh->e_shoff);

    for (uint16_t i = 0; i < eh->e_shnum; ++i) {
        if (shdrs[i].sh_type != SHT_SYMTAB)
            continue;
        if (shdrs[i].sh_link >= eh->e_shnum)
            continue;
        if (shdrs[i].sh_offset > file_size ||
            shdrs[i].sh_size > file_size - shdrs[i].sh_offset)
            continue;

        const auto& strtab = shdrs[shdrs[i].sh_link];
        if (strtab.sh_offset > file_size || strtab.sh_size > file_size - strtab.sh_offset)
            continue;

        const auto* syms = reinterpret_cast<const Elf64_Sym*>(data + shdrs[i].sh_offset);
        const auto* strs = reinterpret_cast<const char*>(data + strtab.sh_offset);
        const size_t count = static_cast<size_t>(shdrs[i].sh_size / sizeof(Elf64_Sym));

        for (size_t k = 0; k < count; ++k) {
            const Elf64_Sym& s = syms[k];
            if (ELF64_ST_TYPE(s.st_info) != STT_FUNC)
                continue;
            if (s.st_size == 0)
                continue;
            if (va < s.st_value || va >= s.st_value + s.st_size)
                continue;
            if (s.st_name >= strtab.sh_size)
                continue;
            return std::string(strs + s.st_name);
        }
    }
    return {};
}

} // namespace

ElfManager::ElfManager() : elf_data(nullptr), file_size(0) {}

ElfManager::~ElfManager() = default;

TargetArch ElfManager::detect_arch() const {
    if (!elf_data || file_size < sizeof(Elf64_Ehdr))
        return TargetArch::Unknown;

    const auto* eh = reinterpret_cast<const Elf64_Ehdr*>(elf_data);
    if (eh->e_machine == EM_X86_64)
        return TargetArch::X86_64;
    if (eh->e_machine == EM_AARCH64)
        return TargetArch::AARCH64;
    return TargetArch::Unknown;
}

TargetOS ElfManager::detect_os() const {
    if (!elf_data || file_size < sizeof(Elf64_Ehdr))
        return TargetOS::Unknown;

    const auto* eh = reinterpret_cast<const Elf64_Ehdr*>(elf_data);
    if (eh->e_phoff + eh->e_phnum * sizeof(Elf64_Phdr) > file_size)
        return TargetOS::Unknown;

    const auto* phdrs = reinterpret_cast<const Elf64_Phdr*>(elf_data + eh->e_phoff);

    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (phdrs[i].p_type == PT_INTERP) {
            return TargetOS::Linux;
        }
    }
    return TargetOS::Unknown; // super os, zero point and stuff isn't supported yet.
}

bool ElfManager::load(const char* path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Failed to open file: " << path << std::endl;
        return false;
    }

    const std::streamsize size = file.tellg();
    if (size <= 0) {
        std::cerr << "File is empty: " << path << std::endl;
        return false;
    }

    file.seekg(0, std::ios::beg);
    m_bytes.resize(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(m_bytes.data()), size)) {
        std::cerr << "Failed to read file: " << path << std::endl;
        m_bytes.clear();
        return false;
    }

    elf_data = m_bytes.data();
    file_size = m_bytes.size();

    if (file_size < sizeof(Elf64_Ehdr) ||
        elf_data[0] != 0x7F || elf_data[1] != 'E' ||
        elf_data[2] != 'L'  || elf_data[3] != 'F') {
        std::cerr << "File is not ELF!" << std::endl;
        elf_data = nullptr;
        file_size = 0;
        m_bytes.clear();
        return false;
    }

    const auto* eh = reinterpret_cast<const Elf64_Ehdr*>(elf_data);

    if (eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_ident[EI_DATA] != ELFDATA2LSB) {
        std::cerr << "Only 64-bit little-endian ELF is supported!" << std::endl;
        elf_data = nullptr;
        file_size = 0;
        m_bytes.clear();
        return false;
    }

    m_arch = detect_arch();
    m_os = detect_os();
    return true;
}

std::vector<SyscallSite> ElfManager::find_syscall_sites() {
    std::vector<SyscallSite> result;

    if (!elf_data || file_size < sizeof(Elf64_Ehdr))
        return result;

    if (m_arch != TargetArch::X86_64) {
        std::cerr << "[relay] syscall site extraction is x86-64 only for now\n";
        return result;
    }

    const auto* eh = reinterpret_cast<const Elf64_Ehdr*>(elf_data);

    if (eh->e_phoff + eh->e_phnum * sizeof(Elf64_Phdr) > file_size)
        return result;

    const auto* phdrs = reinterpret_cast<const Elf64_Phdr*>(elf_data + eh->e_phoff);

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(
            &decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
        return result;

    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        const Elf64_Phdr& ph = phdrs[i];
        if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_X))
            continue;
        if (ph.p_offset > file_size || ph.p_filesz > file_size - ph.p_offset)
            continue;

        // 1) decode all the segment
        std::vector<DecodedInsn> decs;
        decs.reserve(static_cast<size_t>(ph.p_filesz / 2));

        uint64_t cursor = 0;
        while (cursor < ph.p_filesz) {
            DecodedInsn d;
            d.offset = cursor;

            const ZyanStatus st = ZydisDecoderDecodeFull(
                &decoder,
                elf_data + ph.p_offset + cursor,
                static_cast<ZyanUSize>(ph.p_filesz - cursor),
                &d.ins,
                d.ops
            );

            if (ZYAN_SUCCESS(st)) {
                decs.push_back(d);
                cursor += d.ins.length;
            } else {
                ++cursor; // resync
            }
        }

        // 2) For each syscall, collect its metadata.
        for (size_t k = 0; k < decs.size(); ++k) {
            if (decs[k].ins.mnemonic != ZYDIS_MNEMONIC_SYSCALL)
                continue;

            SyscallSite site;
            site.va = ph.p_vaddr  + decs[k].offset;
            site.file_off = ph.p_offset + decs[k].offset;
            site.insn_size = decs[k].ins.length;
            site.arch = m_arch;
            site.os = m_os;
            site.number = extract_nr(decs, k);
            site.name = syscall_name(m_arch, site.number);
            site.function = function_for(site.va, elf_data, file_size);

            result.push_back(std::move(site));
        }
    }

    return result;
}

std::vector<uint64_t> ElfManager::find_syscalls() {
    const std::vector<SyscallSite> sites = find_syscall_sites();
    std::vector<uint64_t> addrs;
    addrs.reserve(sites.size());

    for (const SyscallSite& s : sites)
        addrs.push_back(s.va);

    return addrs;
}