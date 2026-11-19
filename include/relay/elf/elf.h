#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

#include <elf.h>

#include "backend/mc.h"

struct SyscallSite {
    uint64_t va = 0;   // virtual address (from p_vaddr)
    uint64_t file_off = 0;   // file offset
    uint32_t insn_size = 0;   // 2 (syscall) / 4 (svc)
    int64_t number = -1;  // number from RAX/X8; -1 - undefined staticaly
    std::string name; // "write", "mmap", ... or "?"
    std::string function; // function name from .symtab (like "__write")
    quant::codegen::mc::TargetArch arch = quant::codegen::mc::TargetArch::Unknown; // qu-backend arch
    quant::codegen::mc::TargetOS os = quant::codegen::mc::TargetOS::Unknown; // qu-backend os
};


class ElfManager {
public:
    ElfManager();
    ~ElfManager();

    bool load(const char* path);
    std::vector<uint64_t> find_syscalls();
    std::vector<SyscallSite> find_syscall_sites();

    uint8_t* elf_data;
    size_t file_size;
private:
    quant::codegen::mc::TargetArch detect_arch() const;
    quant::codegen::mc::TargetOS detect_os() const;
    uint64_t get_runtime_address(const uint8_t* elf_data, uint64_t target_file_offset);

    std::vector<uint8_t> m_bytes;
    quant::codegen::mc::TargetOS m_os;
    quant::codegen::mc::TargetArch m_arch;
};
