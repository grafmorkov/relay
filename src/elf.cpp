#include "elf/elf.h"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <vector>
#include <Zydis/Zydis.h>

ElfManager::ElfManager() : file_size(0), elf_data(nullptr) {

}

ElfManager::~ElfManager() = default;

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
    file_size = static_cast<int>(m_bytes.size());

    if (file_size < static_cast<int>(sizeof(Elf64_Ehdr)) ||
        elf_data[0] != 0x7F || elf_data[1] != 'E' || elf_data[2] != 'L' || elf_data[3] != 'F') {
        std::cerr << "File is not ELF!" << std::endl;
        elf_data = nullptr;
        file_size = 0;
        m_bytes.clear();
        return false;
    }

    return true;
}

std::vector<uint64_t> ElfManager::find_syscalls() {
    if(file_size < sizeof(Elf64_Ehdr)) {
        return {};
    }

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)elf_data;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    if (ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr) > (size_t)file_size) {
        return {};
    }

    Elf64_Phdr* phdrs = (Elf64_Phdr*)(elf_data + ehdr->e_phoff);

    std::vector<uint64_t> result;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && (phdrs[i].p_flags & PF_X)) {
            uint64_t offset = phdrs[i].p_offset;
            uint64_t size = phdrs[i].p_filesz;
            uint64_t vaddr = phdrs[i].p_vaddr;

            if (offset + size > (uint64_t)file_size) {
                continue;
            }

            uint64_t cursor = 0;
            ZydisDecodedInstruction instruction;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

            while (cursor < size) {
                ZyanStatus status = ZydisDecoderDecodeFull(
                    &decoder,
                    elf_data + offset + cursor,
                    size - cursor,
                    &instruction,
                    operands
                );

                if (ZYAN_SUCCESS(status)) {
                    if (instruction.mnemonic == ZYDIS_MNEMONIC_SYSCALL) {
                        result.push_back(vaddr + cursor);
                    }
                    cursor += instruction.length;
                } else {
                    cursor++;
                }
            }
        }
    }

    return result;
}
