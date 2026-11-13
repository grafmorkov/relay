#include "elf/elf.h"
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <Zydis/Zydis.h>

ElfManager::ElfManager() : m_fd(0), file_size(0), elf_data(0) {

}

ElfManager::~ElfManager() {
    if(!elf_data) return;
    msync(elf_data, file_size, MS_SYNC);
    munmap(elf_data, file_size);
    close(m_fd);
}

bool ElfManager::load(const char* path) {
    m_fd = open(path, O_RDWR);
    if (m_fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(m_fd, &st) < 0) {
        perror("fstat");
        close(m_fd);
        return 1;
    }
    file_size = st.st_size;

    elf_data = static_cast<uint8_t*>(mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, m_fd, 0));
    if (elf_data == MAP_FAILED) {
        perror("mmap");
        close(m_fd);
        return 1;
    }

    if (file_size < sizeof(Elf64_Ehdr) || elf_data[0] != 0x7F || elf_data[1] != 'E' || elf_data[2] != 'L' || elf_data[3] != 'F') {
        fprintf(stderr, "File is not ELF!\n");
        munmap(elf_data, file_size);
        close(m_fd);
        return 1;
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
