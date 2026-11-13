#include <iostream>
#include <cstdint>
#include <vector>
#include <elf.h>

class ElfManager {
public:
    ElfManager();
    ~ElfManager();

    bool load(const char* path);
    std::vector<uint64_t> find_syscalls();

    uint8_t* elf_data;
    int file_size;
private:
    uint64_t get_runtime_address(const uint8_t* elf_data, uint64_t target_file_offset);

    int m_fd;
};