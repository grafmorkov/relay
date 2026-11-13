#include <iostream>
#include <elf/elf.h>
#include <cinttypes>
#include <stdio.h>

int main(){
    ElfManager manager;

    if(!manager.load("test"))
    {
        std::cerr << "Failed to open file!" << std::endl;
        return 1;
    }

    std::vector<uint64_t> result = manager.find_syscalls();

    for (uint64_t address : result) {
        std::cout << "syscall: 0x" << std::hex << address << "\n";
    }
    return 0;
}
