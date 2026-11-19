#include <elf/elf.h>

#include <iostream>
#include <vector>

int main(int argc, char** argv) {
    const char* path = (argc > 1) ? argv[1] : "test";

    ElfManager manager;
    if (!manager.load(path)) {
        std::cerr << "Failed to open file!" << std::endl;
        return 1;
    }

    const std::vector<SyscallSite> sites = manager.find_syscall_sites();

    for (const SyscallSite& s : sites) {
        std::cout << "syscall: 0x" << std::hex << s.va
                  << "  nr=" << std::dec << s.number
                  << "  " << s.name;

        if (!s.function.empty())
            std::cout << "  @" << s.function;

        std::cout << '\n';
    }

    if (sites.empty())
        std::cerr << "no syscall instructions found\n";

    return 0;
}