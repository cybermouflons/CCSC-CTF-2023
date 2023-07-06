#include <cstdlib>
#include <cstddef>
#include <exception>
#include <iostream>
#include <memory>
#include <sys/types.h>
#include <vector>

#include "../include/vm.hpp"

int main(int argc, char *argv[]) try {

    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <input-file>\n";
        std::exit(EXIT_FAILURE);
    }

    std::unique_ptr<VirtualMachine8> vm = std::make_unique<VirtualMachine8>();

    std::string path {argv[1]};

    vm->parse(path);
    vm->execute();

    return 0;
} catch(std::exception& e) {
    std::cerr << e.what() << std::endl;
    std::exit(EXIT_FAILURE);
}