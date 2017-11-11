#include <iostream>

#include "klee/API.h"


int main(int argc, char **argv, char **envp) {
    std::cout << run_main(argc, argv, envp) << std::endl;
    return 0;
}
