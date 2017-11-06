#include <iostream>

#include "Klee/API.h"


int main(int argc, char **argv, char **envp) {
    std::cout << run_main(argc, argv, envp) << std::endl;
//    std::cout << test_run(3, 7) << std::endl;
    return 0;
}