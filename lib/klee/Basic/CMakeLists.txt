klee_add_component(kleeBasic STATIC
        # List your source files here.
        KTest.cpp
        CmdLineOptions.cpp
        ConstructSolverChain.cpp
        Statistics.cpp
        )

# Use C++11 to compile our pass (i.e., supply -std=c++11).
target_compile_features(kleeBasic PRIVATE cxx_range_for cxx_auto_type)

# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
set_target_properties(kleeBasic PROPERTIES
        COMPILE_FLAGS "-fno-rtti"
        )

# Find the libraries that correspond to the LLVM components
# that we wish to use

set(LLVM_COMPONENTS
        support
        )

klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(kleeBasic PUBLIC ${LLVM_LIBS})

target_link_libraries(kleeBasic PRIVATE
        # FIXME: THIS IS STUPID.
        # `ConstructSolverChain.cpp` should be in
        # `kleaverSolver` not in in `kleeBasic`.
        # We are creating a circular dependency because
        # of this because `kleaverSolver` depends on `kleeBasic`.
        kleaverSolver
        )