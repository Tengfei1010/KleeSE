add_library(kleeBasic STATIC
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
llvm_map_components_to_libnames(llvm_libs support core irreader)
target_link_libraries(kleeBasic PUBLIC ${llvm_libs})

target_link_libraries(kleeBasic PRIVATE
        kleaverSolver
        )