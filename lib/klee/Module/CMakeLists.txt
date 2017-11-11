add_library(kleeModule STATIC
        # List your source files here.
        Checks.cpp
        Constraints.cpp
        InstructionInfoTable.cpp
        InstructionOperandTypeCheckPass.cpp
        IntrinsicCleaner.cpp
        KInstruction.cpp
        LowerSwitch.cpp
        KModule.cpp
        ModuleUtil.cpp
        Optimize.cpp
        PhiCleaner.cpp
        RaiseAsm.cpp
        )

# Use C++11 to compile our pass (i.e., supply -std=c++11).
target_compile_features(kleeModule PRIVATE cxx_range_for cxx_auto_type)

# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
set_target_properties(kleeModule PROPERTIES
        COMPILE_FLAGS "-fno-rtti"
        )

# Find the libraries that correspond to the LLVM components
# that we wish to use

llvm_map_components_to_libnames(llvm_libs support irreader bitwriter ipo linker core)
target_link_libraries(kleeModule PUBLIC ${llvm_libs})

target_link_libraries(kleeModule PRIVATE
        kleeSupport
        # FIXME:
        # There is a circular dependency between `kleeModule` and `kleeCore`.
        # `ModuleUtil.cpp` uses `klee::SpecialFunctionHandler` (in `kleeCore`) but
        # `kleeCore` uses `kleeModule`.
        kleeCore
        )