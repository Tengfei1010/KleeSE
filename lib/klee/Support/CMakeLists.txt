klee_add_component(kleeSupport STATIC
        # List your source files here.
        CompressionStream.cpp
        ErrorHandling.cpp
        FileHandling.cpp
        MemoryUsage.cpp
        PrintVersion.cpp
        RNG.cpp
        TreeStream.cpp
        Time.cpp
        Timer.cpp
        )

# Use C++11 to compile our pass (i.e., supply -std=c++11).
target_compile_features(kleeSupport PRIVATE cxx_range_for cxx_auto_type)

# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
set_target_properties(kleeSupport PROPERTIES
        COMPILE_FLAGS "-fno-rtti"
        )

target_link_libraries(kleeSupport PRIVATE ${ZLIB_LIBRARIES})

set(LLVM_COMPONENTS
        support
        )
klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(kleeSupport PUBLIC ${LLVM_LIBS})
