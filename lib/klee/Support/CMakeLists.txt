add_library(kleeSupport STATIC
        # List your source files here.
        CompressionStream.cpp
        ErrorHandling.cpp
        FileHandling.cpp
        MemoryUsage.cpp
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

set(LLVM_COMPONENTS
        support
        )
llvm_map_components_to_libnames(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(kleeSupport PUBLIC ${LLVM_LIBS})

find_package(ZLIB)
if (ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIRS})
    target_link_libraries(kleeSupport PUBLIC ${ZLIB_LIBRARIES})
endif()
