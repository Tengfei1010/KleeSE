klee_add_component(kleeCore STATIC
        # List your source files here.
        AddressSpace.cpp
        CallPathManager.cpp
        Context.cpp
        CoreStats.cpp
        ExecutionState.cpp
        Executor.cpp
        ExecutorTimers.cpp
        ExternalDispatcher.cpp
        ExecutorUtil.cpp
        ImpliedValue.cpp
        Memory.cpp
        MemoryManager.cpp
        PTree.cpp
        Searcher.cpp
        SeedInfo.cpp
        SpecialFunctionHandler.cpp
        StatsTracker.cpp
        TimingSolver.cpp
        UserSearcher.cpp
        API.cpp
        )

# Use C++11 to compile our pass (i.e., supply -std=c++11).
target_compile_features(kleeCore PRIVATE cxx_range_for cxx_auto_type)

# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
set(LLVM_COMPONENTS
        core
        support
        )

if ("${LLVM_PACKAGE_VERSION}" VERSION_EQUAL "3.6" OR
        "${LLVM_PACKAGE_VERSION}" VERSION_GREATER "3.6")
    list(APPEND LLVM_COMPONENTS mcjit executionengine native)
else()
    list(APPEND LLVM_COMPONENTS jit engine)
endif()


klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(kleeCore PUBLIC ${LLVM_LIBS})
target_link_libraries(kleeCore PRIVATE
        kleeBasic
        kleeModule
        kleaverSolver
        kleaverExpr
        kleeSupport
        )