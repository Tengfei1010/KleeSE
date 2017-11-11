add_library(kleeCore STATIC
        # List your source files here.
        AddressSpace.cpp
        CallPathManager.cpp
        Context.cpp
        CoreStats.cpp
        ExecutionState.cpp
        Executor.cpp
        ExecutorTimers.cpp
        Expr.cpp
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
set_target_properties(kleeCore PROPERTIES
        COMPILE_FLAGS "-fno-rtti"
        )

llvm_map_components_to_libnames(llvm_libs support core mcjit executionengine native)
target_link_libraries(kleeCore PUBLIC ${llvm_libs})


target_link_libraries(kleeCore PRIVATE
        kleeBasic
        kleeModule
        kleaverSolver
        kleaverExpr
        kleeSupport
        )