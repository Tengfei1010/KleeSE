add_library(kleaverSolver STATIC
        # List your source files here.
        AssignmentValidatingSolver.cpp
        CachingSolver.cpp
        CexCachingSolver.cpp
        ConstantDivision.cpp
        CoreSolver.cpp
        DummySolver.cpp
        FastCexSolver.cpp
        IncompleteSolver.cpp
        IndependentSolver.cpp
        KQueryLoggingSolver.cpp
        QueryLoggingSolver.cpp
        SMTLIBLoggingSolver.cpp
        STPBuilder.cpp
        STPSolver.cpp
        Solver.cpp
        SolverImpl.cpp
        SolverStats.cpp
        ValidatingSolver.cpp
        )

# Use C++11 to compile our pass (i.e., supply -std=c++11).
target_compile_features(kleaverSolver PRIVATE cxx_range_for cxx_auto_type)

# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
set_target_properties(kleaverSolver PROPERTIES
        COMPILE_FLAGS "-fno-rtti"
        )

set(LLVM_COMPONENTS
        support
        )
set(MINISAT_COMPONENTS minisat)
set(STP_COMPONENTS stp)
llvm_map_components_to_libnames(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(kleaverSolver PUBLIC ${LLVM_LIBS})

target_link_libraries(kleaverSolver PUBLIC ${MINISAT_COMPONENTS})
target_link_libraries(kleaverSolver PUBLIC ${STP_COMPONENTS})

target_link_libraries(kleaverSolver PRIVATE
        kleeBasic
        kleaverExpr
        kleeSupport
        )
