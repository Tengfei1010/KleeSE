klee_add_component(kleaverSolver STATIC
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
        Z3Builder.cpp
        Z3Solver.cpp
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

set(LLVM_COMPONENTS
        support
        )
klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(kleaverSolver PUBLIC ${LLVM_LIBS})

target_link_libraries(kleaverSolver PRIVATE
        kleeBasic
        kleaverExpr
        kleeSupport
        ${KLEE_SOLVER_LIBRARIES})