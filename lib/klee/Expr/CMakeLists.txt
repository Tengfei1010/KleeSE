klee_add_component(kleaverExpr STATIC
  ArrayCache.cpp
  Assigment.cpp
  Constraints.cpp
  ExprBuilder.cpp
  Expr.cpp
  ExprEvaluator.cpp
  ExprPPrinter.cpp
  ExprSMTLIBPrinter.cpp
  ExprUtil.cpp
  ExprVisitor.cpp
  Lexer.cpp
  Parser.cpp
  Updates.cpp
)

# Use C++11 to compile our pass (i.e., supply -std=c++11).
target_compile_features(kleaverExpr PRIVATE cxx_range_for cxx_auto_type)

# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
set_target_properties(kleaverExpr PROPERTIES
        COMPILE_FLAGS "-fno-rtti"
        )

set(LLVM_COMPONENTS
        support
        )
klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})
target_link_libraries(kleaverExpr PUBLIC ${LLVM_LIBS})
target_link_libraries(kleaverExpr PRIVATE
        kleeSupport
        )