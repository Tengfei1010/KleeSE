add_library(KleeExpr STATIC
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
target_compile_features(KleeExpr PRIVATE cxx_range_for cxx_auto_type)

# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
set_target_properties(KleeExpr PROPERTIES
        COMPILE_FLAGS "-fno-rtti"
        )

llvm_map_components_to_libnames(llvm_libs support)
target_link_libraries(KleeExpr PUBLIC ${llvm_libs})