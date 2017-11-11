//
// Created by kevin on 11/2/17.
//

#ifndef KLEE_API_H
#define KLEE_API_H

#include "klee/Config/Version.h"
#include "klee/ExecutionState.h"
#include "klee/Expr.h"
#include "klee/Internal/ADT/KTest.h"
#include "klee/Internal/ADT/TreeStream.h"
#include "klee/Internal/Support/Debug.h"
#include "klee/Internal/Support/ErrorHandling.h"
#include "klee/Internal/Support/FileHandling.h"
#include "klee/Internal/Support/ModuleUtil.h"
//#include "klee/Internal/Support/PrintVersion.h"
#include "klee/Internal/System/Time.h"
#include "klee/Interpreter.h"
#include "klee/Statistics.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/Errno.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/Signals.h"

#if LLVM_VERSION_CODE < LLVM_VERSION(3, 5)
#include "llvm/Support/system_error.h"
#endif

#if LLVM_VERSION_CODE >= LLVM_VERSION(4, 0)

#include <llvm/Bitcode/BitcodeReader.h>

#else
#include <llvm/Bitcode/ReaderWriter.h>
#endif

#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <cerrno>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>


using namespace llvm;
using namespace klee;


class kleeHandler : public InterpreterHandler {
private:
    Interpreter *m_interpreter;
    TreeStreamWriter *m_pathWriter, *m_symPathWriter;
    llvm::raw_ostream *m_infoFile;

    SmallString<128> m_outputDirectory;

    unsigned m_numTotalTests;     // Number of tests received from the interpreter
    unsigned m_numGeneratedTests; // Number of tests successfully generated
    unsigned m_pathsExplored; // number of paths explored so far

    // used for writing .ktest files
    int m_argc;
    char **m_argv;

public:
    kleeHandler(int argc, char **argv);

    ~kleeHandler();

    llvm::raw_ostream &getInfoStream() const { return *m_infoFile; }

    /// Returns the number of test cases successfully generated so far
    unsigned getNumTestCases() { return m_numGeneratedTests; }

    unsigned getNumPathsExplored() { return m_pathsExplored; }

    void incPathsExplored() { m_pathsExplored++; }

    void setInterpreter(Interpreter *i);

    void processTestCase(const ExecutionState &state,
                         const char *errorMessage,
                         const char *errorSuffix);

    std::string getOutputFilename(const std::string &filename);

    llvm::raw_fd_ostream *openOutputFile(const std::string &filename);

    std::string getTestFilename(const std::string &suffix, unsigned id);

    llvm::raw_fd_ostream *openTestFile(const std::string &suffix, unsigned id);

    // load a .path file
    static void loadPathFile(std::string name,
                             std::vector<bool> &buffer);

    static void getKTestFilesInDir(std::string directoryPath,
                                   std::vector<std::string> &results);

    static std::string getRunTimeLibraryPath(const char *argv0);
};

int run_main(int argc, char **argv, char **envp);

#endif //PROJECT_API_H