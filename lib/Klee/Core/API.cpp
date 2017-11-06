/* -*- mode: c++; c-basic-offset: 2; -*- */

//===-- main.cpp ------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "Klee/Config/Version.h"
#include "Klee/ExecutionState.h"
#include "Klee/Expr.h"
#include "Klee/Internal/ADT/KTest.h"
#include "Klee/Internal/ADT/TreeStream.h"
#include "Klee/Internal/Support/Debug.h"
#include "Klee/Internal/Support/ErrorHandling.h"
#include "Klee/Internal/Support/FileHandling.h"
#include "Klee/Internal/Support/ModuleUtil.h"
//#include "Klee/Internal/Support/PrintVersion.h"
#include "Klee/Internal/System/Time.h"
#include "Klee/Interpreter.h"
#include "Klee/Statistics.h"
#include "Klee/API.h"

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

namespace {
    cl::opt<std::string>
            InputFile(cl::desc("<input bytecode>"), cl::Positional, cl::init("-"));

    cl::opt<std::string>
            EntryPoint("entry-point",
                       cl::desc("Consider the function with the given name as the entrypoint"),
                       cl::init("main"));

    cl::opt<std::string>
            RunInDir("run-in", cl::desc("Change to the given directory prior to executing"));

    cl::opt<std::string>
            Environ("environ", cl::desc("Parse environ from given file (in \"env\" format)"));

    cl::list<std::string>
            InputArgv(cl::ConsumeAfter,
                      cl::desc("<program arguments>..."));

    cl::opt<bool>
            NoOutput("no-output",
                     cl::desc("Don't generate test files"));

    cl::opt<bool>
            WarnAllExternals("warn-all-externals",
                             cl::desc("Give initial warning for all externals."));

    cl::opt<bool>
            WriteCVCs("write-cvcs",
                      cl::desc("Write .cvc files for each test case"),
                      cl::init(true)
    );

    cl::opt<bool>
            WriteKQueries("write-kqueries",
                          cl::desc("Write .kquery files for each test case"),
                          cl::init(true)
    );

    cl::opt<bool>
            WriteSMT2s("write-smt2s",
                       cl::desc("Write .smt2 (SMT-LIBv2) files for each test case"));

    cl::opt<bool>
            WriteCov("write-cov",
                     cl::desc("Write coverage information for each test case"));

    cl::opt<bool>
            WriteTestInfo("write-test-info",
                          cl::desc("Write additional test case information"));

    cl::opt<bool>
            WritePaths("write-paths",
                       cl::desc("Write .path files for each test case"));

    cl::opt<bool>
            WriteSymPaths("write-sym-paths",
                          cl::desc("Write .sym.path files for each test case"));

    cl::opt<bool>
            OptExitOnError("exit-on-error",
                           cl::desc("Exit if errors occur"));


    enum LibcType {
        NoLibc, KleeLibc, UcLibc
    };

    cl::opt<LibcType>
            Libc("libc",
                 cl::desc("Choose libc version (none by default)."),
                 cl::values(clEnumValN(NoLibc, "none", "Don't link in a libc"),
                            clEnumValN(KleeLibc, "klee", "Link in klee libc"),
                            clEnumValN(UcLibc, "uclibc", "Link in uclibc (adapted for klee)")),
                 cl::init(NoLibc));


    cl::opt<bool>
            WithPOSIXRuntime("posix-runtime",
                             cl::desc(
                                     "Link with POSIX runtime.  Options that can be passed as arguments to the programs are: --sym-arg <max-len>  --sym-args <min-argvs> <max-argvs> <max-len> + file model options"),
                             cl::init(false));

    cl::opt<bool>
            OptimizeModule("optimize",
                           cl::desc("Optimize before execution"),
                           cl::init(false));

    cl::opt<bool>
            CheckDivZero("check-div-zero",
                         cl::desc("Inject checks for division-by-zero"),
                         cl::init(true));

    cl::opt<bool>
            CheckOvershift("check-overshift",
                           cl::desc("Inject checks for overshift"),
                           cl::init(true));

    cl::opt<std::string>
            OutputDir("output-dir",
                      cl::desc("Directory to write results in (defaults to klee-out-N)"),
                      cl::init(""));

    cl::opt<bool>
            ReplayKeepSymbolic("replay-keep-symbolic",
                               cl::desc("Replay the test cases only by asserting "
                                                "the bytes, not necessarily making them concrete."));

    cl::list<std::string>
            ReplayKTestFile("replay-ktest-file",
                            cl::desc("Specify a ktest file to use for replay"),
                            cl::value_desc("ktest file"));

    cl::list<std::string>
            ReplayKTestDir("replay-ktest-dir",
                           cl::desc("Specify a directory to replay ktest files from"),
                           cl::value_desc("output directory"));

    cl::opt<std::string>
            ReplayPathFile("replay-path",
                           cl::desc("Specify a path file to replay"),
                           cl::value_desc("path file"));

    cl::list<std::string>
            SeedOutFile("seed-out");

    cl::list<std::string>
            SeedOutDir("seed-out-dir");

    cl::list<std::string>
            LinkLibraries("link-llvm-lib",
                          cl::desc("Link the given libraries before execution"),
                          cl::value_desc("library file"));

    cl::opt<unsigned>
            MakeConcreteSymbolic("make-concrete-symbolic",
                                 cl::desc("Probabilistic rate at which to make concrete reads symbolic, "
                                                  "i.e. approximately 1 in n concrete reads will be made symbolic (0=off, 1=all).  "
                                                  "Used for testing."),
                                 cl::init(0));

    cl::opt<unsigned>
            StopAfterNTests("stop-after-n-tests",
                            cl::desc(
                                    "Stop execution after generating the given number of tests.  Extra tests corresponding to partially explored paths will also be dumped."),
                            cl::init(0));

    cl::opt<bool>
            Watchdog("watchdog",
                     cl::desc("Use a watchdog process to enforce --max-time."),
                     cl::init(0));
}

extern cl::opt<double> MaxTime;

/***/

KleeHandler::KleeHandler(int argc, char **argv)
        : m_interpreter(0), m_pathWriter(0), m_symPathWriter(0), m_infoFile(0),
          m_outputDirectory(), m_numTotalTests(0), m_numGeneratedTests(0),
          m_pathsExplored(0), m_argc(argc), m_argv(argv) {

    // create output directory (OutputDir or "klee-out-<i>")
    bool dir_given = OutputDir != "";
    SmallString<128> directory(dir_given ? OutputDir : InputFile);

    if (!dir_given) sys::path::remove_filename(directory);

    if (auto ec = sys::fs::make_absolute(directory)) {
        klee_error("unable to determine absolute path: %s", ec.message().c_str());
    }

    if (dir_given) {
        // OutputDir
        if (mkdir(directory.c_str(), 0775) < 0)
            klee_error("cannot create \"%s\": %s", directory.c_str(), strerror(errno));

        m_outputDirectory = directory;
    } else {
        // "klee-out-<i>"
        int i = 0;
        for (; i <= INT_MAX; ++i) {
            SmallString<128> d(directory);
            llvm::sys::path::append(d, "klee-out-");
            raw_svector_ostream ds(d);
            ds << i;
            // SmallString is always up-to-date, no need to flush. See Support/raw_ostream.h
            // create directory and try to link klee-last
            if (mkdir(d.c_str(), 0775) == 0) {
                m_outputDirectory = d;

                SmallString<128> klee_last(directory);
                llvm::sys::path::append(klee_last, "klee-last");

                if (((unlink(klee_last.c_str()) < 0) && (errno != ENOENT)) ||
                    symlink(m_outputDirectory.c_str(), klee_last.c_str()) < 0) {

                    klee_warning("cannot create klee-last symlink: %s", strerror(errno));
                }

                break;
            }

            // otherwise try again or exit on error
            if (errno != EEXIST)
                klee_error("cannot create \"%s\": %s", m_outputDirectory.c_str(), strerror(errno));
        }
        if (i == INT_MAX && m_outputDirectory.str().equals(""))
            klee_error("cannot create output directory: index out of range");
    }

    klee_message("output directory is \"%s\"", m_outputDirectory.c_str());

    // open warnings.txt
    std::string file_path = getOutputFilename("warnings.txt");
    if ((klee_warning_file = fopen(file_path.c_str(), "w")) == NULL)
        klee_error("cannot open file \"%s\": %s", file_path.c_str(), strerror(errno));

    // open messages.txt
    file_path = getOutputFilename("messages.txt");
    if ((klee_message_file = fopen(file_path.c_str(), "w")) == NULL)
        klee_error("cannot open file \"%s\": %s", file_path.c_str(), strerror(errno));

    // open info
    m_infoFile = openOutputFile("info");
}

KleeHandler::~KleeHandler() {
    delete m_pathWriter;
    delete m_symPathWriter;
    fclose(klee_warning_file);
    fclose(klee_message_file);
    delete m_infoFile;
}

void KleeHandler::setInterpreter(Interpreter *i) {
    m_interpreter = i;

    if (WritePaths) {
        m_pathWriter = new TreeStreamWriter(getOutputFilename("paths.ts"));
        assert(m_pathWriter->good());
        m_interpreter->setPathWriter(m_pathWriter);
    }

    if (WriteSymPaths) {
        m_symPathWriter = new TreeStreamWriter(getOutputFilename("symPaths.ts"));
        assert(m_symPathWriter->good());
        m_interpreter->setSymbolicPathWriter(m_symPathWriter);
    }
}

std::string KleeHandler::getOutputFilename(const std::string &filename) {
    SmallString<128> path = m_outputDirectory;
    sys::path::append(path, filename);
    return path.str();
}

llvm::raw_fd_ostream *KleeHandler::openOutputFile(const std::string &filename) {
    llvm::raw_fd_ostream *f;
    std::string Error;
    std::string path = getOutputFilename(filename);
    f = klee_open_output_file(path, Error);
    if (!Error.empty()) {
        klee_warning("error opening file \"%s\".  KLEE may have run out of file "
                             "descriptors: try to increase the maximum number of open file "
                             "descriptors by using ulimit (%s).",
                     path.c_str(), Error.c_str());
        return NULL;
    }
    return f;
}

std::string KleeHandler::getTestFilename(const std::string &suffix, unsigned id) {
    std::stringstream filename;
    filename << "test" << std::setfill('0') << std::setw(6) << id << '.' << suffix;
    return filename.str();
}

llvm::raw_fd_ostream *KleeHandler::openTestFile(const std::string &suffix,
                                                unsigned id) {
    return openOutputFile(getTestFilename(suffix, id));
}


/* Outputs all files (.ktest, .kquery, .cov etc.) describing a test case */
void KleeHandler::processTestCase(const ExecutionState &state,
                                  const char *errorMessage,
                                  const char *errorSuffix) {
    if (errorMessage && OptExitOnError) {
        m_interpreter->prepareForEarlyExit();
        klee_error("EXITING ON ERROR:\n%s\n", errorMessage);
    }

    if (!NoOutput) {
        std::vector<std::pair<std::string, std::vector<unsigned char> > > out;
        bool success = m_interpreter->getSymbolicSolution(state, out);

        if (!success)
            klee_warning("unable to get symbolic solution, losing test case");

        double start_time = util::getWallTime();

        unsigned id = ++m_numTotalTests;

        if (success) {
            KTest b;
            b.numArgs = m_argc;
            b.args = m_argv;
            b.symArgvs = 0;
            b.symArgvLen = 0;
            b.numObjects = out.size();
            b.objects = new KTestObject[b.numObjects];
            assert(b.objects);
            for (unsigned i = 0; i < b.numObjects; i++) {
                KTestObject *o = &b.objects[i];
                o->name = const_cast<char *>(out[i].first.c_str());
                o->numBytes = out[i].second.size();
                o->bytes = new unsigned char[o->numBytes];
                assert(o->bytes);
                std::copy(out[i].second.begin(), out[i].second.end(), o->bytes);
            }

            if (!kTest_toFile(&b, getOutputFilename(getTestFilename("ktest", id)).c_str())) {
                klee_warning("unable to write output test case, losing it");
            } else {
                ++m_numGeneratedTests;
            }

            for (unsigned i = 0; i < b.numObjects; i++)
                delete[] b.objects[i].bytes;
            delete[] b.objects;
        }

        if (errorMessage) {
            llvm::raw_ostream *f = openTestFile(errorSuffix, id);
            *f << errorMessage;
            delete f;
        }

        if (m_pathWriter) {
            std::vector<unsigned char> concreteBranches;
            m_pathWriter->readStream(m_interpreter->getPathStreamID(state),
                                     concreteBranches);
            llvm::raw_fd_ostream *f = openTestFile("path", id);
            for (std::vector<unsigned char>::iterator I = concreteBranches.begin(),
                         E = concreteBranches.end();
                 I != E; ++I) {
                *f << *I << "\n";
            }
            delete f;
        }

        if (errorMessage || WriteKQueries) {
            std::string constraints;
            m_interpreter->getConstraintLog(state, constraints, Interpreter::KQUERY);
            llvm::raw_ostream *f = openTestFile("kquery", id);
            *f << constraints;
            delete f;
        }

        if (WriteCVCs) {
            // FIXME: If using Z3 as the core solver the emitted file is actually
            // SMT-LIBv2 not CVC which is a bit confusing
            std::string constraints;
            m_interpreter->getConstraintLog(state, constraints, Interpreter::STP);
            llvm::raw_ostream *f = openTestFile("cvc", id);
            *f << constraints;
            delete f;
        }

        if (WriteSMT2s) {
            std::string constraints;
            m_interpreter->getConstraintLog(state, constraints, Interpreter::SMTLIB2);
            llvm::raw_ostream *f = openTestFile("smt2", id);
            *f << constraints;
            delete f;
        }

        if (m_symPathWriter) {
            std::vector<unsigned char> symbolicBranches;
            m_symPathWriter->readStream(m_interpreter->getSymbolicPathStreamID(state),
                                        symbolicBranches);
            llvm::raw_fd_ostream *f = openTestFile("sym.path", id);
            for (std::vector<unsigned char>::iterator I = symbolicBranches.begin(), E = symbolicBranches.end();
                 I != E; ++I) {
                *f << *I << "\n";
            }
            delete f;
        }

        if (WriteCov) {
            std::map<const std::string *, std::set<unsigned> > cov;
            m_interpreter->getCoveredLines(state, cov);
            llvm::raw_ostream *f = openTestFile("cov", id);
            for (std::map<const std::string *, std::set<unsigned> >::iterator
                         it = cov.begin(), ie = cov.end();
                 it != ie; ++it) {
                for (std::set<unsigned>::iterator
                             it2 = it->second.begin(), ie = it->second.end();
                     it2 != ie; ++it2)
                    *f << *it->first << ":" << *it2 << "\n";
            }
            delete f;
        }

        if (m_numGeneratedTests == StopAfterNTests)
            m_interpreter->setHaltExecution(true);

        if (WriteTestInfo) {
            double elapsed_time = util::getWallTime() - start_time;
            llvm::raw_ostream *f = openTestFile("info", id);
            *f << "Time to generate test case: "
               << elapsed_time << "s\n";
            delete f;
        }
    }
}

// load a .path file
void KleeHandler::loadPathFile(std::string name,
                               std::vector<bool> &buffer) {
    std::ifstream f(name.c_str(), std::ios::in | std::ios::binary);

    if (!f.good())
        assert(0 && "unable to open path file");

    while (f.good()) {
        unsigned value;
        f >> value;
        buffer.push_back(!!value);
        f.get();
    }
}

void KleeHandler::getKTestFilesInDir(std::string directoryPath,
                                     std::vector<std::string> &results) {
    std::error_code ec;
    for (llvm::sys::fs::directory_iterator i(directoryPath, ec), e; i != e && !ec;
         i.increment(ec)) {
        std::string f = (*i).path();
        if (f.substr(f.size() - 6, f.size()) == ".ktest") {
            results.push_back(f);
        }
    }

    if (ec) {
        llvm::errs() << "ERROR: unable to read output directory: " << directoryPath
                     << ": " << ec.message() << "\n";
        exit(1);
    }
}

std::string KleeHandler::getRunTimeLibraryPath(const char *argv0) {
    // allow specifying the path to the runtime library
    const char *env = getenv("KLEE_RUNTIME_LIBRARY_PATH");
    if (env)
        return std::string(env);

    // Take any function from the execution binary but not main (as not allowed by
    // C++ standard)
    void *MainExecAddr = (void *) (intptr_t) getRunTimeLibraryPath;
    SmallString<128> toolRoot(
            llvm::sys::fs::getMainExecutable(argv0, MainExecAddr)
    );

    // Strip off executable so we have a directory path
    llvm::sys::path::remove_filename(toolRoot);

    SmallString<128> libDir;

    if (strlen(KLEE_INSTALL_BIN_DIR) != 0 &&
        strlen(KLEE_INSTALL_RUNTIME_DIR) != 0 &&
        toolRoot.str().endswith(KLEE_INSTALL_BIN_DIR)) {
        KLEE_DEBUG_WITH_TYPE("klee_runtime", llvm::dbgs() <<
                                                          "Using installed KLEE library runtime: ");
        libDir = toolRoot.str().substr(0,
                                       toolRoot.str().size() - strlen(KLEE_INSTALL_BIN_DIR));
        llvm::sys::path::append(libDir, KLEE_INSTALL_RUNTIME_DIR);
    } else {
        KLEE_DEBUG_WITH_TYPE("klee_runtime", llvm::dbgs() <<
                                                          "Using build directory KLEE library runtime :");
        libDir = KLEE_DIR;
        llvm::sys::path::append(libDir, RUNTIME_CONFIGURATION);
        llvm::sys::path::append(libDir, "lib");
    }

    KLEE_DEBUG_WITH_TYPE("klee_runtime", llvm::dbgs() <<
                                                      libDir.c_str() << "\n");
    return libDir.str();
}

//===----------------------------------------------------------------------===//
// main Driver function
//
static std::string strip(std::string &in) {
    unsigned len = in.size();
    unsigned lead = 0, trail = len;
    while (lead < len && isspace(in[lead]))
        ++lead;
    while (trail > lead && isspace(in[trail - 1]))
        --trail;
    return in.substr(lead, trail - lead);
}

static void parseArguments(int argc, char **argv) {
//    cl::SetVersionPrinter(klee::printVersion);
    // This version always reads response files
    cl::ParseCommandLineOptions(argc, argv, " klee\n");
}


// This is a terrible hack until we get some real modeling of the
// system. All we do is check the undefined symbols and warn about
// any "unrecognized" externals and about any obviously unsafe ones.

// Symbols we explicitly support
static const char *modelledExternals[] = {
        "_ZTVN10__cxxabiv117__class_type_infoE",
        "_ZTVN10__cxxabiv120__si_class_type_infoE",
        "_ZTVN10__cxxabiv121__vmi_class_type_infoE",

        // special functions
        "_assert",
        "__assert_fail",
        "__assert_rtn",
        "__errno_location",
        "__error",
        "calloc",
        "_exit",
        "exit",
        "free",
        "abort",
        "klee_abort",
        "klee_assume",
        "klee_check_memory_access",
        "klee_define_fixed_object",
        "klee_get_errno",
        "klee_get_valuef",
        "klee_get_valued",
        "klee_get_valuel",
        "klee_get_valuell",
        "klee_get_value_i32",
        "klee_get_value_i64",
        "klee_get_obj_size",
        "klee_is_symbolic",
        "klee_make_symbolic",
        "klee_mark_global",
        "klee_prefer_cex",
        "klee_posix_prefer_cex",
        "klee_print_expr",
        "klee_print_range",
        "klee_report_error",
        "klee_set_forking",
        "klee_silent_exit",
        "klee_warning",
        "klee_warning_once",
        "klee_alias_function",
        "klee_stack_trace",
        "llvm.dbg.declare",
        "llvm.dbg.value",
        "llvm.va_start",
        "llvm.va_end",
        "malloc",
        "realloc",
        "_ZdaPv",
        "_ZdlPv",
        "_Znaj",
        "_Znwj",
        "_Znam",
        "_Znwm",
        "__ubsan_handle_add_overflow",
        "__ubsan_handle_sub_overflow",
        "__ubsan_handle_mul_overflow",
        "__ubsan_handle_divrem_overflow",
};
// Symbols we aren't going to warn about
static const char *dontCareExternals[] = {
        // static information, pretty ok to return
        "getegid",
        "geteuid",
        "getgid",
        "getuid",
        "getpid",
        "gethostname",
        "getpgrp",
        "getppid",
        "getpagesize",
        "getpriority",
        "getgroups",
        "getdtablesize",
        "getrlimit",
        "getrlimit64",
        "getcwd",
        "getwd",
        "gettimeofday",
        "uname",

        // fp stuff we just don't worry about yet
        "frexp",
        "ldexp",
        "__isnan",
        "__signbit",
};
// Extra symbols we aren't going to warn about with klee-libc
static const char *dontCareKlee[] = {
        "__ctype_b_loc",
        "__ctype_get_mb_cur_max",

        // io system calls
        "open",
        "write",
        "read",
        "close",
};
// Extra symbols we aren't going to warn about with uclibc
static const char *dontCareUclibc[] = {
        "__dso_handle",

        // Don't warn about these since we explicitly commented them out of
        // uclibc.
        "printf",
        "vprintf"
};
// Symbols we consider unsafe
static const char *unsafeExternals[] = {
        "fork", // oh lord
        "exec", // heaven help us
        "error", // calls _exit
        "raise", // yeah
        "kill", // mmmhmmm
};
#define NELEMS(array) (sizeof(array)/sizeof(array[0]))

void externalsAndGlobalsCheck(const Module *m) {
    std::map<std::string, bool> externals;
    std::set<std::string> modelled(modelledExternals,
                                   modelledExternals + NELEMS(modelledExternals));
    std::set<std::string> dontCare(dontCareExternals,
                                   dontCareExternals + NELEMS(dontCareExternals));
    std::set<std::string> unsafe(unsafeExternals,
                                 unsafeExternals + NELEMS(unsafeExternals));

    switch (Libc) {
        case KleeLibc:
            dontCare.insert(dontCareKlee, dontCareKlee + NELEMS(dontCareKlee));
            break;
        case UcLibc:
            dontCare.insert(dontCareUclibc,
                            dontCareUclibc + NELEMS(dontCareUclibc));
            break;
        case NoLibc: /* silence compiler warning */
            break;
    }

    if (WithPOSIXRuntime)
        dontCare.insert("syscall");

    for (Module::const_iterator fnIt = m->begin(), fn_ie = m->end();
         fnIt != fn_ie; ++fnIt) {
        if (fnIt->isDeclaration() && !fnIt->use_empty())
            externals.insert(std::make_pair(fnIt->getName(), false));
        for (Function::const_iterator bbIt = fnIt->begin(), bb_ie = fnIt->end();
             bbIt != bb_ie; ++bbIt) {
            for (BasicBlock::const_iterator it = bbIt->begin(), ie = bbIt->end();
                 it != ie; ++it) {
                if (const CallInst *ci = dyn_cast<CallInst>(it)) {
                    if (isa<InlineAsm>(ci->getCalledValue())) {
                        klee_warning_once(&*fnIt,
                                          "function \"%s\" has inline asm",
                                          fnIt->getName().data());
                    }
                }
            }
        }
    }
    for (Module::const_global_iterator
                 it = m->global_begin(), ie = m->global_end();
         it != ie; ++it)
        if (it->isDeclaration() && !it->use_empty())
            externals.insert(std::make_pair(it->getName(), true));
    // and remove aliases (they define the symbol after global
    // initialization)
    for (Module::const_alias_iterator
                 it = m->alias_begin(), ie = m->alias_end();
         it != ie; ++it) {
        std::map<std::string, bool>::iterator it2 =
                externals.find(it->getName());
        if (it2 != externals.end())
            externals.erase(it2);
    }

    std::map<std::string, bool> foundUnsafe;
    for (std::map<std::string, bool>::iterator
                 it = externals.begin(), ie = externals.end();
         it != ie; ++it) {
        const std::string &ext = it->first;
        if (!modelled.count(ext) && (WarnAllExternals ||
                                     !dontCare.count(ext))) {
            if (unsafe.count(ext)) {
                foundUnsafe.insert(*it);
            } else {
                klee_warning("undefined reference to %s: %s",
                             it->second ? "variable" : "function",
                             ext.c_str());
            }
        }
    }

    for (std::map<std::string, bool>::iterator
                 it = foundUnsafe.begin(), ie = foundUnsafe.end();
         it != ie; ++it) {
        const std::string &ext = it->first;
        klee_warning("undefined reference to %s: %s (UNSAFE)!",
                     it->second ? "variable" : "function",
                     ext.c_str());
    }
}

static Interpreter *theInterpreter = 0;

static bool interrupted = false;

// Pulled out so it can be easily called from a debugger.
extern "C"
void halt_execution() {
    theInterpreter->setHaltExecution(true);
}

extern "C"
void stop_forking() {
    theInterpreter->setInhibitForking(true);
}

static void interrupt_handle() {
    if (!interrupted && theInterpreter) {
        llvm::errs() << "KLEE: ctrl-c detected, requesting interpreter to halt.\n";
        halt_execution();
        sys::SetInterruptFunction(interrupt_handle);
    } else {
        llvm::errs() << "KLEE: ctrl-c detected, exiting.\n";
        exit(1);
    }
    interrupted = true;
}


// returns the end of the string put in buf
static char *format_tdiff(char *buf, long seconds) {
    assert(seconds >= 0);

    long minutes = seconds / 60;
    seconds %= 60;
    long hours = minutes / 60;
    minutes %= 60;
    long days = hours / 24;
    hours %= 24;

    buf = strrchr(buf, '\0');
    if (days > 0) buf += sprintf(buf, "%ld days, ", days);
    buf += sprintf(buf, "%02ld:%02ld:%02ld", hours, minutes, seconds);
    return buf;
}


/*!
 * This is main function in klee
 * @param argc
 * @param argv
 * @param envp
 * @return
 */
int run_main(int argc, char **argv, char **envp) {
    atexit(llvm_shutdown);  // Call llvm_shutdown() on exit.
    llvm::InitializeNativeTarget();

    parseArguments(argc, argv);
    sys::PrintStackTraceOnErrorSignal(argv[0]);
    sys::SetInterruptFunction(interrupt_handle);

    // Load the bytecode...
    std::string errorMsg;
    LLVMContext ctx;
    Module *mainModule = klee::loadModule(ctx, InputFile, errorMsg);
    if (!mainModule) {
        klee_error("error loading program '%s': %s", InputFile.c_str(),
                   errorMsg.c_str());
    }


    std::string LibraryDir = KleeHandler::getRunTimeLibraryPath(argv[0]);
    Interpreter::ModuleOptions Opts(LibraryDir.c_str(), EntryPoint,
            /*Optimize=*/OptimizeModule,
            /*CheckDivZero=*/CheckDivZero,
            /*CheckOvershift=*/CheckOvershift);


    // Get the desired main function.  klee_main initializes uClibc
    // locale and other data and then calls main.
    Function *mainFn = mainModule->getFunction(EntryPoint);
    if (!mainFn) {
        klee_error("'%s' function not found in module.", EntryPoint.c_str());
    }

    // FIXME: Change me to std types.
    int pArgc;
    char **pArgv;
    char **pEnvp;

    pEnvp = envp;
    pArgc = InputArgv.size() + 1;
    pArgv = new char *[pArgc];
    for (unsigned i = 0; i < InputArgv.size() + 1; i++) {

        std::string &arg = (i == 0 ? InputFile : InputArgv[i - 1]);
        unsigned size = arg.size() + 1;
        char *pArg = new char[size];

        std::copy(arg.begin(), arg.end(), pArg);
        pArg[size - 1] = 0;

        pArgv[i] = pArg;
    }

    std::vector<bool> replayPath;

    if (ReplayPathFile != "") {
        KleeHandler::loadPathFile(ReplayPathFile, replayPath);
    }

    Interpreter::InterpreterOptions IOpts;
    IOpts.MakeConcreteSymbolic = MakeConcreteSymbolic;
    KleeHandler *handler = new KleeHandler(pArgc, pArgv);
    Interpreter *interpreter =
            theInterpreter = Interpreter::create(ctx, IOpts, handler);
    handler->setInterpreter(interpreter);

    for (int i = 0; i < argc; i++) {
        handler->getInfoStream() << argv[i] << (i + 1 < argc ? " " : "\n");
    }
    handler->getInfoStream() << "PID: " << getpid() << "\n";

    const Module *finalModule =
            interpreter->setModule(mainModule, Opts);
    externalsAndGlobalsCheck(finalModule);

    if (ReplayPathFile != "") {
        interpreter->setReplayPath(&replayPath);
    }

    char buf[256];
    time_t t[2];
    t[0] = time(NULL);
    strftime(buf, sizeof(buf), "Started: %Y-%m-%d %H:%M:%S\n", localtime(&t[0]));
    handler->getInfoStream() << buf;
    handler->getInfoStream().flush();

    if (!ReplayKTestDir.empty() || !ReplayKTestFile.empty()) {
        assert(SeedOutFile.empty());
        assert(SeedOutDir.empty());

        std::vector<std::string> kTestFiles = ReplayKTestFile;
        for (std::vector<std::string>::iterator
                     it = ReplayKTestDir.begin(), ie = ReplayKTestDir.end();
             it != ie; ++it)
            KleeHandler::getKTestFilesInDir(*it, kTestFiles);
        std::vector<KTest *> kTests;
        for (std::vector<std::string>::iterator
                     it = kTestFiles.begin(), ie = kTestFiles.end();
             it != ie; ++it) {
            KTest *out = kTest_fromFile(it->c_str());
            if (out) {
                kTests.push_back(out);
            } else {
                klee_warning("unable to open: %s\n", (*it).c_str());
            }
        }

        if (RunInDir != "") {
            int res = chdir(RunInDir.c_str());
            if (res < 0) {
                klee_error("Unable to change directory to: %s - %s", RunInDir.c_str(),
                           sys::StrError(errno).c_str());
            }
        }

        unsigned i = 0;
        for (std::vector<KTest *>::iterator
                     it = kTests.begin(), ie = kTests.end();
             it != ie; ++it) {
            KTest *out = *it;
            interpreter->setReplayKTest(out);
            llvm::errs() << "KLEE: replaying: " << *it << " (" << kTest_numBytes(out)
                         << " bytes)"
                         << " (" << ++i << "/" << kTestFiles.size() << ")\n";
            // XXX should put envp in .ktest ?
            interpreter->runFunctionAsMain(mainFn, out->numArgs, out->args, pEnvp);
            if (interrupted) break;
        }
        interpreter->setReplayKTest(0);
        while (!kTests.empty()) {
            kTest_free(kTests.back());
            kTests.pop_back();
        }
    } else {
        std::vector<KTest *> seeds;
        for (std::vector<std::string>::iterator
                     it = SeedOutFile.begin(), ie = SeedOutFile.end();
             it != ie; ++it) {
            KTest *out = kTest_fromFile(it->c_str());
            if (!out) {
                klee_error("unable to open: %s\n", (*it).c_str());
            }
            seeds.push_back(out);
        }
        for (std::vector<std::string>::iterator
                     it = SeedOutDir.begin(), ie = SeedOutDir.end();
             it != ie; ++it) {
            std::vector<std::string> kTestFiles;
            KleeHandler::getKTestFilesInDir(*it, kTestFiles);
            for (std::vector<std::string>::iterator
                         it2 = kTestFiles.begin(), ie = kTestFiles.end();
                 it2 != ie; ++it2) {
                KTest *out = kTest_fromFile(it2->c_str());
                if (!out) {
                    klee_error("unable to open: %s\n", (*it2).c_str());
                }
                seeds.push_back(out);
            }
            if (kTestFiles.empty()) {
                klee_error("seeds directory is empty: %s\n", (*it).c_str());
            }
        }

        if (!seeds.empty()) {
            klee_message("KLEE: using %lu seeds\n", seeds.size());
            interpreter->useSeeds(&seeds);
        }
        if (RunInDir != "") {
            int res = chdir(RunInDir.c_str());
            if (res < 0) {
                klee_error("Unable to change directory to: %s - %s", RunInDir.c_str(),
                           sys::StrError(errno).c_str());
            }
        }
        interpreter->runFunctionAsMain(mainFn, pArgc, pArgv, pEnvp);

        while (!seeds.empty()) {
            kTest_free(seeds.back());
            seeds.pop_back();
        }
    }

    t[1] = time(NULL);
    strftime(buf, sizeof(buf), "Finished: %Y-%m-%d %H:%M:%S\n", localtime(&t[1]));
    handler->getInfoStream() << buf;

    strcpy(buf, "Elapsed: ");
    strcpy(format_tdiff(buf, t[1] - t[0]), "\n");
    handler->getInfoStream() << buf;

    // Free all the args.
    for (unsigned i = 0; i < InputArgv.size() + 1; i++)
        delete[] pArgv[i];
    delete[] pArgv;

    delete interpreter;

    uint64_t queries =
            *theStatisticManager->getStatisticByName("Queries");
    uint64_t queriesValid =
            *theStatisticManager->getStatisticByName("QueriesValid");
    uint64_t queriesInvalid =
            *theStatisticManager->getStatisticByName("QueriesInvalid");
    uint64_t queryCounterexamples =
            *theStatisticManager->getStatisticByName("QueriesCEX");
    uint64_t queryConstructs =
            *theStatisticManager->getStatisticByName("QueriesConstructs");
    uint64_t instructions =
            *theStatisticManager->getStatisticByName("Instructions");
    uint64_t forks =
            *theStatisticManager->getStatisticByName("Forks");

    handler->getInfoStream()
            << "KLEE: done: explored paths = " << 1 + forks << "\n";

    // Write some extra information in the info file which users won't
    // necessarily care about or understand.
    if (queries)
        handler->getInfoStream()
                << "KLEE: done: avg. constructs per query = "
                << queryConstructs / queries << "\n";
    handler->getInfoStream()
            << "KLEE: done: total queries = " << queries << "\n"
            << "KLEE: done: valid queries = " << queriesValid << "\n"
            << "KLEE: done: invalid queries = " << queriesInvalid << "\n"
            << "KLEE: done: query cex = " << queryCounterexamples << "\n";

    std::stringstream stats;
    stats << "\n";
    stats << "KLEE: done: total instructions = "
          << instructions << "\n";
    stats << "KLEE: done: completed paths = "
          << handler->getNumPathsExplored() << "\n";
    stats << "KLEE: done: generated tests = "
          << handler->getNumTestCases() << "\n";

    bool useColors = llvm::errs().is_displayed();
    if (useColors)
        llvm::errs().changeColor(llvm::raw_ostream::GREEN,
                /*bold=*/true,
                /*bg=*/false);

    llvm::errs() << stats.str();

    if (useColors)
        llvm::errs().resetColor();

    handler->getInfoStream() << stats.str();

    delete handler;

    return 0;
}

int test_run(int a1, int a2) {
    return a1 + a2;
}
