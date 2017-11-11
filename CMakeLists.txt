cmake_minimum_required(VERSION 3.1)
project(KleeSE)

################################################################################
# Global clean target
################################################################################
# CMake already uses the "clean" target name but it doesn't clean everything
# unfortunately. We can't modify the target so we provide our own "clean_all"
# target that runs clean. Other rules for performing clean up should declare
# that "clean_all" depends on those rules.
add_custom_target(clean_all
        # Invoke CMake's own clean target
        COMMAND
        "${CMAKE_COMMAND}"
        "--build"
        "${CMAKE_BINARY_DIR}"
        "--target"
        "clean"
        )

set(LLVM_VERSION_MAJOR 5)
set(LLVM_VERSION_MINOR 0)

################################################################################
# Solvers
################################################################################
# STP
include(${CMAKE_SOURCE_DIR}/cmake/find_stp.cmake)

################################################################################
# Support for compressed logs
################################################################################
find_package(ZLIB)
if (ZLIB_FOUND)
    set(ENABLE_ZLIB_DEFAULT ON)
else()
    set(ENABLE_ZLIB_DEFAULT OFF)
endif()
option(ENABLE_ZLIB "Enable use of zlib" ${ENABLE_ZLIB_DEFAULT})
if (ENABLE_ZLIB)
    message(STATUS "Zlib support enabled")
    if (ZLIB_FOUND)
        set(HAVE_ZLIB_H 1) # For config.h
        set(TARGET_LIBS ${TARGET_LIBS} z)
        list(APPEND KLEE_COMPONENT_EXTRA_LIBRARIES ${ZLIB_LIBRARIES})
        list(APPEND KLEE_COMPONENT_EXTRA_INCLUDE_DIRS ${ZLIB_INCLUDE_DIRS})
    else()
        message(FATAL_ERROR "ENABLE_ZLIB is true but zlib could not be found")
    endif()
else()
    message(STATUS "Zlib support disabled")
    unset(HAVE_ZLIB_H) # For config.h
endif()

################################################################################
# Find LLVM
################################################################################
include(${CMAKE_SOURCE_DIR}/cmake/string_to_list.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/find_llvm.cmake)
set(NEEDED_LLVM_VARS
        LLVM_PACKAGE_VERSION
        LLVM_VERSION_MAJOR
        LLVM_VERSION_MINOR
        LLVM_VERSION_PATCH
        LLVM_DEFINITIONS
        LLVM_ENABLE_ASSERTIONS
        LLVM_ENABLE_EH
        LLVM_ENABLE_RTTI
        LLVM_INCLUDE_DIRS
        LLVM_LIBRARY_DIRS
        LLVM_TOOLS_BINARY_DIR
        LLVM_ENABLE_VISIBILITY_INLINES_HIDDEN
        TARGET_TRIPLE
        )

foreach (vname ${NEEDED_LLVM_VARS})
    message(STATUS "${vname}: \"${${vname}}\"")
    if (NOT (DEFINED "${vname}"))
        message(FATAL_ERROR "${vname} was not defined")
    endif()
endforeach()

if (LLVM_ENABLE_ASSERTIONS)
    # Certain LLVM debugging macros only work when LLVM was built with asserts
    set(ENABLE_KLEE_DEBUG 1) # for config.h
else()
    unset(ENABLE_KLEE_DEBUG) # for config.h
endif()

# Warn about mixing build types.
# This is likely a bad idea because some of LLVM's header files use the NDEBUG
# macro which can change things like data layout.
if (LLVM_ENABLE_ASSERTIONS AND (NOT ENABLE_KLEE_ASSERTS))
    message(WARNING
            "LLVM was built with assertions but KLEE will be built without them.\n"
            "This might lead to unexpected behaviour."
            )
elseif ((NOT LLVM_ENABLE_ASSERTIONS) AND ENABLE_KLEE_ASSERTS)
    message(WARNING
            "LLVM was built without assertions but KLEE will be built with them.\n"
            "This might lead to unexpected behaviour."
            )
endif()

if (LLVM_ENABLE_VISIBILITY_INLINES_HIDDEN)
    list(APPEND KLEE_COMPONENT_CXX_FLAGS "-fvisibility-inlines-hidden")
endif()


list(APPEND KLEE_COMPONENT_CXX_DEFINES ${LLVM_DEFINITIONS})
list(APPEND KLEE_COMPONENT_EXTRA_INCLUDE_DIRS ${LLVM_INCLUDE_DIRS})

# Find llvm-link
set(LLVM_LINK "${LLVM_TOOLS_BINARY_DIR}/llvm-link")
if (NOT EXISTS "${LLVM_LINK}")
    message(FATAL_ERROR "Failed to find llvm-link at \"${LLVM_LINK}\"")
endif()

# Find llvm-ar
set(LLVM_AR "${LLVM_TOOLS_BINARY_DIR}/llvm-ar")
if (NOT EXISTS "${LLVM_AR}")
    message(FATAL_ERROR "Failed to find llvm-ar at \"${LLVM_AR}\"")
endif()

# Find llvm-as
set(LLVM_AS "${LLVM_TOOLS_BINARY_DIR}/llvm-as")
if (NOT EXISTS "${LLVM_AS}")
    message(FATAL_ERROR "Failed to find llvm-as at \"${LLVM_AS}\"")
endif()

################################################################################
# Find bitcode compiler
################################################################################
include("${CMAKE_SOURCE_DIR}/cmake/find_bitcode_compiler.cmake")
message(STATUS "LLVMCC: ${LLVMCC}")
if (NOT EXISTS "${LLVMCC}")
    message(FATAL_ERROR "Cannot find C bitcode compiler \"${LLVMCC}\"")
endif()
message(STATUS "LLVMCXX: ${LLVMCXX}")
if (NOT EXISTS "${LLVMCXX}")
    message(FATAL_ERROR "Cannot find C++ bitcode compiler \"${LLVMCXX}\"")
endif()

################################################################################
# KleeSE runtime support
################################################################################
# This is set here and not in `runtime` because `config.h` needs to be generated.

set(available_klee_runtime_build_types
        "Release"
        "Release+Debug"
        "Release+Asserts"
        "Release+Debug+Asserts"
        "Debug"
        "Debug+Asserts"
        )
if (NOT KLEE_RUNTIME_BUILD_TYPE)
    message(STATUS "KLEE_RUNTIME_BUILD_TYPE is not set. Setting default")
    message(STATUS "The available runtime build types are: ${available_klee_runtime_build_types}")
    set(KLEE_RUNTIME_BUILD_TYPE "Release+Debug+Asserts" CACHE String
            "Options are ${available_klee_runtime_build_types}"
            FORCE)
endif()
# Provide drop down menu options in cmake-gui
set_property(CACHE
        KLEE_RUNTIME_BUILD_TYPE
        PROPERTY STRINGS ${available_klee_runtime_build_types})
message(STATUS "KLEE_RUNTIME_BUILD_TYPE: ${KLEE_RUNTIME_BUILD_TYPE}")

set(KLEE_INSTALL_RUNTIME_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/klee/runtime")

# Location where KLEE will look for the built runtimes by default.
set(KLEE_RUNTIME_DIRECTORY "${CMAKE_BINARY_DIR}/${KLEE_RUNTIME_BUILD_TYPE}/lib")


################################################################################
# KleeSE POSIX Runtime Support
################################################################################
option(ENABLE_POSIX_RUNTIME "Enable KLEE's POSIX runtime" OFF)
if (ENABLE_POSIX_RUNTIME)
    message(STATUS "POSIX runtime enabled")
    if (NOT ENABLE_KLEE_UCLIBC)
        message(WARNING "Enabling POSIX runtime without klee-uclibc support."
                "The runtime might not work without it. Pass `-DENABLE_KLEE_UCLIBC=ON`"
                " to enable klee-uclibc support.")
    endif()
else()
    message(STATUS "POSIX runtime disabled")
endif()

################################################################################
# kleeSE uclibc support
################################################################################
option(ENABLE_klee_UCLIBC "Enable support for klee-uclibc" OFF)
if (ENABLE_klee_UCLIBC)
    message(STATUS "klee-uclibc support enabled")
    set(SUPPORT_klee_UCLIBC 1) # For config.h
    set(klee_UCLIBC_PATH "" CACHE PATH "Path to klee-uclibc root directory")
    if (NOT IS_DIRECTORY "${klee_UCLIBC_PATH}")
        message(FATAL_ERROR
                "klee_UCLIBC_PATH (\"${klee_UCLIBC_PATH}\") is not a valid directory.\n"
                "Try passing -Dklee_UCLIBC_PATH=<path> to cmake where <path> is the path"
                " to the root of the klee-uclibc directory.")
    endif()

    # Find the C library bitcode archive
    set(klee_UCLIBC_BCA_NAME "klee-uclibc.bca")
    set(klee_UCLIBC_C_BCA "${klee_UCLIBC_PATH}/lib/libc.a")
    if (NOT EXISTS "${klee_UCLIBC_C_BCA}")
        message(FATAL_ERROR
                "klee-uclibc library not found at \"${klee_UCLIBC_C_BCA}\"")
    endif()
    message(STATUS "Found klee-uclibc library: \"${klee_UCLIBC_C_BCA}\"")

    # Make a symlink to klee_UCLIBC_C_BCA so klee can find it where it
    # is expected.
    file(MAKE_DIRECTORY "${klee_RUNTIME_DIRECTORY}")
    execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink
            "${klee_UCLIBC_C_BCA}"
            "${klee_RUNTIME_DIRECTORY}/${klee_UCLIBC_BCA_NAME}"
            )
    list(APPEND klee_COMPONENT_CXX_DEFINES
            -Dklee_UCLIBC_BCA_NAME=\"${klee_UCLIBC_BCA_NAME}\")

    # Add klee-uclibc to the install target. We install the original
    # file rather than the symlink because CMake would just copy the symlink
    # rather than the file.
    install(FILES "${klee_UCLIBC_C_BCA}"
            DESTINATION "${klee_INSTALL_RUNTIME_DIR}"
            RENAME "${klee_UCLIBC_BCA_NAME}"
            )

else()
    message(STATUS "klee-uclibc support disabled")
    set(SUPPORT_klee_UCLIBC 0) # For config.h
endif()

################################################################################
# Generate `config.h`
################################################################################
configure_file(${CMAKE_SOURCE_DIR}/include/klee/Config/config.h.cmin
        ${CMAKE_BINARY_DIR}/include/klee/Config/config.h)

set(CMAKE_CXX_STANDARD 11)
find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
include_directories("${CMAKE_BINARY_DIR}/include")
include_directories("${PROJECT_SOURCE_DIR}/include")
add_subdirectory(lib)
add_subdirectory(runtime)

set(SOURCE_FILES main.cpp)
add_executable(klee ${SOURCE_FILES})
target_link_libraries(klee kleeCore)
