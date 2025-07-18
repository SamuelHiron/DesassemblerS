cmake_minimum_required(VERSION 3.30)

project(desassam
    VERSION 1.0.0 # add a version
    DESCRIPTION "A disassembler to recover CFG"
    LANGUAGES CXX C # c and c++
)

include(FetchContent) # Used to download and include external projects at configure time.

 
set(CMAKE_CXX_STANDARD 23) # project uses C++23, 
set(CMAKE_CXX_STANDARD_REQUIRED True) # and this standard is required.

# find_package(fmt REQUIRED)
FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt
    GIT_TAG        1c9fce2ffefecfdce794e1859584e25877b7b592
    FIND_PACKAGE_ARGS
) # 12.0.2
FetchContent_MakeAvailable(fmt)


# if(ENABLE_TESTING)
#     message(STATUS "Building tests")
#     find_package(GTest CONFIG REQUIRED)
#     add_subdirectory(test)
# endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)
message(STATUS "Found Capstone version ${CAPSTONE_VERSION}")

# Ajouter les chemins d'accès aux en-têtes de Capstone
include_directories(${CAPSTONE_INCLUDE_DIRS})
link_directories(${CAPSTONE_LIBRARY_DIRS})



add_subdirectory(external/triskel)

add_executable(desassam src/main.cpp) 

# External Dependencies
FetchContent_Declare(
    LIEF
    GIT_REPOSITORY https://github.com/lief-project/LIEF.git
    GIT_TAG        7e61aa2e56d67b46a0b055363a4cb4fbe4662ef8 # 0.16.3
    FIND_PACKAGE_ARGS
)
FetchContent_MakeAvailable(LIEF)

# ---- LLVM ----

find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

target_include_directories(desassam PRIVATE ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

execute_process(
  COMMAND llvm-config --libs --system-libs DebugInfoDWARF Support
  OUTPUT_VARIABLE LLVM_LIBS
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

string(REPLACE " " ";" LLVM_LIBS_LIST ${LLVM_LIBS})

target_link_libraries(desassam PRIVATE 
    triskel
    LIEF::LIEF
    ${CAPSTONE_LIBRARIES}
    fmt::fmt

    ${LLVM_LIBS_LIST}
)


# target_compile_options(desassam PRIVATE 
#     -Wall 
#     -Wextra 
#     -Wuninitialized
#     -fsanitize=undefined,address
# )

# target_link_options(desassam PRIVATE 
#     -fsanitize=undefined,address
# )
