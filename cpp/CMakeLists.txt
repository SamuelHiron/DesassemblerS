cmake_minimum_required(VERSION 3.30)

project(desassam
    VERSION 1.0.0 # add a version
    DESCRIPTION "A disassembler to recover CFG"
    LANGUAGES CXX C # c and c++
)

include(FetchContent) # Used to download and include external projects at configure time.

 
set(CMAKE_CXX_STANDARD 23) # project uses C++23, 
set(CMAKE_CXX_STANDARD_REQUIRED True) # and this standard is required.


# FetchContent_Declare(
#     fmt
#     GIT_REPOSITORY https://github.com/fmtlib/fmt
#     GIT_TAG        1c9fce2ffefecfdce794e1859584e25877b7b592
#     FIND_PACKAGE_ARGS
# ) # 12.0.2
# FetchContent_MakeAvailable(fmt)
# message(STATUS "Found fmt version ${fmt_VERSION}")


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


add_executable(desassam main.cpp) # executable_name: triskel-gui, source file main.cppi

# External Dependencies
FetchContent_Declare(
    LIEF
    GIT_REPOSITORY https://github.com/lief-project/LIEF.git
    GIT_TAG        7e61aa2e56d67b46a0b055363a4cb4fbe4662ef8 # 0.16.3
    FIND_PACKAGE_ARGS
)
FetchContent_MakeAvailable(LIEF)

target_link_libraries(desassam PRIVATE 
    # fmt:fmt
    LIEF::LIEF
    ${CAPSTONE_LIBRARIES}
)# link the executable to the LIEF library, format library and capstone 