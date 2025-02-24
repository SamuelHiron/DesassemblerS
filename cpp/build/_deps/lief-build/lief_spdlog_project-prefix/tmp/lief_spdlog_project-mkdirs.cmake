# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_spdlog_project-prefix/src/lief_spdlog_project")
  file(MAKE_DIRECTORY "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_spdlog_project-prefix/src/lief_spdlog_project")
endif()
file(MAKE_DIRECTORY
  "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_spdlog_project-prefix/src/lief_spdlog_project-build"
  "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_spdlog_project-prefix"
  "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_spdlog_project-prefix/tmp"
  "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_spdlog_project-prefix/src/lief_spdlog_project-stamp"
  "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_spdlog_project-prefix/src"
  "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_spdlog_project-prefix/src/lief_spdlog_project-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_spdlog_project-prefix/src/lief_spdlog_project-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_spdlog_project-prefix/src/lief_spdlog_project-stamp${cfgdir}") # cfgdir has leading slash
endif()
