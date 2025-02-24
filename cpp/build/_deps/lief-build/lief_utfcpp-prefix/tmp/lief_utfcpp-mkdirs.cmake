# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_utfcpp-prefix/src/lief_utfcpp")
  file(MAKE_DIRECTORY "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_utfcpp-prefix/src/lief_utfcpp")
endif()
file(MAKE_DIRECTORY
  "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_utfcpp-prefix/src/lief_utfcpp-build"
  "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_utfcpp-prefix"
  "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_utfcpp-prefix/tmp"
  "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_utfcpp-prefix/src/lief_utfcpp-stamp"
  "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_utfcpp-prefix/src"
  "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_utfcpp-prefix/src/lief_utfcpp-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_utfcpp-prefix/src/lief_utfcpp-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-build/lief_utfcpp-prefix/src/lief_utfcpp-stamp${cfgdir}") # cfgdir has leading slash
endif()
