# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

if("/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//spdlog-1.14.1.zip" STREQUAL "")
  message(FATAL_ERROR "LOCAL can't be empty")
endif()

if(NOT EXISTS "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//spdlog-1.14.1.zip")
  message(FATAL_ERROR "File not found: /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//spdlog-1.14.1.zip")
endif()

if("SHA256" STREQUAL "")
  message(WARNING "File cannot be verified since no URL_HASH specified")
  return()
endif()

if("429dfdf3afc1984feb59e414353c21c110bc79609f6d7899d52f6aa388646f6d" STREQUAL "")
  message(FATAL_ERROR "EXPECT_VALUE can't be empty")
endif()

message(VERBOSE "verifying file...
     file='/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//spdlog-1.14.1.zip'")

file("SHA256" "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//spdlog-1.14.1.zip" actual_value)

if(NOT "${actual_value}" STREQUAL "429dfdf3afc1984feb59e414353c21c110bc79609f6d7899d52f6aa388646f6d")
  message(FATAL_ERROR "error: SHA256 hash of
  /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//spdlog-1.14.1.zip
does not match expected value
  expected: '429dfdf3afc1984feb59e414353c21c110bc79609f6d7899d52f6aa388646f6d'
    actual: '${actual_value}'
")
endif()

message(VERBOSE "verifying file... done")
