# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

if("/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//frozen-f6dbec6.zip" STREQUAL "")
  message(FATAL_ERROR "LOCAL can't be empty")
endif()

if(NOT EXISTS "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//frozen-f6dbec6.zip")
  message(FATAL_ERROR "File not found: /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//frozen-f6dbec6.zip")
endif()

if("SHA256" STREQUAL "")
  message(WARNING "File cannot be verified since no URL_HASH specified")
  return()
endif()

if("f961ec0f403d7720da12ec25a39790211d0bcecc342177838f3dd1fa6adb8ac3" STREQUAL "")
  message(FATAL_ERROR "EXPECT_VALUE can't be empty")
endif()

message(VERBOSE "verifying file...
     file='/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//frozen-f6dbec6.zip'")

file("SHA256" "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//frozen-f6dbec6.zip" actual_value)

if(NOT "${actual_value}" STREQUAL "f961ec0f403d7720da12ec25a39790211d0bcecc342177838f3dd1fa6adb8ac3")
  message(FATAL_ERROR "error: SHA256 hash of
  /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//frozen-f6dbec6.zip
does not match expected value
  expected: 'f961ec0f403d7720da12ec25a39790211d0bcecc342177838f3dd1fa6adb8ac3'
    actual: '${actual_value}'
")
endif()

message(VERBOSE "verifying file... done")
