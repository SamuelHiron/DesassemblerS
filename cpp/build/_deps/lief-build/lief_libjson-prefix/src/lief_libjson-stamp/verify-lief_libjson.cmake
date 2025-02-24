# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

if("/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//json-3.11.2.zip" STREQUAL "")
  message(FATAL_ERROR "LOCAL can't be empty")
endif()

if(NOT EXISTS "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//json-3.11.2.zip")
  message(FATAL_ERROR "File not found: /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//json-3.11.2.zip")
endif()

if("SHA256" STREQUAL "")
  message(WARNING "File cannot be verified since no URL_HASH specified")
  return()
endif()

if("62b1d12b8c7e4afcf96827d05426ca6d9184b9eefdfac512dd533726b98ad8f7" STREQUAL "")
  message(FATAL_ERROR "EXPECT_VALUE can't be empty")
endif()

message(VERBOSE "verifying file...
     file='/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//json-3.11.2.zip'")

file("SHA256" "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//json-3.11.2.zip" actual_value)

if(NOT "${actual_value}" STREQUAL "62b1d12b8c7e4afcf96827d05426ca6d9184b9eefdfac512dd533726b98ad8f7")
  message(FATAL_ERROR "error: SHA256 hash of
  /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//json-3.11.2.zip
does not match expected value
  expected: '62b1d12b8c7e4afcf96827d05426ca6d9184b9eefdfac512dd533726b98ad8f7'
    actual: '${actual_value}'
")
endif()

message(VERBOSE "verifying file... done")
