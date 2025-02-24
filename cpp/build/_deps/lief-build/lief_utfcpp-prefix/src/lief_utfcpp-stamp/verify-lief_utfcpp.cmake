# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

if("/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//utfcpp-4.0.5.zip" STREQUAL "")
  message(FATAL_ERROR "LOCAL can't be empty")
endif()

if(NOT EXISTS "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//utfcpp-4.0.5.zip")
  message(FATAL_ERROR "File not found: /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//utfcpp-4.0.5.zip")
endif()

if("SHA256" STREQUAL "")
  message(WARNING "File cannot be verified since no URL_HASH specified")
  return()
endif()

if("91c9134a0d1c45be05ad394147cc8fda044f8313f23dc60d9ac5371175a8eff1" STREQUAL "")
  message(FATAL_ERROR "EXPECT_VALUE can't be empty")
endif()

message(VERBOSE "verifying file...
     file='/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//utfcpp-4.0.5.zip'")

file("SHA256" "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//utfcpp-4.0.5.zip" actual_value)

if(NOT "${actual_value}" STREQUAL "91c9134a0d1c45be05ad394147cc8fda044f8313f23dc60d9ac5371175a8eff1")
  message(FATAL_ERROR "error: SHA256 hash of
  /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//utfcpp-4.0.5.zip
does not match expected value
  expected: '91c9134a0d1c45be05ad394147cc8fda044f8313f23dc60d9ac5371175a8eff1'
    actual: '${actual_value}'
")
endif()

message(VERBOSE "verifying file... done")
