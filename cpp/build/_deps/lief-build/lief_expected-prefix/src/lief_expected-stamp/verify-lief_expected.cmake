# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

if("/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//expected-1.1.0.zip" STREQUAL "")
  message(FATAL_ERROR "LOCAL can't be empty")
endif()

if(NOT EXISTS "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//expected-1.1.0.zip")
  message(FATAL_ERROR "File not found: /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//expected-1.1.0.zip")
endif()

if("SHA256" STREQUAL "")
  message(WARNING "File cannot be verified since no URL_HASH specified")
  return()
endif()

if("4b2a347cf5450e99f7624247f7d78f86f3adb5e6acd33ce307094e9507615b78" STREQUAL "")
  message(FATAL_ERROR "EXPECT_VALUE can't be empty")
endif()

message(VERBOSE "verifying file...
     file='/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//expected-1.1.0.zip'")

file("SHA256" "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//expected-1.1.0.zip" actual_value)

if(NOT "${actual_value}" STREQUAL "4b2a347cf5450e99f7624247f7d78f86f3adb5e6acd33ce307094e9507615b78")
  message(FATAL_ERROR "error: SHA256 hash of
  /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//expected-1.1.0.zip
does not match expected value
  expected: '4b2a347cf5450e99f7624247f7d78f86f3adb5e6acd33ce307094e9507615b78'
    actual: '${actual_value}'
")
endif()

message(VERBOSE "verifying file... done")
