# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

if("/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//mbedtls-3.6.1.zip" STREQUAL "")
  message(FATAL_ERROR "LOCAL can't be empty")
endif()

if(NOT EXISTS "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//mbedtls-3.6.1.zip")
  message(FATAL_ERROR "File not found: /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//mbedtls-3.6.1.zip")
endif()

if("SHA256" STREQUAL "")
  message(WARNING "File cannot be verified since no URL_HASH specified")
  return()
endif()

if("f061424cab7363c5582505afa37f1a863705ee9c5bb76a0885735e047bcc1b21" STREQUAL "")
  message(FATAL_ERROR "EXPECT_VALUE can't be empty")
endif()

message(VERBOSE "verifying file...
     file='/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//mbedtls-3.6.1.zip'")

file("SHA256" "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//mbedtls-3.6.1.zip" actual_value)

if(NOT "${actual_value}" STREQUAL "f061424cab7363c5582505afa37f1a863705ee9c5bb76a0885735e047bcc1b21")
  message(FATAL_ERROR "error: SHA256 hash of
  /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//mbedtls-3.6.1.zip
does not match expected value
  expected: 'f061424cab7363c5582505afa37f1a863705ee9c5bb76a0885735e047bcc1b21'
    actual: '${actual_value}'
")
endif()

message(VERBOSE "verifying file... done")
