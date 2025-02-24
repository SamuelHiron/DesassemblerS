# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

if("/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//tcb-span-b70b0ff.zip" STREQUAL "")
  message(FATAL_ERROR "LOCAL can't be empty")
endif()

if(NOT EXISTS "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//tcb-span-b70b0ff.zip")
  message(FATAL_ERROR "File not found: /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//tcb-span-b70b0ff.zip")
endif()

if("SHA256" STREQUAL "")
  message(WARNING "File cannot be verified since no URL_HASH specified")
  return()
endif()

if("f3d47ed83507fce94245a9f3cf97bc433cd1116f94d11ac0dca1a6f53bbeb239" STREQUAL "")
  message(FATAL_ERROR "EXPECT_VALUE can't be empty")
endif()

message(VERBOSE "verifying file...
     file='/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//tcb-span-b70b0ff.zip'")

file("SHA256" "/home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//tcb-span-b70b0ff.zip" actual_value)

if(NOT "${actual_value}" STREQUAL "f3d47ed83507fce94245a9f3cf97bc433cd1116f94d11ac0dca1a6f53bbeb239")
  message(FATAL_ERROR "error: SHA256 hash of
  /home/samuel/Documents/DesassemblerS/cpp/build/_deps/lief-src/third-party//tcb-span-b70b0ff.zip
does not match expected value
  expected: 'f3d47ed83507fce94245a9f3cf97bc433cd1116f94d11ac0dca1a6f53bbeb239'
    actual: '${actual_value}'
")
endif()

message(VERBOSE "verifying file... done")
