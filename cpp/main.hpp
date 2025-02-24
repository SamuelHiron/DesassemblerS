#pragma once

#include <map>
#include <string>


using Binary = std::map<size_t, u_int8_t>;

struct Instruction {
  size_t address;
  std::string mnemonic;
};

