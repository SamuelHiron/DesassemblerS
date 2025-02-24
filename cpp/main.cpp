#include <iostream>
#include "LIEF/LIEF.hpp"
#include <queue>
std::map<size_t, u_int8_t> binary_contents;

int explore_address(size_t address){
  std::cout << "Exploring address: 0x" << std::hex << address << std::dec << std::endl;
  // Get the binary
  get_insturctions(address);
  return 0;
}

int get_insturctions(size_t address){
  std::array<u_int8_t, 16> bytes;
  for(size_t i = 0; i < 16; i++){
    bytes[i] = binary_contents[address + i];
  }
  // instruction de max 16 octets chargée dans le tableau bytes
  // On peut maintenant décoder l'instruction 
  return 0;
}


int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>" << std::endl;
        return 1;
    }

    // Parse the ELF binary
    std::unique_ptr<LIEF::ELF::Binary> binary = LIEF::ELF::Parser::parse(argv[1]);

    if (!binary) {
        std::cerr << "Failed to parse binary!" << std::endl;
        return 1;
    }

    //Chargement du Binaire
    for(const LIEF::ELF::Segment& segment : binary->segments()){
      if(segment.type() == LIEF::ELF::Segment::TYPE::LOAD){
        for(size_t i = 0; i < segment.physical_size(); i++){
          binary_contents[segment.virtual_address() + i] = segment.content()[i];
        }
      }
    }

    // Print binary type and entry point
   std::cout << "Entry Point: 0x" << std::hex << binary->entrypoint() << std::dec << std::endl;

    // Addresses to explore for potential new blocks
    std::queue<size_t> queue;

   // Iterate over symbols and print functions
    std::cout << "Functions found in binary:\n";
    for (const auto& function : binary->functions()) {
        std::cout << "  " << function.name() << " address: 0x" << std::hex << function.address() << std::dec << std::endl;// std::hex and std::dec are used to switch between hex and decimal
        if (function.name() == "main" || function.name() == "foo" || function.name() == "bar") {
          queue.push(function.address());
        } 
    }
    std::map<size_t, size_t> addr2block; //Pour ne traiter qu'une seule fois la même adresse

    while(!queue.empty()){
      auto address = queue.front();
      queue.pop();
      if (addr2block.count(address)){
        explore_address(address);
        addr2block[address] = 1;
      }
    }
    return 0;
}
