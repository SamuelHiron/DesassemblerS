#include <iostream>
#include <capstone/capstone.h>
#include "LIEF/LIEF.hpp"
#include <queue>
std::map<size_t, u_int8_t> binary_contents;

struct CSH {
  csh handle;

  CSH(){ //Constructeur
    auto is_open = cs_open(CS_ARCH_X86, CS_MODE_64, &handle); // On ouvre une session pour désassemebler du x86-64, result dans handle
    assert(is_open== CS_ERR_OK); // Capstone c'est bien initialisé
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // info détaillée sur désassemblage
  }

  ~CSH(){ //Destructeur
    cs_close(&handle); // On ferme la session
  }

  operator csh&() { return handle; } //convertir implicitement un objet CSH en une référence de type csh&
};


int explore_address_and_get_instruction(size_t address, std::queue<size_t>& queue){
  std::cout << "\nExploring address: 0x" << std::hex << address << std::dec << std::endl;

  std::array<u_int8_t, 16> bytes;
  for(size_t i = 0; i < 16; i++){
    bytes[i] = binary_contents[address + i];
  }
  // instruction de max 16 octets chargée dans le tableau bytes
  // On peut maintenant décoder l'instruction avec Capstone
  cs_insn* insn;
  size_t count = cs_disasm(CSH(), bytes.data(), bytes.size(), address, 0, &insn);
  if(count > 0){
    std::cout << "0x" << std::hex << insn[0].address << std::dec << ": " << insn[0].mnemonic << " " << insn[0].op_str <<std::endl;
    std::cout << "Bytes: "<< std::hex << insn[0].size << std::dec << std::endl;
    // std::cout << "0x" << std::hex << insn[0].address << std::dec << ": " << insn[0].mnemonic << " " << insn[0].op_str <<std::endl;
    queue.push(address + insn[0].size);
    cs_free(insn, count);
  }
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
        if (function.name()[0] != '_' && function.name()!= "frame_dummy" && function.name() != "register_tm_clones" && function.name() != "deregister_tm_clones") {
          std::cout<< "Adding function to queue "<< function.name() << std::endl;
          queue.push(function.address());
        } 
    }
    std::map<size_t, size_t> addr2block; //Pour ne traiter qu'une seule fois la même adresse

    CSH handle; //Capstone Handle

    std::cout << queue.size() << " functions to explore" << std::endl;
    while(!queue.empty()){
      auto address = queue.front();
      queue.pop();
      if (!addr2block.count(address)){
        explore_address_and_get_instruction(address, queue);
        addr2block[address] = 1;
      }
    }
    return 0;
}
