#include <iostream>
#include <capstone/capstone.h>
#include "LIEF/LIEF.hpp"
#include <queue>
#include <strings.h>

std::unordered_map<size_t, u_int8_t> binary_contents;
std::unordered_map<size_t, size_t> basic_block_start_address;
std::unordered_map<size_t, size_t> addr2block;
size_t current_id_block = 0;

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


struct BasicBlock{
  size_t id; 
  size_t start_address; 
  size_t end_address;
  bool end;
  std::vector<size_t> ids_successors;
  std::vector<cs_insn> instructions;
  BasicBlock(size_t start_address) : id(current_id_block), start_address(start_address), end(false) {
    current_id_block++;
  }
  
  void print_BasicBlock() const { 
    std::cout << "Basic Block " << id << std::endl;
    for(const auto& insn : instructions){
      std::cout << "0x" << std::hex << insn.address << std::dec << ": " << insn.mnemonic << " " << insn.op_str <<std::endl;     
    }
    std::cout << std::endl;
  } 
}; 

int explore_BasicBlock(BasicBlock block, CSH handle, std::vector<BasicBlock>& blocks) {
  std::cout << "Exploring Basic Block " << block.id << std::endl;
  auto current_address = block.start_address;
  if (addr2block.count(current_address)){
    std::cout<<"Je ne vois pas comment ça peut arriver mais soyons prudent"<<std::endl;
    block.end = true;
  }
  while(!block.end){ //par défaut initialisé à false
    std::cout << "Exploring address: 0x" << std::hex << current_address << std::dec << std::endl;
    // On décode 1 instruction
    std::array<u_int8_t, 16> bytes;
    for(size_t i = 0; i < 16; i++){
      bytes[i] = binary_contents[current_address + i];
    }
    cs_insn* insn_tab;
    size_t count = cs_disasm(handle, bytes.data(), bytes.size(), current_address, 1, &insn_tab);
    assert(count == 1); // On s'occupe d'une instruction à la fois et ça c'est bien passé
    auto insn = insn_tab[0];    
    block.instructions.push_back(insn); // on la stocke
    addr2block[current_address] = block.id; // on note qu'on a traité cette adresse
    auto next_address = insn.address + insn.size; // on prépare la prochaine adresse

    // On gère plusieurs cas
    if (cs_insn_group(handle, &insn, CS_GRP_CALL) || cs_insn_group(handle, &insn, CS_GRP_JUMP) )  { 
      block.end = true;
      // 2 potentiellement nouveaux blocs à créer
      // le bloc juste après l'appel commence à next_address
      if(insn.id != X86_INS_JMP && insn.id != X86_INS_LJMP){
        if (!basic_block_start_address.count(next_address) && !addr2block.count(next_address)) { // cas où l'adresse n'a jamais été traitée et elle n'est pas en début de bloc
          auto block_successor = BasicBlock{next_address}; // création d'un nouveau bloc
          basic_block_start_address[next_address] = block_successor.id-1;
          block.ids_successors.push_back(block_successor.id);
          blocks.push_back(block_successor);
        } else if (basic_block_start_address.count(next_address)){ //cas où l'adresse est déjà le début d'un bloc mais elle n'a pas encore été traitée 
          block.ids_successors.push_back(addr2block[next_address]); // on ajoute l'id du bloc existant à la liste des successeurs de ce bloc
        }
      }
     
      // le bloc loin  
      const auto &op = insn.detail->x86.operands[0];
      if (op.type == X86_OP_IMM) { // cas où l'instruction contient l'adresse de l'appel
        std::cout << "0x" << std::hex  << op.imm << std::dec  << "X86_OP_IMM" <<std::endl;
         if (!basic_block_start_address.count(op.imm) && !addr2block.count(op.imm)) {// cas où l'adresse n'a jamais été traitée et elle n'est pas en début de bloc
            auto block_successor = BasicBlock{static_cast<size_t>(op.imm)}; // création d'un nouveau bloc
            basic_block_start_address[next_address] = block_successor.id-1;
            block.ids_successors.push_back(block_successor.id);
            blocks.push_back(block_successor);
          } else if (basic_block_start_address.count(op.imm)){  //cas où l'adresse est déjà le début d'un bloc mais elle n'a pas encore été traitée
            block.ids_successors.push_back(addr2block[op.imm]); // on ajoute l'id du bloc existant à la liste des successeurs de ce bloc
          } else { //cas où l'adresse est déjà traitée
            auto id_basic_bloc_to_split = addr2block[op.imm]; // Problème ici Bloc à split
          } 
      } else if (op.type == X86_OP_MEM) {
        std::cout << "0x" << std::hex  << std::dec  << "X86_OP_MEM" <<std::endl;
      } else if (op.type == X86_OP_REG) {
        std::cout << "0x" << std::hex << std::dec  << "X86_OP_REG" <<std::endl;
      }
    } else if (cs_insn_group(handle, &insn, CS_GRP_RET) && cs_insn_group(handle, &insn, CS_GRP_INT)  ){  
      block.end = true;
    }
    current_address = next_address;

    //cs_free(&insn, count); // manière + belle de le faire existe cf Jack's code
  }
  block.print_BasicBlock();

  return 0;
  
}

int explore_address_and_get_instruction_BasicBlock(size_t address, BasicBlock* block) {
  // std::cout << "\nExploring address: 0x" << std::hex << address << std::dec << std::endl;
  
  std::array<u_int8_t, 16> bytes;
  for(size_t i = 0; i < 16; i++){
    bytes[i] = binary_contents[address + i];
  }
  // instruction de max 16 octets chargée dans le tableau bytes
  // On peut maintenant décoder l'instruction avec Capstone
  cs_insn* insn;
  // block->print_BasicBlock();
  size_t count = cs_disasm(CSH(), bytes.data(), bytes.size(), address, 0, &insn);
  if (count > 0){
    block->instructions.push_back(insn[0]);
    cs_free(insn, count);
  }

  // block->print_BasicBlock();
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
    std::cout << "Entry Point: 0x" << std::hex << binary->entrypoint() << std::dec << "\n" << std::endl;

    // Addresses to explore for potential new blocks
    std::queue<size_t> queue;
    std::vector<BasicBlock> blocks;
    blocks.push_back({binary->entrypoint()});
    basic_block_start_address[binary->entrypoint()] = 1;

   // Iterate over symbols and print functions
    for (const auto& function : binary->functions()) {
        // std::cout << "  " << function.name() << " address: 0x" << std::hex << function.address() << std::dec << std::endl;// std::hex and std::dec are used to switch between hex and decimal
        if (function.name()[0] != '_' && function.name()!= "frame_dummy" && function.name() != "register_tm_clones" && function.name() != "deregister_tm_clones") {
          // std::cout<< "Adding function to queue "<< function.name() << std::endl;
          blocks.push_back({function.address()});
          basic_block_start_address[function.address()] = current_id_block -1 ;
         queue.push(function.address());
        } 
    }
    std::unordered_map<size_t, size_t> addr2block; //Pour ne traiter qu'une seule fois la même adresse

    CSH handle; //Capstone Handle

    std::cout << queue.size() << " functions to explore\n" << std::endl;

    
    int i = 0;
    while(i != blocks.size()) {
      explore_BasicBlock(blocks[i], handle, blocks);
      i++;
    }
    std::cout << "Fin de l'exploration" << std::endl;
    std::cout << "Nombre de blocs: " << blocks.size() << std::endl; 
    for(const auto& block : blocks){
      block.print_BasicBlock();
    }
    return 0;
}


//(cs_insn_group(handle, insn.get(), CS_GRP_JUMP))
// all jump instructions (conditional+direct+indirect jumps)

// const auto& op = detail->x86.operands[0];
// if (op.type == X86_OP_IMM) 