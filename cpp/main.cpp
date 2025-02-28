#include <capstone/capstone.h>
#include <strings.h>
#include <iostream>
#include <queue>
#include "LIEF/LIEF.hpp"

size_t current_id_block ; // On en a besoin pour les 2 structs
std::unordered_map<size_t, u_int8_t> binary_contents; // On en a besoin aussi dans le main
int bloc_null = 0;
struct CSH {
    csh handle;

    CSH() {  // Constructeur
        auto is_open =
            cs_open(CS_ARCH_X86, CS_MODE_64,
                    &handle);  // On ouvre une session pour désassemebler du
                               // x86-64, result dans handle
        assert(is_open == CS_ERR_OK);  // Capstone c'est bien initialisé
        cs_option(handle, CS_OPT_DETAIL,
                  CS_OPT_ON);  // info détaillée sur désassemblage
    }

    ~CSH() {                // Destructeur
        cs_close(&handle);  // On ferme la session
    }

    operator csh&() {
        return handle;
    }  // convertir implicitement un objet CSH en une référence de type csh&
};

struct BasicBlock {
    size_t id;
    size_t start_address;
    bool end;
    std::vector<size_t> ids_successors;
    std::vector<cs_insn> instructions;
    BasicBlock(size_t start_address)
        : id(current_id_block), start_address(start_address), end(false) {
        current_id_block++;
    }
    BasicBlock(size_t start_address,  std::vector<cs_insn> instructions, std::vector<size_t> ids_successors)
        : id(current_id_block), start_address(start_address), instructions(instructions), ids_successors(ids_successors), end(false) {
        current_id_block++;
    }

    void print_BasicBlock() const {
        
        std::cout << "Basic Block n°" << id ;
        std::cout << " | Parents de :";
        for(const auto & id_successor : ids_successors){
            std::cout << " "<< id_successor;
        }
        std::cout<< std::endl;
        for (const auto& insn : instructions) {
            std::cout << "0x" << std::hex << insn.address << std::dec << ": "
                      << insn.mnemonic << " " << insn.op_str << std::endl;
        }
        if (instructions.empty()){
            std::cout << std::hex << "\n start_address: 0x" << start_address<< std::dec  << std::endl;
            std::cout << "nombre de blocs dans le même état = " << bloc_null << std::endl;
            bloc_null++;
        }

        std::cout << std::endl;
    }
};

struct RecursiveDescent {
    std::unordered_map<size_t, size_t> basic_block_start_address;
    std::unordered_map<size_t, size_t> addr2block;
    std::vector<BasicBlock> blocks;
    std::unique_ptr<LIEF::ELF::Binary> binary;
    CSH handle;



    int init_cfg(){
        blocks.push_back({binary->entrypoint()});
        basic_block_start_address[binary->entrypoint()] = 1;

        // Iterate over symbols and print functions
        for (const auto& function : binary->functions()) {
        // std::cout << "  " << function.name() << " address: 0x" << std::hex <<
        // function.address() << std::dec << std::endl;// std::hex and std::dec
        // are used to switch between hex and decimal
            if (function.name()[0] != '_' && function.name() != "frame_dummy" &&
                function.name() != "register_tm_clones" &&
                function.name() != "deregister_tm_clones") {
                // std::cout<< "Adding function to queue "<< function.name() <<
                // std::endl;
                blocks.push_back({function.address()});
                basic_block_start_address[function.address()] =
                    current_id_block - 1;
           }
        }


        std::cout << blocks.size()-1 << " functions found \n" << std::endl;

        int index_block = 0;
        while (index_block != blocks.size()) {
            explore_BasicBlock(index_block);
            index_block++;
        }
        std::cout << "\n________________________________________________\n\nFin de l'exploration" << std::endl;
        std::cout << "Nombre de blocs trouvés: " << blocks.size()<< "\n" << std::endl;

        for (const auto& block : blocks) {
            block.print_BasicBlock();  
        }
        return 0;
    }

    int split_BasicBlock(size_t id_basic_bloc_to_split, size_t split_address){
        std::vector<cs_insn> debut_split_instructions;
        std::vector<cs_insn> fin_split_instructions;
 
        int i = 0;
        while (i< blocks[id_basic_bloc_to_split].instructions.size()){
            if(blocks[id_basic_bloc_to_split].instructions[i].address < split_address){
                debut_split_instructions.push_back(blocks[id_basic_bloc_to_split].instructions[i]);
            } else {
                fin_split_instructions.push_back(blocks[id_basic_bloc_to_split].instructions[i]);
            }
            i++;
        }
        auto block_successor = BasicBlock{split_address, fin_split_instructions, blocks[id_basic_bloc_to_split].ids_successors};  // création d'un nouveau bloc
        basic_block_start_address[split_address] = block_successor.id - 1; // pour garder la 1ere adresse d'un bloc associée à son id
        blocks[id_basic_bloc_to_split].instructions = debut_split_instructions;
        blocks[id_basic_bloc_to_split].ids_successors.clear();
        blocks.push_back(block_successor);
        return 0;     
    }

    int explore_BasicBlock(const int index_block) {
        std::cout << "Exploring Basic Block " << blocks[index_block].id
                  << std::endl;
        auto current_address = blocks[index_block].start_address;
        if (addr2block.count(current_address)) {
            std::cout << "Ce block" << addr2block[current_address] << " a déjà vu cette adresse " << current_address  << std::endl; 
            blocks[index_block].end = true; // dans le cas split d'un bloc déjà vu
        }

        // int i =0; si boucle infinie
        while (!blocks[index_block].end) {  // par défaut initialisé à false
 
            // if (i == 5) {
            //   blocks[index_block]end = true;
            // }
            // i++;
            addr2block[current_address] = index_block;

            std::cout << "Exploring address: 0x" << std::hex << current_address
                      << std::dec << std::endl;
            // On décode 1 instruction
           std::array<u_int8_t, 16> bytes;
            for (size_t i = 0; i < 16; i++) {
                bytes[i] = binary_contents[current_address + i];
            }
            cs_insn* insn_tab;
            size_t count = cs_disasm(handle, bytes.data(), bytes.size(),
                                     current_address, 1, &insn_tab);
            assert(count == 1);  // On s'occupe d'une instruction à la fois et
                                 // ça c'est bien passé
            auto insn = insn_tab[0];
            blocks[index_block].instructions.push_back(insn);  // on la stocke

            addr2block[current_address] =
                blocks[index_block].id;  // on note qu'on a traité cette adresse
            auto next_address =
                insn.address + insn.size;  // on prépare la prochaine adresse
            if (cs_insn_group(handle, &insn, CS_GRP_CALL) ||
                cs_insn_group(handle, &insn, CS_GRP_JUMP)) {
                blocks[index_block].end = true;              
                
                // 2 potentiellement nouveaux blocs à créer
                // le bloc juste après l'appel commence à next_address
                if (insn.id != X86_INS_JMP && insn.id != X86_INS_LJMP) {
                    if (!basic_block_start_address.count(next_address) &&
                        !addr2block.count(next_address)) {  // cas où l'adresse n'a jamais été
                                              // traitée et elle n'est pas en
                                              // début de bloc
                        auto block_successor = BasicBlock{
                            next_address};  // création d'un nouveau bloc
                        basic_block_start_address[next_address] =
                            block_successor.id - 1; // pour garder la 1ere adresse d'un bloc associée à son id
                        blocks[index_block].ids_successors.push_back(
                            block_successor.id);
                        blocks.push_back(block_successor);
                    } else if (basic_block_start_address.count(
                                   next_address)) {  // cas où l'adresse est
                                                     // déjà le début d'un bloc
                                                     // mais elle n'a pas encore
                                                     // été traitée
                        blocks[index_block].ids_successors.push_back(
                            basic_block_start_address[next_address]);  // on ajoute l'id du
                                                        // bloc existant à la
                                                        // liste des successeurs
                                                        // de ce bloc                
                    }
                }

                // le bloc loin
                const auto& op = insn.detail->x86.operands[0];
                if (op.type == X86_OP_IMM) {  // cas où l'instruction contient
                                              // l'adresse de l'appel                 
                    std::cout << "0x" << std::hex << op.imm << std::dec
                              << "  X86_OP_IMM" << std::endl;            

                    if (!basic_block_start_address.count(op.imm) &&
                        !addr2block.count(
                            op.imm)) {  // cas où l'adresse n'a jamais été
                                        // traitée et elle n'est pas en début de
                                        // bloc
                        auto block_successor = BasicBlock{static_cast<size_t>(
                            op.imm)};  // création d'un nouveau bloc
                        basic_block_start_address[static_cast<size_t>(op.imm)] =
                            block_successor.id - 1; // pour garder la 1ere adresse d'un bloc associée à son id
                        blocks[index_block].ids_successors.push_back(
                            block_successor.id);
                        
                        blocks.push_back(block_successor);

                    } else if (basic_block_start_address.count(
                                   op.imm)) {  // cas où l'adresse est déjà le
                                               // début d'un bloc mais elle n'a
                                               // pas encore été traitée
                       blocks[index_block].ids_successors.push_back(basic_block_start_address[op.imm]);  // on ajoute l'id du bloc
                                                 // existant à la liste des
                                                  // successeurs de ce bloc
                    } else {  // cas où l'adresse est déjà traitée
                        auto id_basic_bloc_to_split =
                            addr2block[op.imm];  // Problème ici Bloc à split
                        size_t split_address = static_cast<size_t>(op.imm);
                        std::cout << "bloc à split est n°" << id_basic_bloc_to_split << "à l'adresse 0x" << std::hex<< op.imm << std::dec <<  std::endl;
                        split_BasicBlock(id_basic_bloc_to_split, split_address);
                        std::cout << "index_block "<< index_block << "current_id_block - 1"<< current_id_block - 1 << std::endl; 
                        blocks[index_block].ids_successors.push_back(current_id_block - 1);// on a un successeur
                        if(index_block == id_basic_bloc_to_split){
                         blocks[current_id_block-1].ids_successors.push_back(current_id_block - 1);   
                        }
                    }           
                } else if (op.type == X86_OP_MEM) {
                    std::cout << "0x" << std::hex << std::dec << "  X86_OP_MEM"
                              << std::endl;
                } else if (op.type == X86_OP_REG) {
                    std::cout << "0x" << std::hex << std::dec << "  X86_OP_REG"
                              << std::endl;
                }

                // std::cout << "CALL ou JUMP" << std::endl;
            } else if (cs_insn_group(handle, &insn, CS_GRP_RET) ||
                       cs_insn_group(handle, &insn, CS_GRP_INT)) {
                // std::cout << "RET ou INT" << std::endl;
                blocks[index_block].end = true;
            }
            // if (!basic_block_start_address.count(next_address)){  
            current_address = next_address;
            // } else {
            //     blocks[index_block].end = true;
            // }
            cs_free(
                insn_tab,
                count);  // manière + belle de le faire existe cf Jack's code
        }
        //blocks[index_block].print_BasicBlock();

        return 0;
    }
    
};



int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>" << std::endl;
        return 1;
    }

    // Parse the ELF binary
    std::unique_ptr<LIEF::ELF::Binary> binary =
        LIEF::ELF::Parser::parse(argv[1]);

    if (!binary) {
        std::cerr << "Failed to parse binary!" << std::endl;
        return 1;
    }

    // Chargement du Binaire
    for (const LIEF::ELF::Segment& segment : binary->segments()) {
        if (segment.type() == LIEF::ELF::Segment::TYPE::LOAD) {
            for (size_t i = 0; i < segment.physical_size(); i++) {
                binary_contents[segment.virtual_address() + i] =
                    segment.content()[i];
            }
        }
    }

    // Print binary type and entry point
    std::cout << "Entry Point: 0x" << std::hex << binary->entrypoint()
              << std::dec << "\n"
              << std::endl;
    RecursiveDescent rd;
    rd.binary = std::move(binary);
    rd.init_cfg();
    
    return 0;
}

