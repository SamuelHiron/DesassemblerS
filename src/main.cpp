#include <capstone/capstone.h>
#include <fmt/base.h>
#include <strings.h>
#include <cstddef>
#include <iostream>
#include <new>
#include <sstream>
#include <string>
#include <triskel/triskel.hpp>
#include <unordered_map>
#include <utility>
#include "LIEF/LIEF.hpp"
#include "x86.h"

size_t current_id_block;  // On en a besoin pour les 2 structs
std::unordered_map<size_t, u_int8_t>
    binary_contents;  // On en a besoin aussi dans le main
using InstructionPtr = std::shared_ptr<cs_insn>;
int bloc_null        = 0;

struct CSH {
    csh handle;

    CSH() {  // Constructeur
        auto is_open =
            cs_open(CS_ARCH_X86, CS_MODE_64,
                    &handle);  // On ouvre une session pour désassembler du
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

struct Position_Registre {
    size_t position;
    uint16_t registre;
};

struct Position_Value {
    size_t position;
    size_t value;  // peut etre une float
};

struct BasicBlock {
    bool function_start;
    size_t id;
    size_t start_address;
    bool end;
    std::vector<size_t> childs_id;
    std::vector<size_t> parents_id;
    std::vector<InstructionPtr> instructions;
    std::unordered_map<uint16_t, std::vector<Position_Registre>>
        unknown_regs_dependencies;
    std::unordered_map<size_t, Position_Value> known_regs;
    BasicBlock(size_t start_address)
        : id(current_id_block),
          start_address(start_address),
                    end(false) {
        current_id_block++;
    }
    BasicBlock(size_t start_address, bool function_start)
        : id(current_id_block),
        function_start(function_start),
        start_address(start_address),
                    end(false) {
        current_id_block++;
    }
    BasicBlock(size_t start_address,
               std::vector<size_t> childs_id,
               std::vector<size_t> parents_id)
        : id(current_id_block),
          start_address(start_address),
          childs_id(std::move(childs_id)),
          parents_id(std::move(parents_id)),
          end(false) {
        current_id_block++;
    }

    void print_BasicBlock() const {
        fmt::print("Basic Block n° {}", id);
        fmt::print(" | Enfants de :");
        for (const auto& parent_id : parents_id) {
             fmt::print(" {}", parent_id);
        }
        fmt::print( " | Parents de :");
        for (const auto& child_id : childs_id) {
            fmt::print( " {}",  child_id);
        }
        fmt::println("" );
        for (const auto& insn : instructions) {
            fmt::print( "{:#x}: {} {}", insn->address, insn->mnemonic, insn->op_str);
        }
        if (instructions.empty()) {
            fmt::print(  "\n start_address: {0:#x}", start_address);
            fmt::print( "nombre de blocs dans le même état = ", bloc_null);
            bloc_null++;
        }
        fmt::print("" );
    }
};

int replace_id(std::vector<size_t>& parents_id,
               size_t id_to_supress,
               size_t id_to_add) {
    for (int i = 0; i < parents_id.size(); i++) {
        if (parents_id[i] == id_to_supress) {
            parents_id[i] = id_to_add;
        }
    }
    return 0;
}

struct RecursiveDescent {
    std::unordered_map<size_t, size_t> basic_block_start_address;
    std::unordered_map<size_t, size_t> addr2block;  // address already treated
    std::vector<BasicBlock> blocks;
    std::unique_ptr<LIEF::ELF::Binary> binary;

    CSH handle;

    int find_CFGs_entrypoints() {
        blocks.push_back({binary->entrypoint()});
        basic_block_start_address[binary->entrypoint()] = 1;

        // Iterate over symbols and print functions
        for (const auto& function : binary->functions()) {
            blocks.push_back({function.address()});
            basic_block_start_address[function.address()] =
                current_id_block - 1;
        fmt::print(  "{} functions found \n",  blocks.size() - 1  );
        }
        return 0;
    }
    
    int recursive_descent(){
        int index_block = 0;
        while (index_block != blocks.size()) {
            explore_BasicBlock(index_block);
            index_block++;
        }
        return 0;
    }

    int print_CFGs(){
        fmt::println( "\n__________________________________________\n\nFin de l'exploration");
        fmt::println( "Nombre de blocs trouvés: {}",  blocks.size());
        for (const auto& block : blocks) {
            block.print_BasicBlock();
        }
        return 0;
    }

    int print_dependencies_same_bb(){
        fmt::print("\n_______________________________________________\n\n");
        fmt::print( "Analyse VSA:\n");
        for (int i = 0; i < blocks.size(); i++) {
            fmt::print("\nBlock {} Dependencies:", i);
            print_unknown_regs_dependencies(
                blocks[i].unknown_regs_dependencies);
            fmt::print( "Block {} Known Regs:", i);
            print_known_regs(blocks[i].known_regs);
        }
        return 0;
    }

    int show_cfg_triskel_each_graph(const std::string& good_name){
        int nb_graph = 0;
        for(auto &block: blocks){
            if(block.parents_id.size() == 0 || block.function_start){ // attention block parent ou function = root
                                //parcours des enfants pour choper tous les bb
                std::unordered_map<size_t, size_t> block_deja_vus;

                std::vector<size_t> blocks_id;
                size_t index_graph = 0;
                find_every_successors(block.id, index_graph ,blocks_id, block_deja_vus);
                if(blocks_id.size() < 500){ 
                    auto renderer = triskel::make_svg_renderer();
                    auto builder  = triskel::make_layout_builder();

                    int num_insn  = 0;
                    std::ostringstream oss; //remplacer par fmt::format
                    // Create nodes for each block
                    for(auto index_block: blocks_id){
                        fmt::print("id : {} graphid: {}\n", index_block, block_deja_vus[index_block]);
                        if(index_block == block.id){
                            oss << "Root of the Graph\n";
                        }
                        oss << "Block ID: " <<  index_block << "\n";
                        for (const auto& insn : blocks[index_block].instructions) {
                            oss << num_insn << " 0x"<< std::hex << insn->address << std::dec<< ": " <<insn->mnemonic << " "<< insn->op_str << std::endl;
                            num_insn++;
                        }
                        builder->make_node(*renderer, oss.str());
                        oss.str("");  // cleans the content
                        oss.clear();  // cleans any flag
                        num_insn = 0;
                    }
                    fmt::print("\nLes arretes sont :\n");
                    for (auto index_block: blocks_id) {
                        if(block.id == index_block || !blocks[index_block].function_start){
                            for (auto child_id : blocks[index_block].childs_id) {
                                fmt::print("ids: {} -> {} donc graph_ids ", index_block, child_id);
                                fmt::println("{} -> {}", block_deja_vus[index_block], block_deja_vus[child_id]);
                                builder->make_edge(block_deja_vus[index_block], block_deja_vus[child_id]);
                            }
                        }
                    }
                    fmt::println("End Graph \n");
                    std::string new_name = good_name + std::to_string(nb_graph) + ".svg";
                    auto layout = builder->build();
                    layout->render_and_save(*renderer, new_name);
                    nb_graph++;
                }   
            }
        }
        return 0;
    }

    int find_every_successors(size_t index_block, size_t &index_graph,std::vector<size_t> &blocks_id, std::unordered_map<size_t, size_t> &block_deja_vus){
        if(!block_deja_vus.contains(index_block)){
            blocks_id.push_back(index_block);
            if(!blocks[index_block].function_start) {
                block_deja_vus[index_block] = index_graph;
            } else {
                return 0;
            }
            index_graph++;
        }
        for(auto child_id : blocks[index_block].childs_id){
            if(!block_deja_vus.contains(child_id) && !blocks[child_id].function_start){
                find_every_successors(child_id, index_graph, blocks_id, block_deja_vus);
            }
        }
        return 0;
    }

    int print_instruction_regs_RW(const InstructionPtr insn) {
        uint16_t regs_read[64]  = {0};
        uint16_t regs_write[64] = {0};
        uint8_t read_count      = 0;
        uint8_t write_count     = 0;
        fmt::print( "\nProcessing instruction: {} {}", insn->mnemonic, insn->op_str  );
        if (cs_regs_access(handle, insn.get(), regs_read, &read_count,
                           regs_write, &write_count) == CS_ERR_OK) {
            if (read_count > 0) {
                fmt::print( "\t| Registers read : ");
                for (uint8_t i = 0; i < read_count; i++) {
                    fmt::print("{} ",cs_reg_name(handle, regs_read[i]));
                }
            }

            if (write_count > 0) {
                fmt::print( " \t| Registers modified : ");
                for (uint8_t i = 0; i < write_count; i++) {
                    std::string regName = cs_reg_name(handle, regs_write[i]);
                    fmt::print( "{} ",  regName);
                }
                fmt::println("" );
            }
        }
        return 0;
    }

    int split_BasicBlock(size_t id_basic_bloc_to_split,
                         size_t split_address,
                         size_t index_block_parent) {
        std::vector<InstructionPtr> debut_split_instructions;

        auto block_successor =
            BasicBlock{split_address,
                       blocks[id_basic_bloc_to_split].childs_id,
                       {index_block_parent}};  // création d'un nouveau bloc
        blocks[id_basic_bloc_to_split].known_regs.clear();
        blocks[id_basic_bloc_to_split].unknown_regs_dependencies.clear();
        // le nouveau block
        if (blocks[id_basic_bloc_to_split].id !=
            index_block_parent) {  // si il n'est pas son propre parent
            block_successor.parents_id.push_back(
                blocks[id_basic_bloc_to_split].id);
        }
        basic_block_start_address[split_address] =
            block_successor
                .id;  // pour garder la 1ere adresse d'un bloc associée à son id
        blocks.push_back(block_successor);
        if (index_block_parent ==
            id_basic_bloc_to_split) {  // si il est son propre parent
            blocks[block_successor.id].childs_id.push_back(block_successor.id);
        }

        int i = 0;
        int j = 0;
        // les instructions
        while (i < blocks[id_basic_bloc_to_split].instructions.size()) {
            if (blocks[id_basic_bloc_to_split].instructions[i]->address <
                split_address) {
                debut_split_instructions.push_back(
                    blocks[id_basic_bloc_to_split].instructions[i]);
                instruction_RW_regs(
                    blocks[id_basic_bloc_to_split].instructions[i], i,
                    id_basic_bloc_to_split);
                j++;
            } else {
                blocks[block_successor.id].instructions.push_back(
                    blocks[id_basic_bloc_to_split].instructions[i]);
                instruction_RW_regs(
                    blocks[id_basic_bloc_to_split].instructions[i], i - j,
                    block_successor.id);
            }
            i++;
        }

        // le block split
        blocks[id_basic_bloc_to_split].instructions = debut_split_instructions;
        for (auto insn : debut_split_instructions) {
            // fmt::print( "{0:#x} {} {}", insn->address, insn->mnemonic, insn->op_str); # TODO
            std::cout << "0x" << std::hex <<insn->address << std::dec << ": "<< insn->mnemonic << " " << insn->op_str << std::endl;
        }
        for (auto id_child :
             blocks[id_basic_bloc_to_split]
                 .childs_id) {  // on adapte les parents_id de ses enfants
            replace_id(blocks[id_child].parents_id, id_basic_bloc_to_split,
                       block_successor.id);
        }
        blocks[id_basic_bloc_to_split].childs_id.clear();
        blocks[id_basic_bloc_to_split].childs_id.push_back(block_successor.id);
        if (id_basic_bloc_to_split != index_block_parent) {
            blocks[index_block_parent].childs_id.push_back(block_successor.id);
        }
        return 0;
    }

    // ajoute à mon vector de block un nouveau block commençant par next_address
    // et en mettant la connexion au parent de l'id de l'enfant. Le booléen far
    // permet de traiter si on saute à une addresse si on split un bloc
    int init_next_bb(size_t next_address, size_t index_block_parent, bool far, bool function_start) {
        if (!basic_block_start_address.contains(next_address) &&
            !addr2block.contains(
                next_address)) {  // cas où l'adresse n'a jamais été
                                  // traitée et elle n'est pas en
                                  // début de bloc
            auto block_successor =
                BasicBlock{next_address, function_start};  // création d'un nouveau bloc
            basic_block_start_address[next_address] =
                block_successor.id;  // pour garder la 1ere adresse d'un bloc
                                     // associée à son id
            blocks[index_block_parent].childs_id.push_back(
                block_successor.id);  // on ajoute l'id de l'enfant à la liste
                                      // des enfants du bloc parent
            block_successor.parents_id.push_back(
                index_block_parent);  // on ajoute l'id du parent à la liste des
                                      // parents du bloc enfant
            blocks.push_back(block_successor);
        } else if (basic_block_start_address.contains(
                       next_address)) {  // cas où l'adresse est
                                         // déjà le début d'un bloc
                                         // mais elle n'a pas encore
                                         // été traitée
            blocks[index_block_parent].childs_id.push_back(
                basic_block_start_address[next_address]);  // on ajoute l'id du
                                                           // bloc existant à la
                                                           // liste des
                                                           // successeurs de ce
                                                           // bloc
            blocks[basic_block_start_address[next_address]]
                .parents_id.push_back(
                    index_block_parent);  // sa position dans le vector est
                                          // aussi son id
        } else if (far) {  // cas où l'adresse est déjà traitée
            auto id_basic_bloc_to_split =
                addr2block[next_address];  // Problème ici Bloc à split
            size_t split_address =
                next_address;  // renommage pour que cela soit plus clair
            fmt::print( "bloc à split est n° {0:d} à l'adresse {0:#x}", id_basic_bloc_to_split, split_address);
            split_BasicBlock(id_basic_bloc_to_split, split_address, index_block_parent); // Interogation call ?
        }
        return 0;
    }

    void print_unknown_regs_dependencies(
        const std::unordered_map<uint16_t, std::vector<Position_Registre>>&
            unknown_regs_dependencies) {
        for (const auto& pair : unknown_regs_dependencies) {
            uint16_t reg                                      = pair.first;
            const std::vector<Position_Registre>& dependances = pair.second;
            fmt::print( "Registre: {}\n", cs_reg_name(handle, reg));
            for (const auto& dependance : dependances) {
                fmt::print("  Position_Instr: {}, Registre: {}", dependance.position, cs_reg_name(handle, dependance.registre));
            }
        }
    }

    void print_known_regs(
        const std::unordered_map<size_t, Position_Value>& known_regs) {
        for (const auto& pair : known_regs) {
            uint16_t reg = pair.first;
            fmt::println("Registre: {}",  cs_reg_name(handle, reg));
            fmt::println( "  Position_Instr: {}, Value: {}",  pair.second.position, pair.second.value);
        }
    }

    int instruction_RW_regs(const InstructionPtr insn,
                            size_t position_instruction,
                            const size_t index_block) {  // split bloc à traiter
        uint16_t regs_read[64]  = {0};
        uint16_t regs_write[64] = {0};
        uint8_t read_count      = 0;
        uint8_t write_count     = 0;
        if (cs_regs_access(handle, insn.get(), regs_read, &read_count,
                           regs_write, &write_count) == CS_ERR_OK) {
            bool no_read_unknown = true;  // Si le nombre d'inconnu de read = 0
            if (write_count > 0) {
                // cas où on est pas capable de résoudre la dépendance
                for (uint8_t k = 0; k < write_count; k++) {
                    for (uint8_t l = 0; l < read_count; l++) {
                        if (!blocks[index_block].known_regs.contains(
                                regs_read[l])) {
                            blocks[index_block]
                                .unknown_regs_dependencies[regs_write[k]]
                                .push_back(
                                    {position_instruction, regs_read[l]});
                            no_read_unknown = false;
                        }
                    }
                    if (no_read_unknown) {
                        // print_known_regs(blocks[index_block].known_regs);
                        print_instruction_regs_RW(insn);
                        size_t value = get_reg_value(insn, index_block, position_instruction,regs_write[k]); // cas où float et pas déterminable avec instruction

                        if (blocks[index_block].unknown_regs_dependencies.contains(
                                regs_write[k])) {
                            blocks[index_block].unknown_regs_dependencies.erase(
                                regs_write[k]);
                        }
                    }
                }
            }
        }
        return 0;
    }



    size_t get_reg_value(const InstructionPtr &insn, const size_t index_block, size_t position_instruction, size_t regs_write_value){ // A traiter
        size_t value = 0;
        fmt::print("Analyse Instruction mem value");
        if (insn->id == X86_INS_MOV){
            auto op0 =insn->detail->x86.operands[0];
            auto op1 = insn->detail->x86.operands[1];
            auto op2 = insn->detail->x86.operands[2];
            if(op0.type == X86_OP_REG){
                if(op1.type==X86_OP_IMM){
                    if (op2.type == X86_OP_INVALID){
                        value = op1.imm;
                    } else {
                        fmt::print("BIZARRE");
                        print_instruction_regs_RW(insn);
                    }
                } else if (op1.type == X86_OP_REG && blocks[index_block].known_regs.contains(op1.reg)){
                    if (op2.type == X86_OP_INVALID){
                        value = blocks[index_block].known_regs[op1.reg].value;
                    } else {
                        fmt::print("BIZARRE");
                        print_instruction_regs_RW(insn);
                    }
                }
            } 
        }
        // int i = 0;
        // for(auto op : insn->detail->x86.operands){
        //     if(op0.type == X86_OP_IMM){
        //         fmt::print("\nValue de l'op n°{}  = {:x} ",i, op0.imm);
        //     } else if(op0.type == X86_OP_INVALID) {
        //         continue;
        //     } else if(op0.type == X86_OP_REG) {
        //         fmt::print( "\nRegister: {}", cs_reg_name(handle,op0.reg));
        //     } else if(op0.type== X86_OP_MEM){
        //         fmt::print("\nPlus DUR");
        //         fmt::print( "\nDétails instructions op: {} ", i  );
        //         std::string reg_base;
        //         if (cs_reg_name(handle, op0.mem.base)){
        //             reg_base = cs_reg_name(handle, op0.mem.base);
        //             fmt::print( "Base Register: {}", reg_base);
        //         }
        //         if ( cs_reg_name(handle, op0.mem.index) != NULL){
        //             fmt::print( "Index"  );
        //         }
        //         fmt::print( "Scale: {}", op0.mem.scale  );
        //         fmt::print( "Displacement: {}",  op0.mem.disp  );
        //         if ( cs_reg_name(handle, op0.mem.segment) != NULL){
        //             fmt::print( "Segment"  );
        //         }
        //     }
        //     i++;
        // }
        blocks[index_block].known_regs[regs_write_value] = {position_instruction, value};
        fmt::println("\n");
        return value;
    }

    int explore_BasicBlock(const int index_block) {
        // fmt::print( "Exploring Basic Block "  blocks[index_block].id 
        // );
        // if(index_block> 1000) {
        //     fmt::print("Trop de bloc dans ce graphe, fonction à trouver");
        //     return 0;
        // }
        auto current_address = blocks[index_block].start_address;
        if (addr2block.contains(current_address)) {
            fmt::print( "Ce block {} a déjà vu cette addresse {}", addr2block[current_address],  current_address);
            blocks[index_block].end = true;  // dans le cas split d'un bloc déjà vu
        }

        int position_instruction = 0;                          // pour la position de l'instruction & ne pas aller trop loin je pourrai mettre zone RX
        while (!blocks[index_block].end && position_instruction<200) {  // end par défaut initialisé à false, position_instruction pour éviter le crash
            // pour etre sur refait pas une lecture de bloc

            addr2block[current_address] = index_block;
            fmt::println( "Exploring address: {0:#x}",  current_address);  // On décode 1 instruction
            std::array<u_int8_t, 16> bytes;
            for (size_t i = 0; i < 16; i++) {
                bytes[i] = binary_contents[current_address + i];
            }
            cs_insn* raw_pointer;
            size_t count = cs_disasm(handle, bytes.data(), bytes.size(),
                                     current_address, 1, &raw_pointer);
            assert(count == 1);  // On s'occupe d'une instruction à la fois et
                                 // ça c'est bien passé

            auto insn = std::shared_ptr<cs_insn>{
                raw_pointer, [](cs_insn* insn) { cs_free(insn, 1); }};

            instruction_RW_regs(insn, position_instruction, index_block);

            blocks[index_block].instructions.push_back(insn);  // on la stocke
            addr2block[current_address] =
                blocks[index_block].id;  // on note qu'on a traité cette adresse
            auto next_address =
                insn->address + insn->size;  // on prépare la prochaine adresse

            const auto& op = insn->detail->x86.operands[0];
            if (cs_insn_group(handle, insn.get(), CS_GRP_CALL) ||
                cs_insn_group(handle, insn.get(), CS_GRP_JUMP)) {
                bool function_start = false;

                blocks[index_block].end = true;

                // 2 potentiellement nouveaux blocs à créer
                // le bloc juste après l'appel commence à next_address
                if (insn->id != X86_INS_JMP && insn->id != X86_INS_LJMP) {
                    bool far = false;
                    init_next_bb(next_address, index_block,
                                 far, function_start);  // ajoute le bb qui commence à l'adresse
                                        // suivante au vector de cfg
                }

                // le bloc loin
                const auto& op0 = insn->detail->x86.operands[0];
                if (op0.type == X86_OP_IMM) {  // cas où l'instruction contient
                                              // l'adresse de l'appel
                                              // init_next_bb(static_cast<size_t>(op0.imm),
                                              // index_block, far);

                    fmt::print( "{0:#x} X86_OP_IMM", op0.imm);
                    bool far = true;
                    if (cs_insn_group(handle, insn.get(), CS_GRP_CALL)) {
                        function_start = true;
                    }
                    init_next_bb(static_cast<size_t>(op0.imm), index_block, far, function_start);

                } else if (op0.type == X86_OP_MEM) {
                    print_known_regs(blocks[index_block].known_regs);
                    print_X86_OP(op0);
                    auto op1 = insn->detail->x86.operands[1];
                    print_X86_OP(op1);
                    size_t jmp_address = find_block_address_op(op0, index_block);
                    fmt::println("jump address 0x{:x}", jmp_address);
                    bool far = true;
                    if (cs_insn_group(handle, insn.get(), CS_GRP_CALL)) {
                        function_start = true;
                    }
                    if(op1.type == X86_OP_INVALID && jmp_address != 0){
                        init_next_bb(jmp_address, index_block, far, function_start);
                    }
                } else if (op0.type == X86_OP_REG) {
                    fmt::print( "  X86_OP_REG");
                }
                // fmt::print( "CALL ou JUMP"  );
            } else if (cs_insn_group(handle, insn.get(), CS_GRP_RET) ||
                       cs_insn_group(handle, insn.get(), CS_GRP_INT)) {
                // fmt::print( "RET ou INT"  );
                blocks[index_block].end = true;
            }
            current_address = next_address;
            if (addr2block.contains(current_address)) {
                blocks[index_block].childs_id.push_back(
                    addr2block[current_address]);
                blocks[addr2block[current_address]].parents_id.push_back(
                    index_block);
                break;
            }
            position_instruction++;
        }

        return 0;
    }


    void print_X86_OP(const cs_x86_op op){
        if (op.type == X86_OP_MEM){
            fmt::println( " Plus DUR X86_OP_MEM => Détails instructions operand :");
            if (cs_reg_name(handle, op.mem.base)!= NULL){
                fmt::print( "Base Register: {} + ", cs_reg_name(handle, op.mem.base));
            }
            if ( cs_reg_name(handle, op.mem.index) != NULL){
                fmt::print( "Index Register: {} * ", cs_reg_name(handle, op.mem.index));
                fmt::print( " Scale {} +", op.mem.scale);
            }
            fmt::print( " Displacement: {}",  op.mem.disp);
            if ( cs_reg_name(handle, op.mem.segment) != NULL){
                fmt::print( " with Segment Don't know how to Handle"  );
            }
            fmt::println("");
        } else if (op.type == X86_OP_REG){
            fmt::println("reg {} ", cs_reg_name(handle, op.reg));
        } else if (op.type == X86_OP_IMM){
            fmt::println("Nous avons une valeur : {}", op.imm);
        } else if (op.type == X86_OP_INVALID){
            fmt::println("Cette operand est nulle");
        }            
    }

    size_t find_block_address_op(const cs_x86_op op, size_t index_block){
        // Base Register+(Index Register×Scale Factor)+Displacement
        size_t value = 0;
        if (cs_reg_name(handle, op.mem.base)!= NULL){ // Base Register
            if (blocks[index_block].known_regs.contains(op.mem.base)) {
                // cas où on est pas capable de résoudre la dépendance
                value = blocks[index_block].known_regs[op.mem.base].value;
            } else {
                return 0;
            }
        } 
        if ( cs_reg_name(handle, op.mem.index) != NULL){ // Index Register * scale
            if (blocks[index_block].known_regs.contains(op.mem.index)) {
                // cas où on est pas capable de résoudre la dépendance
                value += blocks[index_block].known_regs[op.mem.index].value * op.mem.scale;
            } else {
                return 0;
            }
        }
        value += op.mem.disp;
        if ( cs_reg_name(handle, op.mem.segment) != NULL){
            fmt::print( " Segment Handle TODO"  );
            return 0;
        }
        return value;

    }


};

static auto name_file_output(const int &argc, char ** &argv) -> std::string{
    std::string input_path = argv[1];  // Chemin du fichier donné en argument
    size_t found = input_path.find_last_of("/\\");
    std::string output_filename;
    if (argc == 3 && std::strcmp(argv[2], "asm") == 0){
        output_filename = "./out_cfg/asm/" + input_path.substr(found + 1) + "_"; 
    } else if(argc == 3 && std::strcmp(argv[2], "C") == 0){
        output_filename = "./out_cfg/C/" + input_path.substr(found + 1)+"_"; 
    } else if(argc == 3 && std::strcmp(argv[2], "distro") == 0){
        output_filename = "./out_cfg/distro/" + input_path.substr(found + 1)+"_"; 
    } else {
        output_filename = "./out_cfg/test/out"; 
    }
    // 🔹 Récupérer juste le nom du fichier sans extension

    // 🔹 Définir le chemin de sortie (dans le même dossier ou un autre dossier)
    return output_filename;
}




int main(int argc, char** argv) {
    if (argc < 2) {
        fmt::print(stderr,"Usage: {} <binary> asm|C|", argv[0]);
        return 1;
    }

    std::string good_name = name_file_output(argc, argv);
    // Parse the ELF binary
    std::unique_ptr<LIEF::ELF::Binary> binary =
        LIEF::ELF::Parser::parse(argv[1]);

    if (!binary) {
        fmt::print(stderr, "Failed to parse binary!");
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
    fmt::println( "Entry Point: {0:#x}", binary->entrypoint());
    RecursiveDescent rd;
    rd.binary = std::move(binary);
    rd.find_CFGs_entrypoints();
    rd.recursive_descent();
    rd.print_CFGs();
    rd.print_dependencies_same_bb();
    fmt::println("\n___________________________\nOutil de Jack");
    rd.show_cfg_triskel_each_graph(good_name);

    return 0;
}
