#include <capstone/capstone.h>
#include <fmt/base.h>
#include <strings.h>
#include <iostream>
#include <sstream>
#include <triskel/triskel.hpp>
#include <unordered_map>
#include <utility>
#include "LIEF/LIEF.hpp"

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
    int64_t value;  // peut etre une float
};

struct BasicBlock {
    size_t id;
    size_t start_address;
    bool end;
    std::vector<size_t> childs_id;
    std::vector<size_t> parents_id;
    std::vector<InstructionPtr> instructions;
    std::unordered_map<uint16_t, std::vector<Position_Registre>>
        unknown_regs_dependencies;
    std::unordered_map<uint16_t, Position_Value> known_regs;
    BasicBlock(size_t start_address)
        : id(current_id_block),
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
            std::cout << "0x" << std::hex <<insn->address << std::dec << ": "<< insn->mnemonic << " " << insn->op_str << std::endl;
            // fmt::print( "{0:#x}: {} {}", insn->address, insn->mnemonic, insn->op_str);
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

    int init_cfg() {
        blocks.push_back({binary->entrypoint()});
        basic_block_start_address[binary->entrypoint()] = 1;

        // Iterate over symbols and print functions
        for (const auto& function : binary->functions()) {
            // fmt::print( "  "  function.name()  " address: 0x" 
            // {0:#x} function.address()    );//
            // {0:#x}and  are used to switch between hex and decimal
            if (function.name()[0] != '_' && function.name() != "frame_dummy" &&
                function.name() != "register_tm_clones" &&
                function.name() != "deregister_tm_clones") {
                // std::cout "Adding function to queue " function.name() 
                // );
                blocks.push_back({function.address()});
                basic_block_start_address[function.address()] =
                    current_id_block - 1;
            }
        }
        fmt::print(  "{} functions found \n",  blocks.size() - 1  );
        int index_block = 0;
        while (index_block != blocks.size()) {
            explore_BasicBlock(index_block);
            index_block++;
        }
        fmt::print("\n_______________________________________________\n\n");
        fmt::print( "Analyse VSA:\n");
        for (int i = 0; i < blocks.size(); i++) {
            fmt::print("\nBlock {} Dependencies:", i);
            print_unknown_regs_dependencies(
                blocks[i].unknown_regs_dependencies);
            fmt::print( "Block {} Known Regs:", i);
            print_known_regs(blocks[i].known_regs);
        }
        fmt::print( "\n________________________________________________"
                     "\n\nFin de l'exploration");
        fmt::println( "Nombre de blocs trouvés: {}",  blocks.size());
        for (const auto& block : blocks) {
            block.print_BasicBlock();
        }
        return 0;
    }

    int show_cfg_triskel(std::string good_name) {
        auto renderer = triskel::make_svg_renderer();
        auto builder  = triskel::make_layout_builder();
        int num_insn  = 0;

        std::ostringstream oss;
        // Create nodes for each block
        for (auto block : blocks) {
            oss << "Block ID: " <<  block.id << "\n";
            for (const auto& insn : block.instructions) {
                oss << num_insn << " 0x"<< std::hex << insn->address << std::dec<< ": " <<insn->mnemonic << " "<< insn->op_str << std::endl;
                num_insn++;
            }
            builder->make_node(*renderer, oss.str());
            oss.str("");  // cleans the content
            oss.clear();  // cleans any flag
            num_insn = 0;
        }
        // Create nodes for each block
        // size_t blocks_index = 0;
        // while(blocks_index<blocks.size()){
        //     oss << "Block ID: " <<  blocks[blocks_index].id << "\n";
        //     for (const auto& insn : blocks[blocks_index].instructions) {
        //         oss << num_insn << " 0x"<< std::hex << insn->address << std::dec<< ": " <<insn->mnemonic << " "<< insn->op_str << std::endl;
        //         num_insn++;
        //     }
        //     builder->make_node(*renderer, oss.str());
        //     oss.str("");  // cleans the content
        //     oss.clear();  // cleans any flag
        //     num_insn = 0;
        // }
            
        // Create edges for each node
        for (auto block : blocks) {
            for (auto child_id : block.childs_id) {
                builder->make_edge(block.id, child_id);
            }
        }
        auto layout = builder->build();
        layout->render_and_save(*renderer, good_name);
        return 1;
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
                fmt::print( "\tRegisters read:");
                for (uint8_t i = 0; i < read_count; i++) {
                    fmt::print("{}",cs_reg_name(handle, regs_read[i]));
                }
                fmt::println("" );
            }

            if (write_count > 0) {
                fmt::print( "\tRegisters modified:");
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
    int init_next_bb(size_t next_address, size_t index_block_parent, bool far) {
        if (!basic_block_start_address.count(next_address) &&
            !addr2block.count(
                next_address)) {  // cas où l'adresse n'a jamais été
                                  // traitée et elle n'est pas en
                                  // début de bloc
            auto block_successor =
                BasicBlock{next_address};  // création d'un nouveau bloc
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
        } else if (basic_block_start_address.count(
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
            split_BasicBlock(id_basic_bloc_to_split, split_address, index_block_parent);
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
        const std::unordered_map<uint16_t, Position_Value>& known_regs) {
        for (const auto& pair : known_regs) {
            uint16_t reg = pair.first;
            fmt::println("Registre: {}",  cs_reg_name(handle, reg));
            fmt::println( "  Position_Instr: {}, Value: {}",  pair.second.position, pair.second.value);
        }
    }

    int instruction_RW_regs(const InstructionPtr insn,
                            size_t position_instruction,
                            const size_t index_block) {  // split bloc à traiter
        print_instruction_regs_RW(insn);
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
                        if (!blocks[index_block].known_regs.count(
                                regs_read[l])) {
                            blocks[index_block]
                                .unknown_regs_dependencies[regs_write[k]]
                                .push_back(
                                    {position_instruction, regs_read[l]});
                            no_read_unknown = false;
                        }
                    }
                    if (no_read_unknown) {
                        print_known_regs(blocks[index_block].known_regs);
                        // int64_t value = get_reg_value(); // cas où float
                        blocks[index_block].known_regs[regs_write[k]] = {
                            position_instruction, 0};  // value à remplacer

                        if (blocks[index_block].unknown_regs_dependencies.count(
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

    // int64_t get_reg_value(const InstructionPtr insn, const size_t
    // index_block){ // A traiter
    //     int64_t value;
    //     auto op = insn->detail->x86.operands[0];
    //     fmt::print( "Détails instructions"  );
    //     std::string reg_base;
    //     if (cs_reg_name(handle, op.mem.base)){
    //         reg_base = cs_reg_name(handle, op.mem.base);
    //         fmt::print( "Base Register: "  reg_base  );
    //     }

    //     if ( cs_reg_name(handle, op.mem.index) != NULL){
    //         fmt::print( "Index"  );
    //     }
    //     fmt::print( "Scale: "  op.mem.scale  );
    //     fmt::print( "Displacement: "  op.mem.disp  );
    //     if ( cs_reg_name(handle, op.mem.segment) != NULL){
    //         fmt::print( "Segment"  );
    //     }
    //     return value;
    // }

    int explore_BasicBlock(const int index_block) {
        // fmt::print( "Exploring Basic Block "  blocks[index_block].id 
        // );
        auto current_address = blocks[index_block].start_address;
        if (addr2block.count(current_address)) {
            fmt::print( "Ce block {} a déjà vu cette addresse {}", addr2block[current_address],  current_address);
            blocks[index_block].end = true;  // dans le cas split d'un bloc déjà vu
        }

        int i = 0;                          // pour la position de l'instruction
        while (!blocks[index_block].end) {  // end par défaut initialisé à false
            // pour etre sur refait pas une lecture de bloc

            addr2block[current_address] = index_block;
            fmt::print( "Exploring address: {0:#x}",  current_address);  // On décode 1 instruction
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

            instruction_RW_regs(insn, i, index_block);

            blocks[index_block].instructions.push_back(insn);  // on la stocke
            addr2block[current_address] =
                blocks[index_block].id;  // on note qu'on a traité cette adresse
            auto next_address =
                insn->address + insn->size;  // on prépare la prochaine adresse

            const auto& op = insn->detail->x86.operands[0];
            if (cs_insn_group(handle, insn.get(), CS_GRP_CALL) ||
                cs_insn_group(handle, insn.get(), CS_GRP_JUMP)) {
                blocks[index_block].end = true;

                // 2 potentiellement nouveaux blocs à créer
                // le bloc juste après l'appel commence à next_address
                if (insn->id != X86_INS_JMP && insn->id != X86_INS_LJMP) {
                    bool far = false;
                    init_next_bb(next_address, index_block,
                                 far);  // ajoute le bb qui commence à l'adresse
                                        // suivante au vector de cfg
                }

                // le bloc loin
                const auto& op = insn->detail->x86.operands[0];
                if (op.type == X86_OP_IMM) {  // cas où l'instruction contient
                                              // l'adresse de l'appel
                                              // init_next_bb(static_cast<size_t>(op.imm),
                                              // index_block, far);

                    fmt::print( "{0:#x} X86_OP_IMM", op.imm);
                    bool far = true;
                    init_next_bb(static_cast<size_t>(op.imm), index_block, far);

                } else if (op.type == X86_OP_MEM) {
                    fmt::print( "X86_OP_MEM");
                    print_instruction_regs_RW(insn);
                } else if (op.type == X86_OP_REG) {
                    fmt::print( "  X86_OP_REG");
                }
                // fmt::print( "CALL ou JUMP"  );
            } else if (cs_insn_group(handle, insn.get(), CS_GRP_RET) ||
                       cs_insn_group(handle, insn.get(), CS_GRP_INT)) {
                // fmt::print( "RET ou INT"  );
                blocks[index_block].end = true;
            }
            current_address = next_address;
            if (addr2block.count(current_address)) {
                blocks[index_block].childs_id.push_back(
                    addr2block[current_address]);
                blocks[addr2block[current_address]].parents_id.push_back(
                    index_block);
                break;
            }
            i++;
        }

        return 0;
    }
};

static auto find_file_name(int argc, char ** argv) -> std::string{
    std::string input_path = argv[1];  // Chemin du fichier donné en argument
    size_t found = input_path.find_last_of("/\\");
    std::string output_filename;
    if (argc == 3){
        output_filename = "./out_cfg/" + input_path.substr(found + 1) + ".svg"; 
    } else {
        output_filename = "./out_cfg/out.svg"; 
    }
    // 🔹 Récupérer juste le nom du fichier sans extension

    // 🔹 Définir le chemin de sortie (dans le même dossier ou un autre dossier)
    return output_filename;
}

int main(int argc, char** argv) {
    if (argc < 2) {

        fmt::print(stderr,"Usage: {} <binary> ?<arg to get a name>", argv[0]);
        return 1;
    }

    std::string good_name = find_file_name(argc, argv);
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
    rd.init_cfg();
    rd.show_cfg_triskel(good_name);

    return 0;
}
