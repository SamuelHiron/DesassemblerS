#include <capstone/capstone.h>
#include <strings.h>
#include <unordered_map>
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

struct Position_Registre{
    size_t position;
    uint16_t registre;
};

struct Position_Value{
    size_t position;
    int64_t value; // peut etre une float
};

struct BasicBlock {
    size_t id;
    size_t start_address;
    bool end;
    std::vector<size_t> childs_id;
    std::vector<size_t> parents_id;
    std::vector<cs_insn> instructions;
    std::unordered_map<uint16_t, std::vector<Position_Registre>> unknown_regs_dependencies; 
    std::unordered_map<uint16_t, Position_Value> known_regs; 
    BasicBlock(size_t start_address)
        : id(current_id_block), start_address(start_address), instructions(), unknown_regs_dependencies(), known_regs(), end(false) {
        current_id_block++;
    }
    BasicBlock(size_t start_address, std::vector<size_t> childs_id, std::vector<size_t> parents_id)
        : id(current_id_block), start_address(start_address), instructions(), unknown_regs_dependencies(), known_regs(),childs_id(childs_id), parents_id(parents_id), end(false) {
        current_id_block++;
        
    }

    void print_BasicBlock() const {
        std::cout << "Basic Block n°" << id ; 
        std::cout << " | Enfants de :";
        for(const auto & parent_id : parents_id){
            std::cout << " "<< parent_id;
        }
        std::cout << " | Parents de :";
        for(const auto & child_id : childs_id){
            std::cout << " "<< child_id;
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

int replace_id(std::vector<size_t> &parents_id, size_t id_to_supress, size_t id_to_add){
    for(int i = 0; i< parents_id.size();i++){
        if(parents_id[i] == id_to_supress){
            parents_id[i] = id_to_add;
        }
    }
    return 0;
}



struct RecursiveDescent {
    std::unordered_map<size_t, size_t> basic_block_start_address;
    std::unordered_map<size_t, size_t> addr2block; //address already treated
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
        std::cout << "\n________________________________________________\n\n";
        std::cout << "Analyse VSA:\n";
        for(int i =0; i<blocks.size(); i++){
            std::cout << "\nBlock "<< i << " Dependencies:" << std::endl;
            print_unknown_regs_dependencies(blocks[i].unknown_regs_dependencies);
            std::cout << "Block "<< i << " Known Regs:" << std::endl;
            print_known_regs(blocks[i].known_regs);
        }
        std::cout << "\n________________________________________________\n\nFin de l'exploration" << std::endl;
        std::cout << "Nombre de blocs trouvés: " << blocks.size()<< "\n" << std::endl;
        for (const auto& block : blocks) {
            block.print_BasicBlock();  
        }
        return 0;
    }

    int print_instruction_regs_RW(const cs_insn insn){
        uint16_t regs_read[64] = {0};
        uint16_t regs_write[64] = {0} ;
        uint8_t read_count = 0;
        uint8_t write_count = 0;
        std::cout << "\nProcessing instruction: " << insn.mnemonic << " " << insn.op_str << std::endl;
        if (cs_regs_access(handle, &insn, regs_read, &read_count, regs_write, &write_count) == CS_ERR_OK) {
            if (read_count > 0) {
                std::cout << "\tRegisters read:";
                for (uint8_t i = 0; i < read_count; i++) {
                    std::cout << " " << cs_reg_name(handle, regs_read[i]);
                }
                std::cout << std::endl;
            }
    
            if (write_count > 0) {
                std::cout << "\tRegisters modified:";
                for (uint8_t i = 0; i < write_count; i++) {
                    std::string regName = cs_reg_name(handle, regs_write[i]);
                    std::cout << " " << regName;
                }
                std::cout << std::endl;
            }
        }
        return 0;
}

    int split_BasicBlock(size_t id_basic_bloc_to_split, size_t split_address, size_t index_block_parent){
        std::vector<cs_insn> debut_split_instructions;
        int i = 0;
        int j = 0;
        auto block_successor = BasicBlock{split_address, blocks[id_basic_bloc_to_split].childs_id, {index_block_parent}};  // création d'un nouveau bloc
        blocks[id_basic_bloc_to_split].known_regs.clear();
        blocks[id_basic_bloc_to_split].unknown_regs_dependencies.clear();
        // le nouveau block
        if(blocks[id_basic_bloc_to_split].id != index_block_parent){ // si il n'est pas son propre parent
            block_successor.parents_id.push_back(blocks[id_basic_bloc_to_split].id);
        }
        basic_block_start_address[split_address] = block_successor.id; // pour garder la 1ere adresse d'un bloc associée à son id
        blocks.push_back(block_successor);
        if(index_block_parent == id_basic_bloc_to_split){// si il est son propre parent
            blocks[block_successor.id].childs_id.push_back(block_successor.id);   
        }

        
        //les instructions
        while (i< blocks[id_basic_bloc_to_split].instructions.size()){
            if(blocks[id_basic_bloc_to_split].instructions[i].address < split_address){
                debut_split_instructions.push_back(blocks[id_basic_bloc_to_split].instructions[i]);
                instruction_RW_regs(blocks[id_basic_bloc_to_split].instructions[i], i, id_basic_bloc_to_split);
                j++;
            } else {
                block_successor.instructions.push_back(blocks[id_basic_bloc_to_split].instructions[i]);
                instruction_RW_regs(blocks[id_basic_bloc_to_split].instructions[i], i-j, block_successor.id);
            }
            i++;
        }

        //le block split
        blocks[id_basic_bloc_to_split].instructions = debut_split_instructions;
        for(auto id_child : blocks[id_basic_bloc_to_split].childs_id){ //on adapte les parents_id de ses enfants
            replace_id(blocks[id_child].parents_id, id_basic_bloc_to_split, block_successor.id);
        }
        blocks[id_basic_bloc_to_split].childs_id.clear();
        blocks[id_basic_bloc_to_split].childs_id.push_back(block_successor.id);
        if (id_basic_bloc_to_split != index_block_parent){
            blocks[index_block_parent].childs_id.push_back(block_successor.id);
        }


        return 0;     
    }

    //ajoute à mon vector de block un nouveau block commençant par next_address et en mettant la connexion au parent de l'id de l'enfant. Le booléen far permet de traiter si on saute à une addresse si on split un bloc
    int init_next_bb(size_t next_address, size_t index_block_parent, bool far){
        if (!basic_block_start_address.count(next_address) &&
            !addr2block.count(next_address)) {  // cas où l'adresse n'a jamais été
                                    // traitée et elle n'est pas en
                                    // début de bloc
            auto block_successor = BasicBlock{next_address};  // création d'un nouveau bloc
            basic_block_start_address[next_address] = block_successor.id; // pour garder la 1ere adresse d'un bloc associée à son id
            blocks[index_block_parent].childs_id.push_back(block_successor.id); //on ajoute l'id de l'enfant à la liste des enfants du bloc parent
            block_successor.parents_id.push_back(index_block_parent); // on ajoute l'id du parent à la liste des parents du bloc enfant
            blocks.push_back(block_successor);
        } 
        else if (basic_block_start_address.count(next_address)) {  // cas où l'adresse est
                                            // déjà le début d'un bloc
                                            // mais elle n'a pas encore
                                            // été traitée
            blocks[index_block_parent].childs_id.push_back(basic_block_start_address[next_address]);  // on ajoute l'id du
                                            // bloc existant à la
                                            // liste des successeurs
                                            // de ce bloc
            blocks[basic_block_start_address[next_address]].parents_id.push_back(index_block_parent); //sa position dans le vector est aussi son id
        } else if (far) {  // cas où l'adresse est déjà traitée
            auto id_basic_bloc_to_split = addr2block[next_address];  // Problème ici Bloc à split
            size_t split_address = next_address; //renommage pour que cela soit plus clair
            std::cout << "bloc à split est n°" << id_basic_bloc_to_split << "à l'adresse 0x" << std::hex<< split_address << std::dec <<  std::endl;
            split_BasicBlock(id_basic_bloc_to_split, split_address, index_block_parent);
        } 
        return 0;
    }

    void print_unknown_regs_dependencies(const std::unordered_map<uint16_t, std::vector<Position_Registre>>& unknown_regs_dependencies) {
        for (const auto& pair : unknown_regs_dependencies) {
            uint16_t reg = pair.first;
            const std::vector<Position_Registre>& dependances = pair.second;
            std::cout << "Registre: " << cs_reg_name(handle, reg) << "\n";
            for (const auto& dependance : dependances) {
                std::cout << "  Position_Instr: " << dependance.position << ", Registre: " << cs_reg_name(handle, dependance.registre) << "\n";
            }
        }
    }

    void print_known_regs(const std::unordered_map<uint16_t, Position_Value>& known_regs) {
        for (const auto& pair : known_regs) {
            uint16_t reg = pair.first;
            std::cout << "Registre: " << cs_reg_name(handle, reg) << "\n";
            std::cout << "  Position_Instr: " << pair.second.position << ", Value: " << pair.second.value << "\n";
        }
    }
    
    int instruction_RW_regs(const cs_insn insn, size_t position_instruction, const size_t index_block){ //split bloc à traiter
        print_instruction_regs_RW(insn);
        uint16_t regs_read[64] = {0};
        uint16_t regs_write[64] = {0};
        uint8_t read_count = 0;
        uint8_t write_count = 0;
        if (cs_regs_access(handle, &insn, regs_read, &read_count, regs_write, &write_count) == CS_ERR_OK) {
            bool no_read_unknown = true; // Si le nombre d'inconnu de read = 0
            if (write_count > 0) {
                //cas où on est pas capable de résoudre la dépendance
                for (uint8_t k = 0; k < write_count; k++){
                    for (uint8_t l = 0; l < read_count; l++){
                        if(!blocks[index_block].known_regs.count(regs_read[l])){
                            blocks[index_block].unknown_regs_dependencies[regs_write[k]].push_back({position_instruction, regs_read[l]});
                            no_read_unknown = false;
                        }
                    }
                    if(no_read_unknown){
                        print_known_regs(blocks[index_block].known_regs);
                        int64_t value = get_reg_value(); // cas où float
                        blocks[index_block].known_regs[regs_write[k]] = {position_instruction, value}; // 0 à remplacer
                        
                        if(blocks[index_block].unknown_regs_dependencies.count(regs_write[k])){
                            blocks[index_block].unknown_regs_dependencies.erase(regs_write[k]);
                        }
                    }
                }
            }
        }
        return 0;
    }   

    int64_t get_reg_value(const cs_insn insn, const size_t index_block){
        int64_t value;
        auto op = insn->detail->x86.operands[0];
        std::cout << "Détails instructions" << std::endl;
        std::string reg_base; 
        if (cs_reg_name(handle, op.mem.base)){
            reg_base = cs_reg_name(handle, op.mem.base);
            std::cout << "Base Register: " << reg_base << std::endl;
        }

        if ( cs_reg_name(handle, op.mem.index) != NULL){
            std::cout << "Index" << std::endl;
        } 
        std::cout << "Scale: " << op.mem.scale << std::endl;
        std::cout << "Displacement: " << op.mem.disp << std::endl;
        if ( cs_reg_name(handle, op.mem.segment) != NULL){
            std::cout << "Segment" << std::endl;
        }
        return value;
    }


    int explore_BasicBlock(const int index_block) {
        // std::cout << "Exploring Basic Block " << blocks[index_block].id << std::endl;
        auto current_address = blocks[index_block].start_address;
        if (addr2block.count(current_address)) {
            std::cout << "Ce block" << addr2block[current_address] << " a déjà vu cette adresse " << current_address  << std::endl; 
            blocks[index_block].end = true; // dans le cas split d'un bloc déjà vu
        }



        int i =0; //pour la position de l'instruction
        while (!blocks[index_block].end && !addr2block.count(current_address)) {  // end par défaut initialisé à false
            // pour etre sur refait pas une lecture de bloc

            addr2block[current_address] = index_block;
            std::cout << "Exploring address: 0x" << std::hex << current_address << std::dec << std::endl; //On décode 1 instruction
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

            instruction_RW_regs(insn, i, index_block);

            blocks[index_block].instructions.push_back(insn);  // on la stocke
            addr2block[current_address] =
                blocks[index_block].id;  // on note qu'on a traité cette adresse
            auto next_address =
                insn.address + insn.size;  // on prépare la prochaine adresse


            const auto& op = insn.detail->x86.operands[0];
            //if(insn.detail->x86.operands.size()>1){
            const auto& op1 = insn.detail->x86.operands[1];
            
            if (cs_insn_group(handle, &insn, CS_GRP_CALL) ||
                cs_insn_group(handle, &insn, CS_GRP_JUMP)) {
                blocks[index_block].end = true;              
                
                // 2 potentiellement nouveaux blocs à créer
                // le bloc juste après l'appel commence à next_address
                if (insn.id != X86_INS_JMP && insn.id != X86_INS_LJMP) { 
                    bool far = false;
                    init_next_bb(next_address, index_block, far); //ajoute le bb qui commence à l'adresse suivante au vector de cfg

                }

                // le bloc loin
                const auto& op = insn.detail->x86.operands[0];
                if (op.type == X86_OP_IMM) {  // cas où l'instruction contient
                                              // l'adresse de l'appel  
                        std::cout << "0x" << std::hex << op.imm << std::dec
                        << "  X86_OP_IMM" << std::endl;   
                    bool far = true;
                    init_next_bb(static_cast<size_t>(op.imm), index_block, far);                        
                } else if (op.type == X86_OP_MEM) {
                    std::cout << "0x" << std::hex << std::dec << "  X86_OP_MEM" << std::endl;
                    print_instruction_regs_RW(insn);
                } else if (op.type == X86_OP_REG) {
                    std::cout << "0x" << std::hex << std::dec << "  X86_OP_REG" << std::endl;
                }
                // std::cout << "CALL ou JUMP" << std::endl;
            } else if (cs_insn_group(handle, &insn, CS_GRP_RET) ||
                       cs_insn_group(handle, &insn, CS_GRP_INT)) {
                // std::cout << "RET ou INT" << std::endl;
                blocks[index_block].end = true;
            }
            current_address = next_address;
/* 
            // cs_free( // my use_after_free
                insn_tab,
                count); */  // manière + belle de le faire existe cf Jack's code
            i++;
        }
        

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





