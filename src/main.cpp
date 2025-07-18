#include <capstone/capstone.h>
#include <fmt/base.h>
#include <strings.h>
#include <cstddef>
#include <cstdio>
#include <cstdio>
#include <iostream>
#include <string>
#include <string_view>
#include <triskel/triskel.hpp>
#include <unordered_map>
#include <utility>
#include "LIEF/Abstract/Section.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/Abstract/Section.hpp"
#include "LIEF/ELF/Segment.hpp"
#include "LIEF/LIEF.hpp"
#include "x86.h"
#include <fmt/format.h>
#include <fmt/core.h>
#include <fstream>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/ELF.h>
#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/DebugInfo/DWARF/DWARFCompileUnit.h>
#include <llvm/DebugInfo/DWARF/DWARFDebugLine.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/raw_ostream.h>


std::unordered_map<size_t, u_int8_t>
    binary_contents;  // On en a besoin aussi dans le main
using InstructionPtr = std::shared_ptr<cs_insn>;
int block_null        = 0;

struct CSH 
{
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

struct Position_Registre 
{
    size_t position;
    uint16_t registre;
};

struct Position_Value 
{
    size_t position;
    size_t value;  // peut etre une float
};

struct BasicBlock 
{
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
        : function_start{false},
          id{generate_id_block()},
          start_address{start_address},
          end{false},
          childs_id{},
          parents_id{},
          instructions{},
          unknown_regs_dependencies{},
          known_regs{}
    {}

    BasicBlock(size_t start_address, bool function_start)
        : function_start{function_start},
          id{generate_id_block()},
          start_address{start_address},
          end{false},
          childs_id{},
          parents_id{},
          instructions{},
          unknown_regs_dependencies{},
          known_regs{} 
    {}

    BasicBlock(size_t start_address,
               std::vector<size_t> childs_id,
               std::vector<size_t> parents_id)
        : function_start{false},
          id{generate_id_block()},
          start_address{start_address},
          end{false},
          childs_id{std::move(childs_id)},
          parents_id{std::move(parents_id)},
          instructions{},
          unknown_regs_dependencies{},
          known_regs{} 
    {}

    size_t generate_id_block()
    {
        static size_t current_id_block = 0;
        return current_id_block++; // makes copy of  current_id_block, increments the real current_id_block, then returns the value in the copy
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
            fmt::println( "{:#x}: {} {}", insn->address, insn->mnemonic, insn->op_str);
        }
        if (instructions.empty()) {
            fmt::print(  "\n start_address: {0:#x}", start_address);
            fmt::print( "nombre de blocks dans le même état = ", block_null);
            ++block_null;
        }
        fmt::println("" );
    }

    void print_BasicBlock_investigate() const 
    {
        // Determine the maximum width for each column
        size_t maxAddressWidth = 10;
        size_t maxMnemonicWidth = 10;
        size_t maxOpStrWidth = 30;
        if(instructions.size()==1){
            fmt::println( "{:#0{}x}: {:<{}} {:<{}} ---------------debut/fin block\n", instructions[0]->address, maxAddressWidth, instructions[0]->mnemonic, maxMnemonicWidth, instructions[0]->op_str , maxOpStrWidth);
            return;
        }
        fmt::println( "{:#0{}x}: {:<{}} {:<{}} ---------------debut block", instructions[0]->address, maxAddressWidth, instructions[0]->mnemonic, maxMnemonicWidth, instructions[0]->op_str , maxOpStrWidth);
        for (size_t index_insn = 1; index_insn < instructions.size() - 1; ++index_insn) {
            fmt::println( "{:#0{}x}: {:<{}} {:<{}} |", instructions[index_insn]->address, maxAddressWidth, instructions[index_insn]->mnemonic, maxMnemonicWidth, instructions[index_insn]->op_str, maxOpStrWidth);
        }
        if(instructions.size()>1){
            fmt::println( "{:#0{}x}: {:<{}} {:<{}}  ---------------fin block", instructions[instructions.size()-1]->address, maxAddressWidth, instructions[instructions.size()-1]->mnemonic, maxMnemonicWidth-1, instructions[instructions.size()-1]->op_str, maxOpStrWidth);
        }
        if (instructions.empty()) {
            fmt::print(  "\n start_address: {0:#x}", start_address);
            fmt::print( "nombre de blocks dans le même état = ", block_null);
            ++block_null;
        }
        fmt::println("" );
    }

};

int replace_id_triskel(std::vector<size_t>& parents_id,
               size_t id_to_supress,
               size_t id_to_add) 
{
    for (size_t i = 0; i < parents_id.size(); ++i) 
    {
        if (parents_id[i] == id_to_supress) {
            parents_id[i] = id_to_add;
        }
    }
    return 0;
}


int fill_bitmap(std::unordered_map<size_t, size_t>& bitmap, size_t start_address, size_t size, size_t value) 
{
    for(size_t address = start_address; address< start_address + size; ++address)
    {
            bitmap[address] = value;
    }
 
    return 0;
}

struct RecursiveDescent 
{
    std::unordered_map<size_t, size_t> basic_block_start_address;
    std::unordered_map<size_t, size_t> addr2block;  // address already treated
    std::unordered_map<size_t, size_t> entrypoints;  // address already treated

    std::vector<BasicBlock> blocks;
    std::unique_ptr<LIEF::ELF::Binary> binary;

    CSH handle;

    int find_CFGs_entrypoints() {
        blocks.push_back({binary->entrypoint()});
        basic_block_start_address[binary->entrypoint()] = 1;
        // Iterate over symbols and print functions
        for (const auto& function : binary->functions()) {
            auto block = BasicBlock{function.address()};
            blocks.push_back(block);
            basic_block_start_address[function.address()] =
                block.id;
            entrypoints[function.address()]=1;
            fmt::println("function_address = {:#x}     function_size={:#x}", function.address(), function.size());
        }
        fmt::print(  "{} functions found \n",  blocks.size() - 1  );
        return 0;
    }




    void readDwarfLines(const std::string &binary_path, bool try_add_address) {
        auto binaryOrErr = llvm::object::ObjectFile::createObjectFile(binary_path);
        if (!binaryOrErr) {
            llvm::errs() << "Error opening file: " << llvm::toString(binaryOrErr.takeError()) << "\n";
            return;
        }

        llvm::object::OwningBinary<llvm::object::ObjectFile> owningBinary = std::move(*binaryOrErr);
        llvm::object::ObjectFile *obj = owningBinary.getBinary();

        auto dwarf_ctx = llvm::DWARFContext::create(*obj);

        for (const std::unique_ptr<llvm::DWARFUnit> &cu : dwarf_ctx->compile_units()) {
            if (!cu) continue;

            const llvm::DWARFDebugLine::LineTable *line_table = dwarf_ctx->getLineTableForUnit(cu.get());
            if (!line_table) continue;

            fmt::print("CU at offset {:#x} has {} files and {} lines\n",
                    cu->getOffset(),
                    line_table->Prologue.FileNames.size(),
                    line_table->Rows.size());

            for (const auto &row : line_table->Rows) {
                if (!row.IsStmt)
                    continue;

                if (row.File == 0 || row.File > line_table->Prologue.FileNames.size())
                    continue;

                const auto &file_entry = line_table->Prologue.FileNames[row.File - 1];
                auto expectedName = file_entry.Name.getAsCString();
                if (!expectedName) {
                    llvm::errs() << "Error getting filename string: " << llvm::toString(expectedName.takeError()) << "\n";
                    continue;
                }
                std::string file_name = *expectedName;
                uint64_t addr = row.Address.Address;
                if(entrypoints[addr] == 1)
                {
                    continue;
                }
                // 🔹 Ajout du basic block pour cette adresse DWARF
                if (try_add_address){
                    BasicBlock block(addr);
                    blocks.push_back(block);
                    basic_block_start_address[addr] = block.id;
                }


                fmt::print("  [DWARF] {:#x} -> {}:{}\n", 
                        addr, file_name, row.Line);
                entrypoints[addr] = 1;
            }
        }

    }


        

    int recursive_descent(std::unordered_map<size_t, size_t>& bitmap, std::string option, size_t & nb_jmp_indirect){
        size_t index_block = 0;
        while (index_block != blocks.size()) {
            explore_BasicBlock(index_block, bitmap, option, nb_jmp_indirect);
            ++index_block;
        }
        return 0;
    }

    int print_CFGs(){
        fmt::println( "\n__________________________________________\n\nFin de l'exploration");
        fmt::println( "Nombre de blocks trouvés: {}",  blocks.size());
        for (const auto& block : blocks) {
            if(block.instructions.size()!= 0)
            {
                block.print_BasicBlock();
            }
        }
        return 0;
    }

    // inputs: segments et bb on veut déterminer le code manquant, pq, et s'en prémunir
    size_t print_CFG_investigate(const std::vector<LIEF::ELF::Segment>& segments, const std::string & optionPadding)
    {
        fmt::println("_______________________________________________ \n\n investigate\nIl y a {} blocks\n", blocks.size());

        size_t total_empty_bytes = 0;
        size_t current_bytes_empty = 0;
        size_t nb_zeros_padding = 0; // pour essayer virer padding
        bool padding_potential = false;
        size_t len_all_bytes = 0;
        size_t block_last_address = blocks[0].instructions[blocks[0].instructions.size()-1]->address + blocks[0].instructions[blocks[0].instructions.size()-1]->size;
        size_t index_current_block = 0;
        size_t nb_zero_current_line = 0;
        size_t next_start_address = blocks[0].start_address;
        bool start_not_disass = true;
        fmt::println("block {} start_address {:#x}", index_current_block, blocks[index_current_block].start_address);
        for (const LIEF::ELF::Segment& segment : segments) 
        {
            if ((segment.flags() & LIEF::ELF::Segment::FLAGS::X) == LIEF::ELF::Segment::FLAGS::X) 
            {
                size_t start_unknown_address = segment.virtual_address();

                for (size_t index_segment = 0; index_segment < segment.physical_size(); ++index_segment) 
                {
                    size_t current_address = segment.virtual_address() + index_segment;

                    if (current_address == blocks[index_current_block].start_address)
                    { // on est sur du code connu
                        blocks[index_current_block].print_BasicBlock_investigate();
                        size_t block_last_address = blocks[index_current_block].instructions[blocks[index_current_block].instructions.size()-1]->address + blocks[index_current_block].instructions[blocks[index_current_block].instructions.size()-1]->size;
                        current_address = block_last_address;
                        start_not_disass = true;
                        ++index_current_block;
                        padding_potential = false;
                        
                        while(index_current_block != blocks.size() && blocks[index_current_block].instructions.size()==0)
                        {
                            ++index_current_block;
                        } 
                        if (index_current_block == blocks.size()){
                            index_current_block = 0; 
                            if(optionPadding=="ON")
                            {
                                start_unknown_address = current_address;
                                if (segment.virtual_size() + segment.virtual_address() - current_address < 20 ){
                                    padding_potential = true;
                                    nb_zeros_padding = 0;
                                } else if (segment.virtual_size() + segment.virtual_address() - current_address < 7 )
                                {                                    
                                    padding_potential = true;
                                    nb_zeros_padding = 3;
                                } else 
                                {
                                    nb_zeros_padding = 0;
                                }
                            }
                            next_start_address = segment.virtual_size() + segment.virtual_address();
                        } else {
                            next_start_address = blocks[index_current_block].start_address;
                            //On veut etre sur que ce soit peut d'addresses
                            if(optionPadding=="ON")
                            {
                                start_unknown_address = current_address;
                                if (next_start_address - current_address< 7){
                                    padding_potential = true;
                                    nb_zeros_padding = 3;
                                } else if (next_start_address - current_address < 20)
                                {
                                    padding_potential = true;
                                    nb_zeros_padding = 0;
                                } else 
                                {
                                    nb_zeros_padding = 0;
                                }
                            }
                        }
                        index_segment = block_last_address - segment.virtual_address()-1;
                        current_bytes_empty = 0;
                        //fmt::println("next_start_address - current_address = {}", next_start_address - current_address);
                    } else if(start_not_disass) {
                        fmt::println("{:#x}  <========= Start address byte not disassembled !!!", current_address);
                        // fmt::println("next_start_address {:#x}", next_start_address);
                        recover_insn_from_bytes_cs(next_start_address - current_address, current_address, 0);
                        fmt::print("{:x} ",binary_contents[current_address]);
                        nb_zero_current_line = 2;
                        start_not_disass = false;
                        ++current_bytes_empty;
                        if(binary_contents[current_address] == 0){
                            ++nb_zeros_padding; // on compte le nombre de 0
                        }
                    } else if (current_address + 1  == next_start_address) {
                        fmt::println("{:x} ",binary_contents[current_address]);
                        //fmt::println("start_unknown_address:{:#x} next_start_address:{:#x}, nb_zero_padding:{}, (start_unknown_address-next_start_address)/2 {},  padding_potential {}",start_unknown_address, next_start_address, nb_zeros_padding, (next_start_address-start_unknown_address)/2, padding_potential);
                        if(optionPadding=="ON" && ((nb_zeros_padding >= 2 && padding_potential) || (next_start_address-start_unknown_address)/2 < nb_zeros_padding))
                        {
                            fmt::print("<<<PADDING bytes not added>>>");
                        } else 
                        {
                            total_empty_bytes += current_bytes_empty;
                            fmt::print("~~~~~~~~~~~~~ unknown code ~~~~~~~~~~~~~~");
                        }
                        fmt::println("  <============= End\n");
                    } else {
                        if(binary_contents[current_address] == 0){
                            ++nb_zeros_padding; // on compte le nombre de 0
                        }
                        ++current_bytes_empty;
                        if(nb_zero_current_line %12 == 0){
                            fmt::println("{:x} ",binary_contents[current_address]);
                            nb_zero_current_line = 1;
                        } else {
                            if(nb_zero_current_line ==1 ){
                                fmt::print("{:#x} ", current_address);
                            }
                            fmt::print("{:x} ",binary_contents[current_address]);
                            ++nb_zero_current_line;
                        }
                    }
                }
                len_all_bytes += segment.virtual_size();
            }
        }
        fmt::print("\n{} {} {}", (100*(len_all_bytes- total_empty_bytes))/len_all_bytes, total_empty_bytes, len_all_bytes);
        //fmt::println("\n{} d'addresses de code non couvertes sur {} => ~ {}% octets de code non couverts", total_empty_bytes, len_all_bytes, (total_empty_bytes*100)/len_all_bits);
        return 0;
    }

    int print_dependencies_same_bb()
    {
        fmt::print("\n_______________________________________________\n\n");
        fmt::println( "Analyse VSA:\n");
        for (size_t i = 0; i < blocks.size(); ++i) {
            fmt::println("\nblock & depencies");
            blocks[i].print_BasicBlock();
            fmt::println("\nBlock {} Dependencies:", i);
            print_unknown_regs_dependencies(
                blocks[i].unknown_regs_dependencies);
            fmt::println( "\nBlock {} Known Regs:", i);
            print_known_regs(blocks[i].known_regs);
        }
        return 0;
    }

    int build_CFGs_triskel(const std::string& good_name)
    {
        int nb_graph = 0;
        int nb_trop_grand = 0;
        for(auto &block: blocks)
        {
            if((block.parents_id.size() == 0 || block.function_start) && block.instructions.size() !=0)
            { // attention block parent ou function = root
                //fmt::println("block.parents_id.size = {},  block.function_start = {}", block.parents_id.size(), block.function_start);
                //parcours des enfants pour choper tous les bb
                std::unordered_map<size_t, size_t> block_deja_vus;
                std::vector<size_t> blocks_id;
                size_t index_graph = 0;
                find_every_successors(block.id, index_graph ,blocks_id, block_deja_vus); // On obtient tous les ids des blocks enfant de block
                if(blocks_id.size() < 127){//Evite un graph trop grand
                    fmt::println("root_block address = {} & nb_graph {}", block.start_address, nb_graph);
                if(blocks_id.size() < 127){//Evite un graph trop grand
                    fmt::println("root_block address = {} & nb_graph {}", block.start_address, nb_graph);
                    auto renderer = triskel::make_svg_renderer();
                    auto builder  = triskel::make_layout_builder();
                    int num_insn  = 0;
                    // Create nodes for each block
                    //fmt::print("\nLes nodes du graphe {} sont :\n", nb_graph);
                    for(auto index_block: blocks_id){
                        num_insn = 0;
                        std::string oss; //remplacer par fmt::format
                        //fmt::print("id : {} graphid: {}\n", index_block, block_deja_vus[index_block]);
                        if(index_block == block.id){
                            oss += "Root of the Graph\n";
                        }
                        oss += fmt::format("Block ID: {}\n", index_block);
                        for (const auto& insn : blocks[index_block].instructions) {
                            oss += fmt::format("{} {:#x}: {} {}\n", num_insn, insn->address, insn->mnemonic, insn->op_str);
                            ++num_insn;
                        }
                        builder->make_node(*renderer, oss);
                     }
                    //fmt::print("\nLes arretes du graphe {} sont :\n", nb_graph);
                    for (auto index_block: blocks_id) {
                        if(block.id == index_block || !blocks[index_block].function_start){
                            for (auto child_id : blocks[index_block].childs_id) {
                                // fmt::print("ids: {} -> {} donc graph_ids ", index_block, child_id);
                                // fmt::println("{} -> {}", block_deja_vus[index_block], block_deja_vus[child_id]);
                                builder->make_edge(block_deja_vus[index_block], block_deja_vus[child_id]);
                            }
                        }
                    }
                    // fmt::println("End Graph {}\n", nb_graph);
                    std::string new_name = good_name + std::to_string(nb_graph) + ".svg";
                    auto layout = builder->build();
                    layout->render_and_save(*renderer, new_name);
                    ++nb_graph;
                } else {
                    auto renderer = triskel::make_svg_renderer();
                    auto builder  = triskel::make_layout_builder();
                    int num_insn  = 0;
                    // Create nodes for each block
                    // fmt::println("\nLes nodes du graphe {} sont :", nb_graph);
                    // for(size_t index_block=0; index_block <= block.childs_id.size(); ++index_block){
                    // for(size_t index_block=0; index_block <= block.childs_id.size(); ++index_block){
                    //     num_insn = 0;
                    std::string oss; 
                    // fmt::println("Root too Big id : {} == {} graphid: {} ", block.id, blocks_id[0], block_deja_vus[block.id]);
                    oss += "Root of the Graph Too Big \n";
                    oss+= fmt::format("nb_enfants {} | nb de noeuds {}", block.childs_id.size(), blocks_id.size());
                    // oss += fmt::format("Block ID: {}\n", block.id);//index_block);
                    for (const auto& insn : block.instructions){//index_block].instructions) {
                        oss += fmt::format("{} {:#x}: {} {}\n", num_insn, insn->address, insn->mnemonic, insn->op_str);
                        ++num_insn;
                    }
                    builder->make_node(*renderer, oss);

                    for(size_t i = 0; i< block.childs_id.size(); ++i){
                    for(size_t i = 0; i< block.childs_id.size(); ++i){
                        // fmt::print(" {} == {}  => graphid :{}  |", block.childs_id[i], blocks_id[i+1], block_deja_vus[blocks_id[i+1]]);
                        std::string oss;
                        oss += "Child root graph too big";
                        for (const auto& insn : blocks[block.childs_id[i]].instructions){//index_block].instructions) {
                            oss += fmt::format("{} {:#x}: {} {}\n", num_insn, insn->address, insn->mnemonic, insn->op_str);
                            ++num_insn;
                        }
                        builder->make_node(*renderer, oss);
                        builder->make_edge(0, i+1);
                    }
                    
                   
                    fmt::print("\nLes arretes du graphe {} sont :\n", nb_graph); 
                    // fmt::println("End Graph {}\n", nb_graph);
                    std::string new_name = good_name + std::to_string(nb_graph) + ".svg";
                    auto layout = builder->build();
                    layout->render_and_save(*renderer, new_name);
                    ++nb_graph;
                    ++nb_trop_grand;
                    fmt::println("\ngraphe pour root {} trop grand {}>=100\n Il y en a {}", block.id, blocks_id.size(), nb_trop_grand);
                }  
            }
        }
        return 0;
            }
        }
    }

    int find_every_successors(const size_t & index_block, size_t &index_graph, std::vector<size_t> &blocks_id, std::unordered_map<size_t, size_t> &block_deja_vus)
    {
        if(!block_deja_vus.contains(index_block))
        {
            blocks_id.push_back(index_block);
            if (index_block >= blocks.size()) 
            {
                fmt::println(stderr, "Erreur: index_block hors limites: {}", index_block);
                return -1;
            }
            if(!blocks[index_block].function_start) 
            {
                block_deja_vus[index_block] = index_graph;
            } else 
            {
                return 0;
            }
            ++index_graph;
        }
        if (blocks[index_block].childs_id.size()== 0)
        {
            return 0;
        }
        for(const auto child_id : blocks[index_block].childs_id)
        {
            if (child_id >= blocks.size()) 
            {
                fmt::println(stderr, "Erreur: index_block hors limites: {}", child_id);
                return -1;
            }
            if(!block_deja_vus.contains(child_id) && !blocks[child_id].function_start)
            {
                find_every_successors(child_id, index_graph, blocks_id, block_deja_vus);
            }
        }
        return 0;
    }

    int print_instruction_regs_RW(const InstructionPtr & insn) 
    {
        uint16_t regs_read[64]  = {0};
        uint16_t regs_write[64] = {0};
        uint8_t read_count      = 0;
        uint8_t write_count     = 0;
        // fmt::print( "\nProcessing instruction: {} {}", insn->mnemonic, insn->op_str  );
        if (cs_regs_access(handle, insn.get(), regs_read, &read_count,
                           regs_write, &write_count) == CS_ERR_OK) 
        {
            if (read_count > 0) 
            {
                fmt::print( "\t| Registers read : ");
                for (uint8_t i = 0; i < read_count; ++i) 
                {
                    fmt::print("{} ",cs_reg_name(handle, regs_read[i]));
                }
            }

            if (write_count > 0) 
            {
                fmt::print( " \t| Registers modified : ");
                for (uint8_t i = 0; i < write_count; ++i) 
                {
                    std::string regName = cs_reg_name(handle, regs_write[i]);
                    fmt::print( "{} ",  regName);
                }
                fmt::println("" );
            }
        }
        return 0;
    }

    int split_BasicBlock(size_t id_basic_block_to_split,
                         size_t split_address,
                         size_t index_block_parent) 
    {
        std::vector<InstructionPtr> debut_split_instructions;

        auto block_successor =
            BasicBlock{split_address,
                       blocks[id_basic_block_to_split].childs_id,
                       {index_block_parent}};  // création d'un nouveau bloc
        blocks[id_basic_block_to_split].known_regs.clear();
        blocks[id_basic_block_to_split].unknown_regs_dependencies.clear();
        // le nouveau block
        if (blocks[id_basic_block_to_split].id !=
            index_block_parent) {  // si il n'est pas son propre parent
            block_successor.parents_id.push_back(
                blocks[id_basic_block_to_split].id);
        }
        basic_block_start_address[split_address] =
            block_successor
                .id;  // pour garder la 1ere adresse d'un block associée à son id
        blocks.push_back(block_successor);
        if (index_block_parent ==
            id_basic_block_to_split) {  // si il est son propre parent
            blocks[block_successor.id].childs_id.push_back(block_successor.id);
        }

        size_t i = 0;
        size_t j = 0;
        // les instructions
        while (i < blocks[id_basic_block_to_split].instructions.size()) 
        {
            if (blocks[id_basic_block_to_split].instructions[i]->address <
                split_address) 
            {
                debut_split_instructions.push_back(
                    blocks[id_basic_block_to_split].instructions[i]);
                instruction_RW_regs(
                    blocks[id_basic_block_to_split].instructions[i], i,
                    id_basic_block_to_split);
                ++j;
            } else 
            {
                blocks[block_successor.id].instructions.push_back(
                    blocks[id_basic_block_to_split].instructions[i]);
                instruction_RW_regs(
                    blocks[id_basic_block_to_split].instructions[i], i - j,
                    block_successor.id);
            }
            ++i;
        }

        // le block split
        blocks[id_basic_block_to_split].instructions = debut_split_instructions;
        // for (auto insn : debut_split_instructions) {
        //     fmt::print( "{:#x} {} {}", insn->address, insn->mnemonic, insn->op_str);
        // }
        for (auto id_child :
             blocks[id_basic_block_to_split]
                 .childs_id) {  // on adapte les parents_id de ses enfants
            replace_id_triskel(blocks[id_child].parents_id, id_basic_block_to_split,
                       block_successor.id);
        }
        blocks[id_basic_block_to_split].childs_id.clear();
        blocks[id_basic_block_to_split].childs_id.push_back(block_successor.id);
        if (id_basic_block_to_split != index_block_parent) {
            blocks[index_block_parent].childs_id.push_back(block_successor.id);
        }
        return 0;
    }

    // ajoute à mon vector de block un nouveau block commençant par next_address
    // et en mettant la connexion au parent de l'id de l'enfant. Le booléen far
    // permet de traiter si on saute à une addresse si on split un bloc
    int init_next_bb(size_t next_address, size_t index_block_parent, bool far, bool function_start) 
    {
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
                                      // des enfants du block parent
            block_successor.parents_id.push_back(
                index_block_parent);  // on ajoute l'id du parent à la liste des
                                      // parents du block enfant
            blocks.push_back(block_successor);
        } else if (basic_block_start_address.contains(
                       next_address)) {  // cas où l'adresse est
                                         // déjà le début d'un bloc
                                         // mais elle n'a pas encore
                                         // été traitée
            blocks[index_block_parent].childs_id.push_back(
                basic_block_start_address[next_address]);  // on ajoute l'id du
                                                           // block existant à la
                                                           // liste des
                                                           // successeurs de ce
                                                           // bloc
            blocks[basic_block_start_address[next_address]]
                .parents_id.push_back(
                    index_block_parent);  // sa position dans le vector est
                                          // aussi son id
        } else if (far) {  // cas où l'adresse est déjà traitée
            auto id_basic_block_to_split =
                addr2block[next_address];  // Problème ici block à split
            size_t split_address =
                next_address;  // renommage pour que cela soit plus clair
            //fmt::print( "block à split est n° {0:d} à l'adresse {0:#x}", id_basic_block_to_split, split_address);
            split_BasicBlock(id_basic_block_to_split, split_address, index_block_parent); // Interogation call ?
        }
        return 0;
    }

    void print_unknown_regs_dependencies(
        const std::unordered_map<uint16_t, std::vector<Position_Registre>>&
            unknown_regs_dependencies) 
    {
        fmt::println("Dependencies:");
        for (const auto& pair : unknown_regs_dependencies) {
            uint16_t reg                                      = pair.first;
            const std::vector<Position_Registre>& dependances = pair.second;
            fmt::println( " Registre: {}", cs_reg_name(handle, reg));
            for (const auto& dependance : dependances) {
                fmt::println("  Position_Instr: {}, Registre: {}", dependance.position, cs_reg_name(handle, dependance.registre));
            }
        }
    }

    void print_known_regs(
        const std::unordered_map<size_t, Position_Value>& known_regs) 
        {
        fmt::println("Known regs:");
        for (const auto& pair : known_regs) {
            uint16_t reg = pair.first;
            fmt::println(" Registre: {}",  cs_reg_name(handle, reg));
            fmt::println( "  Position_Instr: {}, Value: {}",  pair.second.position, pair.second.value);
        }
    }

    int instruction_RW_regs(const InstructionPtr& insn,
                            size_t position_instruction,
                            const size_t index_block) 
    {  // split block à traiter
        uint16_t regs_read[64]  = {0};
        uint16_t regs_write[64] = {0};
        uint8_t read_count      = 0;
        uint8_t write_count     = 0;            
        //print_instruction_regs_RW(insn);
        if (cs_regs_access(handle, insn.get(), regs_read, &read_count,
                           regs_write, &write_count) == CS_ERR_OK) {
            bool no_read_unknown = true;  // Si le nombre d'inconnu de read = 0
            if (write_count > 0) {
                // on voit si on est  capable de résoudre la dépendance
                for (uint8_t k = 0; k < write_count; ++k) {
                    for (uint8_t l = 0; l < read_count; ++l) {
                        if (!blocks[index_block].known_regs.contains(regs_read[l])) {
                            blocks[index_block]
                                .unknown_regs_dependencies[regs_write[k]]
                                .push_back({position_instruction, regs_read[l]});
                            blocks[index_block].known_regs.erase(regs_write[k]); // on supprime le fait qu'on connaissait la valeur
                            no_read_unknown = false;
                        }
                    }
                    if (no_read_unknown) { // si on est capable on update
                        size_t value = x86_get_reg_value(insn, index_block, position_instruction,regs_write[k]); // cas où float et pas déterminable avec instruction
                        if (blocks[index_block].unknown_regs_dependencies.contains(regs_write[k])) {
                            blocks[index_block].unknown_regs_dependencies.erase(regs_write[k]);
                        }
                    }
                }
            }
        }
        return 0;
    }



    size_t x86_get_reg_value(const InstructionPtr &insn, const size_t index_block, size_t position_instruction, size_t regs_write_value)
    { // A traiter
        size_t value = 0;
        //fmt::println("Analyse Instruction mem value");
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
        blocks[index_block].known_regs[regs_write_value] = {position_instruction, value};
        //fmt::println("\n");
        return value;
    }

    // 0 to get as much instruction to decode as possible
    std::shared_ptr<cs_insn> recover_insn_from_bytes_cs(const size_t& len_to_disassemble, size_t current_address, const size_t& nb_instr_to_decode)
    {
        std::vector<uint8_t> bytes(len_to_disassemble);
        for (size_t i = 0; i < len_to_disassemble; ++i) {
            bytes[i] = binary_contents[current_address + i];
        }
        cs_insn* raw_pointer;
        size_t count = cs_disasm(handle, bytes.data(), bytes.size(),
                                 current_address, nb_instr_to_decode, &raw_pointer);
        std::shared_ptr<cs_insn> insn{};
        if(nb_instr_to_decode == 1){ // cas recursive descent
            assert(count == 1);  // On s'occupe d'une instruction à la fois et
                                 // ça c'est bien passé
                                 // 
            insn = std::shared_ptr<cs_insn>{raw_pointer, [=](cs_insn* insn) { cs_free(insn, nb_instr_to_decode); }};
        } 
        else { // cas linear sweep on a pas besoin de l'instruction après
            if (count > 0) {
                size_t j;
                for (j = 0; j < count; ++j) {
                    fmt::println(" {:#x}, {}, {}", raw_pointer[j].address, raw_pointer[j].mnemonic,
                            raw_pointer[j].op_str);
                }
                cs_free(raw_pointer, count);
            } else{
                fmt::println("ERROR: Failed to disassemble given code!\n");
            }
        }
        

        
        return insn;
    }


    int explore_BasicBlock(const size_t index_block, std::unordered_map<size_t, size_t> &bitmap, std::string optionMOV, size_t& nb_jmp_indirect) 
    {
        auto current_address = blocks[index_block].start_address;
        if (addr2block.contains(current_address)) {
            //fmt::print( "Ce block {} a déjà vu cette addresse {}", addr2block[current_address],  current_address);
            blocks[index_block].end = true;  // dans le cas split d'un block déjà vu
            // On pourrait changer les indices de tous les suivants en faisant -1 et sur tous les précédents en faisant enfants et ou parents id -1
        }

        int position_instruction = 0;                          // pour la position de l'instruction & ne pas aller trop loin je pourrai mettre zone RX
        while (!blocks[index_block].end && position_instruction<200) {  // end par défaut initialisé à false, position_instruction pour éviter le crash
            // pour etre sur refait pas une lecture de bloc
            
            addr2block[current_address] = index_block;
            // fmt::println( "Exploring address: {0:#x}",  current_address);  // On décode 1 instruction
                        
            // On chope l'instruction, elle fait au max 16 octets, on fait 1 instruction à la fois
            auto insn = recover_insn_from_bytes_cs(16, current_address, 1);

            // On update les dépendances
            instruction_RW_regs(insn, position_instruction, index_block);
            //print_unknown_regs_dependencies(blocks[index_block].unknown_regs_dependencies);
            //print_known_regs(blocks[index_block].known_regs);

            blocks[index_block].instructions.push_back(insn);  // on la stocke
            addr2block[current_address] = blocks[index_block].id;  // on note qu'on a traité cette adresse
            auto next_address = insn->address + insn->size;  // on prépare la prochaine adresse
            fill_bitmap(bitmap, insn->address, insn->size, 1); // On ajoute à l'adresse de l'instruction

            if (cs_insn_group(handle, insn.get(), CS_GRP_CALL) ||
                cs_insn_group(handle, insn.get(), CS_GRP_JUMP)) {
                bool function_start = false;
                bool mandatory_jump = true;
                blocks[index_block].end = true;
                //supprimer tous les jmp par contre prendre en compte tout ce qui est jmp conditionnel jz...
                if (insn->id != X86_INS_JMP && insn->id != X86_INS_LJMP) { 
                    bool far = false;
                    mandatory_jump = false;
                    init_next_bb(next_address, index_block,
                                 far, function_start);  // ajoute le bb qui commence à l'adresse
                                        // suivante au vector de cfg
                }

                // le block loin
                const auto& op0 = insn->detail->x86.operands[0];
                if (op0.type == X86_OP_IMM) {  // cas où l'instruction contient
                                              // l'adresse de l'appel
                                              // init_next_bb(static_cast<size_t>(op0.imm),
                                              // index_block, far);

                    //fmt::print( "{0:#x} X86_OP_IMM", op0.imm);
                    //fmt::print( "{0:#x} X86_OP_IMM", op0.imm);
                    bool far = true;
                    if (cs_insn_group(handle, insn.get(), CS_GRP_CALL)) {
                        function_start = true;
                    }
                    if(next_address != static_cast<size_t>(op0.imm) || mandatory_jump){
                        init_next_bb(static_cast<size_t>(op0.imm), index_block, far, function_start);
                    }

                } else if (op0.type == X86_OP_MEM && optionMOV == "ON") {
                    //print_known_regs(blocks[index_block].known_regs);
                    //print_x86_op(op0);
                    auto op1 = insn->detail->x86.operands[1];
                    //print_x86_op(op1);
                    size_t jmp_address = x86_find_block_address_op(op0, index_block);
                    //fmt::println("jump address 0x{:x}", jmp_address);
                    bool far = true;
                    if (cs_insn_group(handle, insn.get(), CS_GRP_CALL)) {
                        function_start = true;
                    }
                    if(op1.type == X86_OP_INVALID && jmp_address != 0 && (next_address != jmp_address || mandatory_jump) ){
                        init_next_bb(jmp_address, index_block, far, function_start);
                    }else {
                        //fmt::println("X86_OP_MEM");
                        ++nb_jmp_indirect;
                        //fmt::println("#jmp_indirect= {}", nb_jmp_indirect);
                    }
                } else if (op0.type == X86_OP_MEM) {// l'optionMOV est désactivé
                    //fmt::println("X86_OP_MEM");
                    ++nb_jmp_indirect;
                    //fmt::println("#jmp_indirect= {}", nb_jmp_indirect);
                } else if (op0.type == X86_OP_REG) {
                    //fmt::print( "  X86_OP_REG");
                    ++nb_jmp_indirect;
                    //fmt::println("#jmp_indirect= {}", nb_jmp_indirect);
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
            ++position_instruction;
        }

        return 0;
    }


    void print_x86_op(const cs_x86_op op)
    {
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

    size_t x86_find_block_address_op(const cs_x86_op op, size_t index_block)
    {
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

    size_t enrich_by_fuzz(const std::string& good_name)
    {
        fmt::println("good_name = {}", good_name);
        auto addresses_file = "./addresses/" + good_name+".addresses";
        std::ifstream file(addresses_file);

        if(!file.is_open())
        {
            fmt::println("No fuzzing file available");
            return 1;
        }
        int nb_bb_en_plus_grace_fuzz = 0;
        std::string address_line; //one address by line
        while(std::getline(file, address_line))
        {
            size_t address = std::stoul(address_line, nullptr, 16); // Assuming the address is in hexadecimal format
            if (!addr2block.contains(address)) 
            {
                auto block = BasicBlock{address};
                blocks.push_back(block);
                basic_block_start_address[address] =
                block.id;
                ++nb_bb_en_plus_grace_fuzz;
            }
        }
        fmt::println("Le fuzzing a permis d'avoir {} bbs en +", nb_bb_en_plus_grace_fuzz);
        return 0;
    }



};

static auto name_file_output(const int &argc, char ** &argv) -> std::string
{
    std::string input_path = argv[1];  // Chemin du fichier donné en argument
    size_t found = input_path.find_last_of("/\\");
    std::string output_filename;
    fmt::println("comparaison importante = {}, {}", argv[3], input_path);
    if (argc == 4 && std::strcmp(argv[2], "asm") == 0){
        output_filename = "./out_cfg/asm/" + input_path.substr(found + 1) + "_"; 
    } else if(argc == 4 && std::strcmp(argv[2], "C") == 0){
        output_filename = "./out_cfg/C/" + input_path.substr(found + 1)+"_"; 
    } else if(argc == 4 && std::strcmp(argv[2], "Cpp") == 0){
        output_filename = "./out_cfg/Cpp/" + input_path.substr(found + 1)+"_"; 
    } else if(argc == 4 && std::strcmp(argv[2], "Go") == 0){
        output_filename = "./out_cfg/Go/" + input_path.substr(found + 1)+"_"; 
    } else if(argc == 4 && std::strcmp(argv[2], "Rust") == 0){
        output_filename = "./out_cfg/Rust/" + input_path.substr(found + 1)+"_"; 
    }else if(argc == 4 && std::strcmp(argv[2], "distro") == 0){
        output_filename = "./out_cfg/distro/" + input_path.substr(found + 1)+"_"; 
    } else if(argc == 4 && std::strcmp(argv[2], "binutils") == 0){
        output_filename = "./out_cfg/binutils/" + input_path.substr(found + 1)+"_"; 
    } else {
        output_filename = "./out_cfg/test/out"; 
    }
    // 🔹 Récupérer juste le nom du fichier sans extension

    // 🔹 Définir le chemin de sortie (dans le même dossier ou un autre dossier)
    return output_filename;
}

bool compare_address_bb(const BasicBlock &block_a, const BasicBlock &block_b)
{
    return block_a.start_address < block_b.start_address;
}

int main(int argc, char** argv) 
{
    if (argc < 6) {
        fmt::println(stderr,"Usage: {} <binary> asm|C|Cpp|Go|Rust|distro|nothing <1_optionMOV:ON|OFF> <2_optionPadding<ON|OFF> <3_optionHelpFuzzing<ON|OFF>", argv[0]);
        return 1;
    }

    fmt::println( "binary:{}  ,  optionMOV:{}   ,   optionPad:{}, optionAideFuzzing:{}", argv[1], argv[3], argv[4], argv[5]);

    std::string good_name = name_file_output(argc, argv);
    // Parse the ELF binary
    std::unique_ptr<LIEF::ELF::Binary> binary =
        LIEF::ELF::Parser::parse(argv[1]);

    if (!binary) {
        fmt::println(stderr, "Failed to parse binary {}!", good_name);
        return 1;
    }
    const auto entrypoint = binary->entrypoint();
    fmt::println( "Entry Point: {0:#x}", entrypoint);
    std::unordered_map<size_t, size_t> bitmap; //to see if the analysis left out some bits
    const auto segments = binary->segments();

        // Create a vector of Segment pointers
    std::vector<LIEF::ELF::Segment> segmentPtrs;
    for (const auto & segment : segments) {
        segmentPtrs.push_back(segment);
    }

    // Chargement du Binaire
    for (const LIEF::ELF::Segment& segment : segments) 
    {
        if ((segment.flags() & LIEF::ELF::Segment::FLAGS::X) == LIEF::ELF::Segment::FLAGS::X) 
        {
            for (size_t i = 0; i < segment.physical_size(); ++i) {
                binary_contents[segment.virtual_address() + i] =
                    segment.content()[i];
            }
            fmt::println("Code Segment : start address={:#x}, end address={:#x}", segment.virtual_address(), segment.virtual_address() + segment.virtual_size());
            fill_bitmap(bitmap, segment.virtual_address(), segment.virtual_size(), 0);
        }
    }
    
    // Print binary type and entry point
    RecursiveDescent rd;
    rd.binary = std::move(binary);
    const std::string optionMov = argv[3];
    const std::string optionPadding = argv[4];
    rd.find_CFGs_entrypoints();
    rd.readDwarfLines(argv[1], false);
    size_t nb_jmp_indirect = 0;
    rd.recursive_descent(bitmap, optionMov, nb_jmp_indirect);
    //rd.print_CFGs();
    
    const std::string optionHelpFuzzing = argv[5];
    if(optionHelpFuzzing == "ON")
    {
        std::string input_path = argv[1];  // Chemin du fichier donné en argument
        size_t found = input_path.find_last_of("/\\");
        auto binary_name = input_path.substr(found + 1);
        rd.enrich_by_fuzz(binary_name);
        rd.recursive_descent(bitmap, optionMov, nb_jmp_indirect);
    }
    
    //rd.print_dependencies_same_bb();
    // fmt::println("\n___________________________\nOutil de Jack");
    //rd.build_CFGs_triskel(good_name);
    
    fmt::println("\n-------------------------------------\nBitmap Analysis");
    std::sort(rd.blocks.begin(), rd.blocks.end(), compare_address_bb);

    rd.print_CFG_investigate(segmentPtrs, optionPadding); //stats sur le CFG 
    fmt::println(" {}",nb_jmp_indirect);
    return 0;
}
