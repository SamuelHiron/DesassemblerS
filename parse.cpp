#include <iostream> //standard input & output std::cout, stdcerr
#include <fstream> // for file stream operation, read the ELF file
#include <cstring> // for memory comparison functions (std::memcmp)
#include <cstdint> //type fixes uint64_t
#include <unordered_map>
#include <vector>

// Flags ELF Segments
const uint32_t PF_E = 1;
const uint32_t PF_W = 2;
const uint32_t PF_R = 4;


struct ElfHeader {
  unsigned char e_ident[16];
  uint16_t  e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry; // program entry
  uint64_t e_phoff; 
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct ElfSegment{//64 BITS
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};

struct ElfSymbol {
  uint32_t st_name;
  uint8_t st_info;
  uint8_t st_other;
  uint16_t st_shndx;
  uint64_t st_value;
  uint64_t st_size;
};


// Fonction pour lire l'en-tête du ELF
bool readElfHeader(std::ifstream& file, ElfHeader& header) {
  file.read(reinterpret_cast<char*>(&header), sizeof(ElfHeader));
  return file.good();
}

// Fonction pour vérifier si le fichier est un ELF
bool isElfFile(const ElfHeader& header){
  const unsigned char elfMagic[] = {0x7f, 'E', 'L', 'F'};
  return std::memcmp(header.e_ident, elfMagic, 4) == 0;
} 

int architectureAndEndianess(const ElfHeader& header){
  int response = 0;
  if (header.e_ident[4] == 1) {
    std::cout << "Architecture: 32 bits";
  } else if (header.e_ident[4] == 2){
    std::cout << "Architecture: 64 bits";
    response += 1;
  }
  if (header.e_ident[5] == 1) {
    std::cout << " and endianness: LSB." << std::endl;
    response += 2;
  } else if (header.e_ident[4] == 2){
    std::cout << " and endianness: MSB." << std::endl;
  }
  return response;
}


// Fonction pour lire les segments
bool readSegments(std::ifstream& file, const ElfHeader& header, std::vector<ElfSegment>& segments) {
  file.seekg(header.e_phoff);

  for (uint16_t i = 0; i < header.e_phnum; i++){
    ElfSegment segment;
    file.read(reinterpret_cast<char*>(&segment), sizeof(ElfSegment));

    if (!file.good()){
      return false;
    }

    segments.push_back(segment);
  }
  return true;
}

std::string readSegmentFlag(const ElfSegment& segment) {
  std::string flags;
  flags += (segment.p_flags & PF_R) ? 'R' : '.';
  flags += (segment.p_flags & PF_W) ? 'W' : '.';
  flags += (segment.p_flags & PF_E) ? 'E' : '.';
  return flags;
}

//bool loadSegmentByteMap(std::ifstream& file, const std::vector<ElfSegment>& segments, std::unordered_map<uint64_t, uint8_t>& byteMap){
//  for (const auto& segment : segments){
//    file.seekg(segment.p_offset);

//    for(uint)
//  }
//}



int main(int argc, char* argv[]){
  if(argc != 2) {
    std::cerr << "Usage: "<< argv[0]<< " <elf-file>" << std::endl;
    return 1;
  }

  std::ifstream file(argv[1], std::ios::binary);

  if(!file){
    std::cerr << "Error: Could not open file " << argv[1] << std::endl;
    return 1;
  }

  ElfHeader header;
  if(!readElfHeader(file, header)){
    std::cerr<< "Error: Could not read ELF header" << std::endl;
    return 1;
  }
  if(!isElfFile(header)){
    std::cerr << "Error: file is not an ELF file" << std::endl;
    return 1;
  }

  std::cout << "ELF file detected !" << std::endl;
  
  int architectureEndianess = architectureAndEndianess(header);
  if (architectureEndianess != 3){
    if (architectureEndianess != 2) {
      std::cerr << "Error: MSB not supported" << std::endl;
    }
    if(architectureEndianess != 1) {
      std::cerr << "Error: 32 bits not supported" << std::endl;
    }    
    return 1;
  }

  std::cout <<"Entry point: 0x" << std::hex << header.e_entry << std::endl;


  std::vector<ElfSegment> segments;
  if(!readSegments(file, header, segments)){
    std::cerr << "Error: Could not read segments" << std::endl;
    return 1;
  }

  std::cout << "Segments:" << std::endl;
  for (const auto& segment : segments) {
    std::cout << " Type: " << segment.p_type << " Offset 0x" << segment.p_offset 
      << " VirtualAddr: 0x" << segment.p_vaddr << " FileSize: 0x" << segment.p_filesz
      << " MemSize: 0x" << segment.p_memsz <<" Flags: " << readSegmentFlag(segment) << std::endl;
  }

  return 0;
}

