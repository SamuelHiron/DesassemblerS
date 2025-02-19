use object::elf;
use object::read::elf::{FileHeader, Sym};
use std::error::Error;
use std::fs;

/// Print segments
fn print_segment(segment : &elf::ProgramHeader64<object::Endianness>, endian: object::Endianness){
    
    println!("Type: {:?}, Offset 0x{:08x} VirtualAddr: 0x{:08x} FileSize: 0x{:08x} MemSize: 0x{:08x} Flags: {:?}", segment.p_type, segment.p_offset.get(endian), segment.p_vaddr.get(endian), segment.p_filesz.get(endian), segment.p_memsz.get(endian), segment.p_flags);
}




/// Reads a file and displays the name of each symbol.
fn main() -> Result<(), Box<dyn Error>> {
    // ../binaries/easiest_program_to_disassemble
    // ../binaries/easiest_program_to_disassemble_stripped
   let data = fs::read("../binaries/easiest_program_to_disassemble")?;
   let elf = elf::FileHeader64::<object::Endianness>::parse(&*data)?;
   let endian = elf.endian()?;
   println!("Entry point: 0x{:08x}", elf.e_entry(endian));
   let segments = elf.program_headers(endian, &*data)?;
   for segment in segments.iter() {
       print_segment(segment, endian);
   }
   let sections = elf.sections(endian, &*data)?;
   let symbols = sections.symbols(endian, &*data, elf::SHT_DYNSYM)?;
   for symbol in symbols.iter() {
       let name = symbol.name(endian, symbols.strings())?;
       println!("{}", String::from_utf8_lossy(name));
   }
   Ok(())
}

