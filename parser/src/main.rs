
#![allow(clippy::needless_return)] // Pour éviter les warnings de return
use std::env; // to use args
use std::fs; //to use filesystem
use std::process; // Pour quitter si erreur
use object::elf;
use object::read::elf::{FileHeader, Sym};
use std::error::Error;

/// Print segments
fn print_segment(segment : &elf::ProgramHeader64<object::Endianness>, endian: object::Endianness, entry_point: u64) {




    let flags = segment.p_flags.get(endian);
    let r = if flags & 0x4!= 0 {'R'} else {'-'};
    let w = if flags & 0x2!= 0 {'W'} else {'-'};
    let x = if flags & 0x1!= 0 {'E'} else {'-'};
    let mut printable_flags = format!("{}{}{}", r, w, x);
    if  segment.p_vaddr.get(endian)<= entry_point && segment.p_filesz.get(endian) +segment.p_vaddr.get(endian) > entry_point {
        println!("\n Segment containing entry point: 0x{:08x}", entry_point);
        printable_flags.push( '\n');
    }

    let type_segment = segment.p_type.get(endian);
    match type_segment {
        0 => print!("NULL          "),
        1 => print!("LOAD          "),
        2 => print!("DYNAMIC       "),
        3 => print!("INTERP        "),
        4 => print!("NOTE          "),
        5 => print!("SHLIB         "),
        6 => print!("PHDR          "),
        0x6474e550 => print!("GNU_EH_FRAME  "),
        0x6474e551 => print!("GNU_STACK     "),
        0x6474e552 => print!("GNU_RELRO     "),
        0x6474e553 => print!("GNU_PROPERTY  "),
        _ => print!("Unknown"),
        
    }


    println!("Offset 0x{:08x} VirtualAddr: 0x{:08x} FileSize: 0x{:08x} MemSize: 0x{:08x} Flags: {}", segment.p_offset.get(endian), segment.p_vaddr.get(endian), segment.p_filesz.get(endian), segment.p_memsz.get(endian), printable_flags);

}




/// Reads a file and displays the name of each symbol.
fn main() -> Result<(), Box<dyn Error>> {
    // ../binaries/easiest_program_to_disassemble
    // ../binaries/easiest_program_to_disassemble_stripped
   let args: Vec<String> = env::args().collect();
   
   let mut content = fs::read("../binaries/easiest_program_to_disassemble")?;
   if args.len() == 2 {
       content = fs::read(&args[1])?;
   }
   let elf = elf::FileHeader64::<object::Endianness>::parse(&*content)?;
   let endian = elf.endian()?;
   let magic = elf.e_ident().magic;
   if ([0x7f, b'E', b'L', b'F'] != magic){
    eprintln!("Not an ELF file");
    std::process::exit(1);
   }
   let arch = elf.e_ident().class;
   let data = elf.e_ident().data;
   match arch {
       1 => print!(":Architecture 32 bits "),
       2 => print!("Architecture 64 bits "),
       _ => print!("Architecture Unknown ")
   }
   match data {
       1 => println!("and Little endian"),
       2 => println!("and Big endian"),
       _ => println!("Endianness Unknown")
   }
   println!("ELF Header:");
   println!("  Magic:   7f == {:02x} {}{}{}", magic[0], magic[1] as char, magic[2] as char, magic[3] as char);
   print!("ELF file type is ");
   let file_type = elf.e_type(endian);
    match file_type {
            0 => println!("NONE"),
            1 => println!("REL"),
            2 => println!("EXEC (Executable file)"),
            3 => println!("DYN"),
            4 => println!("CORE"),
            _ => println!("Unknown"),
    }
    println!("Entry point 0x{:x}", elf.e_entry(endian));
    println!("There are {} program headers/segments, starting at offset {}\n",
    elf.e_phnum(endian), elf.e_phoff(endian));
    let segments = elf.program_headers(endian, &*content)?;
   for segment in segments.iter() {
       print_segment(segment, endian, elf.e_entry(endian));
   }
/*    let sections = elf.sections(endian, &content)? */;
//    let symbols = sections.symbols(endian, &content, elf::SHT_DYNSYM)?;
//    for symbol in symbols.iter() {
//        let name = symbol.name(endian, symbols.strings())?;
//        println!("{}", String::from_utf8_lossy(name));
//    }
   Ok(())
}
