#![allow(clippy::needless_return)] // Pour éviter les warnings de return
use std::env; // to use args
use lief::elf::binary::Binary;

fn main() {
    let args: Vec<String> = env::args().collect();
    let file_path = if args.len() > 1 {
        &args[1]
    } else {
        "../binaries/easiest_program_to_disassemble_dwarf"
    };
    match Binary::parse(file_path) {
       Some(binary) => { 
           println!("{:#?}", binary);
       },
       None => {
           println!("Error while parsing the binary");
       }
    }
   return;
}