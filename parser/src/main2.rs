#![allow(clippy::needless_return)] // Pour éviter les warnings de return
use std::env; // to use args
use std::fs; //to use filesystem
use std::process; // Pour quitter si erreur


// Flags ELF Segments
const PF_EXEC: u32 = 0x1;
const PF_WRITE: u32 = 0x2;
const PF_READ: u32 = 0x4;


fn is_elf_file(contents: &[u8]) -> bool {
    if 4 > contents.len() {
        return false;
    } else {
        return 0x7f == contents[0] && b'E' == contents[1] && b'L' == contents[2] && b'F' == contents[3]; 
    }
}

fn architecture_and_endianess(contents: &[u8]) -> (String, String){
    let mut arch = String::from("Unknown");
    let mut end = String::from("Unknown");

    if contents.len() < 18 {
        return (arch, end);
    }

    let class = contents[4];
    let data = contents[5];

    match class {
        1 => arch = String::from("32 bits"),
        2 => arch = String::from("64 bits"),
        _ => arch = String::from("Unknown")
    }

    match data {
        1 => end = String::from("Little endian"),
        2 => end = String::from("Big endian"),
        _ => end = String::from("Unknown")
    }

    return (arch, end);
}




fn main() {
    let args: Vec<String> = env::args().collect();
    dbg!(&args);

    if args.len()<2 {
        eprintln!("cargo run [file_to_inspect]");
        process::exit(1);
    }

    match fs::metadata(&args[1]){
        Ok(_)=>{}
        Err(e) => {
            eprintln!("{} does not exist, {}",&args[1], e);
            process::exit(1); // On quitte car erreur
        }
    }
    let file_path = &args[1];
    

    let contents = fs::read(file_path)
        .expect("Should have been able to read the file");

    let elf_header = 

    if is_elf_file(&contents) {
        println!("{} is an ELF file", file_path);
    } else {
        eprintln!("{} is not an ELF file", file_path);
        process::exit(1);
    }

    let (arch, end) = architecture_and_endianess(&contents);
    if (arch, end) == (String::from("64 bits"), String::from("Little endian")) {
        println!("{} is a 64 bits Little endian executable file", file_path);
    } else {
        eprintln!("Could not determine architecture and endianness");
        process::exit(1); 
    }

    




}

