mod diassembler;
mod pe;
mod vm;

use std::fs;

use crate::diassembler::Disassembler;
use crate::vm::machine::{disassemble, Machine};
use crate::vm::virtualizer::virtualize;

// virtualization of code that is in between a call of function like begin_virtualization and end_virtualization
// which are imported from a stub dll, the code is virtualized, a machine is created from the virtual code and the
// original code segment is replaced by the vmentry of the machine

fn main() {
  /*
    let matches = App::new("Obfuscate")
        .version("0.1.0")
        .author("felix")
        .about("Obfuscate input file")
        .arg(Arg::with_name("file")
            .short('f')
            .long("file")
            .takes_value(true)
            .help("file to obfuscate"))
        .get_matches();

    let file = matches.value_of("file").unwrap_or("input.txt");
    println!("The file passed is: {}", file);
   */

    // Disassembler::from_bytes(fs::read(file).unwrap()).disassemble();

    const SHELLCODE: &[u8] = &[
        0x89, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x08, 0x0f, 0xaf, 0x44, 0x24, 0x08, 0xc2, 0x00,
        0x00,
    ];
    Disassembler::from_bytes(SHELLCODE.to_vec()).disassemble();
    println!("{}", disassemble(&virtualize(SHELLCODE)).unwrap());
    let m = Machine::new(&virtualize(SHELLCODE)).unwrap();
    let f: extern "C" fn(i32) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
    assert_eq!(f(2), 4);
    println!("{}", f(6));
}

/*
use exe::{Buffer, CCharString, ImageSectionHeader, NTHeadersMut, PE, PEType, SectionCharacteristics, VecPE};

fn main() {
    // "../reddeadonline/target/x86_64-pc-windows-msvc/release-lto/loader.exe"
    let mut pefile = VecPE::from_disk_file("target/release/hello_world.exe").unwrap();

    let data: &[u8] = &[0x48, 0x31, 0xC0, 0xC3]; // xor rax,rax / ret

    let mut new_section = ImageSectionHeader::default();
    new_section.set_name(Some(".meow"));
    new_section.virtual_size = 0x1000;
    new_section.size_of_raw_data = data.len() as u32;
    new_section.characteristics = SectionCharacteristics::MEM_EXECUTE
        | SectionCharacteristics::MEM_READ
        | SectionCharacteristics::CNT_CODE;

    assert_eq!(new_section.name.as_str().unwrap(), ".meow");

    let new_section= pefile.append_section(&new_section).unwrap().clone();

    // rewriting entry point to data

    let nt_headers = pefile.get_valid_mut_nt_headers();
    assert!(nt_headers.is_ok());

    if let NTHeadersMut::NTHeaders64(nt_headers_64) = nt_headers.unwrap() {
        nt_headers_64.optional_header.address_of_entry_point = new_section.virtual_address;
    }

    //

    pefile.append(&mut data.to_vec());

    pefile.pad_to_alignment().unwrap();
    pefile.fix_image_size().unwrap();
    pefile.recreate_image(PEType::Disk).unwrap();

    pefile.save("target/release/hello_world_modded.exe").unwrap();
}
 */

