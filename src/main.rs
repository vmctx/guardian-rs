mod diassembler;
mod pe;
mod vm;

use std::fs;
use clap::{App, Arg};
use crate::diassembler::Disassembler;
use crate::vm::machine::{disassemble, Machine};
use crate::vm::virtualizer::virtualize;

// virtualization of code that is in between a call of function like begin_virtualization and end_virtualization
// which are imported from a stub dll, the code is virtualized, a machine is created from the virtual code and the
// original code segment is replaced by the vmentry of the machine

fn main() {

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

    Disassembler::from_bytes(fs::read(file).unwrap()).disassemble();

    const SHELLCODE: &[u8] = &[
        0x89, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x08, 0x0f, 0xaf, 0x44, 0x24, 0x08, 0xc2, 0x00,
        0x00,
    ];
    println!("{}", disassemble(&virtualize(SHELLCODE)).unwrap());
    let m = Machine::new(&virtualize(SHELLCODE)).unwrap();
    let f: extern "C" fn(i32) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
    assert_eq!(f(2), 4);
}

