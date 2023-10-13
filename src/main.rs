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


// todo
// i need to somehow embed the machine.rs as a new section
// OR run machine and embed the run function as a new section
// which is probably easier
// so then i create a machine from code i disassemble in the binary
// so the machine instead of allocating vmenter and exit in the heap
// needs to do so by creating it ahead of time in a section for
// every virtualized function/code block
// then it might be easier to just compile the machine
// and create it dynamically by using something like this
// lea arg1, bytecode
// mov rax, machine::new
// call rax // create new machine
// lea rax, ret_val.vm_enter
// call rax // executes vm
// if not then see below:
// and replace the code with something like (pseudo asm)
// mov arg1, machineforthiscode (section .machines offset 0x6900)
// lea rax, virtual machine (run function, section .vm offset 0)
// call rax (call run function with ptr to machine struct)


use exe::{Buffer, CCharString, Error, ImageSectionHeader, NTHeadersMut, PE, PEType, SectionCharacteristics, VecPE};

fn main() {
    // "../reddeadonline/target/x86_64-pc-windows-msvc/release-lto/loader.exe"
    let mut pefile = VecPE::from_disk_file("../hello_world/target/release/hello_world.exe").unwrap();

    let data: &[u8] = &[  0x89, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x08, 0x0f, 0xaf, 0x44, 0x24, 0x08, 0xc2, 0x00,
        0x00,]; // xor rax,rax / ret


    let m = Machine::new(&virtualize(data)).unwrap();
    let f: extern "C" fn(i32) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
    assert_eq!(f(2), 4);
    println!("{}", f(6));
    let mut bytecode_section = ImageSectionHeader::default();
    bytecode_section.set_name(Some(".byte"));
    bytecode_section.virtual_size = 0x1000;
    bytecode_section.size_of_raw_data = virtualize(data).len() as u32;
    bytecode_section.characteristics = SectionCharacteristics::MEM_EXECUTE
        | SectionCharacteristics::MEM_READ
        | SectionCharacteristics::CNT_CODE;

    let bytecode_section = add_section(&mut pefile, &bytecode_section, &virtualize(data)).unwrap();

    // todo place all the bytecode into the bytecode section for every virtualized code part
    // in this case it would just be data

    let mut vm_section = ImageSectionHeader::default();
    vm_section.set_name(Some(".vm"));
    vm_section.virtual_size = 0x1000;
    vm_section.size_of_raw_data = data.len() as u32;
    vm_section.characteristics = SectionCharacteristics::MEM_EXECUTE
        | SectionCharacteristics::MEM_READ
        | SectionCharacteristics::CNT_CODE;

    // todo include compiled machine into vm section (look independent shellcode maybe as reference)
    let vm_section = add_section(&mut pefile, &vm_section, &data.to_vec()).unwrap();

    // todo generate code that replaces original code (in this case there is none)
    // via dynasm referring to bytecode section with offset and to vm section
    // for turning bytecode into machine that runs
    // see loader for dynasm usage

    // rewriting entry point to data

    let nt_headers = pefile.get_valid_mut_nt_headers();
    assert!(nt_headers.is_ok());

    if let NTHeadersMut::NTHeaders64(nt_headers_64) = nt_headers.unwrap() {
        nt_headers_64.optional_header.address_of_entry_point = vm_section.virtual_address;
    }

    //

    pefile.recreate_image(PEType::Disk).unwrap();
    pefile.save("../hello_world/target/release/hello_world_modded.exe").unwrap();
}

fn add_section(pefile: &mut VecPE, section: &ImageSectionHeader, data: &Vec<u8>) -> Result<ImageSectionHeader, Error> {
    let new_section = pefile.append_section(section)?.clone();
    pefile.append(data);
    pefile.pad_to_alignment().unwrap();
    pefile.fix_image_size().unwrap();
    Ok(new_section)
}
