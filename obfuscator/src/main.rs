use std::ops::BitXor;

use exe::{Buffer, CCharString, Error, ImageSectionHeader, PE, PEType, RVA, SectionCharacteristics, VecPE};
use iced_x86::code_asm::CodeAssembler;
use symbolic_demangle::Demangle;

use crate::diassembler::Disassembler;
use crate::pe::parser::MapFile;
use crate::vm::virtualizer::{virtualize, virtualize_with_ip};

mod diassembler;
mod pe;
mod vm;

// virtualization of code that is in between a call of function like begin_virtualization and end_virtualization
// which are imported from a stub dll, the code is virtualized, a machine is created from the virtual code and the
// original code segment is replaced by the vmentry of the machine


fn main() {
    // "../reddeadonline/target/x86_64-pc-windows-msvc/release-lto/loader.exe"
    let map_data = std::fs::read("../hello_world/target/release/hello_world.map").unwrap();
    let map_string = String::from_utf8(map_data).unwrap();
    let mut map_file = pe::parser::MapFile::load(&map_string).unwrap();
    println!("{}", map_file.functions.len());

    let (function, function_size) = map_file.get_function("hello_world::calc").unwrap();
    println!("target function: {}: {:x}", function.symbol, function_size);

    let mut pefile = VecPE::from_disk_file("../hello_world/target/release/hello_world.exe").unwrap();

    // relocating will probably be done dynamically
    // have to mark them as relocate somehow
    // but for jmps i need to be able to identify label with target
    let (bytecode, virtualized_fns) = virtualize_functions(&pefile, map_file, &["hello_world::calc"]);

    let mut bytecode_section = ImageSectionHeader::default();
    bytecode_section.set_name(Some(".byte"));
    bytecode_section.virtual_size = 0x1000;
    bytecode_section.size_of_raw_data = bytecode.len() as u32;
    bytecode_section.characteristics = SectionCharacteristics::MEM_EXECUTE
        | SectionCharacteristics::MEM_READ
        | SectionCharacteristics::CNT_CODE;

    let bytecode_section = add_section(&mut pefile, &bytecode_section, &bytecode).unwrap();

    // todo place all the bytecode into the bytecode section for every virtualized code part
    // in this case it would just be data


    let mut vm_file = VecPE::from_disk_file("target/x86_64-pc-windows-msvc/release/vm.dll").unwrap();
    let vm_file_text = vm_file.get_section_by_name(".text").unwrap().clone();
    let machine_entry = vm_file.get_entrypoint().unwrap();
    println!("vm machine::new: {:x}", machine_entry.0);

    let mut machine = vm_file.read(vm_file_text.data_offset(pefile.get_type()), vm_file_text.size_of_raw_data as _)
        .unwrap();

    let mut vm_section = ImageSectionHeader::default();
    vm_section.set_name(Some(".vm"));
    vm_section.virtual_size = (machine.len() /* + 0x1000*/) as u32; // 30kb, vm is 26kb
    vm_section.size_of_raw_data = machine.len() as u32;
    vm_section.characteristics = SectionCharacteristics::MEM_EXECUTE
        | SectionCharacteristics::MEM_READ
        | SectionCharacteristics::CNT_CODE;

    let vm_section = add_section(&mut pefile, &vm_section, &machine.to_vec()).unwrap();

    for function in virtualized_fns.iter() {
        patch_function(
            &mut pefile,
            function.rva,
            function.size,
            vm_section.virtual_address.0 + machine_entry.0 - 0x1000,
            bytecode_section.virtual_address.0 + function.bytecode_offset as u32
        );
    }

    pefile.recreate_image(PEType::Disk).unwrap();
    pefile.save("../hello_world/target/release/hello_world_modded.exe").unwrap();
}

struct VirtualizedFn {
    rva: usize,
    size: usize,
    bytecode_offset: usize,
}

fn virtualize_functions(pefile: &VecPE, map_file: MapFile, functions: &[&str]) -> (Vec<u8>, Vec<VirtualizedFn>) {
    let mut bytecode = Vec::new();
    let mut virtualized_fns = Vec::new();

    for function in functions {
        let (function, function_size) = map_file.get_function(function).unwrap();
        println!("found target function: {}: {:x}:{}", function.symbol, function.rva.0, function_size);
        let target_fn_addr = pefile.rva_to_offset(RVA(function.rva.0 as _)).unwrap().0 as _;
        let target_function = pefile.get_slice_ref::<u8>(target_fn_addr, function_size).unwrap();
        let function_size = Disassembler::from_bytes(target_function.to_vec()).disassemble();
        // get again but with "real" (hopefully) size
        let target_function = pefile.get_slice_ref::<u8>(target_fn_addr, function_size).unwrap();
        let mut virtualized_function = virtualize_with_ip(
            pefile.get_image_base().unwrap() + function.rva.0 as u64,
            target_function
        );
        virtualized_fns.push(VirtualizedFn {
            rva: function.rva.0,
            size: function_size,
            bytecode_offset: bytecode.len(), // todo should be correct ?
        });
        bytecode.append(&mut virtualized_function);
        println!("added target function: {}: {:x}:{}", function.symbol, function.rva.0, function_size);
    }

    (bytecode, virtualized_fns)
}

fn patch_function(pefile: &mut VecPE, target_fn: usize, target_fn_size: usize, vm_rva: u32, bytecode_rva: u32) -> usize {
    /*
        for index in 0..pefile.get_buffer().len() {
            if index >= target_fn && index <= target_fn + target_fn_size {
                pefile.remove(index);
            }
        }
     */
    let mut a = CodeAssembler::new(64).unwrap();
    // todo add relocs
    // todo get the fcking right address!!
    /*
        let mut push = Decoder::new(64, &vec![0xff, 0x35, 0x00, 0x00, 0x00, 0x00], 0).decode();
        push.set_memory_displacement64(bytecode_rva as u64 - target_fn_rva.0 as u64);
        a.add_instruction(push).unwrap();
     */

    println!("{:x}", pefile.get_image_base().unwrap());
    println!("rva: {:x}", vm_rva as u64 as u64);
    println!("fn rva: {:x}", target_fn as u64 as u64);
    println!("xor : {:x}", bytecode_rva.bitxor(vm_rva).bitxor(vm_rva));
    a.push(bytecode_rva as i32).unwrap();
    a.jmp(vm_rva as u64 - target_fn as u64).unwrap();

    /*
        let pedata = pefile.clone();
        let mut relocs = RelocationDirectory::parse(&pedata).unwrap();
        { relocs.add_relocation(pefile, RVA(vm_rva)).unwrap(); }
     */

    let patch = a.assemble(0).unwrap();

    println!("{:x}", target_fn);

    let target_fn_offset = pefile.rva_to_offset(RVA(target_fn as u32)).unwrap();
    let target_function_mut = pefile.get_mut_slice_ref::<u8>(target_fn_offset.0 as usize, patch.len()).unwrap();
    target_function_mut.copy_from_slice(patch.as_slice());
    //pefile.get_mut_section_by_name(".text".to_string()).unwrap().
    pefile.pad_to_alignment().unwrap();
    pefile.fix_image_size().unwrap();
    patch.len()
}

fn add_section(pefile: &mut VecPE, section: &ImageSectionHeader, data: &Vec<u8>) -> Result<ImageSectionHeader, Error> {
    let new_section = pefile.append_section(section)?.clone();
    pefile.append(data);
    pefile.pad_to_alignment().unwrap();
    pefile.fix_image_size().unwrap();
    Ok(new_section)
}

fn add_data(pefile: &mut VecPE, data: &Vec<u8>) {
    pefile.append(data);
    pefile.pad_to_alignment().unwrap();
    pefile.fix_image_size().unwrap();
}
