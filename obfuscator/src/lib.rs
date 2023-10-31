use std::ops::BitXor;

use exe::{Buffer, CCharString, Error, ImageSectionHeader, PE, PEType, RVA, SectionCharacteristics, VecPE};
use iced_x86::code_asm::CodeAssembler;
use symbolic_demangle::Demangle;

use crate::diassembler::Disassembler;
use crate::pe::parser::MapFile;
use crate::virt::machine::disassemble;
use crate::virt::virtualizer::virtualize_with_ip;

pub mod virt;
pub mod diassembler;
pub mod pe;

pub fn virtualize_file(path: &str, map_path: &str, path_out: &str, functions: Vec<String>) {
    let map_data = std::fs::read(map_path).unwrap();
    let map_string = String::from_utf8(map_data).unwrap();
    let map_file = MapFile::load(&map_string).unwrap();

    let mut pefile = VecPE::from_disk_file(path).unwrap();

    // relocating will probably be done dynamically
    // have to mark them as relocate somehow
    // but for jmps i need to be able to identify label with target
    let (bytecode, virtualized_fns) = virtualize_functions(&pefile, map_file, &functions);

    let mut bytecode_section = ImageSectionHeader::default();
    bytecode_section.set_name(Some(".byte"));
    bytecode_section.virtual_size = 0x1000;
    bytecode_section.size_of_raw_data = bytecode.len() as u32;
    bytecode_section.characteristics = SectionCharacteristics::MEM_EXECUTE
        | SectionCharacteristics::MEM_READ
        | SectionCharacteristics::CNT_CODE;

    let bytecode_section = add_section(&mut pefile, &bytecode_section, &bytecode).unwrap();

    // todo include
    let mut vm_file = VecPE::from_disk_file("../target/x86_64-pc-windows-msvc/release/vm.dll").unwrap();
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
            bytecode_section.virtual_address.0 + function.bytecode_offset as u32,
        );
    }

    pefile.recreate_image(PEType::Disk).unwrap();
    pefile.save(path_out).unwrap();
}


struct VirtualizedFn {
    rva: usize,
    size: usize,
    bytecode_offset: usize,
}

fn virtualize_functions(pefile: &VecPE, map_file: MapFile, functions: &[String]) -> (Vec<u8>, Vec<VirtualizedFn>) {
    let mut bytecode = Vec::new();
    let mut virtualized_fns = Vec::new();

    for function in functions {
        println!("searching {}", function);
        let (function, function_size) = map_file.get_function(function).unwrap();
        println!("found target function: {}: {:x}:{}", function.symbol, function.rva.0, function_size);
        let target_fn_addr = pefile.rva_to_offset(RVA(function.rva.0 as _)).unwrap().0 as _;
        let target_function = pefile.get_slice_ref::<u8>(target_fn_addr, function_size).unwrap();
        let function_size = Disassembler::from_bytes(target_function.to_vec()).disassemble();
        // get again but with "real" (hopefully) size
        let target_function = pefile.get_slice_ref::<u8>(target_fn_addr, function_size).unwrap();
        println!("{:x}", pefile.get_image_base().unwrap() + function.rva.0 as u64);
        let mut virtualized_function = virtualize_with_ip(
            pefile.get_image_base().unwrap() + function.rva.0 as u64,
            target_function,
        );
        println!("{}", disassemble(&virtualized_function).unwrap());
        println!("{:x?}", virtualized_function);
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
    a.push(bytecode_rva as i32).unwrap();
    a.jmp(vm_rva as u64 - target_fn as u64).unwrap();

    let patch = a.assemble(0).unwrap();

    let target_fn_offset = pefile.rva_to_offset(RVA(target_fn as u32)).unwrap();
    let target_function_mut = pefile.get_mut_slice_ref::<u8>(target_fn_offset.0 as usize, patch.len()).unwrap();
    target_function_mut.copy_from_slice(patch.as_slice());

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
