mod diassembler;
mod pe;
mod vm;

use std::fs;
use std::fs::File;
use std::mem::size_of_val;
use std::ops::BitXor;

use crate::diassembler::Disassembler;
use crate::vm::machine::{Assembler, disassemble, Machine, Register};
use crate::vm::virtualizer::{virtualize, virtualize_with_ip};

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

use exe::{Buffer, CCharString, Error, ImageSectionHeader, NTHeadersMut, Offset, PE, PEType, RelocationDirectory, RVA, SectionCharacteristics, VecPE};
use iced_x86::code_asm::{AsmRegister64, CodeAssembler};
use iced_x86::Decoder;
use memoffset::offset_of;
use symbolic_demangle::Demangle;
use crate::pe::parser::MapFile;

fn main() {
    let mut a = Assembler::default();
    let x = 8u64;
    let y = 8u64;
    let mut z = 0u64;

    a.const_(&x as *const _ as u64);
    a.load();
    a.const_(&y as *const _ as u64);
    a.load();
    a.cmp();
    a.add();
    a.const_(&mut z as *mut _ as u64);
    a.store();

    unsafe { Machine::new(&a.assemble()).unwrap().run() };
    assert_eq!(z, 16);
    #[repr(C)]
    pub struct TestMachine {
        pub(crate) pc: *const u8,
        pub(crate) sp: *mut u64,
        pub regs: [u64; 16],
        pub rflags: u64,
        pub(crate) program: *const u8,
        pub(crate) vmstack: Vec<u64>,
        pub(crate) cpustack: Vec<u8>,
        pub cpustack_ptr: *const u8,
        vmexit: *const u64,
    }
    let test = 0x1000 - 0x100 - std::mem::size_of::<u64>();
    println!("test: {:x}", test);
    // "../reddeadonline/target/x86_64-pc-windows-msvc/release-lto/loader.exe"
    let map_data = std::fs::read("../hello_world/target/release/hello_world.map").unwrap();
    let map_string = String::from_utf8(map_data).unwrap();
    let mut map_file = pe::parser::MapFile::load(&map_string).unwrap();
    println!("{}", map_file.functions.len());

    // get list of function names as strings/literals, pass them to a function that
    // iterates map file and searches for all of these functions then virtualizes them
    // and appends the virtualized data to a vector, also have a second vector containing
    // info abt the virtualized functions and offset in the first vector to bytecode
    //
    //let (bytecode, virtualized_fns) = virtualize_functions(&["hello_world::calc"]);
    // virtualized fns is a Vec<VirtualizedFn> or something
    // insert bytecode into bytecode section then patch functions
    /*
    struct VirtualizedFn {
        rva: RVA,
        size: u32,
        bytecode_offset: RVA
    }

    for function in virtualized_fns.iter() {
        patch_function(
            &mut pefile,
            function.rva,
            function.size,
            vm_section.virtual_address.0 + machine_entry.0 - 0x1000,
           bytecode_section.virtual_address.0 + function.bytecode_offset
        );
    }
     */
    //

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

    // todo include compiled machine into vm section (look independent shellcode maybe as reference)
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
    //

    // create machine linking to program at start of bytecode section
    /*
      let nt_headers = pefile.get_valid_mut_nt_headers();
      assert!(nt_headers.is_ok());
      if let NTHeadersMut::NTHeaders64(nt_headers_64) = nt_headers.unwrap() {
          generate_vm_entry(
              &mut vm1,
             machine_addr as u64,
              nt_headers_64.optional_header.image_base as usize + (vm_section.virtual_address.0 + machine_entry.0 - 0x1000) as usize);
      }
      println!("{:?}", vm1.vmenter.clone().to_vec());
      Disassembler::from_bytes(vm1.vmenter.clone().to_vec()).disassemble();
      generate_vm_exit(&mut vm1);
      println!("{:?}", vm1.vmexit.clone().to_vec());
      println!("--------------------------------");
      Disassembler::from_bytes(vm1.vmexit.clone().to_vec()).disassemble();
      let mut buffer = vec![0u8; size_of_val(&vm1)];
      unsafe { std::ptr::copy(&vm1 as *const _ as *const u8, buffer.as_mut_ptr(), size_of_val(&vm1))}
      add_data(&mut pefile, &buffer);
     */

    // todo generate code that replaces original code (in this case there is none)
    // via dynasm referring to bytecode section with offset and to vm section
    // for turning bytecode into machine that runs
    // see loader for dynasm usage

    // rewriting entry point to data
    //

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
