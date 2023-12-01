use anyhow::anyhow;
use exe::{Buffer, Error, ImageDirectoryEntry, ImageSectionHeader, PE, PEType, RVA, SectionCharacteristics, VecPE};
use iced_x86::code_asm::CodeAssembler;
use include_crypt::{EncryptedFile, include_crypt};

use crate::pe::parser::MapFile;
use crate::virtualizer::disassembler::convert_to_threaded_code;
use crate::virtualizer::Virtualizer;

pub mod virtualizer;
pub mod pe;
#[path = "../../vm/src/shared.rs"]
mod shared;

const VM: EncryptedFile =
    include_crypt!("..\\target\\x86_64-pc-windows-msvc\\release\\vm.dll");
const VM_THREADED: EncryptedFile =
    include_crypt!("..\\target\\x86_64-pc-windows-msvc\\release\\vm_threaded.dll");

pub struct Obfuscator {
    pe: VecPE,
    path: String,
    path_out: String,
    map_file: Option<MapFile>,
    obfuscation: bool,
    functions: Vec<Routine>,
}

struct Routine {
    rva: RVA,
    len: usize,
}

struct VirtualizedRoutine {
    routine: Routine,
    bytecode_rva: RVA,
}

trait PeExt {
    fn add_section_with_data(&mut self, section: &ImageSectionHeader, data: &[u8])
        -> Result<ImageSectionHeader, Error>;
}

impl PeExt for VecPE {
    fn add_section_with_data(&mut self, section: &ImageSectionHeader, data: &[u8]) -> Result<ImageSectionHeader, Error> {
        let new_section = *self.append_section(section)?;
        self.append(data);
        self.pad_to_alignment().unwrap();
        self.fix_image_size().unwrap();
        Ok(new_section)
    }
}

impl Obfuscator {
    pub fn new(path: String, path_out: String) -> Result<Obfuscator, exe::Error> {
        Ok(Self { pe: VecPE::from_disk_file(&path)?, path, path_out, map_file: None, obfuscation: false, functions: Vec::new() })
    }

    /// Path of pe to obfuscate
    pub fn with_path(mut self, path: String) -> Self {
        self.path = path;
        self
    }

    /// Output path of final pe
    pub fn with_path_out(mut self, path: String) -> Self {
        self.path = path;
        self
    }

    pub fn use_obfuscation(&mut self, enable: bool) {
        self.obfuscation = enable;
    }

    pub fn with_map_file(mut self, map_path: String) -> Self {
        let map_data = std::fs::read(map_path).unwrap();
        let map_string = String::from_utf8(map_data).unwrap();
        let map_file = MapFile::load(&map_string).unwrap();
        self.map_file = Some(map_file);
        self
    }

    pub fn add_function(&mut self, function: String) -> anyhow::Result<()> {
        let map_file = self.map_file.as_ref()
            .ok_or(anyhow!("no map file provided"))?;
        let (function, function_size) = map_file.get_function(&function)
            .ok_or(anyhow!("couldn't find function '{function}'"))?;
        self.functions.push(Routine { rva: RVA(function.rva.0 as u32), len: function_size });
        Ok(())
    }

    pub fn add_functions(&mut self, functions: Vec<String>) -> anyhow::Result<()> {
        functions.into_iter().try_for_each(|function| self.add_function(function))
    }

    pub fn virtualize(&mut self) -> anyhow::Result<()> {
        let mut vm_file = if self.obfuscation {
            VecPE::from_disk_data(VM_THREADED.decrypt().as_slice())
        } else {
            VecPE::from_disk_data(VM.decrypt().as_slice())
        };

        let vm_file_exports = vm_file.clone();

        let export_dir = vm_file.get_data_directory(ImageDirectoryEntry::Export)?;
        // zero out any info about exports after virtualizing
        vm_file.write(
            vm_file.rva_to_offset(export_dir.virtual_address)?.into(),
            vec![0x00u8; export_dir.size as usize],
        )?;

        let vm_file_text = *vm_file.get_section_by_name(".text").unwrap();
        let machine_entry = vm_file.get_entrypoint().unwrap();

        let machine = vm_file.read(vm_file_text.data_offset(self.pe.get_type()), vm_file_text.size_of_raw_data as _)
            .unwrap();

        let mut vm_section = ImageSectionHeader::default();
        vm_section.set_name(Some(".vm"));
        vm_section.virtual_size = (machine.len() /* + 0x1000*/) as u32; // 30kb, vm is 26kb
        vm_section.size_of_raw_data = machine.len() as u32;
        vm_section.characteristics = SectionCharacteristics::MEM_EXECUTE
            | SectionCharacteristics::MEM_READ
            | SectionCharacteristics::CNT_CODE;

        let vm_section = self.pe
            .add_section_with_data(&vm_section, &machine)?;

        let (bytecode, virtualized_fns) = self.virtualize_fns(
            RVA(vm_section.virtual_address.0 - 0x1000),
            &vm_file_exports
        )?;

        let mut bytecode_section = ImageSectionHeader::default();
        bytecode_section.set_name(Some(".byte"));
        bytecode_section.virtual_size = bytecode.len() as u32;
        bytecode_section.size_of_raw_data = bytecode.len() as u32;
        bytecode_section.characteristics = SectionCharacteristics::MEM_READ;

        let bytecode_section = self.pe
            .add_section_with_data(&bytecode_section, &bytecode)?;

        for function in virtualized_fns.iter() {
            self.patch_fn(
                &function.routine,
                vm_section.virtual_address.0 + machine_entry.0 - 0x1000,
                bytecode_section.virtual_address.0 + function.bytecode_rva.0,
            );
        }

        self.pe.recreate_image(PEType::Disk)?;
        self.pe.save(&self.path_out)?;
        ok()
    }

    fn virtualize_fns(&mut self, vm_section: RVA, vm: &VecPE) -> anyhow::Result<(Vec<u8>, Vec<VirtualizedRoutine>)> {
        let mut virtualizer = Virtualizer::with_pe(self.pe.clone())?;
        let mut bytecode = Vec::new();
        let mut virtualized_fns = Vec::new();

        for function in &self.functions {
            let target_fn_addr = self.pe.rva_to_offset(function.rva).unwrap().0 as _;
            // todo determine end of function correctly
            let target_function = self.pe.get_slice_ref::<u8>(target_fn_addr, function.len).unwrap();
            let mut virtualized_function = virtualizer.virtualize_with_ip(
                self.pe.get_image_base().unwrap() + function.rva.0 as u64,
                target_function,
            )?;

            virtualized_fns.push(VirtualizedRoutine {
                routine: Routine { rva: RVA(function.rva.0), len: function.len },
                bytecode_rva: RVA(bytecode.len() as u32),
            });

            if self.obfuscation {
                let mut converted = convert_to_threaded_code(vm, vm_section, virtualized_function.as_slice())?;
                bytecode.append(&mut converted);
            } else {
                bytecode.append(&mut virtualized_function);
            }

            virtualizer.reset();
        }

        Ok((bytecode, virtualized_fns))
    }

    fn patch_fn(&mut self, target_fn: &Routine, vm_rva: u32, bytecode_rva: u32) -> usize {
        let mut a = CodeAssembler::new(64).unwrap();
        a.push(bytecode_rva as i32).unwrap();
        // for macro support use call here instead if macro
        a.jmp(vm_rva as u64 - target_fn.rva.0 as u64).unwrap();

        let patch = a.assemble(0).unwrap();

        let target_fn_offset = self.pe.rva_to_offset(target_fn.rva).unwrap();
        let target_function_mut = self.pe.get_mut_slice_ref::<u8>(target_fn_offset.0 as usize, patch.len()).unwrap();
        target_function_mut.copy_from_slice(patch.as_slice());

        self.remove_routine(Routine {
            rva: RVA(target_fn.rva.0 + patch.len() as u32),
            len: target_fn.len - patch.len(),
        });

        self.pe.pad_to_alignment().unwrap();
        self.pe.fix_image_size().unwrap();
        patch.len()
    }

    fn remove_routine(&mut self, routine: Routine) {
        let offset = self.pe.rva_to_offset(routine.rva).unwrap();
        let data = vec![0xCCu8; routine.len];
        // or copy_from_slice ?
        self.pe.write(offset.into(), data).unwrap();
    }
}

fn ok<E>() -> Result<(), E> {
    Ok(())
}