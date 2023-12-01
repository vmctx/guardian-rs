use std::collections::HashMap;
use std::ptr::read_unaligned;

use anyhow::{anyhow, Result};
use exe::{ExportDirectory, RVA, ThunkData, VecPE};

use crate::shared::*;

#[repr(C)]
struct Instruction {
    op_code: Opcode,
    op_size: OpSize,
    jmp_cond: Option<JmpCond>,
    instr_size: Option<u8>,
    instr: Option<Vec<u8>>,
    // some dont have size encoded
    value: Option<u64>,
    //Option<T>
    next_handler: Option<u64>,
}

impl Instruction {
    pub unsafe fn from_ptr(instr_ptr: *const u8) -> Option<Self> {
        let op_code = Opcode::try_from(instr_ptr.read_unaligned()).ok()?;
        let op_size = OpSize::try_from(instr_ptr.add(1).read_unaligned()).ok()?;

        let instr_size = op_code
            .eq(&Opcode::VmExec)
            .then(|| unsafe { instr_ptr.add(2).read_unaligned() });

        let mut instr = Self {
            op_code,
            op_size,
            jmp_cond: op_code
                .eq(&Opcode::Jmp)
                .then(|| unsafe { JmpCond::try_from(instr_ptr.add(2).read_unaligned()).unwrap() }),
            instr_size,
            instr: op_code.eq(&Opcode::VmExec).then(|| unsafe {
                let instr_size = instr_size.unwrap() as usize;
                let mut buffer = vec![0u8; instr_size];
                core::ptr::copy(instr_ptr.add(3), buffer.as_mut_ptr(), instr_size);
                buffer
            }),
            value: None,
            next_handler: None,
        };
        instr.value = instr.read_value(instr_ptr);

        Some(instr)
    }

    unsafe fn read_value(&self, instr_ptr: *const u8) -> Option<u64> {
        let val_ptr = match self.op_code {
            Opcode::Const | Opcode::VmReloc => instr_ptr.add(2),
            Opcode::Jmp => instr_ptr.add(3),
            _ => None?,
        };
        let v = match self.op_size {
            OpSize::Qword => read_unaligned::<u64>(val_ptr as *const u64),
            OpSize::Dword => read_unaligned(val_ptr as *const u32) as u64,
            OpSize::Word => read_unaligned(val_ptr as *const u16) as u64,
            OpSize::Byte => read_unaligned(val_ptr) as u64,
        };
        Some(v)
    }

    pub fn encode_obf(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(self.op_size as u8);
        self.encode_optional(&mut buffer);
        buffer.extend_from_slice(&self.next_handler.unwrap().to_le_bytes());
        buffer
    }

    pub fn encode_optional(&self, buffer: &mut Vec<u8>) {
        match self.op_code {
            Opcode::Jmp => {
                buffer.push(self.jmp_cond.clone().unwrap() as u8);
                buffer.extend_from_slice(&self.value.unwrap().to_le_bytes());
            }
            Opcode::VmExec => {
                buffer.push(self.instr_size.unwrap());
                buffer.extend_from_slice(self.instr.as_ref().unwrap());
            }
            Opcode::Const | Opcode::VmReloc => {
                let value = self.value.unwrap();
                match self.op_size {
                    OpSize::Byte => buffer.extend_from_slice(&(value as u8).to_le_bytes()),
                    OpSize::Word => buffer.extend_from_slice(&(value as u16).to_le_bytes()),
                    OpSize::Dword => buffer.extend_from_slice(&(value as u32).to_le_bytes()),
                    OpSize::Qword => buffer.extend_from_slice(&(value).to_le_bytes()),
                }
            }
            _ => {}
        }
    }

    pub fn length(&self) -> usize {
        let mut length = 2; // opcode + opsize
        length += match self.op_code {
            Opcode::Const | Opcode::VmReloc => self.op_size as u8 as usize,
            Opcode::Jmp => {
                self.op_size as u8 as usize + 1 // jmp cond
            }
            Opcode::VmExec => {
                self.instr_size.unwrap() as usize + 1 // instr_size
            }
            _ => 0,
        };
        length
    }
}

impl Opcode {
    pub fn get_handler(&self, vm: &VecPE, vm_section: RVA) -> Option<u32> {
        let exports = ExportDirectory::parse(vm).ok()?;
        let export_map = exports.get_export_map(vm).ok()?;

        let thunk_data = match self {
            Opcode::Const => export_map.get("const_handler")?,
            Opcode::Load => export_map.get("load_handler")?,
            Opcode::LoadXmm => export_map.get("load_xmm_handler")?,
            Opcode::Store => export_map.get("store_handler")?,
            Opcode::StoreXmm => export_map.get("store_xmm_handler")?,
            Opcode::StoreReg => export_map.get("store_reg_handler")?,
            Opcode::StoreRegZx => export_map.get("store_reg_zx_handler")?,
            Opcode::Add => export_map.get("add_handler")?,
            Opcode::Sub => export_map.get("sub_handler")?,
            Opcode::Div => export_map.get("div_handler")?,
            Opcode::IDiv => export_map.get("idiv_handler")?,
            Opcode::Shr => export_map.get("shr_handler")?,
            Opcode::Combine => export_map.get("combine_handler")?,
            Opcode::Split => export_map.get("split_handler")?,
            Opcode::Mul => export_map.get("mul_handler")?,
            Opcode::And => export_map.get("and_handler")?,
            Opcode::Or => export_map.get("or_handler")?,
            Opcode::Xor => export_map.get("xor_handler")?,
            Opcode::Not => export_map.get("not_handler")?,
            Opcode::Cmp => export_map.get("cmp_handler")?,
            Opcode::RotR => export_map.get("rot_r_handler")?,
            Opcode::RotL => export_map.get("rot_l_handler")?,
            Opcode::Jmp => export_map.get("jmp_handler")?,
            Opcode::Vmctx => export_map.get("vm_ctx_handler")?,
            Opcode::VmAdd => export_map.get("vm_add_handler")?,
            Opcode::VmMul => export_map.get("vm_mul_handler")?,
            Opcode::VmSub => export_map.get("vm_sub_handler")?,
            Opcode::VmReloc => export_map.get("vm_reloc_handler")?,
            Opcode::VmExec => export_map.get("vm_exec_handler")?,
            Opcode::VmExit => export_map.get("vmexit_threaded")?,
        };

        match thunk_data {
            ThunkData::Function(rva) => Some(rva.0 + vm_section.0),
            _ => None,
        }
    }
}

pub fn convert_to_threaded_code(vm: &VecPE, vm_section: RVA, program: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut offset_map = HashMap::<usize, usize>::new();
    let mut new_offset_map = HashMap::<usize, usize>::new();
    let mut pc = program.as_ptr();
    let mut index = 0;

    let mut obfuscated = Vec::new();

    let first_inst = Opcode::try_from(unsafe { pc.read_unaligned() })
        .map_err(|_| anyhow!("invalid bytecode"))?;
    let first_handler = first_inst.get_handler(vm, vm_section)
        .ok_or(anyhow!("handler for '{:?}' not found", first_inst))?;
    obfuscated.extend_from_slice(&(first_handler as u64).to_le_bytes());

    while pc < program.as_ptr_range().end {
        let mut instr = unsafe { Instruction::from_ptr(pc) }
            .ok_or(anyhow!("invalid instruction"))?;
        offset_map.insert(obfuscated.len(), index);
        new_offset_map.insert(index, obfuscated.len());

        if let Some(next_instr) = unsafe { Instruction::from_ptr(pc.add(instr.length())) } {
            instr.next_handler = next_instr.op_code
                .get_handler(vm, vm_section)
                .map(|x| x as u64);
            obfuscated.extend_from_slice(&instr.encode_obf());
        } else {
            break;
        }

        pc = unsafe { pc.add(instr.length()) };
        index += instr.length();
    }

    pc = obfuscated.as_ptr();
    index = 0;

    while pc < obfuscated.as_ptr_range().end {
        if let Some(old_offset) = offset_map.get(&index) {
            let op_code = Opcode::try_from(program[*old_offset])
                .map_err(|_| anyhow!("invalid instruction"))?;
            if op_code == Opcode::Jmp {
                // skip op_size and jmp_cond
                pc = unsafe { pc.add(2) };

                let jmp_target = unsafe { pc.cast::<i64>().read_unaligned() };
                let jmp_offset = (*old_offset as i64).wrapping_sub(jmp_target) as usize;
                let new_offset = *new_offset_map.get(&jmp_offset)
                    .ok_or(anyhow!("couldn't translate jmp_offset"))?;

                unsafe {
                    let jmp_addr =  pc.cast_mut().cast::<u64>();
                    jmp_addr.write_unaligned(index.wrapping_sub(new_offset) as u64);
                }
                // op_size u8, jmp_cond u8, jmp_target u64 = 10
                index += 10;
                pc = unsafe { pc.add(8) };
                continue;
            }
        }

        index += 1;
        pc = unsafe { pc.add(1) };
    }

    Ok(obfuscated)
}

pub fn disassemble(program: &[u8]) -> Result<String> {
    let mut s = String::new();
    let mut pc = program.as_ptr();

    let mut last_instr = None;

    while pc < program.as_ptr_range().end {
        let instruction = unsafe { Instruction::from_ptr(pc) }.unwrap();

        s.push_str(
            format!(
                "{:x}: {:?}",
                pc.wrapping_sub(program.as_ptr() as usize) as usize,
                instruction.op_code
            )
                .as_str(),
        );
        match instruction.op_size {
            OpSize::Byte => s.push('B'),
            OpSize::Word => s.push('W'),
            OpSize::Dword => s.push('D'),
            OpSize::Qword => s.push('Q'),
        }

        #[allow(clippy::single_match)]
        match instruction.op_code {
            Opcode::Const | Opcode::VmReloc => 'label: {
                //let v = *(pc as *const u64);
                let value = instruction.value.unwrap();

                if let Some(last_instr) = last_instr {
                    if last_instr == Opcode::Vmctx {
                        if let Ok(reg) = Register::try_from((value.wrapping_sub(16)) as u8 / 8) {
                            s.push_str(format!(" {:?}", reg).as_str());
                            break 'label;
                        }
                    }
                }

                s.push_str(format!(" {}", value).as_str());
            }
            Opcode::Jmp => unsafe {
                let cond = JmpCond::try_from(read_unaligned(pc.add(2))).unwrap();
                let val = instruction.value.unwrap();
                s.push_str(format!(" {:?} 0x{:x}", cond, val).as_str());
            },
            Opcode::VmExec => {
                /* todo
                let instr_size = pc.add(2).read_unaligned() as usize;
                pc = pc.add(instr_size + 1);
                 */
            }
            _ => {}
        }

        last_instr = Some(instruction.op_code);
        pc = unsafe { pc.add(instruction.length()) };
        s.push('\n');
    }

    Ok(s)
}
