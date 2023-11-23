use std::ptr::read_unaligned;

use anyhow::Result;

use crate::shared::*;

#[repr(C)]
struct Instruction {
    op_code: Opcode,
    op_size: OpSize,
    // some dont have size encoded
    value: Option<u64>,//Option<T>
}

impl Instruction {
    pub unsafe fn from_ptr(instr_ptr: *const u8) -> Option<Self> {
        let op_code = Opcode::try_from(instr_ptr.read_unaligned()).ok()?;
        let op_size = OpSize::try_from(instr_ptr.add(1).read_unaligned()).ok()?;

        let mut instr = Self { op_code, op_size, value: None };
        instr.value = instr.read_value(instr_ptr);

        Some(instr)
    }

    unsafe fn read_value(&self, instr_ptr: *const u8) -> Option<u64> {
        let val_ptr = match self.op_code {
            Opcode::Const => instr_ptr.add(2),
            Opcode::Jmp => instr_ptr.add(3),
            _ => None?
        };
        let v = match self.op_size {
            OpSize::Qword => read_unaligned::<u64>(val_ptr as *const u64),
            OpSize::Dword => read_unaligned(val_ptr as *const u32) as u64,
            OpSize::Word => read_unaligned(val_ptr as *const u16) as u64,
            OpSize::Byte => read_unaligned(val_ptr) as u64,
        };
        Some(v)
    }

    pub fn length(&self) -> usize {
        let mut length = 2; // opcode + opsize
        length += match self.op_code {
            Opcode::Const | Opcode::VmReloc => {
                self.op_size as u8 as usize
            }
            Opcode::Jmp => {
                self.op_size as u8 as usize + 1 // jmp cond
            }
            _ => 0
        };
        length
    }
}


pub fn disassemble(program: &[u8]) -> Result<String> {
    let mut s = String::new();
    let mut pc = program.as_ptr();

    let mut last_instr = None;

    while pc < program.as_ptr_range().end {
        let instruction = unsafe { Instruction::from_ptr(pc) }.unwrap();

        s.push_str(format!("{:x}: {:?}", pc.wrapping_sub(program.as_ptr() as usize) as usize, instruction.op_code).as_str());
        match instruction.op_size {
            OpSize::Byte => s.push('B'),
            OpSize::Word => s.push('W'),
            OpSize::Dword => s.push('D'),
            OpSize::Qword => s.push('Q'),
        }

        #[allow(clippy::single_match)]
        match instruction.op_code {
            Opcode::Const => 'label: {
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
            Opcode::VmExec => unsafe {
                let instr_size = pc.add(2).read_unaligned() as usize;
                pc = pc.add(instr_size + 1);
            }
            _ => {}
        }

        last_instr = Some(instruction.op_code);
        pc = unsafe { pc.add(instruction.length()) };
        s.push('\n');
    }

    Ok(s)
}
