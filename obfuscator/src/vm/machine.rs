use anyhow::Result;
use std::mem::size_of;
use std::ops::{BitAnd, BitOr, BitXor, Not};
use std::ptr::{read_unaligned, write_unaligned};
use memoffset::offset_of;
use x86::bits64::rflags::RFlags;

#[repr(u8)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum Opcode {
    Const,
    ConstD,
    Load,
    LoadD,
    Store,
    StoreD,
    Add,
    AddD,
    Sub,
    SubD,
    Div,
    DivD,
    Mul,
    MulD,
    And,
    AndD,
    Or,
    OrD,
    Xor,
    XorD,
    Not,
    NotD,
    Cmp,
    CmpD,
    Jmp,
    Vmctx,
    VmAdd,
    VmSub,
    Vmexit,
}

#[repr(u8)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum JmpCond {
    Jmp,
    Je,
    Jne, //  Jnz,
    Jbe, // Jna,
    Ja, // Jnbe
    Jle, // Jng
    Jg, // Jnle
}

impl From<iced_x86::Mnemonic> for JmpCond {
    fn from(mnemonic: iced_x86::Mnemonic) -> Self {
        match mnemonic {
            iced_x86::Mnemonic::Jmp => JmpCond::Jmp,
            iced_x86::Mnemonic::Je => JmpCond::Je,
            iced_x86::Mnemonic::Jne => JmpCond::Jne, // jnz is jne
            iced_x86::Mnemonic::Jbe => JmpCond::Jbe, // jna is jbe
            iced_x86::Mnemonic::Ja => JmpCond::Ja, // jnbe is ja
            iced_x86::Mnemonic::Jle => JmpCond::Jle, // jng is jle
            iced_x86::Mnemonic::Jg => JmpCond::Jg, // Jnle is jg
            _ => panic!("unsupported jmp condition"),
        }
    }
}

#[repr(u8)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum Register {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl From<iced_x86::Register> for Register {
    fn from(reg: iced_x86::Register) -> Self {
        match reg {
            iced_x86::Register::RAX => Register::Rax,
            iced_x86::Register::RCX => Register::Rcx,
            iced_x86::Register::RDX => Register::Rdx,
            iced_x86::Register::RBX => Register::Rbx,
            iced_x86::Register::RSP => Register::Rsp,
            iced_x86::Register::RBP => Register::Rbp,
            iced_x86::Register::RSI => Register::Rsi,
            iced_x86::Register::RDI => Register::Rdi,
            iced_x86::Register::R8 => Register::R8,
            iced_x86::Register::R9 => Register::R9,
            iced_x86::Register::R10 => Register::R10,
            iced_x86::Register::R11 => Register::R11,
            iced_x86::Register::R12 => Register::R12,
            iced_x86::Register::R13 => Register::R13,
            iced_x86::Register::R14 => Register::R14,
            iced_x86::Register::R15 => Register::R15,
            iced_x86::Register::EAX => Register::Rax,
            iced_x86::Register::ECX => Register::Rcx,
            iced_x86::Register::EDX => Register::Rdx,
            iced_x86::Register::EBX => Register::Rbx,
            iced_x86::Register::ESP => Register::Rsp,
            iced_x86::Register::EBP => Register::Rbp,
            iced_x86::Register::ESI => Register::Rsi,
            iced_x86::Register::EDI => Register::Rdi,
            iced_x86::Register::R8D => Register::R8,
            iced_x86::Register::R9D => Register::R9,
            iced_x86::Register::R10D => Register::R10,
            iced_x86::Register::R11D => Register::R11,
            iced_x86::Register::R12D => Register::R12,
            iced_x86::Register::R13D => Register::R13,
            iced_x86::Register::R14D => Register::R14,
            iced_x86::Register::R15D => Register::R15,
            _ => panic!("unsupported register"),
        }
    }
}

macro_rules! binary_op {
    ($self:ident, $op:ident) => {{
        let (op2, op1) = ($self.stack_pop::<u64>(), $self.stack_pop::<u64>());
        let result = op1.$op(op2);

        $self.stack_push(result);
    }}
}

macro_rules! binary_op_save_flags {
    ($self:ident, $bit:ident, $op:ident) => {{
        let (op2, op1) = if size_of::<$bit>() == 1 {
            ($self.stack_pop::<u16>() as $bit, $self.stack_pop::<u16>() as $bit)
        } else {
            ($self.stack_pop::<$bit>(), $self.stack_pop::<$bit>())
        };

        let result = op1.$op(op2);

        $self.set_rflags();


        if size_of::<$bit>() == 1 {
            $self.stack_push(result as u16);
        } else {
            $self.stack_push(result);
        }
    }}
}


macro_rules! binary_op_arg1_save_flags {
    ($self:ident, $bit:ident, $op:ident) => {{
        let op1 = $self.stack_pop::<$bit>();
        let result = op1.$op();

        $self.set_rflags();

        $self.stack_push(result);
    }}
}


#[repr(C)]
pub struct Machine {
    pub(crate) pc: *const u8,
    pub(crate) sp: *mut u64,
    pub regs: [u64; 16],
    pub rflags: RFlags,
    pub(crate) program: Vec<u8>,
    pub(crate) vmstack: Vec<u64>,
    pub vmenter: region::Allocation,
    pub(crate) vmexit: region::Allocation,
}

impl Machine {
    #[cfg(target_env = "msvc")]
    #[allow(clippy::fn_to_numeric_cast)]
    pub fn new(program: &[u8]) -> Result<Self> {
        use iced_x86::code_asm::*;

        let mut m = Self {
            pc: std::ptr::null(),
            sp: std::ptr::null_mut(),
            regs: [0; 16],
            rflags: RFlags::new(),
            program: program.to_vec(),
            vmstack: [0; 0x1000].to_vec(),
            vmenter: region::alloc(region::page::size(), region::Protection::READ_WRITE_EXECUTE)?,
            vmexit: region::alloc(region::page::size(), region::Protection::READ_WRITE_EXECUTE)?,
        };

        // Generate VMENTER.
        let regmap: &[(&AsmRegister64, u8)] = &[
            (&rax, Register::Rax.into()),
            (&rcx, Register::Rcx.into()),
            (&rdx, Register::Rdx.into()),
            (&rbx, Register::Rbx.into()),
            (&rsp, Register::Rsp.into()),
            (&rbp, Register::Rbp.into()),
            (&rsi, Register::Rsi.into()),
            (&rdi, Register::Rdi.into()),
            (&r8, Register::R8.into()),
            (&r9, Register::R9.into()),
            (&r10, Register::R10.into()),
            (&r11, Register::R11.into()),
            (&r12, Register::R12.into()),
            (&r13, Register::R13.into()),
            (&r14, Register::R14.into()),
            (&r15, Register::R15.into()),
        ];

        let mut a = CodeAssembler::new(64)?;

        // todo this is kinda ub, since its a
        // potential use after free
        a.mov(rax, &mut m as *mut _ as u64)?;

        // Store the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(qword_ptr(rax + offset), **reg)?;
        }

        // Switch to the VM's CPU stack.


        a.mov(rcx, rax)?;
        a.mov(rax, Self::run as u64)?;
        a.jmp(rax)?;

        // TODO this is what gets patched into the target file
        let insts = a.assemble(m.vmenter.as_ptr::<u64>() as u64)?;

        unsafe {
            std::ptr::copy(insts.as_ptr(), m.vmenter.as_mut_ptr(), insts.len());
        };

        // Generate VMEXIT.
        let regmap: &[(&AsmRegister64, u8)] = &[
            (&rax, Register::Rax.into()),
            (&rdx, Register::Rbx.into()),
            // (&rbx, Register::Rbx.into()),
            // (&rsp, Register::Rsp.into()),
            // (&rbp, Register::Rbp.into()),
            // (&rsi, Register::Rsi.into()),
            // (&rdi, Register::Rdi.into()),
            (&r8, Register::R8.into()),
            (&r9, Register::R9.into()),
            (&r10, Register::R10.into()),
            (&r11, Register::R11.into()),
            // (&r12, Register::R12.into()),
            // (&r13, Register::R13.into()),
            // (&r14, Register::R14.into()),
            // (&r15, Register::R15.into()),
            // (&rcx, Register::Rbx.into()),
        ];

        let mut a = CodeAssembler::new(64)?;

        // Restore the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(**reg, qword_ptr(rcx + offset))?;
        }

        a.ret()?;

        let insts = a.assemble(m.vmexit.as_ptr::<u64>() as u64)?;

        unsafe {
            std::ptr::copy(insts.as_ptr(), m.vmexit.as_mut_ptr(), insts.len());
        };

        Ok(m)
    }

    unsafe fn stack_push<T: Sized>(&mut self, value: T) {
        assert_eq!(size_of::<T>() % 2, 0);
        self.sp = self.sp.cast::<T>().sub(1) as _;
        self.sp.cast::<T>().write_unaligned(value);
    }

    unsafe fn stack_pop<T: Sized>(&mut self) -> T {
        assert_eq!(size_of::<T>() % 2, 0);
        let value = self.sp.cast::<T>().read_unaligned();
        //*self.sp.cast::<T>() = null();
        self.sp = self.sp.cast::<T>().add(1) as _;
        value
    }

    #[inline(always)]
    pub fn set_rflags(&mut self) {
        self.rflags = x86::bits64::rflags::read();
    }

    #[allow(clippy::missing_safety_doc)]
    pub unsafe extern "C" fn run(&mut self) {
        self.pc = self.program.as_ptr();
        let start_pc = self.pc;
        self.sp = self.vmstack.as_mut_ptr()
            .add((self.vmstack.len() - 0x100 - size_of::<u64>()) / size_of::<*mut u64>());

        while self.pc < self.program.as_ptr_range().end {
            let op = Opcode::try_from(*self.pc).unwrap();
            self.pc = self.pc.add(1);

            match op {
                Opcode::Const => {
                    self.stack_push(read_unaligned(self.pc as *const u64));
                    self.pc = self.pc.add(size_of::<u64>());
                },
                Opcode::ConstD => {
                    self.stack_push(read_unaligned(self.pc as *const u32));
                    self.pc = self.pc.add(size_of::<u32>());
                }
                Opcode::Load => {
                    let value = (self.stack_pop::<u64>() as *const u64).read_unaligned();
                    self.stack_push::<u64>(value);
                },
                Opcode::LoadD => {
                    let value = (self.stack_pop::<u64>() as *const u64).read_unaligned();
                    self.stack_push::<u32>(value as u32);
                },
                Opcode::Store => {
                    let target_addr = self.stack_pop::<u64>();
                    let value = self.stack_pop::<u64>();

                    //  *self.stack_pop::<*mut u64>() = self.stack_pop::<u64>();
                    write_unaligned(target_addr as *mut u64, value);
                },
                Opcode::StoreD => {
                    let target_addr = self.stack_pop::<u64>();
                    let value = self.stack_pop::<u32>();

                    //  *self.stack_pop::<*mut u64>() = self.stack_pop::<u64>();
                    write_unaligned(target_addr as *mut u64, value as u64);
                }
                // todo expand on this
                // one solution is to have diff size opcodes
                /*
                opcode Add = 32bit
                opcode AddQ = 64bit
                opcode AddW = 16bit
                opcode AddB = 8 bit

                opcode add:
                    let = stack-1.wrapping_add(read(stack as *const i32/u32))
                opcode addq:
                    let = stack-1.wrapping_add(read(stack))
                 */
                Opcode::Div => binary_op_save_flags!(self, u64, wrapping_div), // unfinished
                Opcode::DivD => binary_op_save_flags!(self, u32, wrapping_div), // unfinished
                Opcode::Mul => {
                    binary_op_save_flags!(self, u64, wrapping_mul);
                },
                Opcode::MulD => {
                    binary_op_save_flags!(self, u32, wrapping_mul);
                },
                Opcode::Add => binary_op_save_flags!(self, u64, wrapping_add),
                Opcode::AddD => binary_op_save_flags!(self, u32, wrapping_add),
                Opcode::Sub => binary_op_save_flags!(self, u64, wrapping_sub),
                Opcode::SubD => binary_op_save_flags!(self, u32, wrapping_sub),
                Opcode::And => binary_op_save_flags!(self, u64, bitand),
                Opcode::AndD => binary_op_save_flags!(self, u32, bitand),
                Opcode::Or => binary_op_save_flags!(self, u64, bitor),
                Opcode::OrD => binary_op_save_flags!(self, u32, bitor),
                Opcode::Xor => binary_op_save_flags!(self, u64, bitxor),
                Opcode::XorD => binary_op_save_flags!(self, u32, bitxor),
                Opcode::Not => binary_op_arg1_save_flags!(self, u64, not),
                Opcode::NotD => binary_op_arg1_save_flags!(self, u32, not),
                Opcode::Cmp => {
                    let (op2, op1) = (self.stack_pop::<u64>(), self.stack_pop::<u64>());
                    let result = op1.wrapping_sub(op2);
                    self.set_rflags();
                    drop(result);
                },
                Opcode::CmpD => {
                    let (op2, op1) = (self.stack_pop::<u32>(), self.stack_pop::<u32>());
                    let result = op1.wrapping_sub(op2);
                    self.set_rflags();
                    drop(result);
                }
                Opcode::Jmp => {
                    let do_jmp = match JmpCond::try_from(*self.pc).unwrap() {
                        JmpCond::Jmp => true,
                        JmpCond::Je => self.rflags.contains(RFlags::FLAGS_ZF),
                        JmpCond::Jne => !self.rflags.contains(RFlags::FLAGS_ZF),
                        JmpCond::Jbe => self.rflags.contains(RFlags::FLAGS_ZF)
                            || self.rflags.contains(RFlags::FLAGS_CF),
                        JmpCond::Ja => (!self.rflags.contains(RFlags::FLAGS_ZF)
                            && !self.rflags.contains(RFlags::FLAGS_CF)),
                        JmpCond::Jle => self.rflags.contains(RFlags::FLAGS_SF) ^ self.rflags.contains(RFlags::FLAGS_OF)
                            || self.rflags.contains(RFlags::FLAGS_ZF),
                        JmpCond::Jg => self.rflags.contains(RFlags::FLAGS_SF) == self.rflags.contains(RFlags::FLAGS_OF) && !self.rflags.contains(RFlags::FLAGS_ZF)
                    };

                    self.pc = self.pc.add(1); // jmpcond

                    if do_jmp {
                        self.pc = start_pc.add(read_unaligned(self.pc as *const u64) as _);
                    } else {
                        self.pc = self.pc.add(size_of::<u64>());
                    }
                }
                Opcode::VmAdd => binary_op!(self, wrapping_add),
                Opcode::VmSub => binary_op!(self, wrapping_sub),
                Opcode::Vmctx => {
                    self.stack_push(self as *const _ as u64);
                }
                Opcode::Vmexit => {
                    break;
                }
            }
        }

        //    std::ptr::drop_in_place(addr_of_mut!((*self).vmstack));
        let vmexit: extern "C" fn(&mut Machine) =
            std::mem::transmute(self.vmexit.as_ptr::<()>());
        vmexit(self);
    }
}

#[derive(Default)]
pub struct Assembler {
    program: Vec<u8>,
}

impl Assembler {
    pub fn assemble(&self) -> Vec<u8> {
        self.program.clone()
    }

    pub fn len(&self) -> usize {
        self.program.len()
    }

    pub fn patch(&mut self, index: usize, value: u64) {
        self.program[index..][..8].copy_from_slice(&value.to_le_bytes());
    }

    pub fn const_(&mut self, v: u64) {
        self.emit(Opcode::Const);
        self.emit_u64(v);
    }

    pub fn constd_(&mut self, v: u32) {
        self.emit(Opcode::ConstD);
        self.emit_u32(v);
    }

    pub fn load(&mut self) {
        self.emit(Opcode::Load);
    }

    pub fn loadd(&mut self) {
        self.emit(Opcode::LoadD);
    }

    pub fn store(&mut self) {
        self.emit(Opcode::Store);
    }

    pub fn stored(&mut self) {
        self.emit(Opcode::StoreD);
    }

    pub fn add(&mut self) {
        self.emit(Opcode::Add);
    }

    pub fn addd(&mut self) {
        self.emit(Opcode::AddD);
    }

    pub fn sub(&mut self) {
        self.emit(Opcode::Sub);
    }

    pub fn subd(&mut self) {
        self.emit(Opcode::SubD);
    }

    pub fn div(&mut self) {
        self.emit(Opcode::Div);
    }

    pub fn divd(&mut self) {
        self.emit(Opcode::DivD);
    }

    pub fn mul(&mut self) {
        self.emit(Opcode::Mul);
    }

    pub fn muld(&mut self) {
        self.emit(Opcode::MulD);
    }

    pub fn and(&mut self) {
        self.emit(Opcode::And);
    }

    pub fn andd(&mut self) {
        self.emit(Opcode::AndD);
    }

    pub fn or(&mut self) {
        self.emit(Opcode::Or);
    }

    pub fn ord(&mut self) {
        self.emit(Opcode::OrD);
    }

    pub fn xor(&mut self) {
        self.emit(Opcode::Xor);
    }

    pub fn xord(&mut self) {
        self.emit(Opcode::XorD);
    }

    pub fn not(&mut self) {
        self.emit(Opcode::Not);
    }

    pub fn notd(&mut self) {
        self.emit(Opcode::NotD);
    }

    pub fn cmp(&mut self) {
        self.emit(Opcode::Cmp);
    }

    pub fn cmpd(&mut self) {
        self.emit(Opcode::CmpD);
    }

    pub fn jmp(&mut self, cond: JmpCond, target: u64) {
        self.emit(Opcode::Jmp);
        self.emit_byte(cond as u8);
        self.emit_u64(target);
    }

    pub fn vmadd(&mut self) {
        self.emit(Opcode::VmAdd);
    }

    pub fn vmsub(&mut self) {
        self.emit(Opcode::VmSub);
    }

    pub fn vmctx(&mut self) {
        self.emit(Opcode::Vmctx);
    }

    pub fn vmexit(&mut self) {
        self.emit(Opcode::Vmexit);
    }

    fn emit(&mut self, op: Opcode) {
        self.program.push(op as u8);
    }

    fn emit_byte(&mut self, byte: u8) {
        self.program.push(byte);
    }

    fn emit_u32(&mut self, value: u32) {
        self.program.extend_from_slice(&value.to_le_bytes());
    }

    fn emit_u64(&mut self, value: u64) {
        self.program.extend_from_slice(&value.to_le_bytes());
    }
}

pub fn disassemble(program: &[u8]) -> Result<String> {
    let mut s = String::new();
    let mut pc = program.as_ptr();
    let mut index = 0;

    while pc < program.as_ptr_range().end {
        let op = Opcode::try_from(unsafe { *pc })?;
        pc = unsafe { pc.add(1) };

        s.push_str(format!("{:x}: {:?}", pc.wrapping_sub(program.as_ptr() as usize) as usize - 1, op).as_str());

        #[allow(clippy::single_match)]
        match op {
            Opcode::Const => unsafe {
                //let v = *(pc as *const u64);
                let v = read_unaligned(pc as *const usize);
                pc = pc.add(size_of::<u64>());
                if let Ok(reg) = Register::try_from((v.wrapping_sub(offset_of!(Machine, regs))) as u8 / 8) {
                    s.push_str(format!(" {:?}", reg).as_str());
                } else {
                    s.push_str(format!(" {}", v).as_str());
                }
            },
            Opcode::ConstD => unsafe {
                //let v = *(pc as *const u64);
                let v = read_unaligned(pc as *const u32);
                pc = pc.add(size_of::<u32>());
                if let Ok(reg) = Register::try_from((v.wrapping_sub(offset_of!(Machine, regs) as u32)) as u8 / 8) {
                    s.push_str(format!(" {:?}", reg).as_str());
                } else {
                    s.push_str(format!(" {}", v).as_str());
                }
            },
            Opcode::Jmp => unsafe {
                let cond = JmpCond::try_from(read_unaligned(pc)).unwrap();
                pc = pc.add(size_of::<u8>());
                let val = read_unaligned(pc as *const u64);
                pc = pc.add(size_of::<u64>());
                s.push_str(format!(" {:?} 0x{:?}", cond, val).as_str());
            }
            _ => {}
        }

        s.push('\n');
        index += 1;
    }

    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembler_and_machine() {
        let mut a = Assembler::default();
        let x = 8u64;
        let y = 2u64;
        let mut z = 0u64;

        a.const_(&x as *const _ as u64);
        a.load();
        a.const_(&y as *const _ as u64);
        a.load();
        a.div();
        a.const_(&mut z as *mut _ as u64);
        a.store();

        unsafe { Machine::new(&a.assemble()).unwrap().run() };
        assert_eq!(z, 4);
    }
}