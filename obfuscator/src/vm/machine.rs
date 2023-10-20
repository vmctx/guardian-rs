use std::arch::asm;
use anyhow::Result;
use std::mem::size_of;
use std::ops::{BitAnd, BitOr, BitXor};
use std::ptr::{read_unaligned, write_unaligned};
use memoffset::offset_of;
use x86::bits64::rflags::RFlags;

#[repr(u8)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum Opcode {
    Const,
    Load,
    Store,
    Add,
    Sub,
    Div,
    Mul,
    And,
    Or,
    Xor,
    Cmp,
    Vmctx,
    Vmexit,
}

#[repr(u8)]
#[derive(num_enum::IntoPrimitive)]
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
        let result = read_unaligned($self.sp.sub(1)).$op(read_unaligned($self.sp));

        $self.set_of_cf();

        write_unaligned(
            $self.sp.sub(1),
            result,
        );

        $self.sp = $self.sp.sub(1);
    }}
}

macro_rules! binary_op_save_flags {
    ($self:ident, $op:ident) => {{
        let result = read_unaligned($self.sp.sub(1)).$op(read_unaligned($self.sp));

        $self.set_rflags();

        write_unaligned(
            $self.sp.sub(1),
            result,
        );

        $self.sp = $self.sp.sub(1);
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
    pub(crate) cpustack: Vec<u8>,
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
            cpustack: [0; 0x1000].to_vec(),
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

        // todo this is kinda up, since its a
        // potential use after free
        a.mov(rax, &mut m as *mut _ as u64)?;

        // Store the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(qword_ptr(rax + offset), **reg)?;
        }

        // Switch to the VM's CPU stack.
        let vm_rsp = unsafe {
            m.cpustack
                .as_ptr()
                .add(m.cpustack.len() - 0x100 - size_of::<u64>()) as u64
        };
        a.mov(rsp, vm_rsp)?;

        a.mov(rcx, rax)?;
        a.mov(rax, Self::run as u64)?; // TODO translate to assembly? probably or patch into target binary
        a.jmp(rax)?;

        // TODO this is what gets patched into the target file
        let insts = a.assemble(m.vmenter.as_ptr::<u64>() as u64)?;

        unsafe {
            std::ptr::copy(insts.as_ptr(), m.vmenter.as_mut_ptr(), insts.len());
        };

        // Generate VMEXIT.
        let regmap: &[(&AsmRegister64, u8)] = &[
            (&rax, Register::Rax.into()),
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

        // Restore the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(**reg, qword_ptr(rcx + offset))?;
        }

        a.jmp(rdx)?;

        let insts = a.assemble(m.vmexit.as_ptr::<u64>() as u64)?;

        unsafe {
            std::ptr::copy(insts.as_ptr(), m.vmexit.as_mut_ptr(), insts.len());
        };

        Ok(m)
    }

    // save carry and overflow cause why not
    #[inline(always)]
    pub fn set_of_cf(&mut self) {
        let rflags = x86::bits64::rflags::read();
        self.rflags.set(RFlags::FLAGS_OF, rflags.contains(RFlags::FLAGS_OF));
        self.rflags.set(RFlags::FLAGS_CF, rflags.contains(RFlags::FLAGS_CF));
    }

    #[inline(always)]
    pub fn set_rflags(&mut self) {
        self.rflags = x86::bits64::rflags::read();
    }

    // TODO to make this useable static in a patched binary, i have to translate the
    // program to assembly like in the machine::new function
    // this is currently JIT (just in time) have to translate to
    // AOT (Ahead of time) but idk if that makes sense because then its
    // literally the same as if its not virtualized like what urgh
    // gotta check virtualizer protector projects to understand
    #[allow(clippy::missing_safety_doc)]
    pub unsafe extern "C" fn run(&mut self) {
        self.pc = self.program.as_ptr();
        self.sp = self.vmstack.as_mut_ptr();

        while self.pc < self.program.as_ptr_range().end {
            let op = Opcode::try_from(*self.pc).unwrap();
            self.pc = self.pc.add(1);

            match op {
                Opcode::Const => {
                    write_unaligned(self.sp.add(1), read_unaligned(self.pc as *const u64));
                    self.sp = self.sp.add(1);
                    self.pc = self.pc.add(size_of::<u64>());
                }
                Opcode::Load => *self.sp = *(*self.sp as *const u64),
                Opcode::Store => {
                    write_unaligned(*self.sp as *mut u64, read_unaligned(self.sp.sub(1)));
                    self.sp = self.sp.sub(2);
                }
                Opcode::Add => binary_op!(self, wrapping_add),
                Opcode::Div => binary_op!(self, wrapping_div),
                Opcode::Mul => binary_op!(self, wrapping_mul),
                Opcode::Sub => binary_op_save_flags!(self, wrapping_sub),
                Opcode::And => binary_op_save_flags!(self, bitand),
                Opcode::Or => binary_op_save_flags!(self, bitor),
                Opcode::Xor => binary_op_save_flags!(self, bitxor),
                Opcode::Cmp => {
                    asm!("cmp {}, {}",
                        in(reg) read_unaligned(self.sp.sub(1)),
                        in(reg) read_unaligned(self.sp)
                    );
                    self.set_rflags();
                }
                Opcode::Vmctx => {
                    write_unaligned(self.sp.add(1), self as *const _ as u64);
                    self.sp = self.sp.add(1);
                }
                Opcode::Vmexit => {
                    let exit_ip = read_unaligned(self.sp);
                    self.sp = self.sp.sub(1);
                    let vmexit: extern "C" fn(&mut Machine, u64) =
                        std::mem::transmute(self.vmexit.as_ptr::<()>());
                    vmexit(self, exit_ip);
                }
            }
        }
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

    pub fn const_(&mut self, v: u64) {
        self.emit(Opcode::Const);
        self.emit_u64(v);
    }

    pub fn load(&mut self) {
        self.emit(Opcode::Load);
    }

    pub fn store(&mut self) {
        self.emit(Opcode::Store);
    }

    pub fn add(&mut self) {
        self.emit(Opcode::Add);
    }

    pub fn sub(&mut self) {
        self.emit(Opcode::Sub);
    }

    pub fn div(&mut self) {
        self.emit(Opcode::Div);
    }

    pub fn mul(&mut self) {
        self.emit(Opcode::Mul);
    }

    pub fn and(&mut self) {
        self.emit(Opcode::And);
    }

    pub fn or(&mut self) {
        self.emit(Opcode::Or);
    }

    pub fn xor(&mut self) {
        self.emit(Opcode::Xor);
    }

    pub fn cmp(&mut self) {
        self.emit(Opcode::Cmp);
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

    fn emit_u64(&mut self, value: u64) {
        self.program.extend_from_slice(&value.to_le_bytes());
    }
}

pub fn disassemble(program: &[u8]) -> Result<String> {
    let mut s = String::new();
    let mut pc = program.as_ptr();

    while pc < program.as_ptr_range().end {
        let op = Opcode::try_from(unsafe { *pc })?;
        pc = unsafe { pc.add(1) };

        s.push_str(format!("{:?}", op).as_str());

        #[allow(clippy::single_match)]
        match op {
            Opcode::Const => unsafe {
                //let v = *(pc as *const u64);
                let v = read_unaligned(pc as *const u64);
                pc = pc.add(size_of::<u64>());
                s.push_str(format!(" {}", v).as_str());
            },
            _ => {}
        }

        s.push('\n');
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