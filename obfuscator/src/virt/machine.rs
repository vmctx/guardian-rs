use anyhow::Result;
use std::mem::size_of;
use std::ptr::read_unaligned;

#[repr(C)]
pub struct Machine {
    pub(crate) pc: *const u8,
    pub(crate) sp: *mut u64,
    pub regs: [u64; 16],
    pub rflags: u64,
    pub(crate) vmstack: Vec<u64>,
}

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
        let op = Opcode::try_from(unsafe { *pc }).unwrap();
        pc = unsafe { pc.add(1) };

        s.push_str(format!("{:x}: {:?}", pc.wrapping_sub(program.as_ptr() as usize) as usize - 1, op).as_str());

        #[allow(clippy::single_match)]
        match op {
            Opcode::Const => unsafe {
                //let v = *(pc as *const u64);
                let v = read_unaligned(pc as *const usize);
                pc = pc.add(size_of::<u64>());
                if let Ok(reg) = Register::try_from((v.wrapping_sub(16)) as u8 / 8) {
                    s.push_str(format!(" {:?}", reg).as_str());
                } else {
                    s.push_str(format!(" {}", v).as_str());
                }
            },
            Opcode::ConstD => unsafe {
                //let v = *(pc as *const u64);
                let v = read_unaligned(pc as *const u32);
                pc = pc.add(size_of::<u32>());
                if let Ok(reg) = Register::try_from((v.wrapping_sub(16 as u32)) as u8 / 8) {
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
