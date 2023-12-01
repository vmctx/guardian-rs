use iced_x86::{InstructionInfoFactory, MemorySize, OpKind};
use exe::{PE, RelocationDirectory, VecPE};
use memoffset::offset_of;
use num_enum::TryFromPrimitiveError;

use crate::shared::{JmpCond, OpSize, Register, XSaveMin, XmmRegister};
use crate::virtualizer::assembler::Machine;

pub trait Reloc {
    fn has_reloc_entry(&self, pe: Option<&VecPE>) -> bool;
}

impl Reloc for iced_x86::Instruction {
    fn has_reloc_entry(&self, pe: Option<&VecPE>) -> bool {
        let Some(pe) = pe else { return false; };
        let pe_image_base = pe.get_image_base().unwrap();

        let reloc_table = RelocationDirectory::parse(pe).unwrap();
        let Ok(relocs) = reloc_table.relocations(pe, pe_image_base) else {
            return false;
        };

        let instr_rva = (self.ip() - pe_image_base) as u32;
        relocs.iter().any(|(rva, _)| {
            rva.0 >= instr_rva && rva.0 < instr_rva + self.len() as u32
        })
    }
}

pub trait OpSized: Sized {
    fn to_le_bytes(self) -> Vec<u8>;
    fn as_op_size() -> OpSize;
}

impl OpSized for u8 {
    fn to_le_bytes(self) -> Vec<u8> { self.to_le_bytes().to_vec() }
    fn as_op_size() -> OpSize { OpSize::Byte }
}

impl OpSized for u16 {
    fn to_le_bytes(self) -> Vec<u8> { self.to_le_bytes().to_vec() }
    fn as_op_size() -> OpSize { OpSize::Word }
}

impl OpSized for u32 {
    fn to_le_bytes(self) -> Vec<u8> { self.to_le_bytes().to_vec() }
    fn as_op_size() -> OpSize { OpSize::Dword }
}

impl OpSized for u64 {
    fn to_le_bytes(self) -> Vec<u8> { self.to_le_bytes().to_vec() }
    fn as_op_size() -> OpSize { OpSize::Qword }
}

impl From<iced_x86::Register> for OpSize {
    fn from(reg: iced_x86::Register) -> Self {
        if !reg.is_gpr() {
            panic!("{:?} unsupported register", reg);
        }

        if reg.is_gpr8() {
            OpSize::Byte
        } else if reg.is_gpr16() {
            OpSize::Word
        } else if reg.is_gpr32() {
            OpSize::Dword
        } else {
            OpSize::Qword
        }
    }
}

impl TryFrom<MemorySize> for OpSize {
    type Error = TryFromPrimitiveError<OpSize>;

    fn try_from(size: MemorySize) -> Result<Self, Self::Error> {
        Self::try_from(size.size() as u8)
    }
}

impl TryFrom<&iced_x86::Instruction> for OpSize {
    type Error = TryFromPrimitiveError<OpSize>;

    fn try_from(inst: &iced_x86::Instruction) -> Result<Self, Self::Error> {
        if inst.memory_size() != MemorySize::Unknown {
            Self::try_from(inst.memory_size())
        } else if inst.op0_register() != iced_x86::Register::None {
            Self::try_from(inst.op0_register().size() as u8)
        } else {
            let value = match inst.op0_kind() {
                OpKind::Immediate8 => OpSize::Byte,
                OpKind::Immediate8to16 => OpSize::Word,
                OpKind::Immediate16 => OpSize::Word,
                OpKind::Immediate8to32 => OpSize::Dword,
                OpKind::Immediate32 => OpSize::Dword,
                OpKind::Immediate8to64 => OpSize::Qword,
                OpKind::Immediate32to64 => OpSize::Qword,
                OpKind::Immediate64 => OpSize::Qword,
                _ => panic!("unsupported operand")
            };
            Ok(value)
        }
    }
}

pub trait FreeReg {
    fn get_free_regs(&self) -> Vec<iced_x86::code_asm::AsmRegister64>;
}

impl FreeReg for iced_x86::Instruction {
    fn get_free_regs(&self) -> Vec<iced_x86::code_asm::AsmRegister64> {
        use iced_x86::code_asm::get_gpr64;

        let reg_map: &[iced_x86::Register] = &[
            iced_x86::Register::RBX,
            iced_x86::Register::RDX,
            iced_x86::Register::RSI,
            iced_x86::Register::RDI,
            iced_x86::Register::R8,
            iced_x86::Register::R9,
            iced_x86::Register::R10,
            iced_x86::Register::R11,
            iced_x86::Register::R12,
            iced_x86::Register::R13,
            iced_x86::Register::R14,
            iced_x86::Register::R15,
        ];

        let mut instr_info_factory = InstructionInfoFactory::new();
        let instr_info = instr_info_factory.info(self);

        let used_regs = instr_info.used_registers().iter()
            .map(|reg| reg.register()).collect::<Vec<iced_x86::Register>>();

        reg_map.iter().filter(|reg| !used_regs.contains(reg))
            .map(|reg| get_gpr64(*reg).unwrap()).collect()
    }
}

pub trait HigherLower8Bit {
    fn is_higher_8_bit(&self) -> bool;
    fn is_lower_8_bit(&self) -> bool;
}

impl HigherLower8Bit for iced_x86::Register {
    fn is_higher_8_bit(&self) -> bool {
        matches!(self, Self::AH | Self::BH |
             Self::CH | Self::DH)
    }

    fn is_lower_8_bit(&self) -> bool {
        matches!(self, Self::AL | Self::BL | Self::CL |
            Self::DL | Self::SIL | Self::DIL
            | Self::SPL | Self::BPL)
    }
}

pub trait RegUp {
    /// get 16 bit reg from 8 bit reg
    fn get_gpr_16(self) -> Self;
}

impl RegUp for iced_x86::Register {
    fn get_gpr_16(self) -> Self {
        match self {
            Self::AH => Self::AX,
            Self::AL => Self::AX,
            Self::BH => Self::BX,
            Self::BL => Self::BX,
            Self::CH => Self::CX,
            Self::CL => Self::CX,
            Self::DH => Self::DX,
            Self::DL => Self::DX,
            Self::SIL => Self::SI,
            Self::DIL => Self::DI,
            Self::SPL => Self::SP,
            Self::BPL => Self::BP,
            Self::R8L => Self::R8W,
            Self::R9L => Self::R9W,
            Self::R10L => Self::R10W,
            Self::R11L => Self::R11W,
            Self::R12L => Self::R12W,
            Self::R13L => Self::R13W,
            Self::R14L => Self::R14W,
            Self::R15L => Self::R15W,
            _ => Self::None
        }
    }
}

impl From<iced_x86::Mnemonic> for JmpCond {
    fn from(mnemonic: iced_x86::Mnemonic) -> Self {
        match mnemonic {
            iced_x86::Mnemonic::Jmp => JmpCond::Jmp,
            iced_x86::Mnemonic::Je => JmpCond::Je,
            iced_x86::Mnemonic::Jne => JmpCond::Jne, // jnz is jne
            iced_x86::Mnemonic::Jbe => JmpCond::Jbe, // jna is jbe
            iced_x86::Mnemonic::Ja => JmpCond::Ja, // jnbe is ja
            iced_x86::Mnemonic::Jae => JmpCond::Jae, // Jae is jnc
            iced_x86::Mnemonic::Jle => JmpCond::Jle, // jng is jle
            iced_x86::Mnemonic::Jg => JmpCond::Jg, // Jnle is jg
            _ => panic!("unsupported jmp condition"),
        }
    }
}

impl From<iced_x86::Register> for Register {
    fn from(reg: iced_x86::Register) -> Self {
        match reg {
            iced_x86::Register::RAX => Register::Rax,
            iced_x86::Register::RBX => Register::Rbx,
            iced_x86::Register::RCX => Register::Rcx,
            iced_x86::Register::RDX => Register::Rdx,
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
            iced_x86::Register::EBX => Register::Rbx,
            iced_x86::Register::ECX => Register::Rcx,
            iced_x86::Register::EDX => Register::Rdx,
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
            iced_x86::Register::AX => Register::Rax,
            iced_x86::Register::BX => Register::Rbx,
            iced_x86::Register::CX => Register::Rcx,
            iced_x86::Register::DX => Register::Rdx,
            iced_x86::Register::SI => Register::Rsi,
            iced_x86::Register::DI => Register::Rdi,
            iced_x86::Register::SP => Register::Rsp,
            iced_x86::Register::BP => Register::Rbp,
            iced_x86::Register::R8W => Register::R8,
            iced_x86::Register::R9W => Register::R9,
            iced_x86::Register::R10W => Register::R10,
            iced_x86::Register::R11W => Register::R11,
            iced_x86::Register::R12W => Register::R12,
            iced_x86::Register::R13W => Register::R13,
            iced_x86::Register::R14W => Register::R14,
            iced_x86::Register::R15W => Register::R15,
            iced_x86::Register::AH => Register::Rax,
            iced_x86::Register::AL => Register::Rax,
            iced_x86::Register::BH => Register::Rbx,
            iced_x86::Register::BL => Register::Rbx,
            iced_x86::Register::CH => Register::Rcx,
            iced_x86::Register::CL => Register::Rcx,
            iced_x86::Register::DH => Register::Rdx,
            iced_x86::Register::DL => Register::Rdx,
            iced_x86::Register::SIL => Register::Rsi,
            iced_x86::Register::DIL => Register::Rdi,
            iced_x86::Register::SPL => Register::Rsp,
            iced_x86::Register::BPL => Register::Rbp,
            iced_x86::Register::R8L => Register::R8,
            iced_x86::Register::R9L => Register::R9,
            iced_x86::Register::R10L => Register::R10,
            iced_x86::Register::R11L => Register::R11,
            iced_x86::Register::R12L => Register::R12,
            iced_x86::Register::R13L => Register::R13,
            iced_x86::Register::R14L => Register::R14,
            iced_x86::Register::R15L => Register::R15,
            _ => panic!("unsupported register"),
        }
    }
}

impl From<iced_x86::Register> for XmmRegister {
    fn from(reg: iced_x86::Register) -> Self {
        match reg {
            iced_x86::Register::XMM0 => XmmRegister::Xmm0,
            iced_x86::Register::XMM1 => XmmRegister::Xmm1,
            iced_x86::Register::XMM2 => XmmRegister::Xmm2,
            iced_x86::Register::XMM3 => XmmRegister::Xmm3,
            iced_x86::Register::XMM4 => XmmRegister::Xmm4,
            iced_x86::Register::XMM5 => XmmRegister::Xmm5,
            iced_x86::Register::XMM6 => XmmRegister::Xmm6,
            iced_x86::Register::XMM7 => XmmRegister::Xmm7,
            iced_x86::Register::XMM8 => XmmRegister::Xmm8,
            iced_x86::Register::XMM9 => XmmRegister::Xmm9,
            iced_x86::Register::XMM10 => XmmRegister::Xmm10,
            iced_x86::Register::XMM11 => XmmRegister::Xmm11,
            iced_x86::Register::XMM12 => XmmRegister::Xmm12,
            iced_x86::Register::XMM13 => XmmRegister::Xmm13,
            iced_x86::Register::XMM14 => XmmRegister::Xmm14,
            iced_x86::Register::XMM15 => XmmRegister::Xmm15,
            _ => panic!("unsupported register"),
        }
    }
}

pub trait MachineRegOffset {
    fn reg_offset(&self) -> u64;
}

impl MachineRegOffset for iced_x86::Register {
    /// Get offset to reg in [Machine] struct
    fn reg_offset(&self) -> u64 {
        if self.is_xmm() {
            offset_of!(Machine, fxsave) as u64 + memoffset::offset_of!(XSaveMin, xmm_registers) as u64
                + u8::from(XmmRegister::from(*self)) as u64 * 16
        } else {
            offset_of!(Machine, regs) as u64
                + u8::from(Register::from(*self)) as u64 * 8
        }
    }
}