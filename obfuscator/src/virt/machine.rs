use anyhow::Result;
use std::ptr::read_unaligned;
use iced_x86::{Encoder, InstructionInfoFactory, MemorySize, OpKind};
use iced_x86::code_asm::{CodeAssembler, qword_ptr};
use num_enum::TryFromPrimitiveError;

#[repr(C)]
pub struct Machine {
    pub(crate) pc: *const u8,
    pub(crate) sp: *mut u64,
    pub regs: [u64; 16],
    pub rflags: u64,
    pub vmstack: *mut u64,
    pub cpustack: *mut u8,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum OpSize {
    Byte = 1,
    Word = 2,
    Dword = 4,
    Qword = 8,
}

#[repr(u8)]
#[derive(PartialEq)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum Opcode {
    Const,
    Load,
    // only diff is that 32 bit doesnt cast as 64 bit ptr
    Store,
    StoreReg,
    Add,
    Sub,
    Div,
    Mul,
    And,
    Or,
    Xor,
    Not,
    Cmp,
    RotR,
    RotL,
    //
    Jmp,
    Vmctx,
    VmAdd,
    VmMul,
    VmSub,
    VmReloc,
    VmExec,
    VmExit,
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

    fn try_from(size: MemorySize) -> std::result::Result<Self, Self::Error> {
        Self::try_from(size.size() as u8)
    }
}

impl TryFrom<&iced_x86::Instruction> for OpSize {
    type Error = TryFromPrimitiveError<OpSize>;

    fn try_from(inst: &iced_x86::Instruction) -> std::result::Result<Self, Self::Error> {
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
                _ => panic!("invalid immediate?")
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
        match self {
            Self::AH | Self::BH |
            Self::CH | Self::DH => true,
            _ => false,
        }
    }

    fn is_lower_8_bit(&self) -> bool {
        match self {
            Self::AL | Self::BL | Self::CL |
            Self::DL | Self::SIL | Self::DIL
            | Self::SPL | Self::BPL => true,
            _ => false,
        }
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

#[repr(u8)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum JmpCond {
    Jmp,
    Je,
    Jne,
    //  Jnz,
    Jbe,
    // Jna,
    Ja,
    // Jnbe
    Jle,
    // Jng
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
        // reg.full_register() and exclude rip?
        // maybe when i add xmm/ymm/zmm support
        // probably only support xmm (128 bit) 0-15
        // will have to see maybe dont allocate struct on stack
        // but its better to
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

    pub fn const_<T: OpSized>(&mut self, v: T) {
        self.emit_sized::<T>(Opcode::Const);
        self.emit_const(v);
    }

    pub fn load<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Load);
    }

    pub fn store<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Store);
    }

    pub fn store_reg<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::StoreReg);
    }

    pub fn add<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Add);
    }

    pub fn sub<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Sub);
    }

    pub fn div<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Div);
    }

    pub fn mul<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Mul);
    }

    pub fn and<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::And);
    }

    pub fn or<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Or);
    }

    pub fn xor<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Xor);
    }

    pub fn not<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Not);
    }

    pub fn cmp<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Cmp);
    }

    pub fn jmp(&mut self, cond: JmpCond, target: u64) {
        self.emit(Opcode::Jmp);
        self.emit_const::<u8>(cond as u8);
        // could also be u8 or u16
        self.emit_const::<u64>(target);
    }

    pub fn rot_right(&mut self) {
        self.emit_sized::<u16>(Opcode::RotR);
    }

    pub fn rot_left(&mut self) {
        self.emit_sized::<u16>(Opcode::RotL);
    }

    pub fn vmadd(&mut self) {
        self.emit(Opcode::VmAdd);
    }

    pub fn vmsub(&mut self) {
        self.emit(Opcode::VmSub);
    }

    pub fn vmmul(&mut self) {
        self.emit(Opcode::VmMul);
    }

    pub fn vmctx(&mut self) {
        self.emit(Opcode::Vmctx);
    }

    pub fn vmreloc(&mut self, image_base: u64) {
        self.emit(Opcode::VmReloc);
        self.emit_const::<u64>(image_base);
    }

    pub fn vmexec(&mut self, mut instr: iced_x86::Instruction, image_base: u64) {
        self.emit(Opcode::VmExec);
        if instr.is_ip_rel_memory_operand() {
            // todo improve and make sure regs are really not used
            let regs = instr.get_free_regs();
            assert!(regs.len() >= 2);

            let mut asm = CodeAssembler::new(64).unwrap();
            asm.push(regs[0]).unwrap();
            asm.push(regs[1]).unwrap();
            asm.mov(regs[0], instr.next_ip() - image_base).unwrap();
            asm.mov(regs[1], qword_ptr(0x60).gs()).unwrap();
            asm.mov(regs[1], qword_ptr(regs[1] + 0x10)).unwrap();
            asm.add(regs[0], regs[1]).unwrap();
            asm.pop(regs[1]).unwrap();
            //
            instr.set_memory_base(iced_x86::Register::from(regs[0]));
            asm.add_instruction(instr).unwrap();
            //
            asm.pop(regs[0]).unwrap();

            let instr_buffer = asm.assemble(0).unwrap();
            self.emit_const(instr_buffer.len() as u8);
            self.program.extend_from_slice(&instr_buffer);
        } else {
            let mut encoder = Encoder::new(64);
            encoder.encode(&instr, instr.ip()).unwrap();
            let instr_buffer = encoder.take_buffer();
            self.emit_const(instr_buffer.len() as u8);
            self.program.extend_from_slice(&instr_buffer);
        }
    }

    pub fn vmexit(&mut self) {
        self.emit(Opcode::VmExit);
    }

    fn emit_sized<T: OpSized>(&mut self, op: Opcode) {
        self.program.push(op.into());
        self.program.push(T::as_op_size().into());
    }

    fn emit(&mut self, op: Opcode) {
        self.program.push(op.into());
        // testing size encoding on every instruction
        self.program.push(u64::as_op_size().into());
    }

    fn emit_const<T: OpSized>(&mut self, value: T) {
        self.program.extend_from_slice(&value.to_le_bytes());
    }
}

pub fn disassemble(program: &[u8]) -> Result<String> {
    let mut s = String::new();
    let mut pc = program.as_ptr();

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
            Opcode::Const => unsafe {
                //let v = *(pc as *const u64);
                let value = instruction.value.unwrap();

                if let Ok(reg) = Register::try_from((value.wrapping_sub(16)) as u8 / 8) {
                    s.push_str(format!(" {:?}", reg).as_str());
                } else {
                    s.push_str(format!(" {}", value).as_str());
                }
            },
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

        pc = unsafe { pc.add(instruction.length()) };

        s.push('\n');
    }

    Ok(s)
}
