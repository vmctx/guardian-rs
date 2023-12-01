#[repr(u8)]
#[derive(PartialEq, Copy, Clone)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum Opcode {
    Const,
    Load,
    LoadXmm,
    // only diff is that 32 bit doesnt cast as 64 bit ptr
    Store,
    StoreXmm,
    StoreReg,
    StoreRegZx,
    Add,
    Sub,
    Div,
    IDiv,
    Shr,
    Combine,
    Split,
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

#[repr(u8)]
#[derive(Debug, Copy, Clone, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum OpSize {
    Byte = 1,
    Word = 2,
    Dword = 4,
    Qword = 8,
}

#[repr(u8)]
#[derive(Clone)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum JmpCond {
    Jmp,
    Je,
    Jne, //  Jnz,
    Jbe, // Jna,
    Ja, // Jnbe
    Jae, // jnc
    Jle, // Jng
    Jg, // Jnle
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

#[repr(u8)]
#[derive(num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum XmmRegister {
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Xmm8,
    Xmm9,
    Xmm10,
    Xmm11,
    Xmm12,
    Xmm13,
    Xmm14,
    Xmm15,
}

impl Register {
    pub const fn offset(self) -> usize {
        self as u8 as usize * 8
    }
}

impl XmmRegister {
    pub const fn offset(self) -> usize {
        self as u8 as usize * 16
    }
}

// 128-bit integers don't currently have a known stable ABI
// dont know if this could cause any problems atm
// https://github.com/rust-lang/rust/pull/116672
#[repr(C, align(16))]
pub struct XSaveMin {
    #[cfg(target_pointer_width = "64")]
    pub xmm_registers: [u128; 16],
    #[cfg(target_pointer_width = "32")]
    pub xmm_registers: [u128; 8],
    float_registers: [u128; 8],
}