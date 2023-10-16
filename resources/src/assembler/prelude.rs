//! Crate prelude, which can be used to import the most important types at once.

pub use super::Asm;
pub use super::MemOp;

pub use super::imm::{Imm16, Imm32, Imm64, Imm8};
pub use super::label::Label;
pub use super::reg::{Reg16, Reg32, Reg64, Reg8};

pub use super::insn::{Add, Call, Dec, Jmp, Jnz, Jz, Mov, Test};
