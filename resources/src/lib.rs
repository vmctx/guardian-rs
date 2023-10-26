#![feature(asm_const)]

#![no_std]
#![no_main]
extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::mem::size_of;
use core::ops::{BitAnd, BitOr, BitXor, Not};
use core::ptr::{addr_of_mut, drop_in_place, read_unaligned, write_unaligned};

use x86::bits64::rflags::RFlags;

use crate::vm::vmexit;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

mod crt;
// mod region;
mod vm;
mod syscalls;
#[allow(dead_code)]
mod assembler;

#[global_allocator]
static ALLOCATOR: allocator::Allocator = allocator::Allocator;

mod allocator;

#[repr(u8)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum Opcode {
    Const,
    Load,
    Store,
    Add,
    AddD,
    Sub,
    SubD,
    Div,
    Mul,
    And,
    Or,
    Xor,
    Not,
    Cmp,
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

macro_rules! binary_op {
    ($self:ident, $op:ident) => {{
        let result = read_unaligned($self.sp.sub(1)).$op(read_unaligned($self.sp));

        write_unaligned(
            $self.sp.sub(1),
            result,
        );

        $self.sp = $self.sp.sub(1);
    }}
}

macro_rules! binary_op_save_flags {
    ($self:ident, $bit:ident, $op:ident) => {{
        let result = read_unaligned($self.sp.sub(1) as *const $bit).$op(read_unaligned($self.sp as *const $bit));

        $self.set_rflags();

        write_unaligned(
            $self.sp.sub(1),
            result as _,
        );

        $self.sp = $self.sp.sub(1);
    }}
}


macro_rules! binary_op_arg1_save_flags {
    ($self:ident, $op:ident) => {{
        let result = read_unaligned($self.sp).$op();

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
    pub rflags: u64,
    pub(crate) vmstack: Vec<u64>,
}

impl Machine {
    #[no_mangle]
    pub unsafe extern "C" fn new_vm(out: *mut Self) {
        *out = Self {
            pc: core::ptr::null(),
            sp: core::ptr::null_mut(),
            regs: [0; 16],
            rflags: 0,
            vmstack: vec![0u64; 0x1000],
        };
    }

    #[allow(clippy::missing_safety_doc)]
    #[no_mangle]
    pub unsafe extern "C" fn run(&mut self, program: *const u8) {
        self.pc = program;
        self.sp = self.vmstack.as_mut_ptr();

       loop {
            let op = Opcode::try_from(*self.pc).unwrap();
            // increase program counter by one byte
            // for const, this will load the address
            self.pc = self.pc.add(1);

            match op {
                Opcode::Const => {
                    write_unaligned(self.sp.add(1), read_unaligned(self.pc as *const u64));
                    self.sp = self.sp.add(1);
                    // increase program counter to skip value (8 bytes)
                    self.pc = self.pc.add(size_of::<u64>());
                }
                Opcode::Load => *self.sp = *(*self.sp as *const u64),
                Opcode::Store => {
                    // stores last value in address loaded by const
                    write_unaligned(*self.sp as *mut u64, read_unaligned(self.sp.sub(1)));
                    self.sp = self.sp.sub(2);
                }
                Opcode::Div => binary_op_save_flags!(self, u64, wrapping_div), // unfinished
                Opcode::Mul => binary_op_save_flags!(self, u64, wrapping_mul),
                Opcode::Add => binary_op_save_flags!(self, u64, wrapping_add),
                Opcode::AddD => binary_op_save_flags!(self, u32, wrapping_add),
                Opcode::Sub => binary_op_save_flags!(self, u64, wrapping_sub),
                Opcode::SubD => binary_op_save_flags!(self, u32, wrapping_sub),
                Opcode::And => binary_op_save_flags!(self, u64, bitand),
                Opcode::Or => binary_op_save_flags!(self, u64, bitor),
                Opcode::Xor => binary_op_save_flags!(self, u64, bitxor),
                Opcode::Not => binary_op_arg1_save_flags!(self, not),
                Opcode::Cmp => {
                    let result = read_unaligned(self.sp.sub(1)).wrapping_sub(read_unaligned(self.sp));
                    self.set_rflags();
                    drop(result);
                },
                Opcode::Jmp => {
                    let rflags = RFlags::from_bits_truncate(self.rflags);
                    let do_jmp = match JmpCond::try_from(*self.pc).unwrap() {
                        JmpCond::Jmp => true,
                        JmpCond::Je => rflags.contains(RFlags::FLAGS_ZF),
                        JmpCond::Jne => !rflags.contains(RFlags::FLAGS_ZF),
                        JmpCond::Jbe => rflags.contains(RFlags::FLAGS_ZF)
                            || rflags.contains(RFlags::FLAGS_CF),
                        JmpCond::Ja => (!rflags.contains(RFlags::FLAGS_ZF)
                            && !rflags.contains(RFlags::FLAGS_CF)),
                        JmpCond::Jle => rflags.contains(RFlags::FLAGS_SF).bitxor(rflags.contains(RFlags::FLAGS_OF))
                            || rflags.contains(RFlags::FLAGS_ZF),
                        JmpCond::Jg => rflags.contains(RFlags::FLAGS_SF) == (rflags.contains(RFlags::FLAGS_OF) && !rflags.contains(RFlags::FLAGS_ZF))
                    };

                    self.pc = self.pc.add(1); // jmpcond

                    if do_jmp {
                        self.pc = program.add(read_unaligned(self.pc as *const u64) as _);
                    } else {
                        self.pc = self.pc.add(size_of::<u64>());
                    }
                }
                Opcode::VmAdd => binary_op!(self, wrapping_add),
                Opcode::VmSub => binary_op!(self, wrapping_sub),
                Opcode::Vmctx => {
                    // pushes self ptr on the stack
                    write_unaligned(self.sp.add(1), self as *const _ as u64);
                    self.sp = self.sp.add(1);
                }
                Opcode::Vmexit => {
                    break;
                }
            }
        }

        drop_in_place(addr_of_mut!((*self).vmstack));
        vmexit(self);
    }

    #[inline(always)]
    pub fn set_rflags(&mut self) {
        self.rflags = x86::bits64::rflags::read().bits();
    }
}


