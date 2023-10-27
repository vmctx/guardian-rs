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

#[repr(u8)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
enum OperandSize {
    Byte,
    Word,
    Dword,
    Qword
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
                   self.stack_push(self as *const _ as u64);
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


