#![no_std]
#![no_main]
extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::convert::TryFrom;
use core::mem::size_of;
use core::ops::{BitAnd, BitOr, BitXor};
use core::ptr::{read_unaligned, write_unaligned};

use memoffset::offset_of;
use winapi::ctypes::c_void;
use x86::bits64::rflags::RFlags;

use assembler::Asm;
use assembler::prelude::{Reg32::*, Reg64::*};
use assembler::prelude::Mov;
use assembler::Reg64;

use crate::assembler::{Imm64, Reg32};
use crate::assembler::prelude::Jmp;
use crate::syscalls::NtAllocateVirtualMemory;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

mod crt;
// mod region;
// mod vm;
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

impl From<Reg64> for Register {
    fn from(reg: Reg64) -> Self {
        match reg {
            rax => Register::Rax,
            rcx => Register::Rcx,
            rdx => Register::Rdx,
            rbx => Register::Rbx,
            rsp => Register::Rsp,
            rbp => Register::Rbp,
            rsi => Register::Rsi,
            rdi => Register::Rdi,
            r8 => Register::R8,
            r9 => Register::R9,
            r10 => Register::R10,
            r11 => Register::R11,
            r12 => Register::R12,
            r13 => Register::R13,
            r14 => Register::R14,
            r15 => Register::R15,
        }
    }
}

impl From<Reg32> for Register {
    fn from(reg: Reg32) -> Self {
        match reg {
            eax => Register::Rax,
            ecx => Register::Rcx,
            edx => Register::Rdx,
            ebx => Register::Rbx,
            esp => Register::Rsp,
            ebp => Register::Rbp,
            esi => Register::Rsi,
            edi => Register::Rdi,
            r8d => Register::R8,
            r9d => Register::R9,
            r10d => Register::R10,
            r11d => Register::R11,
            r12d => Register::R12,
            r13d => Register::R13,
            r14d => Register::R14,
            r15d => Register::R15,
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
    pub(crate) program: [u8; 166],
    pub(crate) vmstack: Vec<u64>,
    pub(crate) cpustack: Vec<u8>,
    vmexit: *const u64,
}

impl Machine {
    #[no_mangle]
    #[inline(never)]
    pub unsafe extern "C" fn vm() {
        let mut m = Self {
            pc: core::ptr::null(),
            sp: core::ptr::null_mut(),
            regs: [0; 16],
            rflags: RFlags::new(),
            program: [11, 0, 24, 0, 0, 0, 0, 0, 0, 0, 3, 1, 11, 0, 48, 0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 2, 11, 0, 48, 0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 1, 11, 0, 16, 0, 0, 0, 0, 0, 0, 0, 3, 2, 11, 0, 16, 0, 0, 0, 0, 0, 0, 0, 3, 1, 11, 0, 48, 0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 1, 6, 11, 0, 16, 0, 0, 0, 0, 0, 0, 0, 3, 2, 11, 0, 48, 0, 0, 0, 0, 0, 0, 0, 3, 1, 1, 11, 0, 48, 0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 11, 0, 48, 0, 0, 0, 0, 0, 0, 0, 3, 2, 12],
            vmstack: vec![0; 0x1000],
            cpustack: vec![0; 0x1000],
            vmexit: core::ptr::null(),
        };

        let regmap: &[(&Reg64, u8)] = &[
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

        let mut asm = Asm::new();

        asm.mov(rax, Imm64::from(&mut m as *mut _ as u64));

        for (reg, regid) in regmap.iter() {
            let offset = offset_of!(Machine, regs) + *regid as usize * 8;
            asm.mov(assembler::MemOp::IndirectDisp(rax, offset as i32), **reg);
        }

        let vm_rsp = unsafe {
            m.cpustack
                .as_ptr()
                .add(m.cpustack.len() - 0x100 - size_of::<u64>()) as u64
        };
        asm.mov(rsp, Imm64::from(vm_rsp));

        asm.mov(rcx, rax);
        asm.mov(rax, Imm64::from(Self::run as u64));
        asm.jmp(rax);

        let rt = asm.into_code();
        let mut vmenter_addr: usize = 0;
        let mut size = 0x1000;
        let _result = unsafe {
            NtAllocateVirtualMemory(
                -1isize as *mut c_void,
                &mut vmenter_addr as *mut usize as _,
                0,
                &mut size,
                0x1000 | 0x2000, // commit | reserve
                0x40, // page RWX
            )
        };

        unsafe {
            core::ptr::copy(rt.as_ptr(), vmenter_addr as *mut u8, rt.len());
        };

        // Generate VMEXIT.
        let regmap: &[(&Reg64, u8)] = &[
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

        let mut asm = Asm::new();

        for (reg, regid) in regmap.iter() {
            let offset = offset_of!(Machine, regs) + *regid as usize * 8;
            asm.mov(**reg, assembler::MemOp::IndirectDisp(rcx, offset as i32));
        }

        asm.jmp(rdx);

        let rt = asm.into_code();
        let mut vmexit_addr: usize = 0;
        let mut size = 0x1000;
        let _result = unsafe {
            NtAllocateVirtualMemory(
                -1isize as *mut c_void,
                &mut vmexit_addr as *mut usize as _,
                0,
                &mut size,
                0x1000 | 0x2000, // commit | reserve
                0x40, // page RWX
            )
        };

        unsafe {
            core::ptr::copy(rt.as_ptr(), vmexit_addr as *mut u8, rt.len());
        };

        m.vmexit = vmexit_addr as _;

        // todo preserve registers before setting up machine
        // either do that here somehow by inserting an asm stub or insert one
        // which is probably better
        // from the obfuscator, so
        // save_regs
        // call vm to generate machine
        // save ptr to vmenter
        // restore_regs
        // call vmenter
        // todo also somehow deallocate vmenter and vmexit after

        let vmenter: extern "C" fn(i32) -> i32 =
            core::mem::transmute(vmenter_addr);
        vmenter(6);
    }

    #[allow(clippy::missing_safety_doc)]
    #[no_mangle]
    pub unsafe extern "C" fn run(&mut self) {
        self.pc = self.program.as_ptr();
        self.sp = self.vmstack.as_mut_ptr();

        while self.pc < self.program.as_ptr_range().end {
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
                Opcode::Add => binary_op!(self, wrapping_add),
                Opcode::Div => binary_op!(self, wrapping_div),
                Opcode::Mul => binary_op!(self, wrapping_mul),
                Opcode::Sub => binary_op_save_flags!(self, wrapping_sub),
                Opcode::And => binary_op_save_flags!(self, bitand),
                Opcode::Or => binary_op_save_flags!(self, bitor),
                Opcode::Xor => binary_op_save_flags!(self, bitxor),
                Opcode::Cmp => {
                    // using asm instead here, because compiler would optimize
                    // out unused variable
                    asm!("cmp {}, {}",
                    in(reg) read_unaligned(self.sp.sub(1)),
                    in(reg) read_unaligned(self.sp)
                    );
                    self.set_rflags();
                }
                Opcode::Vmctx => {
                    // pushes self ptr on the stack
                    write_unaligned(self.sp.add(1), self as *const _ as u64);
                    self.sp = self.sp.add(1);
                }
                Opcode::Vmexit => {
                    let exit_ip = read_unaligned(self.sp);
                    self.sp = self.sp.sub(1);
                    let vmexit: extern "C" fn(&mut Machine, u64) =
                        core::mem::transmute(self.vmexit);
                    vmexit(self, exit_ip);
                }
            }
        }
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
}


