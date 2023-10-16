#![no_std]
#![no_main]
extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;
use core::convert::TryFrom;
use alloc::vec;
use assembler::prelude::{Reg64::*, Reg32::*};
use assembler::Reg64;
use assembler::Asm;
use assembler::prelude::Mov;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

mod crt;
mod region;
mod vm;
mod syscalls;
mod assembler;

#[global_allocator]
static ALLOCATOR: allocator::Allocator = allocator::Allocator;
mod allocator;

use memoffset::offset_of;
use winapi::ctypes::c_void;
use crate::assembler::{Imm64, Reg32};
use crate::assembler::prelude::Jmp;
use crate::syscalls::NtAllocateVirtualMemory;

#[repr(u8)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum Opcode {
    Const,
    Load,
    Store,
    Add,
    Mul,
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
            _ => panic!("unsupported register"),
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
            _ => panic!("unsupported register"),
        }
    }
}


#[repr(C)]
pub struct Machine {
    pub(crate) pc: *const u8,
    pub(crate) sp: *mut u64,
    pub regs: [u64; 16],
    pub(crate) program: [u8; 166],
    pub(crate) vmstack: Vec<u64>,
    pub(crate) cpustack: Vec<u8>,
}

impl Machine {
    #[no_mangle]
    #[inline(never)]
    pub unsafe extern "C" fn vm() {
        let mut m = Self {
            pc: core::ptr::null(),
            sp: core::ptr::null_mut(),
            regs: [0; 16],
            program:  [5, 0, 96, 0, 0, 0, 0, 0, 0, 0, 3, 1, 5, 0, 120, 0, 0, 0, 0, 0,
                0, 0, 3, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 2, 5, 0, 120,
                0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 8, 0, 0, 0, 0, 0, 0,
                0, 3, 1, 5, 0, 88, 0, 0, 0, 0, 0, 0, 0, 3, 2, 5, 0, 120,
                0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 1,
                5, 0, 88, 0, 0, 0, 0, 0, 0, 0, 3, 1, 4, 5, 0, 88, 0, 0, 0, 0,
                0, 0, 0, 3, 2, 5, 0, 120, 0, 0, 0, 0, 0, 0, 0, 3, 1, 1, 5, 0, 120,
                0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 5, 0, 120,
                0, 0, 0, 0, 0, 0, 0, 3, 2, 6],
            vmstack: vec![0; 0x1000],
            cpustack: vec![0; 0x1000],
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

        asm.mov(rax, Imm64::from(&m as *const _ as u64));

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
        asm.mov(rax, Imm64::from(run as u64));
        asm.jmp(rax);

        let rt = asm.into_code();
        let mut address: usize = 0;
        let mut size = 0x1000;
        let _result = unsafe {
            NtAllocateVirtualMemory(
                -1isize as *mut c_void,
                &mut address as *mut usize as _,
                0,
                &mut size,
                0x1000 | 0x2000, // commit | reserve
                0x40, // page RW
            )
        };

        unsafe {
            core::ptr::copy(rt.as_ptr(),address as *mut u8, rt.len());
        };

        let vmenter: extern "C" fn(i32) -> i32 =
            core::mem::transmute(address as *const usize as usize);
        vmenter(6);
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn run(machine: *mut Machine) {
    let machine = machine.as_mut().unwrap();

    machine.pc = machine.program.as_ptr();
    machine.sp = machine.vmstack.as_mut_ptr();

    while machine.pc < machine.program.as_ptr_range().end {
        // unwrap doesnt panic but endless loops
        // i was passing unvirtualized instructions BUT
        // verify that asm is correct tmrw TODO
        // causes? asm is fcked up maybe
        // aka argument order
        let op = Opcode::try_from(*machine.pc).unwrap();
        machine.pc = machine.pc.add(1);

        /* TODO crashes at
        case 2: aka Opcode::Store
        rax = 8
        rcx = 0
        jmp hello_world_modded.7FF773D6756B
        mov rax,qword ptr ds:[rsi+8]
        mov rcx,qword ptr ds:[rax-8]
        mov rax,qword ptr ds:[rax]
        mov qword ptr ds:[rax],rcx   <-- crash
        add qword ptr ds:[rsi+8], 0FFFFFFFFFFFFFFF0h

        decompiled
        **(_QWORD **)a1[1] = *(_QWORD *)(a1[1] - 8i64);
        a1[1] -= 16i64;
        break;
        */

        match op {
            Opcode::Const => {
                *machine.sp.add(1) = *(machine.pc as *const u64);
                machine.sp = machine.sp.add(1);
                machine.pc = machine.pc.add(size_of::<u64>());
            }
            Opcode::Load => *machine.sp = *(*machine.sp as *const u64),
            Opcode::Store => {
                *(*machine.sp as *mut u64) = *machine.sp.sub(1);
                machine.sp = machine.sp.sub(2);
            }
            Opcode::Add => {
                *machine.sp.sub(1) = (*machine.sp.sub(1)).wrapping_add(*machine.sp);
                machine.sp = machine.sp.sub(1);
            }
            Opcode::Mul => {
                *machine.sp.sub(1) = (*machine.sp.sub(1)).wrapping_mul(*machine.sp);
                machine.sp = machine.sp.sub(1);
            }
            Opcode::Vmctx => {
                *machine.sp.add(1) = machine as *const _ as u64;
                machine.sp = machine.sp.add(1);
            }
            Opcode::Vmexit => {
                let exit_ip = *machine.sp;
                machine.sp = machine.sp.sub(1);
                let vmexit: extern "C" fn(&mut Machine, u64) =
                    core::mem::transmute(vm::vmexit as *const usize as usize);
                vmexit(machine, exit_ip);
            }
        }
    }
}
