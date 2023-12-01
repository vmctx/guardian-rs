// guardian-rs
// Copyright (C) 2023 felix-rs

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#![cfg_attr(not(feature = "testing"), feature(asm_const))]
#![cfg_attr(not(feature = "testing"), no_main)]
#![no_std]

#[cfg(all(feature = "threaded", feature = "testing"))]
compile_error!("\t [!] cannot have testing feature with threaded");

extern crate alloc;

use alloc::alloc::dealloc;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::mem::size_of;

use crate::allocator::{allocate, Protection};
use crate::macros::*;
use crate::shared::*;

#[cfg(not(feature = "testing"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

mod allocator;
#[allow(dead_code)]
pub mod assembler;
#[cfg(not(feature = "testing"))]
mod crt;
mod handlers;
mod macros;
mod shared;
#[allow(non_camel_case_types)]
mod syscalls;
#[cfg(not(feature = "testing"))]
mod vm;

#[global_allocator]
static ALLOCATOR: allocator::Allocator = allocator::Allocator;

const VM_STACK_SIZE: usize = 0x1000;
const CPU_STACK_SIZE: usize = 0x8000;

const CPU_STACK_OFFSET: usize = CPU_STACK_SIZE - 0x100 - size_of::<u64>() * 2;

#[repr(C, align(16))]
pub struct Machine {
    pc: *const u8,
    sp: *mut u64,
    regs: [u64; 16],
    fxsave: XSaveMin,
    rflags: u64,
    vmstack: *mut u64,
    #[cfg(not(feature = "testing"))]
    cpustack: *mut u8,
    #[cfg(feature = "testing")]
    cpustack: Vec<u8>,
    instr_buffer: Vec<u8>,
    #[cfg(feature = "testing")]
    pub vmenter: *mut u8,
}

// alignment check
static_assertions::const_assert_eq!(core::mem::size_of::<Machine>() % 16, 0);

#[cfg(not(feature = "testing"))]
unsafe extern "C" fn alloc_new_stack() -> *mut u8 {
    allocate(Layout::new::<[u8; CPU_STACK_SIZE]>(), Protection::ReadWrite)
}

impl Machine {
    #[cfg(not(feature = "testing"))]
    unsafe extern "C" fn alloc_vm(ptr: *mut Self) {
        *ptr = Self {
            pc: core::ptr::null(),
            sp: core::ptr::null_mut(),
            regs: [0; 16],
            fxsave: core::mem::zeroed::<XSaveMin>(),
            rflags: 0,
            vmstack: allocate(Layout::new::<[u64; VM_STACK_SIZE]>(), Protection::ReadWrite).cast(),
            cpustack: core::ptr::null_mut(), // will be written by vmentry
            instr_buffer: Vec::from_raw_parts(
                allocate(Layout::new::<[u8; 0x1000]>(), Protection::ReadWriteExecute), 0, 0x1000,
            ),
        }
    }

    /// Used to setup VM and generate VM Entry for tests
    #[cfg(feature = "testing")]
    pub fn new(program: *const u8) -> Self {
        use crate::assembler::prelude::*;
        use crate::assembler::Reg64::*;
        use crate::assembler::RegXmm::*;
        use alloc::vec;
        use core::mem::forget;

        let mut vmstack = vec![0u64; VM_STACK_SIZE];

        let mut machine = Self {
            pc: core::ptr::null(),
            sp: core::ptr::null_mut(),
            regs: [0; 16],
            fxsave: unsafe { core::mem::zeroed::<XSaveMin>() },
            rflags: 0,
            vmstack: vmstack.as_mut_ptr(),
            cpustack: vec![0u8; CPU_STACK_SIZE],
            instr_buffer: unsafe {
                Vec::from_raw_parts(
                    allocate(Layout::new::<[u8; 0x1000]>(), Protection::ReadWriteExecute), 0, 0x1000,
                )
            },
            vmenter: unsafe {
                allocate(Layout::new::<[u8; 0x1000]>(), Protection::ReadWriteExecute)
            },
        };

        // deallocation is handled manually
        forget(vmstack);

        // Generate VMENTER.
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

        let mut buffer = Vec::new();
        let mut a = Asm::new(&mut buffer);

        a.mov(rax, Imm64::from(&mut machine as *mut _ as u64));

        // Store the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = memoffset::offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(MemOp::IndirectDisp(rax, offset as i32), **reg);
        }

        // save rflags
        a.pushfq();
        a.pop(rcx);
        a.mov(MemOp::IndirectDisp(rax, memoffset::offset_of!(Machine, rflags) as i32), rcx);

        // Switch to the VM's CPU stack.
        let vm_rsp = unsafe {
            machine.cpustack
                .as_ptr()
                .add(CPU_STACK_OFFSET) as u64
        };
        assert_eq!(vm_rsp % 16, 0);
        a.mov(rsp, Imm64::from(vm_rsp));

        a.mov(rcx, rax);

        let xmm_regmap: &[(&RegXmm, u8)] = &[
            (&xmm0, XmmRegister::Xmm0.into()),
            (&xmm1, XmmRegister::Xmm1.into()),
            (&xmm2, XmmRegister::Xmm2.into()),
            (&xmm3, XmmRegister::Xmm3.into()),
            (&xmm4, XmmRegister::Xmm4.into()),
            (&xmm5, XmmRegister::Xmm5.into()),
            (&xmm6, XmmRegister::Xmm6.into()),
            (&xmm7, XmmRegister::Xmm7.into()),
            (&xmm8, XmmRegister::Xmm8.into()),
            (&xmm9, XmmRegister::Xmm9.into()),
            (&xmm10, XmmRegister::Xmm10.into()),
            (&xmm11, XmmRegister::Xmm11.into()),
            (&xmm12, XmmRegister::Xmm12.into()),
            (&xmm13, XmmRegister::Xmm13.into()),
            (&xmm14, XmmRegister::Xmm14.into()),
            (&xmm15, XmmRegister::Xmm15.into()),
        ];

        for (reg, regid) in xmm_regmap.iter() {
            let offset = memoffset::offset_of!(Machine, fxsave)
                + memoffset::offset_of!(XSaveMin, xmm_registers)
                + *regid as usize * 16;
            a.movaps(MemOp::IndirectDisp(rcx, offset as i32), **reg);
        }

        a.mov(rdx, Imm64::from(program as u64));
        a.mov(rax, Imm64::from(Machine::run as u64));
        a.call(rax);

        // Generate VMEXIT.
        let regmap: &[(&Reg64, u8)] = &[
            (&rax, Register::Rax.into()),
            (&rdx, Register::Rdx.into()),
            (&rbx, Register::Rbx.into()),
            (&rsp, Register::Rsp.into()), // change back to old stack from cpustack
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
            (&rcx, Register::Rcx.into()),
        ];

        a.mov(rcx, Imm64::from(&mut machine as *mut _ as u64));

        // restore rflags
        a.mov(rax, MemOp::IndirectDisp(rcx, memoffset::offset_of!(Machine, rflags) as i32));
        a.push(rax);
        a.popfq();

        // restore xmm regs

        for (reg, regid) in xmm_regmap.iter() {
            let offset = memoffset::offset_of!(Machine, fxsave)
                + memoffset::offset_of!(XSaveMin, xmm_registers)
                + *regid as usize * 16;
            a.movaps(**reg, MemOp::IndirectDisp(rcx, offset as i32));
        }

        // Restore the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = memoffset::offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(**reg, MemOp::IndirectDisp(rcx, offset as i32));
        }

        a.ret();

        unsafe {
            core::ptr::copy(buffer.as_ptr(), machine.vmenter, buffer.len());
        };

        machine
    }

    #[inline(never)]
    unsafe fn stack_push<T: Sized>(&mut self, value: T) {
        assert_eq!(size_of::<T>() * 8 % 16, 0);
        // stack overflow
        assert_ne!(self.sp, self.vmstack);
        self.sp = self.sp.cast::<T>().sub(1) as _;
        self.sp.cast::<T>().write_unaligned(value);
    }

    #[inline(never)]
    unsafe fn stack_pop<T: Sized>(&mut self) -> T {
        assert_eq!(size_of::<T>() * 8 % 16, 0);
        let value = self.sp.cast::<T>().read();
        self.sp.cast::<T>().write_unaligned(core::mem::zeroed());
        self.sp = self.sp.cast::<T>().add(1) as _;
        value
    }

    #[allow(clippy::missing_safety_doc)]
    #[no_mangle]
    #[cfg(feature = "threaded")]
    pub unsafe extern "C" fn run(&mut self, program: *const u8) -> *mut Self {
        use core::arch::asm;

        self.pc = program;
        self.sp = self.vmstack
            .add((VM_STACK_SIZE - 0x100 - (size_of::<u64>() * 2)) / size_of::<u64>());
        assert_eq!(self.sp as u64 % 16, 0);
        let mut handler = self.pc.cast::<u64>().read_unaligned();
        let current_image_base: u64;

        asm!(
            "mov {curr_image}, qword ptr gs:[0x60]",
            "mov {curr_image}, [{curr_image} + 0x10]",
            curr_image = out(reg) current_image_base,
        );

        handler += current_image_base;

        self.pc = self.pc.add(size_of::<u64>());

        let first_handler = unsafe {
            core::mem::transmute::<_, extern "C" fn(*mut Machine) -> *mut Machine>(handler)
        };

        first_handler(self)
        // maybe this will be called with
        // push first_handler
        // jmp run
        // so run returns to the first handler
        // then make sure rcx is self

    }

    #[allow(clippy::missing_safety_doc)]
    #[no_mangle]
    //#[cfg(feature = "testing")]
    #[cfg(not(feature = "threaded"))]
    pub unsafe extern "C" fn run(&mut self, program: *const u8) -> &mut Self {
        self.pc = program;
        self.sp = self.vmstack
            .add((VM_STACK_SIZE - 0x100 - (size_of::<u64>() * 2)) / size_of::<u64>());
        assert_eq!(self.sp as u64 % 16, 0);

        loop {
            let op = Opcode::try_from(*self.pc).unwrap();
            let op_size = OpSize::try_from(self.pc.add(1).read_unaligned()).unwrap();
            // skip opcode and op size
            self.pc = self.pc.add(2);

            // todo move ALL handlers to functions for threaded code obfuscation
            // if obfuscation feature is enabled instructions vec ptr should be
            // stored in struct
            // vmexit wont be needed to be moved it will just be calling vmexit directly
            match op {
                Opcode::Const => handlers::r#const::r#const(self, op_size),
                Opcode::Load => handlers::load::load(self, op_size),
                Opcode::LoadXmm => handlers::load::load_xmm(self, op_size),
                Opcode::Store => handlers::store::store(self, op_size),
                Opcode::StoreXmm => handlers::store::store_xmm(self, op_size),
                Opcode::StoreReg => handlers::store::store_reg(self, op_size),
                Opcode::StoreRegZx => handlers::store::store_reg_zx(self, op_size),
                Opcode::Div => handlers::div::div(self, op_size),
                Opcode::IDiv => handlers::div::idiv(self, op_size),
                Opcode::Shr => handlers::div::shr(self, op_size), // possibly unfinished
                Opcode::Combine => handlers::comb::combine(self, op_size),
                Opcode::Split => handlers::split::split(self, op_size),
                Opcode::Mul => handlers::mul::mul(self, op_size),
                Opcode::Add => handlers::add::add(self, op_size),
                Opcode::Sub => handlers::sub::sub(self, op_size),
                Opcode::And => handlers::and::and(self, op_size),
                Opcode::Or => handlers::or::or(self, op_size),
                Opcode::Xor => handlers::xor::xor(self, op_size),
                Opcode::Not => handlers::not::not(self, op_size),
                Opcode::Cmp => handlers::cmp::cmp(self, op_size),
                Opcode::RotR => handlers::rot::rot_r(self, op_size),
                Opcode::RotL => handlers::rot::rot_l(self, op_size),
                Opcode::Jmp => handlers::jmp::jmp(self, op_size),
                Opcode::VmAdd => handlers::add::vm_add(self, op_size),
                Opcode::VmSub => handlers::sub::vm_sub(self, op_size),
                Opcode::VmMul => handlers::mul::vm_mul(self, op_size),
                Opcode::VmReloc => handlers::reloc::vm_reloc(self, op_size),
                Opcode::Vmctx => handlers::ctx::vm_ctx(self, op_size),
                Opcode::VmExec => handlers::exec::vm_exec(self, op_size),
                Opcode::VmExit => break,
            }
        }

        self
    }

    #[cfg(not(feature = "testing"))]
    unsafe extern "C" fn dealloc(&mut self) {
        use core::ptr::{addr_of_mut, drop_in_place};
        dealloc(self.vmstack.cast(), Layout::new::<[u64; VM_STACK_SIZE]>());
        dealloc(self.cpustack.sub(CPU_STACK_OFFSET).add(size_of::<Machine>()), Layout::new::<[u8; CPU_STACK_SIZE]>());
        drop_in_place(addr_of_mut!((self).instr_buffer));
        // rust inlines destructor here deallocating instr_buffer automatically ^-^
    }
}

#[cfg(feature = "testing")]
impl Drop for Machine {
    fn drop(&mut self) {
        unsafe { dealloc(self.vmstack.cast(), Layout::new::<[u64; VM_STACK_SIZE]>()) };
    }
}
