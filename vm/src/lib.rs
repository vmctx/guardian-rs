#![feature(asm_const)]

#![no_std]
#![cfg_attr(not(feature = "testing"), no_main)]

extern crate alloc;

use alloc::alloc::dealloc;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::arch::asm;
use core::convert::TryFrom;
use core::mem::size_of;
use core::ops::BitXor;
use core::slice;

use memoffset::offset_of;
use x86::bits64::rflags::RFlags;

use crate::allocator::Protection;
use crate::assembler::{Asm, Imm64, Reg64, RegXmm};
use crate::assembler::prelude::{Mov, MovAps, Pop, Push};
use crate::assembler::Reg64::*;
use crate::assembler::RegXmm::*;

#[cfg(not(feature = "testing"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(not(feature = "testing"))]
mod crt;
mod handlers;

const VM_STACK_SIZE: usize = 0x1000;
const CPU_STACK_SIZE: usize = 0x4000;

#[cfg(not(feature = "testing"))]
mod vm;
mod syscalls;
#[allow(dead_code)]
pub mod assembler;

#[global_allocator]
static ALLOCATOR: allocator::Allocator = allocator::Allocator;

mod allocator;

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

#[repr(u8)]
#[derive(num_enum::IntoPrimitive)]
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

fn get_msb<N: num_traits::PrimInt>(n: N) -> N {
    let shift = size_of::<N>() * 8 - 1;
    (n >> shift) & N::one()
}

// TODO add rest of flags
macro_rules! calculate_rflags {
    // of also sets cf for now
    ($self:ident, $op1:ident, $op2: ident, $result:ident, $op:ident, OF) => {{
        use x86::bits64::rflags::RFlags;

        let mut rflags = RFlags::from_bits_truncate($self.rflags);
        ::paste::paste! {
            let (_, cf) =  $op1.[<overflowing_ $op>]($op2);
            rflags.set(RFlags::FLAGS_OF, (($crate::get_msb($op1) == 0 && $crate::get_msb($op2) == 0)
                && $crate::get_msb($result) == 1) || (($crate::get_msb($op1) == 1 && $crate::get_msb($op2) == 1)
                && $crate::get_msb($result) == 0)
            );
            rflags.set(RFlags::FLAGS_CF, cf);
        }
        $self.rflags = rflags.bits();
    }};
    ($self:ident, $op1:ident, $op2: ident, $result:ident, $op:ident, CF) => {{
        // combined into OF
    }};
    ($self:ident, $op1:ident, $op2: ident, $result:ident, $op:ident, ZF) => {{
        use x86::bits64::rflags::RFlags;
        let mut rflags = RFlags::from_bits_truncate($self.rflags);
        rflags.set(RFlags::FLAGS_ZF, $result == 0);
        $self.rflags = rflags.bits();
    }};
    ($self:ident, $op1:ident, $op2: ident, $result:ident, $op:ident, PF) => {{
        use x86::bits64::rflags::RFlags;
        let mut rflags = RFlags::from_bits_truncate($self.rflags);
        rflags.set(RFlags::FLAGS_PF, $result.count_ones() % 2 != 0);
        $self.rflags = rflags.bits();
    }};
    ($self:ident, $op1:ident, $op2: ident, $result:ident, $op:ident, SF) => {{
        use x86::bits64::rflags::RFlags;
        let mut rflags = RFlags::from_bits_truncate($self.rflags);
        rflags.set(RFlags::FLAGS_SF, $crate::get_msb($result) == 1);
        $self.rflags = rflags.bits();
    }};
    ($self:ident, $op1:ident, $op2: ident, $result:ident, $op:ident, $($flag:ident),+ $(,)?) => {
        $(
            $crate::calculate_rflags!($self, $op1, $op2, $result, $op, $flag);
        )+
    };
}


pub(crate) use calculate_rflags;

macro_rules! binary_op {
    ($self:ident, $op:ident) => {{
        let (op2, op1) = unsafe { ($self.stack_pop::<u64>(), $self.stack_pop::<u64>()) };
        let result = op1.$op(op2);

        unsafe { $self.stack_push(result);}
    }}
}

pub(crate) use binary_op;

macro_rules! binary_op_sized {
    ($self:ident, $op_size:ident, $op:ident) => {{
       match $op_size {
            OpSize::Qword => binary_op_sized!($self, u64, $op;),
            OpSize::Dword => binary_op_sized!($self, u32, $op;),
            OpSize::Word => binary_op_sized!($self, u16, $op;),
            OpSize::Byte => binary_op_sized!($self, u8, $op;),
        }
    }};
    ($self:ident, $bit:ident, $op:ident;) => {{
        let (op2, op1) = if core::mem::size_of::<$bit>() == 1 {
            unsafe { ($self.stack_pop::<u16>() as $bit, $self.stack_pop::<u16>() as $bit) }
        } else {
            unsafe { ($self.stack_pop::<$bit>(), $self.stack_pop::<$bit>()) }
        };

        let result = op1.$op(op2);

        if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_push(result as u16); }
        } else {
            unsafe { $self.stack_push(result); }
        }
    }}
}

pub(crate) use binary_op_sized;

macro_rules! binary_op_save_flags {
    ($self:ident, $op_size:ident, $op:ident $(, $rflag:ident)*) => {{
       match $op_size {
            OpSize::Qword => binary_op_save_flags!($self, u64, $op, $($rflag),*;),
            OpSize::Dword => binary_op_save_flags!($self, u32, $op, $($rflag),*;),
            OpSize::Word => binary_op_save_flags!($self, u16, $op, $($rflag),*;),
            OpSize::Byte => binary_op_save_flags!($self, u8, $op, $($rflag),*;),
        }
    }};
    ($self:ident, $bit:ident, $op:ident $(, $rflag:ident)* ;) => {{
        let (op2, op1) = if core::mem::size_of::<$bit>() == 1 {
            unsafe { ($self.stack_pop::<u16>() as $bit, $self.stack_pop::<u16>() as $bit) }
        } else {
            unsafe { ($self.stack_pop::<$bit>(), $self.stack_pop::<$bit>()) }
        };

        let result = op1.$op(op2);

        $crate::calculate_rflags!($self, op1, op2, result, $op, $($rflag),*);

        //$self.set_rflags();

        if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_push(result as u16); }
        } else {
            unsafe { $self.stack_push(result); }
        }
    }}
}

pub(crate) use binary_op_save_flags;

macro_rules! binary_op_arg1_save_flags {
    ($self:ident, $op_size:ident, $op:ident) => {{
       match $op_size {
            OpSize::Qword => binary_op_arg1_save_flags!($self, u64, $op;),
            OpSize::Dword => binary_op_arg1_save_flags!($self, u32, $op;),
            OpSize::Word => binary_op_arg1_save_flags!($self, u16, $op;),
            OpSize::Byte => binary_op_arg1_save_flags!($self, u8, $op;),
        }
    }};
    ($self:ident, $bit:ident, $op:ident;) => {{
        let op1 = if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_pop::<u16>() as $bit }
        } else {
            unsafe { $self.stack_pop::<$bit>() }
        };
        let result = op1.$op();

        $self.set_rflags();

         if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_push(result as u16); }
        } else {
            unsafe { $self.stack_push(result); }
        }
    }}
}

pub(crate) use binary_op_arg1_save_flags;

macro_rules! rotate {
    ($self:ident, $bit:ident, $op:ident) => {{
        let op1 = if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_pop::<u16>() as $bit }
        } else {
            unsafe { $self.stack_pop::<$bit>() }
        };

        let result = op1.$op(8);

        if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_push(result as u16); }
        } else {
            unsafe { $self.stack_push(result); }
        }
    }}
}

pub(crate) use rotate;

#[repr(u8)]
#[derive(Debug, Copy, Clone, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum OpSize {
    Byte = 1,
    Word = 2,
    Dword = 4,
    Qword = 8,
}

#[repr(C, align(16))]
pub struct Machine {
    pc: *const u8,
    sp: *mut u64,
    pub regs: [u64; 16],
    fxsave: XSaveMin,
    rflags: u64,
    vmstack: *mut u64,
    #[cfg(not(feature = "testing"))]
    cpustack: *mut u8,
    #[cfg(feature = "testing")]
    cpustack: alloc::vec::Vec<u8>,
    #[cfg(feature = "testing")]
    pub vmenter: region::Allocation,
}

#[repr(C, align(16))]
pub struct XSaveMin {
    #[cfg(target_pointer_width = "64")]
    xmm_registers: [u128; 16],
    #[cfg(target_pointer_width = "32")]
    xmm_registers: [u128; 8],
    float_registers: [u128; 8],
}

// check why anything bigger than this causes issues with my example program
#[cfg(not(feature = "testing"))]
static_assertions::const_assert_eq!(core::mem::size_of::<Machine>() % 16, 0);

impl Machine {
    #[no_mangle]
    #[cfg(not(feature = "testing"))]
    pub unsafe extern "C" fn new_vm(_ptr: *const u64) -> Self {
        // with opt-level z this can generate different code
        // putting self in rcx (input arg) rather than rax
        Self {
            pc: core::ptr::null(),
            sp: core::ptr::null_mut(),
            regs: [0; 16],
            fxsave: core::mem::zeroed::<XSaveMin>(),
            rflags: 0,
            vmstack: allocator::allocate(Layout::new::<[u64; VM_STACK_SIZE]>(), Protection::ReadWrite).cast(),
            cpustack: allocator::allocate(Layout::new::<[u8; CPU_STACK_SIZE]>(), Protection::ReadWrite),
        }
    }

    #[cfg(feature = "testing")]
    #[allow(clippy::fn_to_numeric_cast)]
    pub fn new(program: *const u8) -> anyhow::Result<Self> {
        use alloc::vec;
        use core::mem::forget;
        use iced_x86::code_asm::*;

        let mut vmstack = vec![0u64; VM_STACK_SIZE];

        let mut m = Self {
            pc: core::ptr::null(),
            sp: core::ptr::null_mut(),
            regs: [0; 16],
            fxsave: unsafe { core::mem::zeroed::<XSaveMin>() },
            rflags: 0,
            vmstack: vmstack.as_mut_ptr(),
            cpustack: vec![0u8; CPU_STACK_SIZE],
            vmenter: region::alloc(region::page::size(), region::Protection::READ_WRITE_EXECUTE)?,
        };

        forget(vmstack);

        // Generate VMENTER.
        let regmap: &[(&AsmRegister64, u8)] = &[
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

        let mut a = CodeAssembler::new(64).unwrap();

        a.mov(rax, &mut m as *mut _ as u64).unwrap();

        // Store the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = memoffset::offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(qword_ptr(rax + offset), **reg).unwrap();
        }

        // save rflags
        a.pushfq().unwrap();
        a.pop(rcx).unwrap();
        a.mov(qword_ptr(rax + memoffset::offset_of!(Machine, rflags)), rcx).unwrap();

        // Switch to the VM's CPU stack.
        let vm_rsp = unsafe {
            m.cpustack
                .as_ptr()
                .add(m.cpustack.len() - 0x100 - (size_of::<u64>() * 2)) as u64
        };
        assert_eq!(vm_rsp % 16, 0);
        a.mov(rsp, vm_rsp).unwrap();

        a.mov(rcx, rax).unwrap();

        let xmm_regmap: &[(&AsmRegisterXmm, u8)] = &[
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
                + memoffset::offset_of!(XSaveMin, xmm_registers) + *regid as usize * 16;
            a.movaps(xmmword_ptr(rcx + offset), **reg).unwrap();
        }

        a.mov(rdx, program as u64).unwrap();
        a.mov(rax, Machine::run as u64).unwrap();
        a.call(rax).unwrap();

        // Generate VMEXIT.
        let regmap: &[(&AsmRegister64, u8)] = &[
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

        a.mov(rcx, &mut m as *mut _ as u64).unwrap();

        // restore rflags
        a.mov(rax, qword_ptr(rcx + memoffset::offset_of!(Machine, rflags))).unwrap();
        a.push(rax).unwrap();
        a.popfq().unwrap();

        // restore xmm regs

        for (reg, regid) in xmm_regmap.iter() {
            let offset = memoffset::offset_of!(Machine, fxsave)
                + memoffset::offset_of!(XSaveMin, xmm_registers) + *regid as usize * 16;
            a.movaps(**reg, xmmword_ptr(rcx + offset)).unwrap();
        }

        // Restore the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = memoffset::offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(**reg, qword_ptr(rcx + offset)).unwrap();
        }

        a.ret().unwrap();

        let insts = a.assemble(m.vmenter.as_ptr::<u64>() as u64).unwrap();

        unsafe {
            core::ptr::copy(insts.as_ptr(), m.vmenter.as_mut_ptr(), insts.len());
        };


        Ok(m)
    }

    #[inline(never)]
    unsafe fn stack_push<T: Sized>(&mut self, value: T) {
        assert_eq!(size_of::<T>() % 2, 0);
        // stack overflow
        assert_ne!(self.sp, self.vmstack);
        self.sp = self.sp.cast::<T>().sub(1) as _;
        self.sp.cast::<T>().write_unaligned(value);
    }

    #[inline(never)]
    unsafe fn stack_pop<T: Sized>(&mut self) -> T {
        assert_eq!(size_of::<T>() % 2, 0);
        let value = self.sp.cast::<T>().read_unaligned();
        *self.sp.cast::<T>() = core::mem::zeroed();
        self.sp = self.sp.cast::<T>().add(1) as _;
        value
    }

    #[allow(clippy::missing_safety_doc)]
    #[no_mangle]
    pub unsafe extern "C" fn run(&mut self, program: *const u8) -> &mut Self {
        self.pc = program;
        self.sp = self.vmstack
            .add((VM_STACK_SIZE - 0x100 - (size_of::<u64>() * 2)) / size_of::<u64>());
        assert_eq!(self.sp as u64 % 16, 0);

        let mut instructions = Vec::from_raw_parts(
            allocator::allocate(
                Layout::new::<[u8; 0x1000]>(), Protection::ReadWriteExecute,
            ), 0, 0x1000,
        );

        loop {
            let op = Opcode::try_from(*self.pc).unwrap();
            let op_size = OpSize::try_from(self.pc.add(1).read_unaligned())
                .unwrap();
            // increase program counter by one byte
            // for const, this will load the address
            // this is now at op size
            self.pc = self.pc.add(2);

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
                Opcode::Jmp => {
                    let rflags = RFlags::from_bits_truncate(self.rflags);
                    let do_jmp = match JmpCond::try_from(*self.pc).unwrap() {
                        JmpCond::Jmp => true,
                        JmpCond::Je => rflags.contains(RFlags::FLAGS_ZF),
                        JmpCond::Jne => !rflags.contains(RFlags::FLAGS_ZF),
                        JmpCond::Jbe => rflags.contains(RFlags::FLAGS_ZF)
                            || rflags.contains(RFlags::FLAGS_CF),
                        JmpCond::Ja => !rflags.contains(RFlags::FLAGS_ZF)
                            && !rflags.contains(RFlags::FLAGS_CF),
                        JmpCond::Jle => rflags.contains(RFlags::FLAGS_SF).bitxor(rflags.contains(RFlags::FLAGS_OF))
                            || rflags.contains(RFlags::FLAGS_ZF),
                        JmpCond::Jg => rflags.contains(RFlags::FLAGS_SF) == rflags.contains(RFlags::FLAGS_OF) && !rflags.contains(RFlags::FLAGS_ZF)
                    };

                    self.pc = self.pc.add(1); // skip jmpcond

                    if do_jmp {
                        self.pc = program.add(self.pc.cast::<usize>().read_unaligned());
                    } else {
                        self.pc = self.pc.add(size_of::<u64>());
                    }
                }
                Opcode::VmAdd => binary_op!(self, wrapping_add),
                Opcode::VmSub => binary_op!(self, wrapping_sub),
                Opcode::VmMul => binary_op!(self, wrapping_mul),
                Opcode::VmReloc => {
                    let old_image_base = self.pc.cast::<u64>().read_unaligned();
                    let current_image_base;

                    asm!(
                        "mov rax, qword ptr gs:[0x60]",
                        "mov {}, [rax + 0x10]",
                        out(reg) current_image_base
                    );

                    let addr = self.stack_pop::<u64>()
                        .wrapping_add(old_image_base.abs_diff(current_image_base));
                    self.stack_push::<u64>(addr);

                    self.pc = self.pc.add(op_size as u8 as usize);
                }
                Opcode::Vmctx => self.stack_push(self as *const _ as u64),
                Opcode::VmExec => {
                    let instr_size = self.pc.read_unaligned() as usize;
                    self.pc = self.pc.add(1); // skip instr size
                    reloc_instr(self, instr_size, &mut instructions);
                    instructions.clear();

                    self.pc = self.pc.add(instr_size);
                }
                Opcode::VmExit => break
            }
        }

        self
    }

    #[no_mangle]
    #[cfg(not(feature = "testing"))]
    pub extern "C" fn dealloc(&mut self) {
        #[cfg(not(feature = "testing"))]
        unsafe { dealloc(self.vmstack.cast(), Layout::new::<[u64; VM_STACK_SIZE]>()) }
        // for some reason using self after first dealloc here does not work
        #[cfg(not(feature = "testing"))]
        unsafe { dealloc(self.cpustack, Layout::new::<[u8; CPU_STACK_SIZE]>()) }
    }

    #[inline(always)]
    pub fn set_rflags(&mut self) {
        self.rflags = x86::bits64::rflags::read().bits();
    }
}

#[inline(never)]
pub fn reloc_instr(vm: &mut Machine, instr_size: usize, instr_buffer: &mut Vec<u8>) {
    let mut non_vol_regs: [u64; 9] = [0, 0, 0, 0, 0, 0, 0, 0, 0];

    let non_vol_regmap: &[&Reg64] = &[
        &rbx,
        &rsp,
        &rbp,
        &rsi,
        &rdi,
        &r12,
        &r13,
        &r14,
        &r15,
    ];

    let regmap: &[(&Reg64, u8)] = &[
        (&rax, Register::Rax.into()),
        (&rbx, Register::Rbx.into()),
        (&rdx, Register::Rdx.into()),
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
        (&rcx, Register::Rcx.into()),
    ];

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

    let mut asm = Asm::new(instr_buffer);

    for (reg, regid) in xmm_regmap.iter() {
        let offset = memoffset::offset_of!(Machine, fxsave)
            + memoffset::offset_of!(XSaveMin, xmm_registers) + *regid as usize * 16;
        asm.movaps(**reg, assembler::MemOp::IndirectDisp(rcx, offset as i32));
    }

    for (index, reg) in non_vol_regmap.iter().enumerate() {
        let offset = index * 8;
        asm.mov(assembler::MemOp::IndirectDisp(rdx, offset as i32), **reg);
    }

    for (reg, regid) in regmap.iter() {
        let offset = offset_of!(Machine, regs) + *regid as usize * 8;
        asm.mov(**reg, assembler::MemOp::IndirectDisp(rcx, offset as i32));
    }

    let instructions = unsafe { slice::from_raw_parts(vm.pc, instr_size) };
    asm.code().extend_from_slice(instructions);

    asm.push(rax); // this decreases rsp need to adjust
    asm.mov(rax, Imm64::from(vm as *mut _ as u64));

    let regmap: &[(&Reg64, u8)] = &[
        (&rbx, Register::Rbx.into()),
        (&rcx, Register::Rcx.into()),
        (&rdx, Register::Rdx.into()),
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

    for (reg, regid) in xmm_regmap.iter() {
        let offset = memoffset::offset_of!(Machine, fxsave)
            + memoffset::offset_of!(XSaveMin, xmm_registers) + *regid as usize * 16;
        asm.movaps(assembler::MemOp::IndirectDisp(rax, offset as i32), **reg);
    }

    for (reg, regid) in regmap.iter() {
        let offset = offset_of!(Machine, regs) + *regid as usize * 8;
        asm.mov(assembler::MemOp::IndirectDisp(rax, offset as i32), **reg);
    }

    // save rax too
    asm.mov(rcx, rax);
    asm.pop(rax);
    // save rsp after stack ptr is adjusted again
    asm.mov(assembler::MemOp::IndirectDisp(rcx, offset_of!(Machine, regs) as i32 + (Register::Rsp as u8 as usize * 8) as i32), rsp);
    asm.mov(assembler::MemOp::IndirectDisp(rcx, offset_of!(Machine, regs) as i32), rax);

    asm.mov(rax, Imm64::from(non_vol_regs.as_mut_ptr() as u64));

    for (index, reg) in non_vol_regmap.iter().enumerate() {
        let offset = index * 8;
        asm.mov(**reg, assembler::MemOp::IndirectDisp(rax, offset as i32));
    }
    asm.ret();

    let func = unsafe { core::mem::transmute::<_, extern "C" fn(*mut Machine, *mut u64)>(instr_buffer.as_mut_ptr()) };
    // use non_vol_regs here so no use after free just in case
    func(vm, non_vol_regs.as_mut_ptr());
}

#[cfg(feature = "testing")]
impl Drop for Machine {
    fn drop(&mut self) {
        unsafe { dealloc(self.vmstack as _, Layout::new::<[u64; VM_STACK_SIZE]>()) }
    }
}


