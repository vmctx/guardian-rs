#![feature(asm_const)]

#![no_std]
#![cfg_attr(not(feature = "testing"), no_main)]

extern crate alloc;

use alloc::alloc::dealloc;
use alloc::vec;
use core::alloc::Layout;
use core::convert::TryFrom;
use core::mem::forget;
use core::mem::size_of;
use core::ops::BitXor;
use core::ptr::read_unaligned;

use x86::bits64::rflags::RFlags;

#[cfg(not(feature = "testing"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(not(feature = "testing"))]
mod crt;
mod handlers;
// mod region;

const VM_STACK_SIZE: usize = 0x1000;
const CPU_STACK_SIZE: usize = 0x1000;

#[cfg(not(feature = "testing"))]
mod vm;
mod syscalls;
#[allow(dead_code)]
mod assembler;

#[global_allocator]
static ALLOCATOR: allocator::Allocator = allocator::Allocator;

mod allocator;

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
    Vmexit,
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

macro_rules! binary_op {
    ($self:ident, $op:ident) => {{
        let (op2, op1) = unsafe { ($self.stack_pop::<u64>(), $self.stack_pop::<u64>()) };
        let result = op1.$op(op2);

        unsafe { $self.stack_push(result);}
    }}
}

pub(crate) use binary_op;

macro_rules! binary_op_save_flags {
    ($self:ident, $bit:ident, $op:ident) => {{
        let (op2, op1) = if core::mem::size_of::<$bit>() == 1 {
            unsafe { ($self.stack_pop::<u16>() as $bit, $self.stack_pop::<u16>() as $bit) }
        } else {
            unsafe { ($self.stack_pop::<$bit>(), $self.stack_pop::<$bit>()) }
        };

        let result = op1.$op(op2);

        $self.set_rflags();

        if core::mem::size_of::<$bit>() == 1 {
            unsafe { $self.stack_push(result as u16); }
        } else {
            unsafe { $self.stack_push(result); }
        }
    }}
}

pub(crate) use binary_op_save_flags;

macro_rules! binary_op_arg1_save_flags {
    ($self:ident, $bit:ident, $op:ident) => {{
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

#[repr(C)]
pub struct Machine {
    pc: *const u8,
    sp: *mut u64,
    regs: [u64; 16],
    rflags: u64,
    vmstack: *mut u64,
    #[cfg(not(feature = "testing"))]
    cpustack: *mut u8,
    #[cfg(feature = "testing")]
    cpustack: alloc::vec::Vec<u8>,
    #[cfg(feature = "testing")]
    pub vmenter: region::Allocation,
}

// check why anything bigger than this causes issues with my example program
#[cfg(not(feature = "testing"))]
static_assertions::const_assert_eq!(core::mem::size_of::<Machine>(), 0xa8);

impl Machine {
    #[no_mangle]
    pub unsafe extern "C" fn new_vm(out: *mut Self) {
        #[cfg(not(feature = "testing"))] {
            let mut cpustack = vec![0u8; CPU_STACK_SIZE];
            let mut vmstack = vec![0u64; VM_STACK_SIZE];
            *out = Self {
                pc: core::ptr::null(),
                sp: core::ptr::null_mut(),
                regs: [0; 16],
                rflags: 0,
                vmstack: vmstack.as_mut_ptr(),
                cpustack: cpustack.as_mut_ptr(),
            };
            forget(cpustack);
            forget(vmstack);
        }
    }

    #[cfg(feature = "testing")]
    #[allow(clippy::fn_to_numeric_cast)]
    pub fn new(program: *const u8) -> anyhow::Result<Self> {
        use iced_x86::code_asm::*;

        let mut vmstack = vec![0u64; VM_STACK_SIZE];

        let mut m = Self {
            pc: core::ptr::null(),
            sp: core::ptr::null_mut(),
            regs: [0; 16],
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
                .add(m.cpustack.len() - 0x100 - size_of::<u64>()) as u64
        };
        a.mov(rsp, vm_rsp).unwrap();

        a.mov(rcx, rax).unwrap();
        a.mov(rdx, program as u64).unwrap();
        a.mov(rax, Machine::run as u64).unwrap();
        a.call(rax).unwrap();

        // Generate VMEXIT.
        let regmap: &[(&AsmRegister64, u8)] = &[
            (&rax, Register::Rax.into()),
            (&rdx, Register::Rdx.into()),
            // (&rbx, Register::Rbx.into()),
            (&rsp, Register::Rsp.into()), // change back to old stack from cpustack
            // (&rbp, Register::Rbp.into()),
            // (&rsi, Register::Rsi.into()),
            // (&rdi, Register::Rdi.into()),
            (&r8, Register::R8.into()),
            (&r9, Register::R9.into()),
            (&r10, Register::R10.into()),
            (&r11, Register::R11.into()),
            // (&r12, Register::R12.into()),
            // (&r13, Register::R13.into()),
            // (&r14, Register::R14.into()),
            // (&r15, Register::R15.into()),
            (&rcx, Register::Rcx.into()),
        ];

        // restore rflags
        a.mov(rax, qword_ptr(rax + memoffset::offset_of!(Machine, rflags))).unwrap();
        a.push(rax).unwrap();
        a.popfq().unwrap();

        a.mov(rcx, &mut m as *mut _ as u64).unwrap();

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
        //*self.sp.cast::<T>() = null();
        self.sp = self.sp.cast::<T>().add(1) as _;
        value
    }

    #[allow(clippy::missing_safety_doc)]
    #[no_mangle]
    pub unsafe extern "C" fn run(&mut self, program: *const u8) -> &mut Self {
        self.pc = program;
        self.sp = self.vmstack
            .add((VM_STACK_SIZE - 0x100 - size_of::<u64>()) / size_of::<*mut u64>());

        // todo recode flags to calculate instead, cuz it can cause ub when
        // compilation doesnt do it the way i want
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
                Opcode::Store => handlers::store::store(self, op_size),
                Opcode::StoreReg => handlers::store::store_reg(self, op_size),
                Opcode::Div => handlers::div::div(self, op_size), // unfinished
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
                        self.pc = program.add(read_unaligned(self.pc as *const u64) as _);
                    } else {
                        self.pc = self.pc.add(size_of::<u64>());
                    }
                }
                Opcode::VmAdd => binary_op!(self, wrapping_add),
                Opcode::VmSub => binary_op!(self, wrapping_sub),
                Opcode::VmMul => binary_op!(self, wrapping_mul),
                Opcode::Vmctx => self.stack_push(self as *const _ as u64),
                Opcode::Vmexit => break
            }
        }

        self
    }

    #[no_mangle]
    #[cfg(not(feature = "testing"))]
    pub extern "C" fn dealloc(&mut self, stack_ptr: *mut u8) {
        #[cfg(not(feature = "testing"))]
        unsafe { dealloc(self.vmstack as _, Layout::new::<[u64; VM_STACK_SIZE]>()) }
        #[cfg(not(feature = "testing"))]
        unsafe { dealloc(stack_ptr, Layout::new::<[u8; CPU_STACK_SIZE]>()) }
    }

    #[inline(always)]
    pub fn set_rflags(&mut self) {
        self.rflags = x86::bits64::rflags::read().bits();
    }
}

#[cfg(feature = "testing")]
impl Drop for Machine {
    fn drop(&mut self) {
        unsafe { dealloc(self.vmstack as _, Layout::new::<[u64; VM_STACK_SIZE]>()) }
    }
}


