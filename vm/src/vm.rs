use core::arch::global_asm;
use memoffset::offset_of;

use crate::{CPU_STACK_OFFSET, Machine, Register, XmmRegister};
use crate::alloc_new_stack;

global_asm!(include_str!("vm.asm"),
    sizeof_machine = const core::mem::size_of::<Machine>(),
    rax = const offset_of!(Machine, regs) + Register::Rax.offset(),
    rcx = const offset_of!(Machine, regs) + Register::Rcx.offset(),
    rdx = const offset_of!(Machine, regs) + Register::Rdx.offset(),
    rbx = const offset_of!(Machine, regs) + Register::Rbx.offset(),
    rsp = const offset_of!(Machine, regs) + Register::Rsp.offset(),
    rbp = const offset_of!(Machine, regs) + Register::Rbp.offset(),
    rsi = const offset_of!(Machine, regs) + Register::Rsi.offset(),
    rdi = const offset_of!(Machine, regs) + Register::Rdi.offset(),
    r8 = const offset_of!(Machine, regs) + Register::R8.offset(),
    r9 = const offset_of!(Machine, regs) + Register::R9.offset(),
    r10 = const offset_of!(Machine, regs) + Register::R10.offset(),
    r11 = const offset_of!(Machine, regs) + Register::R11.offset(),
    r12 = const offset_of!(Machine, regs) + Register::R12.offset(),
    r13 = const offset_of!(Machine, regs) + Register::R13.offset(),
    r14 = const offset_of!(Machine, regs) + Register::R14.offset(),
    r15 = const offset_of!(Machine, regs) + Register::R15.offset(),
    xmm0 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm0.offset(),
    xmm1 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm1.offset(),
    xmm2 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm2.offset(),
    xmm3 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm3.offset(),
    xmm4 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm4.offset(),
    xmm5 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm5.offset(),
    xmm6 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm6.offset(),
    xmm7 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm7.offset(),
    xmm8 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm8.offset(),
    xmm9 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm9.offset(),
    xmm10 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm10.offset(),
    xmm11 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm11.offset(),
    xmm12 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm12.offset(),
    xmm13 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm13.offset(),
    xmm14 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm14.offset(),
    xmm15 = const offset_of!(Machine, fxsave) + XmmRegister::Xmm15.offset(),
    rflags = const offset_of!(Machine, rflags),
    alloc_vm = sym Machine::alloc_vm,
    alloc_new_stack = sym alloc_new_stack,
    dealloc = sym Machine::dealloc,
    cpustack = const offset_of!(Machine, cpustack),
    cpustack_offset = const CPU_STACK_OFFSET,
);

#[no_mangle]
unsafe extern "C" fn vmexit_threaded(vm: *mut Machine) -> *mut Machine {
    vm
}
