use core::arch::global_asm;
use crate::{CPU_STACK_SIZE, Machine, Register};
use memoffset::offset_of;

const SIZE_OF_MACHINE: usize = core::mem::size_of::<Machine>();

global_asm!(include_str!("vm.asm"),
    sizeof_machine = const SIZE_OF_MACHINE,
    rax = const offset_of!(Machine, regs) + Register::Rax as u8 as usize * 8,
    rcx = const offset_of!(Machine, regs) + Register::Rcx as u8 as usize * 8,
    rdx = const offset_of!(Machine, regs) + Register::Rdx as u8 as usize * 8,
    rbx = const offset_of!(Machine, regs) + Register::Rbx as u8 as usize * 8,
    rsp = const offset_of!(Machine, regs) + Register::Rsp as u8 as usize * 8,
    rbp = const offset_of!(Machine, regs) + Register::Rbp as u8 as usize * 8,
    rsi = const offset_of!(Machine, regs) + Register::Rsi as u8 as usize * 8,
    rdi = const offset_of!(Machine, regs) + Register::Rdi as u8 as usize * 8,
    r8 = const offset_of!(Machine, regs) + Register::R8 as u8 as usize * 8,
    r9 = const offset_of!(Machine, regs) + Register::R9 as u8 as usize * 8,
    r10 = const offset_of!(Machine, regs) + Register::R10 as u8 as usize * 8,
    r11 = const offset_of!(Machine, regs) + Register::R11 as u8 as usize * 8,
    r12 = const offset_of!(Machine, regs) + Register::R12 as u8 as usize * 8,
    r13 = const offset_of!(Machine, regs) + Register::R13 as u8 as usize * 8,
    r14 = const offset_of!(Machine, regs) + Register::R14 as u8 as usize * 8,
    r15 = const offset_of!(Machine, regs) + Register::R15 as u8 as usize * 8,
    rflags = const offset_of!(Machine, rflags),
    cpustack = const offset_of!(Machine, cpustack),
    cpustack_offset = const CPU_STACK_SIZE - 0x100 - core::mem::size_of::<u64>() * 2
);
