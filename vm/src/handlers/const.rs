use core::ptr::read_unaligned;
use crate::{Machine, OpSize};

pub unsafe fn r#const(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => vm.stack_push(read_unaligned(vm.pc as *const u64)),
        OpSize::Dword => vm.stack_push(read_unaligned(vm.pc as *const u32)),
        OpSize::Word => vm.stack_push(read_unaligned(vm.pc as *const u16)),
        OpSize::Byte => vm.stack_push(read_unaligned(vm.pc))
    }
    vm.pc = vm.pc.add(op_size as u8 as usize);
}