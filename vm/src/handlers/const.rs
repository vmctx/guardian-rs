use crate::{Machine, OpSize};

pub unsafe fn r#const(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => vm.stack_push(vm.pc.cast::<u64>().read_unaligned()),
        OpSize::Dword => vm.stack_push(vm.pc.cast::<u32>().read_unaligned()),
        OpSize::Word => vm.stack_push(vm.pc.cast::<u16>().read_unaligned()),
        OpSize::Byte => vm.stack_push(vm.pc.read_unaligned() as u16)
    }
    vm.pc = vm.pc.add(op_size as u8 as usize);
}