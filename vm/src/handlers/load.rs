use crate::{Machine, OpSize};

pub unsafe fn load(vm: &mut Machine, op_size: OpSize) {
    // pop u64 cause its an address, can be usize for 32bit support ig
    // not sure tho a 100%
    let value = (vm.stack_pop::<u64>() as *const u64).read_unaligned();
    match op_size {
        OpSize::Qword => vm.stack_push::<u64>(value),
        OpSize::Dword => vm.stack_push::<u32>(value as u32),
        OpSize::Word => vm.stack_push::<u16>(value as u16),
        OpSize::Byte => vm.stack_push::<u16>(value as u16) // stack alignment
    };
}