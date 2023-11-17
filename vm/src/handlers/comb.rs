use crate::{Machine, OpSize};

pub unsafe fn combine(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => {
            let combined = (vm.stack_pop::<u64>() + vm.stack_pop::<u64>()) as u128;
            vm.stack_push::<u128>(combined);
        },
        OpSize::Dword => {
            let combined = (vm.stack_pop::<u32>() + vm.stack_pop::<u32>()) as u64;
            vm.stack_push::<u64>(combined);
        },
        OpSize::Word | OpSize::Byte => {
            let combined = (vm.stack_pop::<u16>() + vm.stack_pop::<u16>()) as u32;
            vm.stack_push::<u32>(combined);
        },
    }
}