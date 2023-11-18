use crate::{Machine, OpSize};

pub unsafe fn split(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => {
            let value = vm.stack_pop::<u128>();
            vm.stack_push(value >> 64);
            vm.stack_push(value);
        }
        OpSize::Dword => {
            let value = vm.stack_pop::<u64>();
            vm.stack_push(value >> 32);
            vm.stack_push(value);
        }
        OpSize::Word => {
            let value = vm.stack_pop::<u32>();
            vm.stack_push(value >> 16);
            vm.stack_push(value);
        }
        _ => unreachable!()
    }
}