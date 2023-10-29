use core::hint::black_box;
use crate::{Machine, OpSize};

pub unsafe fn cmp(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => {
            let (op2, op1) = (vm.stack_pop::<u64>(), vm.stack_pop::<u64>());
            let result = op1.wrapping_sub(op2);
            vm.set_rflags();
            black_box(result);
        },
        OpSize::Dword => {
            let (op2, op1) = (vm.stack_pop::<u32>(), vm.stack_pop::<u32>());
            let result = op1.wrapping_sub(op2);
            vm.set_rflags();
            black_box(result);
        },
        OpSize::Word => {
            let (op2, op1) = (vm.stack_pop::<u16>(), vm.stack_pop::<u16>());
            let result = op1.wrapping_sub(op2);
            vm.set_rflags();
            black_box(result);
        },
        OpSize::Byte => {
            let (op2, op1) = (vm.stack_pop::<u16>() as u8, vm.stack_pop::<u16>() as u8);
            let result = op1.wrapping_sub(op2);
            vm.set_rflags();
            black_box(result);
        },
    }
}