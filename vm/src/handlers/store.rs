use core::ptr::write_unaligned;
use crate::{Machine, OpSize};

pub unsafe fn store(vm: &mut Machine, op_size: OpSize) {
    let target_addr = vm.stack_pop::<u64>();
    // only 64 and 32 bit overwrite full
    match op_size {
        OpSize::Qword => {
            let value = vm.stack_pop::<u64>();
            write_unaligned(target_addr as *mut u64, value);
        },
        OpSize::Dword => {
            let value = vm.stack_pop::<u32>();
            write_unaligned(target_addr as *mut u32, value);
        },
        OpSize::Word => {
            let value = vm.stack_pop::<u16>();
            write_unaligned(target_addr as *mut u16, value);
        },
        OpSize::Byte => {
            let value = vm.stack_pop::<u16>();
            write_unaligned(target_addr as *mut u8, value as u8);
        },
    };
}

pub unsafe fn store_reg(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Dword => {
            let target_addr = vm.stack_pop::<u64>();
            let value = vm.stack_pop::<u32>();
            write_unaligned(target_addr as *mut u64, value as u64);
        },
        _ => store(vm, op_size)
    };
}