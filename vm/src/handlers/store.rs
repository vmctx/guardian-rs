use crate::{Machine, OpSize};

pub unsafe fn store(vm: &mut Machine, op_size: OpSize) {
    let register = vm.stack_pop::<*mut u64>();
    // only 64 and 32 bit overwrite full
    match op_size {
        OpSize::Qword => register.write_unaligned(vm.stack_pop::<u64>()),
        OpSize::Dword => register.cast::<u32>().write_unaligned(vm.stack_pop::<u32>()),
        OpSize::Word => register.cast::<u16>().write_unaligned(vm.stack_pop::<u16>()),
        OpSize::Byte => register.cast::<u8>().write_unaligned(vm.stack_pop::<u16>() as u8),
    };
}

pub unsafe fn store_xmm(vm: &mut Machine, _op_size: OpSize) {
    let register = vm.stack_pop::<*mut u128>();
    register.write_unaligned(vm.stack_pop::<u128>())
}

pub unsafe fn store_reg(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Dword => {
            let register = vm.stack_pop::<*mut u64>();
            register.write_unaligned(vm.stack_pop::<u32>() as u64);
        },
        _ => store(vm, op_size)
    };
}

pub unsafe fn store_reg_zx(vm: &mut Machine, op_size: OpSize) {
    let register = vm.stack_pop::<*mut u64>();
    match op_size {
        OpSize::Qword | OpSize::Dword | OpSize::Word => {
            register.write_unaligned(vm.stack_pop::<u16>() as u64);
        },
        OpSize::Byte => register.write_unaligned(vm.stack_pop::<u16>() as u8 as u64),
    };
}