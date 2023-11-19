use crate::{Machine, OpSize};

pub unsafe fn store(vm: &mut Machine, op_size: OpSize) {
    let target_addr = vm.stack_pop::<*mut u64>();
    // only 64 and 32 bit overwrite full
    match op_size {
        OpSize::Qword => target_addr.write_unaligned(vm.stack_pop::<u64>()),
        OpSize::Dword => target_addr.cast::<u32>().write_unaligned(vm.stack_pop::<u32>()),
        OpSize::Word => target_addr.cast::<u16>().write_unaligned(vm.stack_pop::<u16>()),
        OpSize::Byte => target_addr.cast::<u8>().write_unaligned(vm.stack_pop::<u16>() as u8),
    };
}

pub unsafe fn store_xmm(vm: &mut Machine, _op_size: OpSize) {
    let target_addr = vm.stack_pop::<*mut u128>();
    target_addr.write_unaligned(vm.stack_pop::<u128>())
}

pub unsafe fn store_reg(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Dword => {
            let target_addr = vm.stack_pop::<*mut u64>();
            target_addr.write_unaligned(vm.stack_pop::<u32>() as u64);
        },
        _ => store(vm, op_size)
    };
}

pub unsafe fn store_reg_zx(vm: &mut Machine, _op_size: OpSize) {
    let target_addr = vm.stack_pop::<*mut u64>();
    target_addr.write_unaligned(vm.stack_pop::<u16>() as u64);
}