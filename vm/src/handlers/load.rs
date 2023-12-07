use vm_proc::handler;
use crate::{Machine, OpSize};

#[handler]
pub unsafe fn load(vm: &mut Machine, op_size: OpSize) {
    // pop u64 cause its an address, can be usize for 32bit support ig
    // not sure tho a 100%
    // could cast it as diff ptr tho
    let value = vm.stack_pop::<*const u64>();
    match op_size {
        OpSize::Qword => vm.stack_push(value.read_unaligned()),
        OpSize::Dword => vm.stack_push(value.cast::<u32>().read_unaligned()),
        OpSize::Word => vm.stack_push(value.cast::<u16>().read_unaligned()),
        OpSize::Byte => vm.stack_push(value.cast::<u8>().read_unaligned() as u16),
    };
}

#[handler]
pub unsafe fn load_xmm(vm: &mut Machine, _op_size: OpSize) {
    let value = vm.stack_pop::<*const u128>().read_unaligned();
    vm.stack_push::<u128>(value)
}