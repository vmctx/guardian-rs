use vm_proc::handler;
use crate::Machine;
use crate::shared::OpSize;

#[handler]
pub unsafe fn vm_ctx(vm: &mut Machine, _op_size: OpSize) {
    vm.stack_push(vm as *const _ as u64)
}