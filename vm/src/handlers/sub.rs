use vm_proc::handler;
use crate::{binary_op_save_flags, Machine, OpSize};
use crate::macros::binary_op;

#[handler]
pub fn sub(vm: &mut Machine, op_size: OpSize) {
    binary_op_save_flags!(vm, op_size, wrapping_sub, OF, SF, ZF, PF, CF_SUB);
}

#[handler]
pub fn vm_sub(vm: &mut Machine, _op_size: OpSize) {
    binary_op!(vm, wrapping_sub)
}