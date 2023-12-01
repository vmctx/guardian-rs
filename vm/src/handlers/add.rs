use vm_proc::handler;
use crate::{binary_op_save_flags, Machine, OpSize};
use crate::macros::binary_op;

#[handler]
pub fn add(vm: &mut Machine, op_size: OpSize) {
    binary_op_save_flags!(vm, op_size, wrapping_add, OF, SF, ZF, PF, CF_ADD);
}

#[handler]
pub fn vm_add(vm: &mut Machine, _op_size: OpSize) {
    binary_op!(vm, wrapping_add)
}
