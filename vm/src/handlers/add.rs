use vm_proc::handler;
use crate::{binary_op_save_flags, Machine, OpSize};

#[handler]
pub fn add(vm: &mut Machine, op_size: OpSize) {
    binary_op_save_flags!(vm, op_size, wrapping_add, OF, SF, ZF, PF, CF_ADD);
}
