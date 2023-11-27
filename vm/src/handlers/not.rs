use core::ops::Not;
use vm_proc::handler;
use crate::{binary_op_arg1, Machine, OpSize};

#[handler]
pub fn not(vm: &mut Machine, op_size: OpSize) {
    binary_op_arg1!(vm, op_size, not);
}