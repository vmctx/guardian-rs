use core::ops::Not;
use crate::{binary_op_arg1_save_flags, Machine, OpSize};

pub fn not(vm: &mut Machine, op_size: OpSize) {
    binary_op_arg1_save_flags!(vm, op_size, not);
}