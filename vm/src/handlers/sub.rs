use crate::{binary_op_save_flags, Machine, OpSize};

pub fn sub(vm: &mut Machine, op_size: OpSize) {
    binary_op_save_flags!(vm, op_size, wrapping_sub);
}