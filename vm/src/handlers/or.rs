use core::ops::BitOr;
use crate::{binary_op_save_flags, Machine, OpSize};

pub fn or(vm: &mut Machine, op_size: OpSize) {
    binary_op_save_flags!(vm, op_size, bitor);
}