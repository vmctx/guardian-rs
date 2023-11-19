use core::ops::BitXor;
use crate::{binary_op_save_flags, Machine, OpSize};

pub fn xor(vm: &mut Machine, op_size: OpSize) {
    binary_op_save_flags!(vm, op_size, bitxor);
}