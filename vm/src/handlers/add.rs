use crate::{binary_op_save_flags, Machine, OpSize};
use core::ops::Add;
pub fn add(vm: &mut Machine, op_size: OpSize) {
    binary_op_save_flags!(vm, op_size, add, OF, SF, ZF, PF, CF);
}