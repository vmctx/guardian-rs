use crate::{binary_op_save_flags, Machine, OpSize};
use core::ops::Sub;
pub fn sub(vm: &mut Machine, op_size: OpSize) {
    binary_op_save_flags!(vm, op_size, sub, OF, SF, ZF, PF, CF);
}