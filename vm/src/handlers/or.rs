use core::ops::BitOr;
use vm_proc::handler;
use crate::{binary_op_save_flags, Machine, OpSize};

#[handler]
pub fn or(vm: &mut Machine, op_size: OpSize) {
    binary_op_save_flags!(vm, op_size, bitor, SF, ZF, PF);
}