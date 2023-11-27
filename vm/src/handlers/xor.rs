use core::ops::BitXor;
use vm_proc::handler;
use crate::{binary_op_save_flags, Machine, OpSize};

#[handler]
pub fn xor(vm: &mut Machine, op_size: OpSize) {
    binary_op_save_flags!(vm, op_size, bitxor, SF, ZF, PF);
}