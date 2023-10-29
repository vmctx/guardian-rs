use core::ops::BitXor;
use crate::{binary_op_save_flags, Machine, OpSize};

pub fn xor(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => binary_op_save_flags!(vm, u64, bitxor),
        OpSize::Dword => binary_op_save_flags!(vm, u32, bitxor),
        OpSize::Word => binary_op_save_flags!(vm, u16, bitxor),
        OpSize::Byte => binary_op_save_flags!(vm, u8, bitxor),
    }
}