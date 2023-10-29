use core::ops::BitAnd;
use crate::{binary_op_save_flags, Machine, OpSize};

pub fn and(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => binary_op_save_flags!(vm, u64, bitand),
        OpSize::Dword => binary_op_save_flags!(vm, u32, bitand),
        OpSize::Word => binary_op_save_flags!(vm, u16, bitand),
        OpSize::Byte => binary_op_save_flags!(vm, u8, bitand),
    }
}