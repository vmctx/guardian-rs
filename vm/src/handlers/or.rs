use core::ops::BitOr;
use crate::{binary_op_save_flags, Machine, OpSize};

pub fn or(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => binary_op_save_flags!(vm, u64, bitor),
        OpSize::Dword => binary_op_save_flags!(vm, u32, bitor),
        OpSize::Word => binary_op_save_flags!(vm, u16, bitor),
        OpSize::Byte => binary_op_save_flags!(vm, u8, bitor),
    }
}