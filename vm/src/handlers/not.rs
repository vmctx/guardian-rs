use core::ops::Not;
use crate::{binary_op_arg1_save_flags, Machine, OpSize};

pub fn not(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => binary_op_arg1_save_flags!(vm, u64, not),
        OpSize::Dword => binary_op_arg1_save_flags!(vm, u32, not),
        OpSize::Word => binary_op_arg1_save_flags!(vm, u16, not),
        OpSize::Byte => binary_op_arg1_save_flags!(vm, u8, not),
    }
}