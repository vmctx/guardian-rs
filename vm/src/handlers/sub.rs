use crate::{binary_op_save_flags, Machine, OpSize};

pub fn sub(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => binary_op_save_flags!(vm, u64, wrapping_sub),
        OpSize::Dword => binary_op_save_flags!(vm, u32, wrapping_sub),
        OpSize::Word => binary_op_save_flags!(vm, u16, wrapping_sub),
        OpSize::Byte => binary_op_save_flags!(vm, u8, wrapping_sub),
    }
}