use crate::{binary_op_save_flags, Machine, OpSize};

pub fn add(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => binary_op_save_flags!(vm, u64, wrapping_add),
        OpSize::Dword => binary_op_save_flags!(vm, u32, wrapping_add),
        OpSize::Word => binary_op_save_flags!(vm, u16, wrapping_add),
        OpSize::Byte => binary_op_save_flags!(vm, u8, wrapping_add),
    }
}