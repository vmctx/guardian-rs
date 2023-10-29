use crate::{binary_op_save_flags, Machine, OpSize};

pub fn mul(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => binary_op_save_flags!(vm, u64, wrapping_mul),
        OpSize::Dword => binary_op_save_flags!(vm, u32, wrapping_mul),
        OpSize::Word => binary_op_save_flags!(vm, u16, wrapping_mul),
        OpSize::Byte => binary_op_save_flags!(vm, u8, wrapping_mul),
    }
}