use crate::{binary_op_save_flags, Machine, OpSize};

macro_rules! mul_save_flags {
    ($self:ident, $bit:ident, $save_bit:ident) => {{
        let (op2, op1) = unsafe { ($self.stack_pop::<$save_bit>() as $bit, $self.stack_pop::<$save_bit>() as $bit) };

        let result = op1.wrapping_mul(op2);
        $self.set_rflags();

        unsafe { $self.stack_push::<$bit>(result); }
    }}
}

use mul_save_flags;

pub fn mul(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => mul_save_flags!(vm, u128, u64),
        OpSize::Dword => mul_save_flags!(vm, u64, u32),
        OpSize::Word => mul_save_flags!(vm, u32, u16),
        OpSize::Byte => mul_save_flags!(vm, u16, u16),
    }
}
