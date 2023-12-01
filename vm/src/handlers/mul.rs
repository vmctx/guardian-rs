use crate::{Machine, OpSize};

macro_rules! mul_save_flags {
    ($self:ident, $bit:ident, $save_bit:ident) => {{
        let (op2, op1) = unsafe { ($self.stack_pop::<$save_bit>() as $bit, $self.stack_pop::<$save_bit>() as $bit) };

        let result = op1.wrapping_mul(op2);
        // todo of and cf, find out which flags are used (doc says undefined)
        $crate::calculate_rflags!($self, op1, op2, result, ZF, OF);

        unsafe { $self.stack_push::<$bit>(result); }
    }}
}

use mul_save_flags;
use vm_proc::handler;
use crate::macros::binary_op;

#[handler]
pub fn mul(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => mul_save_flags!(vm, u128, u64),
        OpSize::Dword => mul_save_flags!(vm, u64, u32),
        OpSize::Word => mul_save_flags!(vm, u32, u16),
        OpSize::Byte => mul_save_flags!(vm, u16, u16),
    }
}

#[handler]
pub fn vm_mul(vm: &mut Machine, _op_size: OpSize) {
    binary_op!(vm, wrapping_mul)
}

