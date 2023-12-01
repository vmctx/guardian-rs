use crate::{binary_op_sized, Machine, OpSize};

macro_rules! div_save_flags {
    ($self:ident, $bit:ident, $save_bit:ident) => {{
        let (op2, op1) = unsafe { ($self.stack_pop::<$bit>() as $save_bit, $self.stack_pop::<$save_bit>()) };

        let qoutient = op1.wrapping_div(op2);
        let remainder = op1.wrapping_rem(op2);
        // todo find out what flags are affected (docs say undefined)
        $crate::calculate_rflags!($self, op1, op2, qoutient, ZF);

        unsafe { $self.stack_push(remainder as $bit); }
        unsafe { $self.stack_push(qoutient as $bit); }
    }}
}

use div_save_flags;
use vm_proc::handler;

#[handler]
pub fn div(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => div_save_flags!(vm, u64, u128),
        OpSize::Dword => div_save_flags!(vm, u32, u64),
        OpSize::Word => div_save_flags!(vm, u16, u32),
        OpSize::Byte => div_save_flags!(vm, u16, u16),
    }
}

#[handler]
pub fn idiv(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => div_save_flags!(vm, i64, i128),
        OpSize::Dword => div_save_flags!(vm, i32, i64),
        OpSize::Word => div_save_flags!(vm, i16, i32),
        OpSize::Byte => div_save_flags!(vm, i16, i16),
    }
}

#[handler]
pub fn shr(vm: &mut Machine, op_size: OpSize) {
    binary_op_sized!(vm, op_size, wrapping_div);
}
