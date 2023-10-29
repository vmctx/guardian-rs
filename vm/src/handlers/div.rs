use crate::{binary_op_save_flags, Machine, OpSize};

// todo expand on this
// one solution is to have diff size opcodes
/*
opcode Add = 32bit
opcode AddQ = 64bit
opcode AddW = 16bit
opcode AddB = 8 bit

opcode add:
    let = stack-1.wrapping_add(read(stack as *const i32/u32))
opcode addq:
    let = stack-1.wrapping_add(read(stack))
 */
pub fn div(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Qword => binary_op_save_flags!(vm, u64, wrapping_div),
        OpSize::Dword => binary_op_save_flags!(vm, u32, wrapping_div),
        OpSize::Word => binary_op_save_flags!(vm, u16, wrapping_div),
        OpSize::Byte => binary_op_save_flags!(vm, u8, wrapping_div),
    }
}