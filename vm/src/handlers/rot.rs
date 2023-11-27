use vm_proc::handler;
use crate::{rotate, Machine, OpSize};

#[handler]
pub fn rot_r(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Word => rotate!(vm, u16, rotate_right),
        _ => unreachable!()
    }
}

#[handler]
pub fn rot_l(vm: &mut Machine, op_size: OpSize) {
    match op_size {
        OpSize::Word => rotate!(vm, u16, rotate_left),
        _ => unreachable!()
    }
}