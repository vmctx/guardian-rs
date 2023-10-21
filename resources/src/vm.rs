use core::arch::global_asm;
use crate::Machine;

global_asm!(include_str!("vm.asm"));

extern "C" {
    pub fn vmexit(machine: &mut Machine) -> i32;
}
