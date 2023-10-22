use core::arch::global_asm;
use crate::Machine;

const SIZE_OF_MACHINE: usize = core::mem::size_of::<Machine>();

global_asm!(include_str!("vm.asm"), sizeof_machine = const SIZE_OF_MACHINE );

extern "C" {
    pub fn vmexit(machine: &mut Machine) -> i32;
}
