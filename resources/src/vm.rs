use core::arch::global_asm;

global_asm!(include_str!("vm.asm"));

extern "C" {
    pub fn vmenter();
    pub fn vmexit() -> i32;
}
