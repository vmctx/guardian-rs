use core::arch::asm;
use vm_proc::handler;
use crate::Machine;
use crate::shared::OpSize;

#[handler]
pub unsafe fn vm_reloc(vm: &mut Machine, op_size: OpSize) {
    let old_image_base = vm.pc.cast::<u64>().read_unaligned();
    let current_image_base;

    asm!(
    "mov rax, qword ptr gs:[0x60]",
    "mov {}, [rax + 0x10]",
    out(reg) current_image_base
    );

    let addr = vm.stack_pop::<u64>()
        .wrapping_add(old_image_base.abs_diff(current_image_base));
    vm.stack_push::<u64>(addr);

    vm.pc = vm.pc.add(op_size as u8 as usize);
}