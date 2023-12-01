use core::mem::size_of;
use core::ops::BitXor;
use x86::bits64::rflags::RFlags;
use vm_proc::handler;
use crate::Machine;
use crate::shared::{JmpCond, OpSize};

#[handler]
pub unsafe fn jmp(vm: &mut Machine, _op_size: OpSize) {
    let rflags = RFlags::from_bits_truncate(vm.rflags);
    let do_jmp = match JmpCond::try_from(*vm.pc).unwrap() {
        JmpCond::Jmp => true,
        JmpCond::Je => rflags.contains(RFlags::FLAGS_ZF),
        JmpCond::Jne => !rflags.contains(RFlags::FLAGS_ZF),
        JmpCond::Jbe => rflags.contains(RFlags::FLAGS_ZF)
            || rflags.contains(RFlags::FLAGS_CF),
        JmpCond::Ja => !rflags.contains(RFlags::FLAGS_ZF)
            && !rflags.contains(RFlags::FLAGS_CF),
        JmpCond::Jae => !rflags.contains(RFlags::FLAGS_CF),
        JmpCond::Jle => rflags.contains(RFlags::FLAGS_SF)
            .bitxor(rflags.contains(RFlags::FLAGS_OF))
            || rflags.contains(RFlags::FLAGS_ZF),
        JmpCond::Jg => rflags.contains(RFlags::FLAGS_SF)
            == rflags.contains(RFlags::FLAGS_OF)
            && !rflags.contains(RFlags::FLAGS_ZF)
    };

    vm.pc = vm.pc.add(1); // skip jmpcond

    if do_jmp {
        let offset = vm.pc.cast::<i64>().read_unaligned();
        #[cfg(not(feature = "threaded"))] {
            vm.pc = (vm.pc.sub(3) as i64).wrapping_sub(offset) as _;
        }
        // -8 when obfuscated bcuz bytecode offset - 8 = next_handler of
        // previous instruction = current handler of target branch
        #[cfg(feature = "threaded")] {
            vm.pc = ((vm.pc.sub(2) as i64).wrapping_sub(offset) - 8) as _;
        }
    } else {
        vm.pc = vm.pc.add(size_of::<u64>());
    }
}