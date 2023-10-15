#![no_std]
#![no_main]
extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;
use core::convert::TryFrom;
use core::ptr::slice_from_raw_parts;
use alloc::vec;
use core::arch::asm;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

mod crt;
mod region;
mod vm;
mod syscalls;

#[global_allocator]
static ALLOCATOR: allocator::Allocator = allocator::Allocator;
mod allocator;

use memoffset::offset_of;

#[repr(u8)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum Opcode {
    Const,
    Load,
    Store,
    Add,
    Mul,
    Vmctx,
    Vmexit,
}

#[repr(C)]
pub struct Machine {
    pub(crate) pc: *const u8,
    pub(crate) sp: *mut u64,
    pub regs: [u64; 16],
    pub(crate) program: [u8; 166],
    pub(crate) vmstack: Vec<u64>,
    pub(crate) cpustack: Vec<u8>,
}

impl Machine {
    #[no_mangle]
    #[inline(never)]
    pub unsafe extern "C" fn vm() {
        let mut m = Self {
            pc: core::ptr::null(),
            sp: core::ptr::null_mut(),
            regs: [0; 16],
            program:  [5, 0, 96, 0, 0, 0, 0, 0, 0, 0, 3, 1, 5, 0, 120, 0, 0, 0, 0, 0,
                0, 0, 3, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 2, 5, 0, 120,
                0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 8, 0, 0, 0, 0, 0, 0,
                0, 3, 1, 5, 0, 88, 0, 0, 0, 0, 0, 0, 0, 3, 2, 5, 0, 120,
                0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 1,
                5, 0, 88, 0, 0, 0, 0, 0, 0, 0, 3, 1, 4, 5, 0, 88, 0, 0, 0, 0,
                0, 0, 0, 3, 2, 5, 0, 120, 0, 0, 0, 0, 0, 0, 0, 3, 1, 1, 5, 0, 120,
                0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 5, 0, 120,
                0, 0, 0, 0, 0, 0, 0, 3, 2, 6],
            vmstack: vec![0; 0x1000],
            cpustack: vec![0; 0x1000],
        };

        let vm_rsp = unsafe {
            m.cpustack
                .as_ptr()
                .add(m.cpustack.len() - 0x100 - core::mem::size_of::<u64>()) as u64
        };

        let vmenter: extern "C" fn(&mut Machine, u64, u64) =
            core::mem::transmute(vm::vmenter as *const usize as usize);
        vmenter(&mut m, run as *const u64 as u64, vm_rsp)
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn run(machine: *mut Machine) {
    let machine = machine.as_mut().unwrap();

    machine.pc = machine.program.as_ptr();
    machine.sp = machine.vmstack.as_mut_ptr();

    while machine.pc < machine.program.as_ptr_range().end {
        // unwrap doesnt panic but endless loops
        // i was passing unvirtualized instructions BUT
        // verify that asm is correct tmrw TODO
        // causes? asm is fcked up maybe
        // aka argument order
        let op = Opcode::try_from(*machine.pc).unwrap();
        machine.pc = machine.pc.add(1);

        /* TODO crashes at
        case 2: aka Opcode::Store
        rax = 8
        rcx = 0
        jmp hello_world_modded.7FF773D6756B
        mov rax,qword ptr ds:[rsi+8]
        mov rcx,qword ptr ds:[rax-8]
        mov rax,qword ptr ds:[rax]
        mov qword ptr ds:[rax],rcx

        **(_QWORD **)a1[1] = *(_QWORD *)(a1[1] - 8i64);
        a1[1] -= 16i64;
        break;
        */

        match op {
            Opcode::Const => {
                *machine.sp.add(1) = *(machine.pc as *const u64);
                machine.sp = machine.sp.add(1);
                machine.pc = machine.pc.add(size_of::<u64>());
            }
            Opcode::Load => *machine.sp = *(*machine.sp as *const u64),
            Opcode::Store => {
                *(*machine.sp as *mut u64) = *machine.sp.sub(1);
                machine.sp = machine.sp.sub(2);
            }
            Opcode::Add => {
                *machine.sp.sub(1) = (*machine.sp.sub(1)).wrapping_add(*machine.sp);
                machine.sp = machine.sp.sub(1);
            }
            Opcode::Mul => {
                *machine.sp.sub(1) = (*machine.sp.sub(1)).wrapping_mul(*machine.sp);
                machine.sp = machine.sp.sub(1);
            }
            Opcode::Vmctx => {
                *machine.sp.add(1) = machine as *const _ as u64;
                machine.sp = machine.sp.add(1);
            }
            Opcode::Vmexit => {
                let exit_ip = *machine.sp;
                machine.sp = machine.sp.sub(1);
                let vmexit: extern "C" fn(&mut Machine, u64) =
                    core::mem::transmute(vm::vmexit as *const usize as usize);
                vmexit(machine, exit_ip);
            }
        }
    }
}
