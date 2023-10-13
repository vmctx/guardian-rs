#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;
use core::convert::TryFrom;

#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn run(machine: &mut Machine) {
    machine.pc = machine.program.as_ptr();
    machine.sp = machine.vmstack.as_mut_ptr();

    while machine.pc < machine.program.as_ptr_range().end {
        let op = Opcode::try_from(*machine.pc).unwrap();
        machine.pc = machine.pc.add(1);

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
                    core::mem::transmute(machine.vmexit.as_ptr::<()>());
                vmexit(machine, exit_ip);
            }
        }
    }
}

#[allow(clippy::len_without_is_empty)]
pub struct Allocation {
    base: *const (),
    size: usize,
}

impl Allocation {
    /// Returns a pointer to the allocation's base address.
    ///
    /// The address is always aligned to the operating system's page size.
    #[inline(always)]
    pub fn as_ptr<T>(&self) -> *const T {
        self.base.cast()
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum Opcode {
    Const,
    Load,
    Store,
    Add,
    Mul,
    Vmctx,
    Vmexit,
}

impl From<u8> for Opcode {
    fn from(reg: u8) -> Self {
        match reg {
            0 => Opcode::Const,
            1 => Opcode::Load,
            2 => Opcode::Store,
            3 => Opcode::Add,
            4 => Opcode::Mul,
            5 => Opcode::Vmctx,
            6 => Opcode::Vmexit,
            _ => panic!("unsupported register"),
        }
    }
}

pub struct Machine {
    pc: *const u8,
    sp: *mut u64,
    pub regs: [u64; 16],
    program: Vec<u8>,
    vmstack: Vec<u64>,
    cpustack: Vec<u8>,
    pub vmenter: Allocation,
    vmexit: Allocation,
}
