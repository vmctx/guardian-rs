#![no_std]
#![no_main]
extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;
use core::convert::TryFrom;
use core::ptr::slice_from_raw_parts;
use libc_alloc::LibcAlloc;

#[global_allocator]
static ALLOCATOR: LibcAlloc = LibcAlloc;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

mod crt;
mod region;

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

#[repr(u8)]
#[derive(num_enum::IntoPrimitive)]
pub enum Register {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl From<iced_x86::Register> for Register {
    fn from(reg: iced_x86::Register) -> Self {
        match reg {
            iced_x86::Register::RAX => Register::Rax,
            iced_x86::Register::RCX => Register::Rcx,
            iced_x86::Register::RDX => Register::Rdx,
            iced_x86::Register::RBX => Register::Rbx,
            iced_x86::Register::RSP => Register::Rsp,
            iced_x86::Register::RBP => Register::Rbp,
            iced_x86::Register::RSI => Register::Rsi,
            iced_x86::Register::RDI => Register::Rdi,
            iced_x86::Register::R8 => Register::R8,
            iced_x86::Register::R9 => Register::R9,
            iced_x86::Register::R10 => Register::R10,
            iced_x86::Register::R11 => Register::R11,
            iced_x86::Register::R12 => Register::R12,
            iced_x86::Register::R13 => Register::R13,
            iced_x86::Register::R14 => Register::R14,
            iced_x86::Register::R15 => Register::R15,
            iced_x86::Register::EAX => Register::Rax,
            iced_x86::Register::ECX => Register::Rcx,
            iced_x86::Register::EDX => Register::Rdx,
            iced_x86::Register::EBX => Register::Rbx,
            iced_x86::Register::ESP => Register::Rsp,
            iced_x86::Register::EBP => Register::Rbp,
            iced_x86::Register::ESI => Register::Rsi,
            iced_x86::Register::EDI => Register::Rdi,
            iced_x86::Register::R8D => Register::R8,
            iced_x86::Register::R9D => Register::R9,
            iced_x86::Register::R10D => Register::R10,
            iced_x86::Register::R11D => Register::R11,
            iced_x86::Register::R12D => Register::R12,
            iced_x86::Register::R13D => Register::R13,
            iced_x86::Register::R14D => Register::R14,
            iced_x86::Register::R15D => Register::R15,
            _ => panic!("unsupported register"),
        }
    }
}

#[repr(C)]
pub struct Machine {
    pc: *const u8,
    sp: *mut u64,
    pub regs: [u64; 16],
    program: *const u8, // for testing replace this with the array
    program_size: usize,
    vmstack: [u64; 0x1000],
    cpustack: [u64; 0x1000],
    pub vmenter: region::Allocation,
    vmexit: region::Allocation,
}

impl Machine {
    #[no_mangle]
    pub unsafe extern "C" fn new(program: *const u8, size: usize) -> Self {
        use iced_x86::code_asm::*;
        // fails at
        // mov     [rsp+10518h+var_10440], rcx
        let mut m = Self {
            pc: core::ptr::null(),
            sp: core::ptr::null_mut(),
            regs: [0; 16],
            program,
            program_size: size,
            vmstack: [0; 0x1000],
            cpustack: [0; 0x1000],
            vmenter: region::alloc(0x1000, region::Protection::READ_WRITE_EXECUTE).unwrap(),
            vmexit: region::alloc(0x1000, region::Protection::READ_WRITE_EXECUTE).unwrap(),
        };

        // Generate VMENTER.
        let regmap: &[(&AsmRegister64, u8)] = &[
            (&rax, Register::Rax.into()),
            (&rcx, Register::Rcx.into()),
            (&rdx, Register::Rdx.into()),
            (&rbx, Register::Rbx.into()),
            (&rsp, Register::Rsp.into()),
            (&rbp, Register::Rbp.into()),
            (&rsi, Register::Rsi.into()),
            (&rdi, Register::Rdi.into()),
            (&r8, Register::R8.into()),
            (&r9, Register::R9.into()),
            (&r10, Register::R10.into()),
            (&r11, Register::R11.into()),
            (&r12, Register::R12.into()),
            (&r13, Register::R13.into()),
            (&r14, Register::R14.into()),
            (&r15, Register::R15.into()),
        ];

        // thanks to cursey <3 :3 ^-^ >~<
        // remove this, place it into main.rs or something
        // wat i mean is pre assemble the vmenter and vmexit
        // instead of assembling it here
        // so i also dont need to allocate the regions
        // they will be stack/ in data section / in bytecode section
        // allocated maybe, to test just get the output from this code below
        // and replace vmenter and vmexit with the arrays
        // check in pe-bear for relocations!!
        let mut a = CodeAssembler::new(64).unwrap();

        a.mov(rax, &m as *const _ as u64).unwrap();

        // Store the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(qword_ptr(rax + offset), **reg).unwrap();
        }

        // Switch to the VM's CPU stack.
        let vm_rsp = unsafe {
            m.cpustack
                .as_ptr()
                .add(m.cpustack.len() - 0x100 - size_of::<u64>()) as u64
        };
        a.mov(rsp, vm_rsp).unwrap();

        a.mov(rcx, rax).unwrap();
        a.mov(rax, Self::run as u64).unwrap();
        a.jmp(rax).unwrap();

        let insts = a.assemble(m.vmenter.as_ptr::<u64>() as u64).unwrap();

        unsafe {
            core::ptr::copy(insts.as_ptr(), m.vmenter.as_mut_ptr(), insts.len());
        };

        // Generate VMEXIT.
        let regmap: &[(&AsmRegister64, u8)] = &[
            (&rax, Register::Rax.into()),
            (&rbx, Register::Rbx.into()),
            (&rsp, Register::Rsp.into()),
            (&rbp, Register::Rbp.into()),
            (&rsi, Register::Rsi.into()),
            (&rdi, Register::Rdi.into()),
            (&r8, Register::R8.into()),
            (&r9, Register::R9.into()),
            (&r10, Register::R10.into()),
            (&r11, Register::R11.into()),
            (&r12, Register::R12.into()),
            (&r13, Register::R13.into()),
            (&r14, Register::R14.into()),
            (&r15, Register::R15.into()),
        ];

        // look above, same applies here
        let mut a = CodeAssembler::new(64).unwrap();

        // Restore the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(**reg, qword_ptr(rcx + offset)).unwrap();
        }

        a.jmp(rdx).unwrap();

        let insts = a.assemble(m.vmexit.as_ptr::<u64>() as u64).unwrap();

        unsafe {
            core::ptr::copy(insts.as_ptr(), m.vmexit.as_mut_ptr(), insts.len());
        };

        m
    }

    // TODO to make this useable static in a patched binary, i have to translate the
    // program to assembly like in the machine::new function
    // this is currently JIT (just in time) have to translate to
    // AOT (Ahead of time) but idk if that makes sense because then its
    // literally the same as if its not virtualized like what urgh
    // gotta check virtualizer protector projects to understand
    #[allow(clippy::missing_safety_doc)]
    pub unsafe extern "C" fn run(&mut self) {
        let program = slice_from_raw_parts(self.program, self.program_size).as_ref().unwrap();

        self.pc = program.as_ptr();
        self.sp = self.vmstack.as_mut_ptr();

        while self.pc < program.as_ptr_range().end {
            let op = Opcode::try_from(*self.pc).unwrap();
            self.pc = self.pc.add(1);

            match op {
                Opcode::Const => {
                    *self.sp.add(1) = *(self.pc as *const u64);
                    self.sp = self.sp.add(1);
                    self.pc = self.pc.add(size_of::<u64>());
                }
                Opcode::Load => *self.sp = *(*self.sp as *const u64),
                Opcode::Store => {
                    *(*self.sp as *mut u64) = *self.sp.sub(1);
                    self.sp = self.sp.sub(2);
                }
                Opcode::Add => {
                    *self.sp.sub(1) = (*self.sp.sub(1)).wrapping_add(*self.sp);
                    self.sp = self.sp.sub(1);
                }
                Opcode::Mul => {
                    *self.sp.sub(1) = (*self.sp.sub(1)).wrapping_mul(*self.sp);
                    self.sp = self.sp.sub(1);
                }
                Opcode::Vmctx => {
                    *self.sp.add(1) = self as *const _ as u64;
                    self.sp = self.sp.add(1);
                }
                Opcode::Vmexit => {
                    let exit_ip = *self.sp;
                    self.sp = self.sp.sub(1);
                    let vmexit: extern "C" fn(&mut Machine, u64) =
                        core::mem::transmute(self.vmexit.as_ptr::<()>());
                    vmexit(self, exit_ip);
                }
            }
        }
    }
}
