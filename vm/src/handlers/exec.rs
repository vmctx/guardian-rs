use core::slice;

use memoffset::offset_of;

use vm_proc::handler;

use crate::assembler;
use crate::assembler::prelude::*;
use crate::assembler::Reg64::*;
use crate::assembler::RegXmm::*;
use crate::Machine;
use crate::shared::*;

#[handler]
pub unsafe fn vm_exec(vm: &mut Machine, _op_size: OpSize) {
    let instr_size = vm.pc.read_unaligned() as usize;
    vm.pc = vm.pc.add(1); // skip instr size
    reloc_instr(vm, vm.pc, instr_size);

    vm.pc = vm.pc.add(instr_size);
}

fn reloc_instr(
    vm: &mut Machine,
    instr_ptr: *const u8,
    instr_size: usize,
) {
    let mut non_vol_regs: [u64; 9] = [0, 0, 0, 0, 0, 0, 0, 0, 0];

    let non_vol_regmap: &[&Reg64] = &[&rbx, &rsp, &rbp, &rsi, &rdi, &r12, &r13, &r14, &r15];

    let regmap: &[(&Reg64, u8)] = &[
        (&rax, Register::Rax.into()),
        (&rbx, Register::Rbx.into()),
        (&rdx, Register::Rdx.into()),
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
        (&rcx, Register::Rcx.into()),
    ];

    let xmm_regmap: &[(&RegXmm, u8)] = &[
        (&xmm0, XmmRegister::Xmm0.into()),
        (&xmm1, XmmRegister::Xmm1.into()),
        (&xmm2, XmmRegister::Xmm2.into()),
        (&xmm3, XmmRegister::Xmm3.into()),
        (&xmm4, XmmRegister::Xmm4.into()),
        (&xmm5, XmmRegister::Xmm5.into()),
        (&xmm6, XmmRegister::Xmm6.into()),
        (&xmm7, XmmRegister::Xmm7.into()),
        (&xmm8, XmmRegister::Xmm8.into()),
        (&xmm9, XmmRegister::Xmm9.into()),
        (&xmm10, XmmRegister::Xmm10.into()),
        (&xmm11, XmmRegister::Xmm11.into()),
        (&xmm12, XmmRegister::Xmm12.into()),
        (&xmm13, XmmRegister::Xmm13.into()),
        (&xmm14, XmmRegister::Xmm14.into()),
        (&xmm15, XmmRegister::Xmm15.into()),
    ];

    let vm_ptr = vm as *mut _ as u64;

    let mut asm = Asm::new(&mut vm.instr_buffer);

    for (reg, regid) in xmm_regmap.iter() {
        let offset = memoffset::offset_of!(Machine, fxsave)
            + memoffset::offset_of!(XSaveMin, xmm_registers)
            + *regid as usize * 16;
        asm.movaps(**reg, assembler::MemOp::IndirectDisp(rcx, offset as i32));
    }

    for (index, reg) in non_vol_regmap.iter().enumerate() {
        let offset = index * 8;
        asm.mov(assembler::MemOp::IndirectDisp(rdx, offset as i32), **reg);
    }

    asm.mov(rax, MemOp::IndirectDisp(rcx, offset_of!(Machine, rflags) as i32));
    asm.push(rax);
    asm.popfq();

    for (reg, regid) in regmap.iter() {
        let offset = offset_of!(Machine, regs) + *regid as usize * 8;
        asm.mov(**reg, MemOp::IndirectDisp(rcx, offset as i32));
    }

    let instructions = unsafe { slice::from_raw_parts(instr_ptr, instr_size) };
    asm.code().extend_from_slice(instructions);

    asm.push(rax); // this decreases rsp need to adjust
    asm.mov(rax, Imm64::from(vm_ptr));

    let regmap: &[(&Reg64, u8)] = &[
        (&rbx, Register::Rbx.into()),
        (&rcx, Register::Rcx.into()),
        (&rdx, Register::Rdx.into()),
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

    for (reg, regid) in xmm_regmap.iter() {
        let offset = memoffset::offset_of!(Machine, fxsave)
            + memoffset::offset_of!(XSaveMin, xmm_registers)
            + *regid as usize * 16;
        asm.movaps(MemOp::IndirectDisp(rax, offset as i32), **reg);
    }

    for (reg, regid) in regmap.iter() {
        let offset = offset_of!(Machine, regs) + *regid as usize * 8;
        asm.mov(MemOp::IndirectDisp(rax, offset as i32), **reg);
    }

    // save rax too
    asm.mov(rcx, rax);

    // savef rflags
    asm.pushfq();
    asm.pop(rax);
    asm.mov(MemOp::IndirectDisp(rcx, offset_of!(Machine, rflags) as i32), rax);

    asm.pop(rax);
    // save rsp after stack ptr is adjusted again
    asm.mov(MemOp::IndirectDisp(rcx, offset_of!(Machine, regs) as i32 + (Register::Rsp as u8 as usize * 8) as i32), rsp);
    asm.mov(MemOp::IndirectDisp(rcx, offset_of!(Machine, regs) as i32), rax);

    asm.mov(rax, Imm64::from(non_vol_regs.as_mut_ptr() as u64));

    for (index, reg) in non_vol_regmap.iter().enumerate() {
        let offset = index * 8;
        asm.mov(**reg, assembler::MemOp::IndirectDisp(rax, offset as i32));
    }
    asm.ret();

    let func = unsafe {
        core::mem::transmute::<_, extern "C" fn(*mut Machine, *mut u64)>(vm.instr_buffer.as_mut_ptr())
    };
    // use non_vol_regs here so no use after free just in case
    func(vm, non_vol_regs.as_mut_ptr());

    vm.instr_buffer.clear();
}
