use std::ptr::read_unaligned;

use anyhow::Result;
use iced_x86::{Encoder, InstructionInfoFactory, MemorySize, OpKind};
use iced_x86::code_asm::{CodeAssembler, qword_ptr};
use memoffset::offset_of;
use super::traits::{OpSized, FreeReg};

use crate::shared::*;

#[repr(C)]
pub struct Machine {
    pub(crate) pc: *const u8,
    pub(crate) sp: *mut u64,
    pub regs: [u64; 16],
    pub fxsave: XSaveMin,
    pub rflags: u64,
    pub vmstack: *mut u64,
    pub cpustack: *mut u8,
}

#[derive(Default)]
pub struct Assembler {
    program: Vec<u8>,
}

impl Assembler {
    pub fn assemble(&self) -> Vec<u8> {
        self.program.clone()
    }

    pub fn len(&self) -> usize {
        self.program.len()
    }

    pub fn patch(&mut self, index: usize, value: u64) {
        self.program[index..][..8].copy_from_slice(&value.to_le_bytes());
    }

    pub fn const_<T: OpSized>(&mut self, v: T) {
        self.emit_sized::<T>(Opcode::Const);
        self.emit_const(v);
    }

    pub fn load<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Load);
    }

    pub fn load_xmm(&mut self) {
        self.emit(Opcode::LoadXmm);
    }

    pub fn store<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Store);
    }

    pub fn store_xmm(&mut self) {
        self.emit(Opcode::StoreXmm);
    }

    pub fn store_reg<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::StoreReg);
    }

    pub fn store_reg_zx<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::StoreRegZx);
    }

    pub fn add<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Add);
    }

    pub fn sub<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Sub);
    }

    pub fn div<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Div);
    }

    pub fn idiv<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::IDiv);
    }

    pub fn shr<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Shr);
    }

    pub fn combine<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Combine);
    }

    pub fn split<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Split);
    }

    pub fn mul<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Mul);
    }

    pub fn and<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::And);
    }

    pub fn or<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Or);
    }

    pub fn xor<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Xor);
    }

    pub fn not<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Not);
    }

    pub fn cmp<T: OpSized>(&mut self) {
        self.emit_sized::<T>(Opcode::Cmp);
    }

    pub fn jmp(&mut self, cond: JmpCond, target: u64) {
        self.emit(Opcode::Jmp);
        self.emit_const::<u8>(cond as u8);
        // could also be u8 or u16
        self.emit_const::<u64>(target);
    }

    pub fn rot_right(&mut self) {
        self.emit_sized::<u16>(Opcode::RotR);
    }

    pub fn rot_left(&mut self) {
        self.emit_sized::<u16>(Opcode::RotL);
    }

    pub fn vmadd(&mut self) {
        self.emit(Opcode::VmAdd);
    }

    pub fn vmsub(&mut self) {
        self.emit(Opcode::VmSub);
    }

    pub fn vmmul(&mut self) {
        self.emit(Opcode::VmMul);
    }

    pub fn vmctx(&mut self) {
        self.emit(Opcode::Vmctx);
    }

    pub fn vmreloc(&mut self, image_base: u64) {
        self.emit(Opcode::VmReloc);
        self.emit_const::<u64>(image_base);
    }

    pub fn call(&mut self, mut instr: iced_x86::Instruction, image_base: u64) {
        self.emit(Opcode::VmExec);

        let regs = instr.get_non_vol_free_regs();
        assert!(regs.len() >= 2);

        let mut asm = CodeAssembler::new(64).unwrap();
        asm.push(regs[0]).unwrap();
        asm.push(regs[1]).unwrap();
        asm.mov(regs[0], instr.near_branch_target() - image_base).unwrap();
        asm.mov(regs[1], qword_ptr(0x60).gs()).unwrap();
        asm.mov(regs[1], qword_ptr(regs[1] + 0x10)).unwrap();
        asm.add(regs[0], regs[1]).unwrap();
        asm.pop(regs[1]).unwrap();
        //
        asm.call(regs[0]).unwrap();
        //
        asm.pop(regs[0]).unwrap();
        let instr_buffer = asm.assemble(0).unwrap();
        self.emit_const(instr_buffer.len() as u8);
        self.program.extend_from_slice(&instr_buffer);
    }

    pub fn vmexec(&mut self, mut instr: iced_x86::Instruction, image_base: u64) {
        self.emit(Opcode::VmExec);
        // todo check if immediate and reloc entry
        if instr.is_ip_rel_memory_operand() {
            // todo improve and make sure regs are really not used
            let regs = instr.get_free_regs();
            assert!(regs.len() >= 2);

            let mut asm = CodeAssembler::new(64).unwrap();
            asm.push(regs[0]).unwrap();
            asm.push(regs[1]).unwrap();
            asm.mov(regs[0], instr.next_ip() - image_base).unwrap();
            asm.mov(regs[1], qword_ptr(0x60).gs()).unwrap();
            asm.mov(regs[1], qword_ptr(regs[1] + 0x10)).unwrap();
            asm.add(regs[0], regs[1]).unwrap();
            asm.pop(regs[1]).unwrap();
            //
            instr.set_memory_base(iced_x86::Register::from(regs[0]));
            asm.add_instruction(instr).unwrap();
            //
            asm.pop(regs[0]).unwrap();

            let instr_buffer = asm.assemble(0).unwrap();
            self.emit_const(instr_buffer.len() as u8);
            self.program.extend_from_slice(&instr_buffer);
        } else {
            let mut encoder = Encoder::new(64);
            encoder.encode(&instr, instr.ip()).unwrap();
            let instr_buffer = encoder.take_buffer();
            self.emit_const(instr_buffer.len() as u8);
            self.program.extend_from_slice(&instr_buffer);
        }
    }

    pub fn vmexit(&mut self) {
        self.emit(Opcode::VmExit);
    }

    fn emit_sized<T: OpSized>(&mut self, op: Opcode) {
        self.program.push(op.into());
        self.program.push(T::as_op_size().into());
    }

    fn emit(&mut self, op: Opcode) {
        self.program.push(op.into());
        // testing size encoding on every instruction
        self.program.push(u64::as_op_size().into());
    }

    fn emit_const<T: OpSized>(&mut self, value: T) {
        self.program.extend_from_slice(&value.to_le_bytes());
    }
}
