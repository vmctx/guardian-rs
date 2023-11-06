use std::collections::HashMap;
use exe::{PE, VecPE};
use crate::virt::machine::{Machine, Assembler, Register, JmpCond, OpSized, OpSize, HigherLower8Bit, RegUp};
use iced_x86::{Decoder, Encoder, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind};
use memoffset::offset_of;
use crate::diassembler::Disassembler;

trait Asm {
    fn const_<T: OpSized>(&mut self, v: T);
    fn load<T: OpSized>(&mut self);
    fn store<T: OpSized>(&mut self);
    fn add<T: OpSized>(&mut self);
    fn sub<T: OpSized>(&mut self);
    fn div<T: OpSized>(&mut self);
    fn mul<T: OpSized>(&mut self);
    fn and<T: OpSized>(&mut self);
    fn or<T: OpSized>(&mut self);
    fn xor<T: OpSized>(&mut self);
    fn not<T: OpSized>(&mut self);
    fn cmp<T: OpSized>(&mut self);
    fn vmadd(&mut self);
    fn vmsub(&mut self);
    fn vmmul(&mut self);
    fn vmctx(&mut self);
    fn vmexit(&mut self);
    fn load_operand(&mut self, inst: &Instruction, operand: u32);
    fn store_operand(&mut self, inst: &Instruction, operand: u32);
    fn load_reg(&mut self, reg: iced_x86::Register);
    fn store_reg(&mut self, reg: iced_x86::Register);
    fn lea_operand(&mut self, inst: &Instruction);
}

/// A fun little macro that makes writing VM assembly more familiar. For example, instead of:
/// ```
/// self.asm.const_(2);
/// self.asm.const_(3);
/// self.asm.add();
/// ```
/// we can do:
/// ```
/// vmasm!(self,
///     const_ 2;
///     const_ 3;
///     add;
/// );
/// ```
/// Just like we were handwriting assembly in a .asm file.
macro_rules! vmasm {(
    $self:ident,
    $(
        $inst:ident $(::<$($T:ty),*>)? $(, $operand:expr)* ;
    )*
) => ({
    $(
        Asm::$inst $(::<$($T),*>)? (
            $self,
            $($operand),*
        );
    )*
})}

macro_rules! binary_op {
    ($self:ident, $inst:ident, $op:ident) => {{
        assert_eq!($inst.op_count(), 2);

        vmasm!($self,
            load_operand, $inst, 0;
            load_operand, $inst, 1;
        );
        match OpSize::try_from($inst).unwrap() {
            OpSize::Byte => vmasm!($self, $op::<u8>;),
            OpSize::Word => vmasm!($self, $op::<u16>;),
            OpSize::Dword => vmasm!($self, $op::<u32>;),
            OpSize::Qword => vmasm!($self, $op::<u64>;)
        }
        vmasm!($self,
            store_operand, $inst, 0;
        );
    }}
}

macro_rules! sized_op {
    ($self:ident, $inst:ident, $op:ident) => {{
        match OpSize::try_from($inst).unwrap() {
            OpSize::Byte => vmasm!($self, $op::<u8>;),
            OpSize::Word => vmasm!($self, $op::<u16>;),
            OpSize::Dword => vmasm!($self, $op::<u32>;),
            OpSize::Qword => vmasm!($self, $op::<u64>;)
        }
    }}
}

struct Virtualizer {
    asm: Assembler,
    pe: Option<VecPE>,
}

impl Virtualizer {
    pub fn new() -> Self {
        Self {
            asm: Assembler::default(),
            pe: None,
        }
    }

    pub fn with_pe(pe: VecPE) -> Self {
        Self {
            asm: Assembler::default(),
            pe: Some(pe),
        }
    }

    pub fn virtualize(&mut self, program: &[u8]) -> Vec<u8> {
        self.virtualize_with_ip(0, program)
    }

    pub fn virtualize_with_ip(&mut self, ip: u64, program: &[u8]) -> Vec<u8> {
        let mut decoder = Decoder::with_ip(64, program, ip, 0);
        let mut unresolved_jmps = 0;
        let mut jmp_map = HashMap::<u64, usize>::new();

        for mut inst in decoder.iter() {
            if inst.is_ip_rel_memory_operand() { // or if its contained in relocs?
                // todo check pefile for relocs at inst.ip(), if it has entry
                // add relocate opcode that pops latest address from stack
                // relocates it and pushes it back or something like that
                // https://github.com/layerfsd/phantasm-x86-virtualizer/blob/master/chvrn_vm/relocations.cpp
                // -
                // for rip relative just get absolute address?
            }

            if jmp_map.contains_key(&inst.ip()) {
                self.asm.patch(*jmp_map.get(&inst.ip()).unwrap() + 3, self.asm.len() as u64);
                jmp_map.remove(&inst.ip()).unwrap();
                unresolved_jmps -= 1;
            } else {
                jmp_map.insert(inst.ip(), self.asm.len());
            }

            match inst.mnemonic() {
                Mnemonic::Mov => self.mov(&inst),
                //Mnemonic::Movzx => self.movzx(&inst),
                Mnemonic::Add => self.add(&inst),
                Mnemonic::Sub => self.sub(&inst),
                // todo for now dont support them, see div method below
                Mnemonic::Div => self.div(&inst),
                //Mnemonic::Idiv => self.div(inst),
                // same reason as div
                Mnemonic::Shr => self.shr(&inst),
                //Mnemonic::Mul => self.mul(inst),
                Mnemonic::Imul => self.mul(&inst),
                Mnemonic::And => self.and(&inst),
                Mnemonic::Or => self.or(&inst),
                Mnemonic::Xor => self.xor(&inst),
                Mnemonic::Not => self.not(&inst),
                Mnemonic::Cmp => self.cmp(&inst),
                Mnemonic::Lea => self.lea(&inst),
                Mnemonic::Ret => self.ret(),
                Mnemonic::Push => self.push(&inst),
                Mnemonic::Pop => self.pop(&inst),
                Mnemonic::Jmp | Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jbe
                | Mnemonic::Ja | Mnemonic::Jle | Mnemonic::Jg => {
                    if !inst.is_jcc_short_or_near() && !inst.is_jmp_short_or_near() {
                        let mut output = String::new();
                        NasmFormatter::new().format(&inst, &mut output);
                        panic!("unsupported jmp: {}", output);
                    }

                    let condition = JmpCond::from(inst.mnemonic());

                    let target = inst.near_branch_target();

                    if target > inst.ip() {
                        jmp_map.insert(target, self.asm.len());
                        self.asm.jmp(condition, 0);
                        unresolved_jmps += 1;
                    } else if jmp_map.contains_key(&target) {
                        self.asm.jmp(condition, *jmp_map.get(&target).unwrap() as _);
                    } else {
                        unresolved_jmps += 1;
                    }
                }
                _ => {
                    if inst.is_jmp_short() || inst.is_jmp_short_or_near() || inst.is_jmp_near_indirect() || inst.is_jmp_far() || inst.is_jmp_far_indirect() {
                        panic!("unsupported");
                    }

                    let mut encoder = Encoder::new(64);
                    encoder.encode(&inst, inst.ip()).unwrap();
                    let instr_buffer = encoder.take_buffer();
                    Disassembler::from_bytes(instr_buffer).disassemble();
                    if inst.op_kinds().any(|x| x == OpKind::Memory) && inst.is_ip_rel_memory_operand() {
                        println!("{:x}", inst.memory_displacement32());
                        // currently i only know how to calculate it if i know the new rip
                        /*
                        14800+ 20 = 14820
                        14000+ 20 = 14020

                        14800(old_rip) - 14000(rip) = 800 + 14000 (rip)

                        14500+ 20 = 14520
                        14800+ 20 = 14820

                        14200(old_rip) diff 14800(rip) =  14800 - 600(DIFF)
                         */
                        inst.set_memory_displacement32((inst.next_ip() + inst.memory_displacement64()) as u32);
                        println!("{:x}", inst.memory_displacement32());
                    }

                    let mut encoder = Encoder::new(64);
                    encoder.encode(&inst, inst.ip()).unwrap();
                    let instr_buffer = encoder.take_buffer();
                    Disassembler::from_bytes(instr_buffer).disassemble();
                    panic!();
                    // todo check for control flow altering instructions and give error
                    self.asm.vmexec(inst);
                    /*
                    let mut output = String::new();
                    NasmFormatter::new().format(&inst, &mut output);
                    panic!("unsupported instruction: {}", output);
                     */
                    // todo
                    // emit special vmexit (or just vmexitrenter whatever) opcode
                    // relocate instruction into bytecode (max instruction size is 15 bytes afaik?)
                    // so vmreexit (or smthin) relocinstr (instr data (relocated if rip relative)
                    // vmexit (restore registers)
                    // executes instr data somehow (alloc rwx or change bytecode protection
                    // vmreenter with changed registers (maybe without deallocating reallocation
                    // of stack somehow if possible, but not needed)
                    // maybe jit assemble it in the vm like
                    // call vmexit (it will have to restore all registers afaik)
                    // call should make it return here instead of before original vmenter
                    // jitasm.insert(unvirt_instr)M
                    // jitasm.push(self.pc + size_of unvirt instr);
                    // jitasm.jmp(vmenter);
                    // jitasm.execute() // allocates rwx region, moves bytes there
                    // and executes by jmp (original ret addr needs to be saved)
                    // option 2
                    // allocate instructions on vmstack ? or allocate buffer
                    // do the jit assemble above
                    // set first ret addr to addr of buffer (for vmexit)
                    // set second to here + size of inst buffer or sumthin
                    // jmp vmexit (but without dealloc), just restoring rsp etc
                    // then save regs after jmping back
                    // -
                    // it should restore regs, ret to buffer, ret to here, save regs,
                    // continue execution
                }
            }
        }

        if unresolved_jmps != 0 {
            panic!("{} unresolved jmps", unresolved_jmps);
        }

        self.asm.assemble()
    }

    fn mov(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand, inst, 1;
            store_operand, inst, 0;
        );
    }

    // todo
    fn movzx(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand, inst, 1;
            store_operand, inst, 0;
        );
    }

    // https://blog.back.engineering/17/05/2021/#ADD
    fn add(&mut self, inst: &Instruction) {
        binary_op!(self, inst, add)
    }

    fn sub(&mut self, inst: &Instruction) {
        binary_op!(self, inst, sub)
    }

    // todo store remainder, use correct regs
    // https://treeniks.github.io/x86-64-simplified/instructions/binary-arithmetic-instructions/div.html
    // inst.op0_kind().eq(...)
    // inst.op_register(0).size() 1, 2, 4, 8 bytes
    /*
    load_operand inst, 0;
    if op_kind is 8 bit
        load_reg AX
        div
        store_reg AL
        store_reg AH
    else if op_kind is 16 bit
        load_reg AX
        div
        store_reg AX
        store_reg DX
    else if op_kind is 32 bit
        load_reg EAX
        div
        store_reg EAX
        store_reg EDX
    else if op_kind is 64 bit
        load_reg RAX
        div
        store_reg RAX
        store_reg RDX

     */
    fn div(&mut self, inst: &Instruction) {
        use iced_x86::Register::{AX, EAX, RAX};

        // opkind has to be memory or register
        assert_ne!(inst.op0_kind(), OpKind::Immediate8to64);

        match OpSize::try_from(inst.op0_register()).unwrap() {
            OpSize::Byte => panic!("unsupported operand size"),
            OpSize::Word => vmasm!(self,
                load_reg, AX;
                load_operand, inst, 0;
                div::<u16>;
                store_reg, AX; // no clue
            ),
            OpSize::Dword => vmasm!(self,
                load_reg, EAX;
                load_operand, inst, 0;
                div::<u32>;
                store_reg, EAX;
            ),
            OpSize::Qword => vmasm!(self,
                load_reg, RAX;
                load_operand, inst, 0;
                div::<u64>;
                store_reg, RAX;
            )
        };
    }

    // todo untested
    // divide op0 by 2 for op1 times
    fn shr(&mut self, inst: &Instruction) {
        // opkind has to be memory or register
        assert_eq!(inst.op0_kind(), OpKind::Register);
        assert_eq!(inst.op1_kind(), OpKind::Immediate8);

        for _ in 0..inst.immediate8() {
            vmasm!(self,
                load_operand, inst, 0;
            );
            match OpSize::try_from(inst.op0_register()).unwrap() {
                OpSize::Byte => vmasm!(self, const_::<u8>, 2; div::<u8>;),
                OpSize::Word => vmasm!(self, const_::<u16>, 2; div::<u16>;),
                OpSize::Dword => vmasm!(self, const_::<u32>, 2; div::<u32>;),
                OpSize::Qword => vmasm!(self, const_::<u64>, 2; div::<u64>;),
            }
            vmasm!(self,
                store_operand, inst, 0;
            );
        }
    }

    fn mul(&mut self, inst: &Instruction) {
        binary_op!(self, inst, mul)
    }

    fn and(&mut self, inst: &Instruction) {
        binary_op!(self, inst, and)
    }

    fn or(&mut self, inst: &Instruction) {
        binary_op!(self, inst, or)
    }

    fn xor(&mut self, inst: &Instruction) {
        binary_op!(self, inst, xor)
    }

    fn not(&mut self, inst: &Instruction) {
        vmasm!(self,load_operand, inst, 0;);
        sized_op!(self, inst, not);
        vmasm!(self,store_operand, inst, 0;);
    }

    fn cmp(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand, inst, 0;
            load_operand, inst, 1;
        );
        sized_op!(self, inst, cmp);
    }

    // seems to be correct
    fn lea(&mut self, inst: &Instruction) {
        vmasm!(self,
            lea_operand, inst;
            store_operand, inst, 0;
        );
    }

    fn ret(&mut self) {
        /*
        use iced_x86::Register::RSP;

        vmasm!(self,
            load_reg RSP;
            load;
            load_reg RSP;
            const_ 8;
            vmadd;
            store_reg RSP;
            vmexit;
        );
         */
        vmasm!(self,
            vmexit;
        );
    }

    fn push(&mut self, inst: &Instruction) {
        use iced_x86::Register::RSP;

        vmasm!(self,
            load_reg, RSP;
            const_::<u64>, 8;
            vmsub;
            store_reg, RSP;

            load_operand, inst, 0;
            load_reg, RSP;
        );
        sized_op!(self, inst, store);
    }

    fn pop(&mut self, inst: &Instruction) {
        use iced_x86::Register::RSP;

        vmasm!(self,
            load_reg, RSP;
        );
        sized_op!(self, inst, load);
        vmasm!(self,
            store_operand, inst, 0;

            load_reg, RSP;
            const_::<u64>, 8;
            vmadd;
            store_reg, RSP;
        );
    }
}

impl Asm for Virtualizer {
    fn const_<T: OpSized>(&mut self, v: T) {
        self.asm.const_::<T>(v);
    }

    fn load<T: OpSized>(&mut self) {
        self.asm.load::<T>();
    }

    fn store<T: OpSized>(&mut self) {
        self.asm.store::<T>();
    }

    fn add<T: OpSized>(&mut self) {
        self.asm.add::<T>();
    }

    fn sub<T: OpSized>(&mut self) {
        self.asm.sub::<T>();
    }

    fn div<T: OpSized>(&mut self) {
        self.asm.div::<T>();
    }

    fn mul<T: OpSized>(&mut self) {
        self.asm.mul::<T>();
    }

    fn and<T: OpSized>(&mut self) {
        self.asm.and::<T>();
    }

    fn or<T: OpSized>(&mut self) {
        self.asm.or::<T>();
    }

    fn xor<T: OpSized>(&mut self) {
        self.asm.xor::<T>();
    }

    fn not<T: OpSized>(&mut self) {
        self.asm.not::<T>();
    }

    fn cmp<T: OpSized>(&mut self) {
        self.asm.cmp::<T>();
    }

    fn vmadd(&mut self) {
        self.asm.vmadd()
    }

    fn vmsub(&mut self) {
        self.asm.vmsub()
    }

    fn vmmul(&mut self) {
        self.asm.vmmul()
    }

    fn vmctx(&mut self) {
        self.asm.vmctx();
    }

    fn vmexit(&mut self) {
        self.asm.vmexit();
    }

    fn load_operand(&mut self, inst: &Instruction, operand: u32) {
        match inst.op_kind(operand) {
            OpKind::Register => self.load_reg(inst.op_register(operand)),
            OpKind::Memory => {
                self.lea_operand(inst);
                sized_op!(self, inst, load);
            }
            OpKind::Immediate8 => self.const_(inst.immediate8()),
            OpKind::Immediate8to16 => self.const_(inst.immediate8to16() as u16),
            OpKind::Immediate16 => self.const_(inst.immediate16()),
            OpKind::Immediate8to32 => self.const_(inst.immediate8to32() as u32),
            OpKind::Immediate32 => self.const_(inst.immediate32()),
            OpKind::Immediate8to64 => self.const_(inst.immediate8to64() as u64),
            OpKind::Immediate32to64 => self.const_(inst.immediate32to64() as u64),
            OpKind::Immediate64 => self.const_(inst.immediate64()),
            _ => panic!("unsupported operand: {:?}", inst.op_kind(operand)),
        }
    }

    fn store_operand(&mut self, inst: &Instruction, operand: u32) {
        match inst.op_kind(operand) {
            OpKind::Register => self.store_reg(inst.op_register(operand)),
            OpKind::Memory => {
                self.lea_operand(inst);
                sized_op!(self, inst, store);
            }
            _ => panic!("unsupported operand"),
        }
    }

    fn load_reg(&mut self, reg: iced_x86::Register) {
        let r: u8 = Register::from(reg).into();
        let reg_offset = r as u64 * 8;
        self.asm.vmctx();
        self.asm
            .const_(offset_of!(Machine, regs) as u64 + reg_offset);
        self.asm.vmadd();

        let operand_size = OpSize::try_from(reg.size() as u8).unwrap();

        match operand_size {
            OpSize::Byte => if reg.is_higher_8_bit() {
                // load 8 is same as 16 bit anyways it will get truncated
                self.asm.load::<u16>();
                // shift higher bits to lower on stack
                self.asm.rot_right();
            } else {
                self.asm.load::<u8>()
            },
            OpSize::Word => self.asm.load::<u16>(),
            OpSize::Dword => self.asm.load::<u32>(),
            OpSize::Qword => self.asm.load::<u64>()
        }
    }

    fn store_reg(&mut self, reg: iced_x86::Register) {
        let r: u8 = Register::from(reg).into();
        let reg_offset = r as u64 * 8;
        self.asm.vmctx();
        self.asm
            .const_(offset_of!(Machine, regs) as u64 + reg_offset);
        self.asm.vmadd();

        let operand_size = OpSize::try_from(reg.size() as u8).unwrap();

        match operand_size {
            OpSize::Byte => if reg.is_higher_8_bit() {
                self.asm.store_reg::<u8>();
                self.load_reg(reg.get_gpr_16());
                self.asm.rot_left();
                self.store_reg(reg.get_gpr_16());
            } else {
                self.asm.store_reg::<u8>()
            },
            OpSize::Word => self.asm.store_reg::<u16>(),
            OpSize::Dword => self.asm.store_reg::<u32>(),
            OpSize::Qword => self.asm.store_reg::<u64>()
        }
    }

    fn lea_operand(&mut self, inst: &Instruction) {
        if inst.memory_base() == iced_x86::Register::RIP {
            self.const_(inst.next_ip());
            self.asm.vmreloc(self.pe.as_ref()
                .expect("rip relative instr but pe is none")
                .get_image_base().unwrap()
            );
        } else if inst.memory_base() != iced_x86::Register::None {
            self.load_reg(inst.memory_base());
        }

        if inst.memory_index() != iced_x86::Register::None {
            self.load_reg(inst.memory_index());
            self.asm.const_(inst.memory_index_scale() as u64);
            self.asm.vmmul();

            if inst.memory_base() != iced_x86::Register::None {
                self.asm.vmadd();
            }
        }

        // todo check if it has reloc entry and relocate if it does
        // check if theres a reloc entry for this instruction, if there is emit
        // vmrebase opcode (tba, see above)
        self.asm.const_(inst.memory_displacement64());

        if inst.memory_base() != iced_x86::Register::None
            || inst.memory_index() != iced_x86::Register::None
        {
            self.asm.vmadd();
        }
    }
}

pub fn virtualize(program: &[u8]) -> Vec<u8> {
    Virtualizer::new().virtualize(program)
}

pub fn virtualize_with_ip(pe: VecPE, ip: u64, program: &[u8]) -> Vec<u8> {
    Virtualizer::with_pe(pe).virtualize_with_ip(ip, program)
}
