use std::collections::HashMap;
use crate::vm::machine::{Assembler, Register, Machine, JmpCond};
use iced_x86::{Decoder, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind};
use memoffset::offset_of;

trait Asm {
    fn const_(&mut self, v: u64);
    fn load(&mut self);
    fn store(&mut self);
    fn add(&mut self);
    // 32 bit add
    fn addd(&mut self);
    fn sub(&mut self);
    // 32 bit sub
    fn subd(&mut self);
    fn div(&mut self);
    fn mul(&mut self);
    fn and(&mut self);
    fn or(&mut self);
    fn xor(&mut self);
    fn not(&mut self);
    fn cmp(&mut self);
    fn vmadd(&mut self);
    fn vmsub(&mut self);
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
macro_rules! vmasm {
    (
        $self:ident,
        $($inst:ident $($operand:expr),* );* $(;)*
    ) => {{
        $(
            Asm::$inst(
                $self,
                $($operand),*
            );
        )*
    }}
}

macro_rules! binary_op {
    ($self:ident, $inst:ident, $op:ident) => {{
        assert_eq!($inst.op_count(), 2);

        vmasm!($self,
            load_operand $inst, 0;
            load_operand $inst, 1;
            $op;
            store_operand $inst, 0;
        );
    }}
}

struct Virtualizer {
    asm: Assembler,
}

impl Virtualizer {
    pub fn new() -> Self {
        Self {
            asm: Assembler::default(),
        }
    }

    pub fn virtualize(&mut self, program: &[u8]) -> Vec<u8> {
        self.virtualize_with_ip(0, program)
    }

    pub fn virtualize_with_ip(&mut self, ip: u64, program: &[u8]) -> Vec<u8> {
        let mut decoder = Decoder::with_ip(64, program, ip, 0);
        let mut unresolved_jmps = 0;
        let mut jmp_map = HashMap::<u64, usize>::new();

        for inst in decoder.iter() {
            if jmp_map.contains_key(&inst.ip()) {
                self.asm.patch(*jmp_map.get(&inst.ip()).unwrap() + 2, self.asm.len() as u64);
                jmp_map.remove(&inst.ip()).unwrap();
                unresolved_jmps -= 1;
            } else {
                jmp_map.insert(inst.ip(), self.asm.len());
            }

            match inst.mnemonic() {
                Mnemonic::Mov => self.mov(&inst),
                Mnemonic::Movzx => self.movzx(&inst),
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
                // todo need to add jne, jb etc now (mostly same as jmp but with rflag checks)
                // and extensively test jmp to work in real world example
                Mnemonic::Jmp | Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jbe
                | Mnemonic::Ja | Mnemonic::Jle | Mnemonic::Jg => {
                    if !inst.is_jcc_short() && !inst.is_jmp_short() {
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
                    let mut output = String::new();
                    NasmFormatter::new().format(&inst, &mut output);
                    panic!("unsupported instruction: {}", output);
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
            load_operand inst, 1;
            store_operand inst, 0;
        );
    }

    // todo
    fn movzx(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand inst, 1;
            store_operand inst, 0;
        );
    }

    // todo
    fn add(&mut self, inst: &Instruction) {
        if inst.op0_register().is_gpr32() {
            binary_op!(self, inst, addd);
        } else {
            binary_op!(self, inst, add);
        }
    }

    // todo
    fn sub(&mut self, inst: &Instruction) {
        if inst.op0_register().is_gpr32() {
            binary_op!(self, inst, subd);
        } else {
            binary_op!(self, inst, sub);
        }
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
        use iced_x86::Register::RAX;
        // opkind has to be memory or register
        assert_ne!(inst.op0_kind(), OpKind::Immediate8to64);

        vmasm!(self,
            load_reg RAX;
            load_operand inst, 0;
            div;
            store_reg RAX;
        );
    }

    // todo untested
    // divide op0 by 2 for op1 times
    fn shr(&mut self, inst: &Instruction) {
        // opkind has to be memory or register
        assert_eq!(inst.op0_kind(), OpKind::Register);
        assert_eq!(inst.op1_kind(), OpKind::Immediate8);
        assert_eq!(inst.immediate8(), 1);

        vmasm!(self,
            load_operand inst, 0;
            const_ 2;
            div;
            store_operand inst, 0;
        );
    }

    fn mul(&mut self, inst: &Instruction) {
        binary_op!(self, inst, mul);
    }

    fn and(&mut self, inst: &Instruction) {
        binary_op!(self, inst, and);
    }

    fn or(&mut self, inst: &Instruction) {
        binary_op!(self, inst, or);
    }

    fn xor(&mut self, inst: &Instruction) {
        binary_op!(self, inst, xor);
    }

    fn not(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand inst, 0;
            not;
            store_operand inst, 0;
        );
    }

    fn cmp(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand inst, 0;
            load_operand inst, 1;
            cmp;
        );
    }

    // seems to be correct
    fn lea(&mut self, inst: &Instruction) {
        vmasm!(self,
            lea_operand inst;
            store_operand inst, 0;
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
            load_reg RSP;
            const_ 8;
            vmsub;
            store_reg RSP;

            load_operand inst, 0;
            load_reg RSP;
            store;
        );
    }

    fn pop(&mut self, inst: &Instruction) {
        use iced_x86::Register::RSP;

        vmasm!(self,
            load_reg RSP;
            load;
            store_operand inst, 0;

            load_reg RSP;
            const_ 8;
            vmadd;
            store_reg RSP;
        );
    }
}

impl Asm for Virtualizer {
    fn const_(&mut self, v: u64) {
        self.asm.const_(v);
    }

    fn load(&mut self) {
        self.asm.load();
    }

    fn store(&mut self) {
        self.asm.store();
    }

    fn add(&mut self) {
        self.asm.add();
    }

    fn addd(&mut self) {
        self.asm.addd();
    }

    fn sub(&mut self) {
        self.asm.sub();
    }

    fn subd(&mut self) {
        self.asm.subd();
    }

    fn div(&mut self) {
        self.asm.div();
    }

    fn mul(&mut self) {
        self.asm.mul();
    }

    fn and(&mut self) {
        self.asm.and();
    }

    fn or(&mut self) {
        self.asm.or();
    }

    fn xor(&mut self) {
        self.asm.xor();
    }

    fn not(&mut self) {
        self.asm.not();
    }

    fn cmp(&mut self) {
        self.asm.cmp();
    }

    fn vmadd(&mut self) {
        self.asm.vmadd()
    }

    fn vmsub(&mut self) {
        self.asm.vmsub()
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
                self.asm.load();
            }
            // todo maybe use traits to restrict opkinds on some functions
            // like div which can only have register and memory
            // sub can have immediates as example
            OpKind::Immediate8to32 => {
                self.const_(inst.immediate8to32() as u64)
            }
            OpKind::Immediate8to64 => {
                self.const_(inst.immediate8to64() as u64)
            }
            OpKind::Immediate32to64 => {
                self.const_(inst.immediate32to64() as u64)
            }
            _ => panic!("unsupported operand: {:?}", inst.op_kind(operand)),
        }
    }

    fn store_operand(&mut self, inst: &Instruction, operand: u32) {
        match inst.op_kind(operand) {
            OpKind::Register => self.store_reg(inst.op_register(operand)),
            OpKind::Memory => {
                self.lea_operand(inst);
                self.asm.store();
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
        self.asm.load();
    }

    fn store_reg(&mut self, reg: iced_x86::Register) {
        let r: u8 = Register::from(reg).into();
        let reg_offset = r as u64 * 8;
        self.asm.vmctx();
        self.asm
            .const_(offset_of!(Machine, regs) as u64 + reg_offset);
        self.asm.vmadd();
        self.asm.store();
    }

    fn lea_operand(&mut self, inst: &Instruction) {
        if inst.memory_base() != iced_x86::Register::None {
            self.load_reg(inst.memory_base());
        }

        if inst.memory_index() != iced_x86::Register::None {
            self.load_reg(inst.memory_index());
            self.asm.const_(inst.memory_index_scale() as u64);
            self.asm.mul();

            if inst.memory_base() != iced_x86::Register::None {
                self.asm.vmadd();
            }
        }

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

pub fn virtualize_with_ip(ip: u64, program: &[u8]) -> Vec<u8> {
    Virtualizer::new().virtualize_with_ip(ip, program)
}
