use std::collections::HashMap;
use crate::vm::machine::{Assembler, Register, Machine};
use iced_x86::{Decoder, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind};
use iced_x86::Register::EAX;
use memoffset::offset_of;

trait Asm {
    fn const_(&mut self, v: u64);
    fn load(&mut self);
    fn store(&mut self);
    fn add(&mut self);
    fn sub(&mut self);
    fn div(&mut self);
    fn mul(&mut self);
    fn and(&mut self);
    fn or(&mut self);
    fn xor(&mut self);
    fn cmp(&mut self);
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
                self.asm.patch(*jmp_map.get(&inst.ip()).unwrap() + 1, self.asm.len() as u64);
                jmp_map.remove(&inst.ip()).unwrap();
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
                //Mnemonic::Mul => self.mul(inst),
                Mnemonic::Imul => self.mul(&inst),
                Mnemonic::And => self.and(&inst),
                Mnemonic::Or => self.or(&inst),
                Mnemonic::Xor => self.xor(&inst),
                Mnemonic::Cmp => self.cmp(&inst),
                Mnemonic::Ret => self.ret(),
                Mnemonic::Push => self.push(&inst),
                Mnemonic::Pop => self.pop(&inst),
                // todo need to add jne, jb etc now (mostly same as jmp but with rflag checks)
                // and extensively test jmp to work in real world example
                Mnemonic::Jmp | Mnemonic::Je | Mnemonic::Jne => {
                    if !inst.is_jcc_short() && !inst.is_jmp_short() {
                        let mut output = String::new();
                        NasmFormatter::new().format(&inst, &mut output);
                        panic!("unsupported jmp: {}", output);
                    }

                    let target = ip + inst.near_branch_target();
                    println!("target: {}", target);
                    if target > inst.ip() {
                        jmp_map.insert(target, self.asm.len());
                        self.asm.jmp(0);
                    } else if jmp_map.contains_key(&target) {
                        self.asm.jmp(*jmp_map.get(&target).unwrap() as _);
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

    fn add(&mut self, inst: &Instruction) {
        binary_op!(self, inst, add);
    }

    fn sub(&mut self, inst: &Instruction) {
        binary_op!(self, inst, sub);
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

    fn cmp(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand inst, 1;
            load_operand inst, 0;
            cmp;
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
            add;
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
            sub;
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
            add;
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

    fn sub(&mut self) {
        self.asm.sub();
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

    fn cmp(&mut self) {
        self.asm.cmp();
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
        self.asm.add();
        self.asm.load();
    }

    fn store_reg(&mut self, reg: iced_x86::Register) {
        let r: u8 = Register::from(reg).into();
        let reg_offset = r as u64 * 8;
        self.asm.vmctx();
        self.asm
            .const_(offset_of!(Machine, regs) as u64 + reg_offset);
        self.asm.add();
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
                self.asm.add();
            }
        }

        self.asm.const_(inst.memory_displacement64());

        if inst.memory_base() != iced_x86::Register::None
            || inst.memory_index() != iced_x86::Register::None
        {
            self.asm.add();
        }
    }
}

pub fn virtualize(program: &[u8]) -> Vec<u8> {
    Virtualizer::new().virtualize(program)
}

pub fn virtualize_with_ip(ip: u64, program: &[u8]) -> Vec<u8> {
    Virtualizer::new().virtualize_with_ip(ip, program)
}
