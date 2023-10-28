use std::cmp::Ordering;
use std::collections::HashMap;
use crate::virt::machine::{Machine, Assembler, Register, JmpCond};
use iced_x86::{Decoder, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind};
use memoffset::offset_of;

trait Asm {
    fn const_(&mut self, v: u64);
    fn constd_(&mut self, v: u32);
    fn load(&mut self);
    fn loadd(&mut self);
    fn store(&mut self);
    fn stored(&mut self);
    fn add(&mut self);
    // 32 bit add
    fn addd(&mut self);
    fn sub(&mut self);
    // 32 bit sub
    fn subd(&mut self);
    fn div(&mut self);
    fn divd(&mut self);
    fn mul(&mut self);
    fn muld(&mut self);
    fn and(&mut self);
    fn andd(&mut self);
    fn or(&mut self);
    fn ord(&mut self);
    fn xor(&mut self);
    fn xord(&mut self);
    fn not(&mut self);
    fn notd(&mut self);
    fn cmp(&mut self);
    fn cmpd(&mut self);
    fn vmadd(&mut self);
    fn vmsub(&mut self);
    fn vmctx(&mut self);
    fn vmexit(&mut self);
    fn load_operand(&mut self, inst: &Instruction, operand: u32);
    fn store_operand(&mut self, inst: &Instruction, operand: u32);
    fn load_reg(&mut self, inst: &Instruction, reg: iced_x86::Register);
    fn store_reg(&mut self, inst: &Instruction, reg: iced_x86::Register);
    fn lea_operand(&mut self, inst: &Instruction);
}

#[repr(u8)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive, Clone, Copy)]
enum OperandSize {
    Byte,
    Word,
    Dword,
    Qword,
}

impl From<iced_x86::Register> for OperandSize {
    fn from(reg: iced_x86::Register) -> Self {
        if !reg.is_gpr() {
            panic!("{:?} unsupported register", reg);
        }

        if reg.is_gpr8() {
            OperandSize::Byte
        } else if reg.is_gpr16() {
            OperandSize::Word
        } else if reg.is_gpr32() {
            OperandSize::Dword
        } else {
            OperandSize::Qword
        }
    }
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
        // todo add virtual instructions to bit shift left and right
        // then when virtaulizing those higher-8bit registers, just emit shift instructions appropriately so your normal add/sub/etc instructions work as expected
        // so mov ah, someething
        // would be shift lower 8 bit to higher 8 bit, do mov, shift back
        // ALSO !!
        // todo remember that it writing to 16 and 8 bit registers doesn't clear the other bits in a register like writing to 32-bit
        // so when you shift back you need to mask and and the existing value of the register correctly
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
    // https://blog.back.engineering/17/05/2021/#ADD
    fn add(&mut self, inst: &Instruction) {
        match OperandSize::try_from(inst.op0_register()).unwrap() {
            OperandSize::Byte => panic!("unsupported operand size"),
            OperandSize::Word => panic!("unsupported operand size"),
            OperandSize::Dword => binary_op!(self, inst, addd),
            OperandSize::Qword => binary_op!(self, inst, add)
        }
    }

    // todo implement all of this for push and load too, probably
    // https://blog.back.engineering/17/05/2021/#PUSHVSP
    fn sub(&mut self, inst: &Instruction) {
        match OperandSize::try_from(inst.op0_register()).unwrap() {
            OperandSize::Byte => panic!("unsupported operand size"),
            OperandSize::Word => panic!("unsupported operand size"),
            OperandSize::Dword => binary_op!(self, inst, subd),
            OperandSize::Qword => binary_op!(self, inst, sub)
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
        use iced_x86::Register::EAX;
        // opkind has to be memory or register
        assert_ne!(inst.op0_kind(), OpKind::Immediate8to64);

        match OperandSize::try_from(inst.op0_register()).unwrap() {
            OperandSize::Byte => panic!("unsupported operand size"),
            OperandSize::Word => panic!("unsupported operand size"),
            OperandSize::Dword => vmasm!(self,
                load_reg inst, EAX;
                load_operand inst, 0;
                divd;
                store_reg inst, EAX;
            ),
            OperandSize::Qword => vmasm!(self,
                load_reg inst, RAX;
                load_operand inst, 0;
                div;
                store_reg inst, RAX;
            )
        }
    }

    // todo untested
    // divide op0 by 2 for op1 times
    fn shr(&mut self, inst: &Instruction) {
        // opkind has to be memory or register
        assert_eq!(inst.op0_kind(), OpKind::Register);
        assert_eq!(inst.op1_kind(), OpKind::Immediate8);

        for _ in 0..inst.immediate8() {
            match OperandSize::try_from(inst.op0_register()).unwrap() {
                OperandSize::Byte => panic!("unsupported operand size"),
                OperandSize::Word => panic!("unsupported operand size"),
                OperandSize::Dword => vmasm!(self,
                    load_operand inst, 0;
                    const_ 2;
                    divd;
                    store_operand inst, 0;
                ),
                OperandSize::Qword => vmasm!(self,
                    load_operand inst, 0;
                    const_ 2;
                    div;
                    store_operand inst, 0;
                )
            }
        }
    }

    fn mul(&mut self, inst: &Instruction) {
        match OperandSize::try_from(inst.op0_register()).unwrap() {
            OperandSize::Byte => panic!("unsupported operand size"),
            OperandSize::Word => panic!("unsupported operand size"),
            OperandSize::Dword => binary_op!(self, inst, muld),
            OperandSize::Qword => binary_op!(self, inst, mul)
        }
    }

    fn and(&mut self, inst: &Instruction) {
        match OperandSize::try_from(inst.op0_register()).unwrap() {
            OperandSize::Byte => panic!("unsupported operand size"),
            OperandSize::Word => panic!("unsupported operand size"),
            OperandSize::Dword => binary_op!(self, inst, andd),
            OperandSize::Qword => binary_op!(self, inst, and)
        }
    }

    fn or(&mut self, inst: &Instruction) {
        match OperandSize::try_from(inst.op0_register()).unwrap() {
            OperandSize::Byte => panic!("unsupported operand size"),
            OperandSize::Word => panic!("unsupported operand size"),
            OperandSize::Dword => binary_op!(self, inst, ord),
            OperandSize::Qword => binary_op!(self, inst, or)
        }
    }

    fn xor(&mut self, inst: &Instruction) {
        match OperandSize::try_from(inst.op0_register()).unwrap() {
            OperandSize::Byte => panic!("unsupported operand size"),
            OperandSize::Word => panic!("unsupported operand size"),
            OperandSize::Dword => binary_op!(self, inst, xord),
            OperandSize::Qword => binary_op!(self, inst, xor)
        }
    }

    fn not(&mut self, inst: &Instruction) {
        match OperandSize::try_from(inst.op0_register()).unwrap() {
            OperandSize::Byte => panic!("unsupported operand size"),
            OperandSize::Word => panic!("unsupported operand size"),
            OperandSize::Dword => vmasm!(self,
                load_operand inst, 0;
                notd;
                store_operand inst, 0;
            ),
            OperandSize::Qword => vmasm!(self,
                load_operand inst, 0;
                not;
                store_operand inst, 0;
            )
        }
    }

    fn cmp(&mut self, inst: &Instruction) {
        match OperandSize::try_from(inst.op0_register()).unwrap() {
            OperandSize::Byte => panic!("unsupported operand size"),
            OperandSize::Word => panic!("unsupported operand size"),
            OperandSize::Dword => vmasm!(self,
                load_operand inst, 0;
                load_operand inst, 1;
                cmpd;
            ),
            OperandSize::Qword => vmasm!(self,
                load_operand inst, 0;
                load_operand inst, 1;
                cmp;
            )
        }
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
            load_reg inst, RSP;
            const_ 8;
            vmsub;
            store_reg inst, RSP;

            load_operand inst, 0;
            load_reg inst, RSP;
            store;
        );
    }

    fn pop(&mut self, inst: &Instruction) {
        use iced_x86::Register::RSP;

        vmasm!(self,
            load_reg inst, RSP;
            load;
            store_operand inst, 0;

            load_reg inst, RSP;
            const_ 8;
            vmadd;
            store_reg inst, RSP;
        );
    }
}

impl Asm for Virtualizer {
    fn const_(&mut self, v: u64) {
        self.asm.const_(v);
    }

    fn constd_(&mut self, v: u32) {
        self.asm.constd_(v);
    }

    fn load(&mut self) {
        self.asm.load();
    }

    fn loadd(&mut self) {
        self.asm.loadd();
    }

    fn store(&mut self) {
        self.asm.store();
    }

    fn stored(&mut self) {
        self.asm.stored();
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

    fn divd(&mut self) {
        self.asm.divd();
    }

    fn mul(&mut self) {
        self.asm.mul();
    }

    fn muld(&mut self) {
        self.asm.muld();
    }

    fn and(&mut self) {
        self.asm.and();
    }

    fn andd(&mut self) {
        self.asm.andd();
    }

    fn or(&mut self) {
        self.asm.or();
    }

    fn ord(&mut self) {
        self.asm.ord();
    }

    fn xor(&mut self) {
        self.asm.xor();
    }

    fn xord(&mut self) {
        self.asm.xord();
    }

    fn not(&mut self) {
        self.asm.not();
    }

    fn notd(&mut self) {
        self.asm.notd();
    }

    fn cmp(&mut self) {
        self.asm.cmp();
    }

    fn cmpd(&mut self) {
        self.asm.cmpd();
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
            OpKind::Register => self.load_reg(inst, inst.op_register(operand)),
            OpKind::Memory => {
                self.lea_operand(inst);

                match OperandSize::try_from(inst.op0_register()).unwrap() {
                    OperandSize::Byte => panic!("unsupported load_mem size"),
                    OperandSize::Word => panic!("unsupported load_mem size"),
                    OperandSize::Dword => self.asm.loadd(),
                    OperandSize::Qword => self.asm.load()
                }
            }
            // todo maybe use traits to restrict opkinds on some functions
            // like div which can only have register and memory
            // sub can have immediates as example
            OpKind::Immediate8to32 => {
                self.constd_(inst.immediate8to32() as u32)
            }
            OpKind::Immediate32 => {
                self.constd_(inst.immediate32())
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
            OpKind::Register => self.store_reg(inst, inst.op_register(operand)),
            OpKind::Memory => {
                assert_ne!(inst.op0_kind(), OpKind::Register);
                self.lea_operand(inst);

                /*
                let mut operand_size = OperandSize::try_from(inst.op1_register()).unwrap();

                if inst.op_count() != 1 && inst.op0_kind().eq(&OpKind::Register) {
                    println!("store reg, {:?}", inst.op0_register());
                    // get lowest reg, if one reg is 32 bit get 32 bit etc
                    let sec_reg_op_size = OperandSize::from(inst.op0_register());
                    match (sec_reg_op_size as u8).cmp(&(operand_size as u8)) {
                        Ordering::Less => operand_size = sec_reg_op_size,
                        Ordering::Equal => {}
                        Ordering::Greater => {}
                    }
                }
                 */

                match OperandSize::try_from(inst.op1_register()).unwrap() {
                    OperandSize::Byte => panic!("unsupported store_mem size"),
                    OperandSize::Word => panic!("unsupported store_mem size"),
                    OperandSize::Dword => self.asm.stored(),
                    OperandSize::Qword => self.asm.store()
                }
            }
            _ => panic!("unsupported operand"),
        }
    }

    fn load_reg(&mut self, inst: &Instruction, reg: iced_x86::Register) {
        let r: u8 = Register::from(reg).into();
        let reg_offset = r as u64 * 8;
        self.asm.vmctx();
        self.asm
            .const_(offset_of!(Machine, regs) as u64 + reg_offset);
        self.asm.vmadd();

        let operand_size = OperandSize::try_from(reg).unwrap();

        match operand_size {
            OperandSize::Byte => panic!("unsupported load_reg size"),
            OperandSize::Word => panic!("unsupported load_reg size"),
            OperandSize::Dword => self.asm.loadd(),
            OperandSize::Qword => self.asm.load()
        }
    }

    fn store_reg(&mut self, inst: &Instruction, reg: iced_x86::Register) {
        let r: u8 = Register::from(reg).into();
        let reg_offset = r as u64 * 8;
        self.asm.vmctx();
        self.asm
            .const_(offset_of!(Machine, regs) as u64 + reg_offset);
        self.asm.vmadd();

        let operand_size = OperandSize::try_from(reg).unwrap();

        match operand_size {
            OperandSize::Byte => panic!("unsupported load_reg size"),
            OperandSize::Word => panic!("unsupported load_reg size"),
            OperandSize::Dword => self.asm.stored(),
            OperandSize::Qword => self.asm.store()
        }
    }

    fn lea_operand(&mut self, inst: &Instruction) {
        if inst.memory_base() != iced_x86::Register::None {
            self.load_reg(inst, inst.memory_base());
        }

        if inst.memory_index() != iced_x86::Register::None {
            self.load_reg(inst, inst.memory_index());
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
