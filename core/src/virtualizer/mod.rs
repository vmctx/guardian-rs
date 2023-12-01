use std::collections::HashMap;
use exe::{PE, VecPE};

use iced_x86::{Decoder, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind};

use traits::*;

use crate::shared::{JmpCond, OpSize};
use crate::virtualizer::assembler::Assembler;

pub mod assembler;
pub mod disassembler;
mod traits;

trait Asm {
    fn const_<T: OpSized>(&mut self, v: T);
    fn load<T: OpSized>(&mut self);
    fn store<T: OpSized>(&mut self);
    fn add<T: OpSized>(&mut self);
    fn sub<T: OpSized>(&mut self);
    fn div<T: OpSized>(&mut self, signed: bool);
    fn shr<T: OpSized>(&mut self);
    fn combine<T: OpSized>(&mut self);
    fn split<T: OpSized>(&mut self);
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
    fn store_reg_zx(&mut self, inst: &Instruction, reg: iced_x86::Register);
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
        vmasm_sized!($self, $op, $inst;);
        vmasm!($self,
            store_operand, $inst, 0;
        );
    }}
}

/// Same as vmasm! but determines opcode size automatically
macro_rules! vmasm_sized {(
    $self:ident,
    $(
        $op:ident, $inst:ident $(, $operand:expr)* ;
    )*
) => ({
    $(
         match OpSize::try_from($inst).unwrap() {
            OpSize::Byte => vmasm!($self, $op::<u8> $(,$operand),*;),
            OpSize::Word => vmasm!($self, $op::<u16> $(,$operand),*;),
            OpSize::Dword => vmasm!($self, $op::<u32> $(,$operand),*;),
            OpSize::Qword => vmasm!($self, $op::<u64> $(,$operand),*;)
        }
    )*
})}

pub struct Virtualizer {
    asm: Assembler,
    pe: Option<VecPE>,
    image_base: u64,
}

impl Default for Virtualizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Virtualizer {
    pub fn new() -> Self {
        Self {
            asm: Assembler::default(),
            pe: None,
            image_base: 0,
        }
    }

    pub fn with_pe(pe: VecPE) -> anyhow::Result<Self> {
        Ok(Self {
            asm: Assembler::default(),
            image_base: pe.get_image_base()?,
            pe: Some(pe),
        })
    }

    pub fn reset(&mut self) {
        self.asm.clear();
    }

    pub fn virtualize(&mut self, program: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.virtualize_with_ip(0, program)
    }

    pub fn virtualize_with_ip(&mut self, ip: u64, program: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut decoder = Decoder::with_ip(64, program, ip, 0);
        let mut unresolved_jmps = 0;
        // maps buffer offset (jmp) to ip
        let mut jmp_map = HashMap::<u64, u64>::new();
        // maps ip to buffer offset
        let mut target_map = HashMap::<u64, u64>::new();

        for inst in decoder.iter() {
            target_map.insert(inst.ip(), self.asm.len() as u64);

            match inst.mnemonic() {
                Mnemonic::Mov => self.mov(&inst),
                Mnemonic::Movzx => self.movzx(&inst),
                Mnemonic::Add => self.add(&inst),
                Mnemonic::Sub => self.sub(&inst),
                Mnemonic::Inc => self.inc(&inst),
                Mnemonic::Dec => self.dec(&inst),
                Mnemonic::Div => self.div(&inst, false),
                Mnemonic::Idiv => self.div(&inst, true),
                Mnemonic::Shr => self.shr(&inst),
                Mnemonic::Mul => self.mul(&inst),
                Mnemonic::Imul => self.imul(&inst),
                Mnemonic::And => self.and(&inst),
                Mnemonic::Or => self.or(&inst),
                Mnemonic::Xor => self.xor(&inst),
                Mnemonic::Not => self.not(&inst),
                Mnemonic::Cmp => self.cmp(&inst),
                Mnemonic::Lea => self.lea(&inst),
                Mnemonic::Ret => self.ret(),
                Mnemonic::Push => self.push(&inst),
                Mnemonic::Pop => self.pop(&inst),
                // call is executed unvirtualized
                Mnemonic::Jmp | Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jbe
                | Mnemonic::Ja | Mnemonic::Jle | Mnemonic::Jg | Mnemonic::Jae => {
                    if !inst.is_jcc_short_or_near() && !inst.is_jmp_short_or_near() {
                        let mut output = String::new();
                        NasmFormatter::new().format(&inst, &mut output);
                        anyhow::bail!("unsupported jmp: {}", output);
                    }

                    let condition = JmpCond::from(inst.mnemonic());

                    let target = inst.near_branch_target();

                    if target > inst.ip() {
                        jmp_map.insert(self.asm.len() as u64, target);
                        self.asm.jmp(condition, 0);
                        unresolved_jmps += 1;
                    } else if target_map.contains_key(&target) {
                        self.asm.jmp(condition, self.asm.len().wrapping_sub(*target_map.get(&target).unwrap() as usize) as u64);
                    } else {
                        unresolved_jmps += 1;
                    }
                }
                _ => {
                    // check for all control flow altering instructions and give error
                    // those i should all as far as possible add support for
                    // excluding call
                    if inst.is_jmp_short_or_near()
                        || inst.is_jmp_near_indirect() || inst.is_jmp_far()
                        || inst.is_jmp_far_indirect() || inst.is_jcc_short_or_near() {
                        anyhow::bail!("unsupported jmp instruction");
                    }

                    if inst.is_call_near() {
                        self.asm.call(inst, self.image_base)?;
                    } else {
                        self.asm.vmexec(inst, self.pe.as_ref(), self.image_base)?;
                    }
                }
            }
        }

        for (jmp_offset, ip) in jmp_map.into_iter() {
            self.asm.patch(jmp_offset as usize + 3, jmp_offset.wrapping_sub(*target_map.get(&ip).unwrap()));
            unresolved_jmps -= 1;
        }

        anyhow::ensure!(unresolved_jmps == 0, "{unresolved_jmps} unresolved jmps");

        Ok(self.asm.assemble())
    }

    fn mov(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand, inst, 1;
            store_operand, inst, 0;
        );
    }

    fn movzx(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand, inst, 1;
            store_reg_zx, inst, inst.op_register(0);
        );
    }

    // https://blog.back.engineering/17/05/2021/#ADD
    fn add(&mut self, inst: &Instruction) {
        binary_op!(self, inst, add)
    }

    fn sub(&mut self, inst: &Instruction) {
        binary_op!(self, inst, sub)
    }

    fn inc(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand, inst, 0;
        );
        vmasm_sized!(self,
            const_, inst, 1;
            add, inst;
        );
        vmasm!(self,store_operand, inst, 0;);
    }

    fn dec(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand, inst, 0;
            const_::<u64>, 1;
        );
        vmasm_sized!(self,
            const_, inst, 1;
            sub, inst;
        );
        vmasm!(self,store_operand, inst, 0;);
    }

    fn div(&mut self, inst: &Instruction, signed: bool) {
        use iced_x86::Register::*;

        match OpSize::try_from(inst.op0_register()).unwrap() {
            OpSize::Byte => vmasm!(self,
                load_reg, AX;
                load_operand, inst, 0;
                div::<u8>, signed;
                store_reg, AL;
                store_reg, AH;
            ),
            OpSize::Word => vmasm!(self,
                load_reg, DX;
                load_reg, AX;
                combine::<u16>;
                load_operand, inst, 0;
                div::<u16>, signed;
                store_reg, AX;
                store_reg, DX;
            ),
            OpSize::Dword => vmasm!(self,
                load_reg, EDX;
                load_reg, EAX;
                combine::<u32>;
                load_operand, inst, 0;
                div::<u32>, signed;
                store_reg, EAX;
                store_reg, EDX;
            ),
            OpSize::Qword => vmasm!(self,
                load_reg, RDX;
                load_reg, RAX;
                combine::<u64>;
                load_operand, inst, 0;
                div::<u64>, signed;
                store_reg, RAX;
                store_reg, RDX;
            )
        };
    }

    fn shr(&mut self, inst: &Instruction) {
        for _ in 0..inst.immediate8() {
            vmasm!(self, load_operand, inst, 0;);
            vmasm_sized!(self,
                const_, inst, 2;
                shr, inst;
            );
            vmasm!(self, store_operand, inst, 0;);
        }
    }

    fn mul(&mut self, inst: &Instruction) {
        use iced_x86::Register::*;

        match OpSize::try_from(inst.op0_register()).unwrap() {
            OpSize::Byte => vmasm!(self,
                load_reg, AL;
                load_operand, inst, 0;
                mul::<u8>;
                store_reg, AX;
            ),
            OpSize::Word => vmasm!(self,
                load_reg, AX;
                load_operand, inst, 0;
                mul::<u16>;
                split::<u16>;
                store_reg, AX;
                store_reg, DX;
            ),
            OpSize::Dword => vmasm!(self,
                load_reg, EAX;
                load_operand, inst, 0;
                mul::<u32>;
                split::<u32>;
                store_reg, EAX;
                store_reg, EDX;
            ),
            OpSize::Qword => vmasm!(self,
                load_reg, RAX;
                load_operand, inst, 0;
                mul::<u64>;
                split::<u32>;
                store_reg, RAX;
                store_reg, RDX;
            )
        };
    }

    fn imul(&mut self, inst: &Instruction) {
        match inst.op_count() {
            1 => self.mul(inst),
            2 => binary_op!(self, inst, mul),
            3 => {
                vmasm!(self,
                    load_operand, inst, 1;
                    load_operand, inst, 2;
                );
                vmasm_sized!(self, mul, inst;);
                vmasm!(self, store_operand, inst, 0;);
            }
            _ => unreachable!()
        }
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
        vmasm!(self, load_operand, inst, 0;);
        vmasm_sized!(self, not, inst;);
        vmasm!(self, store_operand, inst, 0;);
    }

    fn cmp(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand, inst, 0;
            load_operand, inst, 1;
        );
        vmasm_sized!(self, cmp, inst;);
    }

    fn lea(&mut self, inst: &Instruction) {
        vmasm!(self,
            lea_operand, inst;
            store_operand, inst, 0;
        );
    }

    fn ret(&mut self) {
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
        vmasm_sized!(self,
            store, inst;
        );
    }

    fn pop(&mut self, inst: &Instruction) {
        use iced_x86::Register::RSP;

        vmasm!(self,
            load_reg, RSP;
        );
        vmasm_sized!(self,
            load, inst;
        );
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

    fn div<T: OpSized>(&mut self, signed: bool) {
        if signed {
            self.asm.idiv::<T>();
        } else {
            self.asm.div::<T>();
        }
    }

    fn shr<T: OpSized>(&mut self) {
        self.asm.shr::<T>();
    }

    fn combine<T: OpSized>(&mut self) {
        self.asm.combine::<T>();
    }

    fn split<T: OpSized>(&mut self) {
        self.asm.split::<T>();
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
                vmasm_sized!(self, load, inst;);
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

        if inst.op_kind(operand) != OpKind::Memory && inst.has_reloc_entry(self.pe.as_ref()) {
            self.asm.vmreloc(self.image_base);
        }
    }

    fn store_operand(&mut self, inst: &Instruction, operand: u32) {
        match inst.op_kind(operand) {
            OpKind::Register => self.store_reg(inst.op_register(operand)),
            OpKind::Memory => {
                self.lea_operand(inst);
                vmasm_sized!(self, store, inst;);
            }
            _ => panic!("unsupported operand"),
        }
    }

    fn load_reg(&mut self, reg: iced_x86::Register) {
        self.asm.vmctx();
        self.asm.const_(reg.reg_offset());
        self.asm.vmadd();

        if reg.is_gpr() {
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
        } else {
            // load 128 bit
            self.asm.load_xmm();
        }
    }

    fn store_reg(&mut self, reg: iced_x86::Register) {
        self.asm.vmctx();
        self.asm.const_(reg.reg_offset());
        self.asm.vmadd();

        if reg.is_gpr() {
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
        } else {
            self.asm.store_xmm();
        }
    }

    // used for movzx
    fn store_reg_zx(&mut self, inst: &Instruction, reg: iced_x86::Register) {
        self.asm.vmctx();
        self.asm.const_(reg.reg_offset());
        self.asm.vmadd();

        match OpSize::try_from(inst).unwrap() {
            OpSize::Word => self.asm.store_reg_zx::<u16>(),
            OpSize::Byte => self.asm.store_reg_zx::<u8>(),
            _ => unreachable!()
        }
    }

    fn lea_operand(&mut self, inst: &Instruction) {
        if inst.memory_base() != iced_x86::Register::None
            && inst.memory_base() != iced_x86::Register::RIP {
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

        self.asm.const_(inst.memory_displacement64());

        if inst.memory_base() == iced_x86::Register::RIP {
            self.asm.vmreloc(self.image_base);
        }

        if inst.memory_base() != iced_x86::Register::None
            || inst.memory_index() != iced_x86::Register::None {
            self.asm.vmadd();
        }
    }
}

pub fn virtualize(program: &[u8]) -> anyhow::Result<Vec<u8>> {
    Virtualizer::new().virtualize(program)
}

pub fn virtualize_with_ip(pe: VecPE, ip: u64, program: &[u8]) -> anyhow::Result<Vec<u8>> {
    Virtualizer::with_pe(pe)?.virtualize_with_ip(ip, program)
}
