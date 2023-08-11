use crate::vm::machine::{Assembler, Register, Machine};
use iced_x86::{Decoder, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind};
use memoffset::offset_of;

trait Asm {
    fn const_(&mut self, v: u64);
    fn load(&mut self);
    fn store(&mut self);
    fn add(&mut self);
    fn mul(&mut self);
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
        $a:ident,
        $($inst:ident $($operand:expr),* );* $(;)*
    ) => {{
        $(
            $a.$inst(
                $($operand),*
            );
        )*
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
        let mut decoder = Decoder::new(64, program, 0);

        for inst in &mut decoder {
            self.virtualize_inst(&inst);
        }

        self.asm.assemble()
    }

    fn virtualize_inst(&mut self, inst: &Instruction) {
        match inst.mnemonic() {
            Mnemonic::Mov => self.mov(inst),
            Mnemonic::Imul => self.imul(inst),
            Mnemonic::Ret => self.ret(),
            Mnemonic::Push => self.push(inst),
            Mnemonic::Pop => self.pop(inst),
            _ => {
                let mut output = String::new();
                NasmFormatter::new().format(inst, &mut output);
                panic!("unsupported instruction: {}", output);
            }
        }
    }

    fn mov(&mut self, inst: &Instruction) {
        vmasm!(self,
            load_operand inst, 1;
            store_operand inst, 0;
        );
    }

    fn imul(&mut self, inst: &Instruction) {
        assert_eq!(inst.op_count(), 2);

        vmasm!(self,
            load_operand inst, 1;
            load_operand inst, 0;
            mul;
            store_operand inst, 0;
        );
    }

    fn ret(&mut self) {
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
    }

    fn push(&mut self, inst: &Instruction) {
        use iced_x86::Register::RSP;

        vmasm!(self,
            load_reg RSP;
            const_ unsafe { std::mem::transmute(-8i64) };
            add;
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

    fn mul(&mut self) {
        self.asm.mul();
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
            _ => panic!("unsupported operand"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_env = "msvc")]
    fn virtualizer_and_machine() {
        const SHELLCODE: &[u8] = &[
            0x89, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x08, 0x0f, 0xaf, 0x44, 0x24, 0x08, 0xc2, 0x00,
            0x00,
        ];
        let m = Machine::new(&virtualize(SHELLCODE)).unwrap();
        let f: extern "C" fn(i32) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(2), 4);
    }

    #[test]
    #[cfg(target_env = "gnu")]
    fn virtualizer_and_machine() {
        const SHELLCODE: &[u8] = &[
            0x55, 0x48, 0x89, 0xE5, 0x89, 0x7D, 0xFC, 0x8B, 0x45, 0xFC, 0x0F, 0xAF, 0xC0, 0x5D, 0xC3,
        ];
        let m = Machine::new(&virtualize(SHELLCODE)).unwrap();
        let f: extern "C" fn(i32) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(2), 4);
        assert_eq!(f(4), 16);
    }
}
