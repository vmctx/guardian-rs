//! A simple `x64` jit assembler
pub mod prelude;

mod imm;
mod insn;
mod label;
mod reg;

use alloc::vec::Vec;
pub use imm::{Imm16, Imm32, Imm64, Imm8};
pub use label::Label;
pub use reg::{Reg16, Reg32, Reg64, RegXmm, Reg8};

use imm::Imm;
use reg::Reg;

/// Type representing a memory operand.
pub enum MemOp {
    /// An indirect memory operand, eg `mov [rax], rcx`.
    Indirect(Reg64),
    /// An indirect memory operand with additional displacement, eg `mov [rax + 0x10], rcx`.
    IndirectDisp(Reg64, i32),
}


impl MemOp {
    /// Get the base address register of the memory operand.
    const fn base(&self) -> Reg64 {
        match self {
            MemOp::Indirect(base) => *base,
            MemOp::IndirectDisp(base, ..) => *base,
        }
    }
}

/// Encode the `REX` byte.
const fn rex(w: bool, r: u8, x: u8, b: u8) -> u8 {
    let w = if w { 1 } else { 0 };
    let r = (r >> 3) & 1;
    let x = (x >> 3) & 1;
    let b = (b >> 3) & 1;
    0b0100_0000 | ((w & 1) << 3) | (r << 2) | (x << 1) | b
}

/// Encode the `ModR/M` byte.
const fn modrm(mod_: u8, reg: u8, rm: u8) -> u8 {
    ((mod_ & 0b11) << 6) | ((reg & 0b111) << 3) | (rm & 0b111)
}

/// `x64` jit assembler.
pub struct Asm<'a> {
    buf: &'a mut Vec<u8>,
}

impl Asm<'_> {
    /// Create a new `x64` jit assembler.
    pub fn new(buf: &mut Vec<u8>) -> Asm {
        Asm { buf }
    }

    /* causes ub
    /// Consume the assembler and get the emitted code.
    pub fn into_code(self) -> Vec<u8> {
        self.buf
    }
     */

    /// Return a mutable reference to the emitted code
    pub fn code(&mut self) -> &mut Vec<u8> {
        self.buf
    }

    /// Emit a slice of bytes.
    fn emit(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Emit a slice of optional bytes.
    fn emit_optional(&mut self, bytes: &[Option<u8>]) {
        for byte in bytes.iter().filter_map(|&b| b) {
            self.buf.push(byte);
        }
    }

    /// Emit a slice of bytes at `pos`.
    ///
    /// # Panics
    ///
    /// Panics if [pos..pos+len] indexes out of bound of the underlying code buffer.
    fn emit_at(&mut self, pos: usize, bytes: &[u8]) {
        if let Some(buf) = self.buf.get_mut(pos..pos + bytes.len()) {
            buf.copy_from_slice(bytes);
        } else {
            unimplemented!();
        }
    }

    /// Bind the [Label] to the current location.
    pub fn bind(&mut self, label: &mut Label) {
        // Bind the label to the current offset.
        label.bind(self.buf.len());

        // Resolve any pending relocations for the label.
        self.resolve(label);
    }

    /// If the [Label] is bound, patch any pending relocation.
    pub fn resolve(&mut self, label: &mut Label) {
        if let Some(loc) = label.location() {
            // For now we only support disp32 as label location.
            let loc = i32::try_from(loc).expect("Label location did not fit into i32.");

            // Resolve any pending relocations for the label.
            for off in label.offsets_mut().drain() {
                // Displacement is relative to the next instruction following the jump.
                // We record the offset to patch at the first byte of the disp32 therefore we need
                // to account for that in the disp computation.
                let disp32 = loc - i32::try_from(off).expect("Label offset did not fit into i32") - 4 /* account for the disp32 */;

                // Patch the relocation with the disp32.
                self.emit_at(off, &disp32.to_ne_bytes());
            }
        }
    }

    // -- Encode utilities.

    /// Encode an register-register instruction.
    fn encode_rr<T: Reg>(&mut self, opc: u8, op1: T, op2: T)
    where
        Self: EncodeRR<T>,
    {
        // MR operand encoding.
        //   op1 -> modrm.rm
        //   op2 -> modrm.reg
        let modrm = modrm(
            0b11,      /* mod */
            op2.idx(), /* reg */
            op1.idx(), /* rm */
        );

        let prefix = <Self as EncodeRR<T>>::legacy_prefix();
        let rex = <Self as EncodeRR<T>>::rex(op1, op2);

        self.emit_optional(&[prefix, rex]);
        self.emit(&[opc, modrm]);
    }

    /// Encode an offset-immediate instruction.
    /// Register idx is encoded in the opcode.
    fn encode_oi<T: Reg, U: Imm>(&mut self, opc: u8, op1: T, op2: U)
    where
        Self: EncodeR<T>,
    {
        let opc = opc + (op1.idx() & 0b111);
        let prefix = <Self as EncodeR<T>>::legacy_prefix();
        let rex = <Self as EncodeR<T>>::rex(op1);

        self.emit_optional(&[prefix, rex]);
        self.emit(&[opc]);
        self.emit(op2.bytes());
    }

    /// Encode a register-immediate instruction.
    fn encode_ri<T: Reg, U: Imm>(&mut self, opc: u8, opc_ext: u8, op1: T, op2: U)
    where
        Self: EncodeR<T>,
    {
        // MI operand encoding.
        //   op1           -> modrm.rm
        //   opc extension -> modrm.reg
        let modrm = modrm(
            0b11,      /* mod */
            opc_ext,   /* reg */
            op1.idx(), /* rm */
        );

        let prefix = <Self as EncodeR<T>>::legacy_prefix();
        let rex = <Self as EncodeR<T>>::rex(op1);

        self.emit_optional(&[prefix, rex]);
        self.emit(&[opc, modrm]);
        self.emit(op2.bytes());
    }

    /// Encode a register instruction.
    fn encode_r<T: Reg>(&mut self, opc: u8, opc_ext: u8, op1: T)
    where
        Self: EncodeR<T>,
    {
        // M operand encoding.
        //   op1           -> modrm.rm
        //   opc extension -> modrm.reg
        let modrm = modrm(
            0b11,      /* mod */
            opc_ext,   /* reg */
            op1.idx(), /* rm */
        );

        let prefix = <Self as EncodeR<T>>::legacy_prefix();
        let rex = <Self as EncodeR<T>>::rex(op1);

        self.emit_optional(&[prefix, rex]);
        self.emit(&[opc, modrm]);
    }

    /// Encode a memory-register instruction.
    fn encode_mr<T: Reg>(&mut self, opc: u8, op1: MemOp, op2: T)
    where
        Self: EncodeMR<T>,
    {
        // MR operand encoding.
        //   op1 -> modrm.rm
        //   op2 -> modrm.reg
        let mode = match op1 {
            MemOp::Indirect(..) => {
                assert!(!op1.base().need_sib() && !op1.base().is_pc_rel());
                0b00
            }
            MemOp::IndirectDisp(..) => {
                assert!(!op1.base().need_sib());
                0b10
            }
        };

        let modrm = modrm(
            mode,             /* mode */
            op2.idx(),        /* reg */
            op1.base().idx(), /* rm */
        );
        let prefix = <Self as EncodeMR<T>>::legacy_prefix();
        let rex = <Self as EncodeMR<T>>::rex(&op1, op2);

        self.emit_optional(&[prefix, rex]);
        self.emit(&[opc, modrm]);
        if let MemOp::IndirectDisp(_, disp) = op1 {
            self.emit(&disp.to_ne_bytes());
        }
    }

    /// Encode a memory-register instruction.
    fn encode_mr_xmm<T: Reg>(&mut self, opc: &[u8], op1: MemOp, op2: T)
        where
            Self: EncodeMR<T>,
    {
        // MR operand encoding.
        //   op1 -> modrm.rm
        //   op2 -> modrm.reg
        let mode = match op1 {
            MemOp::Indirect(..) => {
                assert!(!op1.base().need_sib() && !op1.base().is_pc_rel());
                0b00
            }
            MemOp::IndirectDisp(..) => {
                assert!(!op1.base().need_sib());
                0b10
            }
        };

        let modrm = modrm(
            mode,             /* mode */
            op2.idx(),        /* reg */
            op1.base().idx(), /* rm */
        );
        let prefix = <Self as EncodeMR<T>>::legacy_prefix();
        let rex = <Self as EncodeMR<T>>::rex(&op1, op2);

        self.emit_optional(&[prefix, rex]);
        self.emit(opc);
        self.emit(&[modrm]);
        if let MemOp::IndirectDisp(_, disp) = op1 {
            self.emit(&disp.to_ne_bytes());
        }
    }

    /// Encode a register-memory instruction.
    fn encode_rm<T: Reg>(&mut self, opc: u8, op1: T, op2: MemOp)
    where
        Self: EncodeMR<T>,
    {
        // RM operand encoding.
        //   op1 -> modrm.reg
        //   op2 -> modrm.rm
        self.encode_mr(opc, op2, op1);
    }

    /// Encode a register-memory instruction.
    fn encode_rm_xmm<T: Reg>(&mut self, opc: &[u8], op1: T, op2: MemOp)
        where
            Self: EncodeMR<T>,
    {
        // RM operand encoding.
        //   op1 -> modrm.reg
        //   op2 -> modrm.rm
        self.encode_mr_xmm(opc, op2, op1);
    }

    /// Encode a jump to label instruction.
    fn encode_jmp_label(&mut self, opc: &[u8], op1: &mut Label) {
        // Emit the opcode.
        self.emit(opc);

        // Record relocation offset starting at the first byte of the disp32.
        op1.record_offset(self.buf.len());

        // Emit a zeroed disp32, which serves as placeholder for the relocation.
        // We currently only support disp32 jump targets.
        self.emit(&[0u8; 4]);

        // Resolve any pending relocations for the label.
        self.resolve(op1);
    }
}

// -- Encoder helper.

/// Encode helper for register-register instructions.
trait EncodeRR<T: Reg> {
    fn legacy_prefix() -> Option<u8> {
        None
    }

    fn rex(op1: T, op2: T) -> Option<u8> {
        if op1.need_rex() || op2.need_rex() {
            Some(rex(op1.rexw(), op2.idx(), 0, op1.idx()))
        } else {
            None
        }
    }
}

impl EncodeRR<Reg8> for Asm<'_>{}
impl EncodeRR<Reg32> for Asm<'_> {}
impl EncodeRR<Reg16> for Asm<'_> {
    fn legacy_prefix() -> Option<u8> {
        Some(0x66)
    }
}
impl EncodeRR<Reg64> for Asm<'_> {}

/// Encode helper for register instructions.
trait EncodeR<T: Reg> {
    fn legacy_prefix() -> Option<u8> {
        None
    }

    fn rex(op1: T) -> Option<u8> {
        if op1.need_rex() {
            Some(rex(op1.rexw(), 0, 0, op1.idx()))
        } else {
            None
        }
    }
}

impl EncodeR<Reg8> for Asm<'_> {}
impl EncodeR<Reg32> for Asm<'_> {}
impl EncodeR<Reg16> for Asm<'_> {
    fn legacy_prefix() -> Option<u8> {
        Some(0x66)
    }
}
impl EncodeR<Reg64> for Asm<'_>{}
impl EncodeR<RegXmm> for Asm<'_>{}

/// Encode helper for memory-register instructions.
trait EncodeMR<T: Reg> {
    fn legacy_prefix() -> Option<u8> {
        None
    }

    fn rex(op1: &MemOp, op2: T) -> Option<u8> {
        if op2.need_rex() || (op1.base().is_ext()) {
            Some(rex(op2.rexw(), op2.idx(), 0, op1.base().idx()))
        } else {
            None
        }
    }
}

impl EncodeMR<Reg8> for Asm<'_> {}
impl EncodeMR<Reg16> for Asm<'_> {
    fn legacy_prefix() -> Option<u8> {
        Some(0x66)
    }
}
impl EncodeMR<Reg32> for Asm<'_> {}
impl EncodeMR<Reg64> for Asm<'_> {}
impl EncodeMR<RegXmm> for Asm<'_> {}