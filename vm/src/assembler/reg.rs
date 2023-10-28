//! Definition of registers which are used as input operands for various instructions.

/// Trait to interact with register operands.
pub(crate) trait Reg {
    /// Get the raw x64 register code.
    fn idx(&self) -> u8;

    /// Check if the registers needs the `REX.W` bit.
    fn rexw(&self) -> bool;

    /// Check if the register is an extended registers.
    fn is_ext(&self) -> bool {
        self.idx() > 7
    }

    /// Check if the register requires a `REX` byte.
    fn need_rex(&self) -> bool {
        self.is_ext() || self.rexw()
    }

    /// Check if the register requires a `SIB` byte if used as addressing operand.
    ///
    /// See [64 bit
    /// addressing](https://wiki.osdev.org/X86-64_Instruction_Encoding#32.2F64-bit_addressing) for
    /// further details.
    fn need_sib(&self) -> bool {
        self.idx() == 4 || self.idx() == 12
    }

    /// Check if the register is interpreted as `PC` relative if used as addressing operand.
    ///
    /// See [64 bit
    /// addressing](https://wiki.osdev.org/X86-64_Instruction_Encoding#32.2F64-bit_addressing) for
    /// further details.
    fn is_pc_rel(&self) -> bool {
        self.idx() == 5 || self.idx() == 13
    }
}

macro_rules! enum_reg {
    (#[$doc:meta]  $name:ident, { $($reg:ident),+ $(,)? }) => {
        #[$doc]
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone)]
        #[repr(u8)]
        pub enum $name {
            $( $reg, )+
        }

        #[cfg(test)]
        impl $name {
            fn iter() -> impl Iterator<Item = &'static $name> {
                use $name::*;
                [$( $reg, )+].iter()
            }
        }
    };
}

macro_rules! impl_reg {
    (#[$doc:meta] $name:ident, $rexw:expr, { $($reg:ident),+ $(,)? }) => {
        enum_reg!(#[$doc] $name, { $( $reg, )+ });

        impl Reg for $name {
            /// Get the raw x64 register code.
            fn idx(&self) -> u8 {
                *self as u8
            }

            /// Check if the registers needs the `REX.W` bit.
            fn rexw(&self) -> bool {
                $rexw
            }
        }
    }
}

impl_reg!(
    /// Definition of 64 bit registers.
    Reg64, true,  { rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8,  r9,  r10,  r11,  r12,  r13,  r14,  r15  });
impl_reg!(
    /// Definition of 32 bit registers.
    Reg32, false, { eax, ecx, edx, ebx, esp, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d });
impl_reg!(
    /// Definition of 16 bit registers.
    Reg16, false, { ax,  cx,  dx,  bx,  sp,  bp,  si,  di,  r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w });
enum_reg!(
    /// Definition of 8 bit registers.
    Reg8,         { al,  cl,  dl,  bl,  spl, bpl, sil, dil, r8l, r9l, r10l, r11l, r12l, r13l, r14l, r15l,
                          ah,  ch,  dh,  bh });

impl Reg for Reg8 {
    /// Get the raw x64 register code.
    fn idx(&self) -> u8 {
        match self {
            Reg8::ah => 4,
            Reg8::ch => 5,
            Reg8::dh => 6,
            Reg8::bh => 7,
            _ => *self as u8,
        }
    }

    /// Check if the registers needs the `REX.W` bit.
    fn rexw(&self) -> bool {
        false
    }

    /// Check whether the gp register needs a `REX` prefix
    /// Check if the register requires a `REX` byte.
    ///
    /// For 1 byte addressing, register indexes `[4:7]` require a `REX` prefix, or else they will
    /// be decoded as `{AH, CH, DH, BH}` accordingly.
    ///
    /// See [Registers](https://wiki.osdev.org/X86-64_Instruction_Encoding#Registers) for
    /// further details or conduct `Table 3-1. Register Codes` in the *Intel Software Developers
    /// Manual - Volume 2*.
    fn need_rex(&self) -> bool {
        self.idx() > 7 || matches!(self, Reg8::spl | Reg8::bpl | Reg8::sil | Reg8::dil)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reg8() {
        use Reg8::*;

        for r in Reg8::iter() {
            // Check register index.
            let idx = match r {
                al => 0,
                cl => 1,
                dl => 2,
                bl => 3,
                spl => 4,
                bpl => 5,
                sil => 6,
                dil => 7,
                r8l => 8,
                r9l => 9,
                r10l => 10,
                r11l => 11,
                r12l => 12,
                r13l => 13,
                r14l => 14,
                r15l => 15,
                ah => 4,
                ch => 5,
                dh => 6,
                bh => 7,
            };
            assert_eq!(r.idx(), idx);

            // Check REX.W bit.
            assert_eq!(r.rexw(), false);

            // Check need REX byte.
            let rex = match r {
                r8l | r9l | r10l | r11l | r12l | r13l | r14l | r15l | spl | bpl | sil | dil => true,
                _ => false,
            };
            assert_eq!(r.need_rex(), rex);

            // Check need SIB byte.
            let sib = match r {
                spl | r12l | ah => true,
                _ => false,
            };
            assert_eq!(r.need_sib(), sib);

            // Check if is PC relative addressing.
            let rel = match r {
                bpl | r13l | ch => true,
                _ => false,
            };
            assert_eq!(r.is_pc_rel(), rel);
        }
    }

    #[test]
    fn test_reg16() {
        use Reg16::*;

        for r in Reg16::iter() {
            // Check register index.
            let idx = match r {
                ax => 0,
                cx => 1,
                dx => 2,
                bx => 3,
                sp => 4,
                bp => 5,
                si => 6,
                di => 7,
                r8w => 8,
                r9w => 9,
                r10w => 10,
                r11w => 11,
                r12w => 12,
                r13w => 13,
                r14w => 14,
                r15w => 15,
            };
            assert_eq!(r.idx(), idx);

            // Check REX.W bit.
            assert_eq!(r.rexw(), false);

            // Check need REX byte.
            let rex = match r {
                r8w | r9w | r10w | r11w | r12w | r13w | r14w | r15w => true,
                _ => false,
            };
            assert_eq!(r.need_rex(), rex);

            // Check need SIB byte.
            let sib = match r {
                sp | r12w => true,
                _ => false,
            };
            assert_eq!(r.need_sib(), sib);

            // Check if is PC relative addressing.
            let rel = match r {
                bp | r13w => true,
                _ => false,
            };
            assert_eq!(r.is_pc_rel(), rel);
        }
    }

    #[test]
    fn test_reg32() {
        use Reg32::*;

        for r in Reg32::iter() {
            // Check register index.
            let idx = match r {
                eax => 0,
                ecx => 1,
                edx => 2,
                ebx => 3,
                esp => 4,
                ebp => 5,
                esi => 6,
                edi => 7,
                r8d => 8,
                r9d => 9,
                r10d => 10,
                r11d => 11,
                r12d => 12,
                r13d => 13,
                r14d => 14,
                r15d => 15,
            };
            assert_eq!(r.idx(), idx);

            // Check REX.W bit.
            assert_eq!(r.rexw(), false);

            // Check need REX byte.
            let rex = match r {
                r8d | r9d | r10d | r11d | r12d | r13d | r14d | r15d => true,
                _ => false,
            };
            assert_eq!(r.need_rex(), rex);

            // Check need SIB byte.
            let sib = match r {
                esp | r12d => true,
                _ => false,
            };
            assert_eq!(r.need_sib(), sib);

            // Check if is PC relative addressing.
            let rel = match r {
                ebp | r13d => true,
                _ => false,
            };
            assert_eq!(r.is_pc_rel(), rel);
        }
    }

    #[test]
    fn test_reg64() {
        use Reg64::*;

        for r in Reg64::iter() {
            // Check register index.
            let idx = match r {
                rax => 0,
                rcx => 1,
                rdx => 2,
                rbx => 3,
                rsp => 4,
                rbp => 5,
                rsi => 6,
                rdi => 7,
                r8 => 8,
                r9 => 9,
                r10 => 10,
                r11 => 11,
                r12 => 12,
                r13 => 13,
                r14 => 14,
                r15 => 15,
            };
            assert_eq!(r.idx(), idx);

            // Check REX.W bit.
            assert_eq!(r.rexw(), true);

            // Check need REX byte.
            assert_eq!(r.need_rex(), true);

            // Check need SIB byte.
            let sib = match r {
                rsp | r12 => true,
                _ => false,
            };
            assert_eq!(r.need_sib(), sib);

            // Check if is PC relative addressing.
            let rel = match r {
                rbp | r13 => true,
                _ => false,
            };
            assert_eq!(r.is_pc_rel(), rel);
        }
    }
}
