//! Definition of different immediate types which are used as input operands for various
//! instructions.

/// Trait to interact with immediate operands.
pub(crate) trait Imm {
    /// Get immediate operand as slice of bytes.
    fn bytes(&self) -> &[u8];
}

macro_rules! impl_imm {
    (#[$doc:meta] $name:ident, $size:expr, from: { $( $from:ty ),* $(,)? }) => {
        #[$doc]
        pub struct $name([u8; $size]);

        impl Imm for $name {
            /// Get immediate operand as slice of bytes.
            fn bytes(&self) -> &[u8] {
                &self.0
            }
        }

        $(
        impl From<$from> for $name {
            fn from(imm: $from) -> Self {
                let mut buf = [0u8; $size];
                let imm = imm.to_ne_bytes();
                buf[0..imm.len()].copy_from_slice(&imm);
                $name(buf)
            }
        }
        )*
    }
}

impl_imm!(
    /// Type representing an 8 bit immediate.
    Imm8, 1, from: { u8, i8 }
);
impl_imm!(
    /// Type representing a 16 bit immediate.
    Imm16, 2, from: { u16, i16, u8, i8 }
);
impl_imm!(
    /// Type representing a 32 bit immediate.
    Imm32, 4, from: { u32, i32, u16, i16, u8, i8 }
);
impl_imm!(
    /// Type representing a 64 bit immediate.
    Imm64, 8, from: { u64, i64, u32, i32, u16, i16, u8, i8 }
);
