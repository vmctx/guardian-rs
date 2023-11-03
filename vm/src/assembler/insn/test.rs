use super::super::prelude::*;

impl Test<Reg64, Reg64> for Asm<'_> {
    fn test(&mut self, op1: Reg64, op2: Reg64) {
        self.encode_rr(0x85, op1, op2);
    }
}

impl Test<Reg32, Reg32> for Asm<'_> {
    fn test(&mut self, op1: Reg32, op2: Reg32) {
        self.encode_rr(0x85, op1, op2);
    }
}
