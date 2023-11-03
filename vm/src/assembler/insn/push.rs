use super::super::prelude::*;

impl Push<Reg64> for Asm<'_> {
    fn push(&mut self, op1: Reg64) {
        self.encode_r(0xff, 6, op1);
    }
}

impl Push<Reg32> for Asm<'_> {
    fn push(&mut self, op1: Reg32) {
        self.encode_r(0xff, 6, op1);
    }
}
