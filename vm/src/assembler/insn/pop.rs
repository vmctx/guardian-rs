use super::super::prelude::*;

impl Pop<Reg64> for Asm<'_> {
    fn pop(&mut self, op1: Reg64) {
        self.encode_r(0x8f, 0, op1);
    }
}

impl Pop<Reg32> for Asm<'_> {
    fn pop(&mut self, op1: Reg32) {
        self.encode_r(0x8f, 0, op1);
    }
}

impl PopFQ for Asm<'_> {
    fn popfq(&mut self) {
        self.emit(&[0x9D]);
    }
}
