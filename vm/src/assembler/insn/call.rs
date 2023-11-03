use super::super::prelude::*;

impl Call<Reg64> for Asm<'_> {
    fn call(&mut self, op1: Reg64) {
        self.encode_r(0xff, 0x2, op1);
    }
}
