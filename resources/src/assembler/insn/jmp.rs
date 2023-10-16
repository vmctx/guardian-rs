use super::super::prelude::*;

impl Jmp<&mut Label> for Asm {
    fn jmp(&mut self, op1: &mut Label) {
        self.encode_jmp_label(&[0xe9], op1);
    }
}

impl Jmp<Reg64> for Asm {
    fn jmp(&mut self, op1: Reg64) {
        self.encode_r(0xff, 0x4, op1)
    }
}
