use super::super::prelude::*;

impl Jz<&mut Label> for Asm {
    fn jz(&mut self, op1: &mut Label) {
        self.encode_jmp_label(&[0x0f, 0x84], op1);
    }
}
