use super::super::prelude::*;

impl Jnz<&mut Label> for Asm {
    fn jnz(&mut self, op1: &mut Label) {
        self.encode_jmp_label(&[0x0f, 0x85], op1);
    }
}
