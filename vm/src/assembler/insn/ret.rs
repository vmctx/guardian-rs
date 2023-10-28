use super::super::prelude::Asm;

impl Asm {
    pub fn ret(&mut self) {
        self.emit(&[0xc3]);
    }
}
