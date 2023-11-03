use super::super::prelude::Asm;

impl Asm<'_> {
    pub fn ret(&mut self) {
        self.emit(&[0xc3]);
    }
}
