use super::super::prelude::Asm;

impl Asm {
    pub fn nop(&mut self) {
        self.emit(&[0x90]);
    }
}
