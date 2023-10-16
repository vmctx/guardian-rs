use super::super::prelude::*;

// -- MOV : reg reg

impl Mov<Reg64, Reg64> for Asm {
    fn mov(&mut self, op1: Reg64, op2: Reg64) {
        self.encode_rr(0x89, op1, op2);
    }
}

impl Mov<Reg32, Reg32> for Asm {
    fn mov(&mut self, op1: Reg32, op2: Reg32) {
        self.encode_rr(0x89, op1, op2);
    }
}

impl Mov<Reg16, Reg16> for Asm {
    fn mov(&mut self, op1: Reg16, op2: Reg16) {
        self.encode_rr(0x89, op1, op2);
    }
}

impl Mov<Reg8, Reg8> for Asm {
    fn mov(&mut self, op1: Reg8, op2: Reg8) {
        self.encode_rr(0x88, op1, op2);
    }
}

// -- MOV : mem reg

impl Mov<MemOp, Reg64> for Asm {
    fn mov(&mut self, op1: MemOp, op2: Reg64) {
        self.encode_mr(0x89, op1, op2);
    }
}

impl Mov<MemOp, Reg32> for Asm {
    fn mov(&mut self, op1: MemOp, op2: Reg32) {
        self.encode_mr(0x89, op1, op2);
    }
}

impl Mov<MemOp, Reg16> for Asm {
    fn mov(&mut self, op1: MemOp, op2: Reg16) {
        self.encode_mr(0x89, op1, op2);
    }
}

impl Mov<MemOp, Reg8> for Asm {
    fn mov(&mut self, op1: MemOp, op2: Reg8) {
        self.encode_mr(0x88, op1, op2);
    }
}

// -- MOV : reg mem

impl Mov<Reg64, MemOp> for Asm {
    fn mov(&mut self, op1: Reg64, op2: MemOp) {
        self.encode_rm(0x8b, op1, op2);
    }
}

impl Mov<Reg32, MemOp> for Asm {
    fn mov(&mut self, op1: Reg32, op2: MemOp) {
        self.encode_rm(0x8b, op1, op2);
    }
}

impl Mov<Reg16, MemOp> for Asm {
    fn mov(&mut self, op1: Reg16, op2: MemOp) {
        self.encode_rm(0x8b, op1, op2);
    }
}

impl Mov<Reg8, MemOp> for Asm {
    fn mov(&mut self, op1: Reg8, op2: MemOp) {
        self.encode_rm(0x8a, op1, op2);
    }
}

// -- MOV : reg imm

impl Mov<Reg64, Imm64> for Asm {
    fn mov(&mut self, op1: Reg64, op2: Imm64) {
        self.encode_oi(0xb8, op1, op2);
    }
}

impl Mov<Reg32, Imm32> for Asm {
    fn mov(&mut self, op1: Reg32, op2: Imm32) {
        self.encode_oi(0xb8, op1, op2);
    }
}

impl Mov<Reg16, Imm16> for Asm {
    fn mov(&mut self, op1: Reg16, op2: Imm16) {
        self.encode_oi(0xb8, op1, op2);
    }
}

impl Mov<Reg8, Imm8> for Asm {
    fn mov(&mut self, op1: Reg8, op2: Imm8) {
        self.encode_oi(0xb0, op1, op2);
    }
}
