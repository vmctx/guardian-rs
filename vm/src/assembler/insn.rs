//! Trait definitions of various instructions.

mod add;
mod call;
mod dec;
mod jmp;
mod jnz;
mod jz;
mod mov;
mod nop;
mod ret;
mod test;

pub trait Add<T, U> {
    /// Emit an add instruction.
    fn add(&mut self, op1: T, op2: U);
}

pub trait Call<T> {
    /// Emit a call instruction.
    fn call(&mut self, op1: T);
}

pub trait Dec<T> {
    /// Emit a decrement instruction.
    fn dec(&mut self, op1: T);
}

pub trait Jmp<T> {
    /// Emit an unconditional jump instruction.
    fn jmp(&mut self, op1: T);
}

pub trait Jnz<T> {
    /// Emit a conditional jump if not zero instruction (`ZF = 0`).
    fn jnz(&mut self, op1: T);
}

pub trait Jz<T> {
    /// Emit a conditional jump if zero instruction (`ZF = 1`).
    fn jz(&mut self, op1: T);
}

pub trait Mov<T, U> {
    /// Emit an move instruction.
    fn mov(&mut self, op1: T, op2: U);
}

pub trait Test<T, U> {
    /// Emit a logical compare instruction.
    ///
    /// Computes the bit-wise logical AND of first operand and the second operand and sets the
    /// `SF`, `ZF`, and `PF` status flags, the result is discarded.
    fn test(&mut self, op1: T, op2: U);
}
