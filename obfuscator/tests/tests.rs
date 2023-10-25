#[cfg(test)]
mod tests {
    use obfuscator::vm::machine::Machine;
    use obfuscator::vm::virtualizer::virtualize;

    #[test]
    #[cfg(target_env = "msvc")]
    fn virtualizer_and_machine() {
        const SHELLCODE: &[u8] = &[
            0x89, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x08, 0x0f, 0xaf, 0x44, 0x24, 0x08, 0xc3
        ];
        let m = Machine::new(&virtualize(SHELLCODE)).unwrap();
        let f: extern "C" fn(i32) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(2), 4);
    }

    #[test]
    #[cfg(target_env = "msvc")]
    fn virtualize_jmp_lbl() {
        use iced_x86::code_asm::*;
        let mut a = CodeAssembler::new(64).unwrap();
        let mut lbl = a.create_label();

        a.mov(rax, rcx).unwrap(); // mov first arg into rax
        a.jmp(lbl).unwrap(); // jmp to label skipping the add below
        a.add(rax, 10i32).unwrap(); // add 10 to rax, this should be jmped over
        a.set_label(&mut lbl).unwrap(); // jmp should land here skipping the add above
        a.add(rax, 4i32).unwrap(); // add 4 to rax and return, rax should be input + 4
        a.ret().unwrap();

        let m = Machine::new(&virtualize(&a.assemble(0).unwrap())).unwrap();

        let f: extern "C" fn(i32) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(8), 12);
    }

    #[test]
    #[cfg(target_env = "msvc")]
    fn virtualize_div() {
        use iced_x86::code_asm::*;
        let mut a = CodeAssembler::new(64).unwrap();
        a.mov(rax, rcx).unwrap(); // mov first argument into rax (dividend)
        a.mov(rcx, rdx).unwrap(); // mov second argument to rcx (divisor)
        a.xor(rdx, rdx).unwrap(); // clear rdx
        a.div(rcx).unwrap(); // 8 / 4 = 2 in rax
        a.ret().unwrap();

        let m = Machine::new(&virtualize(&a.assemble(0).unwrap())).unwrap();

        let f: extern "C" fn(i32, i32) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(8, 4), 2);
    }

    #[test]
    #[cfg(target_env = "msvc")]
    fn virtualize_push_pop() {
        use iced_x86::code_asm::*;
        let mut a = CodeAssembler::new(64).unwrap();
        a.push(rcx).unwrap();
        a.pop(rax).unwrap();
        a.ret().unwrap();
        let m = Machine::new(&virtualize(&a.assemble(0).unwrap())).unwrap();
        let f: extern "C" fn(i32) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(8), 8);
    }
}
