
#[cfg(test)]
mod tests {
    use obfuscator::virt::virtualizer::virtualize;
    use vm::Machine;

    #[test]
    #[cfg(target_env = "msvc")]
    fn rax_and_eax() {
        use iced_x86::code_asm::*;
        let mut a = CodeAssembler::new(64).unwrap();
        a.mov(rax, rcx).unwrap(); // mov first argument into rax
        a.xor(eax, eax).unwrap();
        a.ret().unwrap();

        let bytecode = virtualize(&a.assemble(0).unwrap());
        let m = Machine::new(bytecode.as_ptr()).unwrap();
        let f: extern "C" fn(i64) -> i64 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(69), 0);
    }

    #[test]
    #[cfg(target_env = "msvc")]
    fn test_unsupported() {
        use iced_x86::code_asm::*;
        let mut a = CodeAssembler::new(64).unwrap();
        a.movzx(rax, cx).unwrap();
        a.ret().unwrap();

        let bytecode = virtualize(&a.assemble(0).unwrap());
        let m = Machine::new(bytecode.as_ptr()).unwrap();
        let f: extern "C" fn(i64) -> i64 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(0x1111222233334444), 0x4444);
    }

    #[test]
    #[cfg(target_env = "msvc")]
    fn test_xmm() {
        use iced_x86::code_asm::*;
        let mut a = CodeAssembler::new(64).unwrap();
        let mut test = 0x45;
        let imm128 = u128::MAX;
        a.mov(rax, (imm128) as u64).unwrap();
        a.movq(xmm1, rax).unwrap();
        // todo is this expected behaviour even tho i dont bitshift imm128?
        a.pinsrq(xmm1, rax, 1).unwrap();
        a.movaps(xmmword_ptr(rcx), xmm1).unwrap();
        a.ret().unwrap();

        let bytecode = virtualize(&a.assemble(0).unwrap());
        let m = Machine::new(bytecode.as_ptr()).unwrap();
        let f: extern "C" fn(&mut u128)  = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(&mut test), ());
        assert_eq!(test, u128::MAX);
    }

    #[test]
    #[cfg(target_env = "msvc")]
    fn rax_and_ax() {
        use iced_x86::code_asm::*;
        let mut a = CodeAssembler::new(64).unwrap();
        a.mov(rax, rcx).unwrap();
        a.mov(ax, 0x7777).unwrap();
        a.ret().unwrap();

        let bytecode = virtualize(&a.assemble(0).unwrap());
        let m = Machine::new(bytecode.as_ptr()).unwrap();
        let f: extern "C" fn(i64) -> i64 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(0x1111222233334444), 0x1111222233337777);
    }

    #[test]
    #[cfg(target_env = "msvc")]
    fn virtualize_variable_mutation() {
        use iced_x86::code_asm::*;
        let mut a = CodeAssembler::new(64).unwrap();
        let mut test = 69;
        a.lea(rax, qword_ptr(rax)).unwrap();
        a.mov(rax, 19i64).unwrap();
        a.mov(qword_ptr(rcx), 68).unwrap();
        a.ret().unwrap();

        let bytecode = virtualize(&a.assemble(0).unwrap());
        let m = Machine::new(bytecode.as_ptr()).unwrap();
        let f: extern "C" fn(&mut i32) -> i64 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(&mut test), 19);
        assert_eq!(test, 68);
    }


    #[test]
    #[cfg(target_env = "msvc")]
    fn rax_and_ah_al() {
        use iced_x86::code_asm::*;

        let mut a = CodeAssembler::new(64).unwrap();
        a.mov(eax, 0x11112222).unwrap();
        a.xor(al, al).unwrap(); // this should encode to normal 8 bit xor
        // bitshift back
        a.ret().unwrap();

        let bytecode = virtualize(&a.assemble(0).unwrap());
        let m = Machine::new(bytecode.as_ptr()).unwrap();
        let f: extern "C" fn() -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(), 0x11112200);

        let mut a = CodeAssembler::new(64).unwrap();
        a.mov(eax, 0x11112222).unwrap();
        a.xor(ah, ah).unwrap(); // this should encode to bitshift higher with lower 8 bit, xor, then
        // bitshift back
        a.ret().unwrap();

        let bytecode = virtualize(&a.assemble(0).unwrap());
        let m = Machine::new(bytecode.as_ptr()).unwrap();
        let f: extern "C" fn() -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(), 0x11110022);
    }

    #[test]
    #[cfg(target_env = "msvc")]
    fn virtualizer_and_machine() {
        const SHELLCODE: &[u8] = &[
            0x89, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x08, 0x0f, 0xaf, 0x44, 0x24, 0x08, 0xc3
        ];
        let bytecode = virtualize(&SHELLCODE);
        let m = Machine::new(bytecode.as_ptr()).unwrap();
        let f: extern "C" fn(i32) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(2), 4);
    }

    #[test]
    #[cfg(target_env = "msvc")]
    fn virtualize_jmp_lbl() {
        use iced_x86::code_asm::*;
        let mut a = CodeAssembler::new(64).unwrap();
        let mut lbl = a.create_label();

        a.mov(rax, rcx).unwrap(); // move first arg into rax
        a.set_label(&mut lbl).unwrap(); // jmp should land here
        a.sub(rax, 1).unwrap(); // substract 4 from rax
        a.cmp(rax, rdx).unwrap();
        a.jg(lbl).unwrap(); // jmp to label if rax is greater than rdx (loops until rax is rdx)
        a.ret().unwrap(); // return value of rax, should be zero

        let bytecode = virtualize(&a.assemble(0).unwrap());
        let m = Machine::new(bytecode.as_ptr()).unwrap();
        let f: extern "C" fn(i64, i64) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(21, 0), 0);
        assert_eq!(f(-2, 0), -3);
    }

    #[test]
    #[cfg(target_env = "msvc")]
    fn virtualize_calc_lbl() {
        use iced_x86::code_asm::*;
        let mut a = CodeAssembler::new(64).unwrap();
        let mut lbl = a.create_label();

        a.xor(eax, eax).unwrap();
        a.mov(r8d, edx).unwrap();
        a.sub(r8d, ecx).unwrap();
        a.jle(lbl).unwrap();
        a.mov(r9d, ecx).unwrap();
        a.not(r9d).unwrap();
        a.add(r9d, edx).unwrap();
        a.lea(eax, qword_ptr(rcx + 1)).unwrap();
        a.imul_2(eax, r9d).unwrap();
        a.add(r8d, 0x0FFFFFFFEu32 as i32).unwrap();
        a.imul_2(r8, r9).unwrap();
        a.shr(r8, 1).unwrap();
        a.add(eax, ecx).unwrap();
        a.add(eax, r8d).unwrap();
        a.set_label(&mut lbl).unwrap();
        a.ret().unwrap();

        let bytecode = virtualize(&a.assemble(0).unwrap());
        let m = Machine::new(bytecode.as_ptr()).unwrap();
        let f: extern "C" fn(i32, i32) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        let (a, b) = (-7, 5);
        let result = f(a, b);
        assert_eq!(result, -18);
        let result = f(result, b - result);
        assert_eq!(result, 82);
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

        let bytecode = virtualize(&a.assemble(0).unwrap());
        let m = Machine::new(bytecode.as_ptr()).unwrap();
        let f: extern "C" fn(i32, i32) -> i32 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(8, 4), 2);
    }

    #[test]
    #[cfg(target_env = "msvc")]
    fn virtualize_push_pop() {
        use iced_x86::code_asm::*;
        let mut a = CodeAssembler::new(64).unwrap();
        a.push(69i32).unwrap();
        a.mov(rax, rcx).unwrap();
        a.pop(rcx).unwrap();
        a.add(rax, rcx).unwrap();
        a.ret().unwrap();
        let bytecode = virtualize(&a.assemble(0).unwrap());
        let m = Machine::new(bytecode.as_ptr()).unwrap();
        let f: extern "C" fn(i32) -> i8 = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };
        assert_eq!(f(-8), 61);
    }
}
