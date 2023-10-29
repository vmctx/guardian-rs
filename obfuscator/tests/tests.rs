use obfuscator::virt::machine::disassemble;
use obfuscator::virt::virtualizer::virtualize;

// todo write test cases to verify instruction generate
// correct opcodes (size etc)

#[test]
#[cfg(target_env = "msvc")]
fn rax_and_eax() {
    use iced_x86::code_asm::*;
    let mut a = CodeAssembler::new(64).unwrap();
    a.mov(rax, rcx).unwrap(); // mov first argument into rax
    a.xor(eax, eax).unwrap();
    a.ret().unwrap();

    let bytecode = virtualize(&a.assemble(0).unwrap());
    println!("{}", disassemble(&bytecode).unwrap());
    // todo assert
}