use obfuscator::virt::machine::disassemble;
use obfuscator::virt::virtualizer::virtualize;

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

    let bytecode = disassemble(&virtualize(&a.assemble(0).unwrap()))
        .unwrap();

    // todo constq rsi = 69, fix that maybe in the disassembler
    assert_eq!(bytecode.as_str(), "\
    0: VmctxQ\n2: ConstQ Rsp\nc: VmAddQ\ne: LoadQ\n10: ConstQ 8\n1a: VmSubQ\n1c: VmctxQ\n1e: ConstQ Rsp\n28: VmAddQ\n2a: StoreRegQ\
    \n2c: ConstQ 69\n36: VmctxQ\n38: ConstQ Rsp\n42: VmAddQ\n44: LoadQ\n46: StoreQ\
    \n48: VmctxQ\n4a: ConstQ Rcx\n54: VmAddQ\n56: LoadQ\
    \n58: VmctxQ\n5a: ConstQ Rax\n64: VmAddQ\n66: StoreRegQ\
    \n68: VmctxQ\n6a: ConstQ Rsp\n74: VmAddQ\n76: LoadQ\n78: LoadQ\
    \n7a: VmctxQ\n7c: ConstQ Rcx\n86: VmAddQ\n88: StoreRegQ\
    \n8a: VmctxQ\n8c: ConstQ Rsp\n96: VmAddQ\n98: LoadQ\n9a: ConstQ 8\na4: VmAddQ\
    \na6: VmctxQ\na8: ConstQ Rsp\nb2: VmAddQ\nb4: StoreRegQ\
    \nb6: VmctxQ\nb8: ConstQ Rax\nc2: VmAddQ\nc4: LoadQ\
    \nc6: VmctxQ\nc8: ConstQ Rcx\nd2: VmAddQ\nd4: LoadQ\nd6: AddQ\
    \nd8: VmctxQ\nda: ConstQ Rax\ne4: VmAddQ\ne6: StoreRegQ\
    \ne8: VmExitQ\n");
}