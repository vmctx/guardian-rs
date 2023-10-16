pub mod machine;
pub mod virtualizer;

#[cfg(test)]
mod tests {
    use crate::vm::machine::{disassemble, Machine};
    use crate::vm::virtualizer::virtualize;

    #[test]
    fn virtualize_and_disassemble() {
        const SHELLCODE: &[u8] = &[
            0x89, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x08, 0x0f, 0xaf, 0x44, 0x24, 0x08, 0xc2, 0x00,
            0x00
        ];
        let program = &virtualize(SHELLCODE);
        println!("{}", disassemble(program).unwrap());
    }

    const SHELLCODE_TEST: &[u8] = &[
        0x50,
        0x48, 0x8d, 0x35, 0xce, 0x50, 0x03, 0x00,
        0xba, 0x06, 0x00, 0x00, 0x00,
        0xe8, 0xce, 0x0e, 0x00, 0x00,
        0x58,
        0xc3,
        0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00,0x00, 0x00, 0x00,
        0x66, 0x90
    ];

    #[test]
    fn string_mutation() {
        // TODO more instruction support
        let mut string = String::new();

        let m = Machine::new(&virtualize(SHELLCODE_TEST)).unwrap();
        let f: extern "C" fn(&mut String) = unsafe { std::mem::transmute(m.vmenter.as_ptr::<()>()) };

        f(&mut string);

        println!("{}", string);
    }
}