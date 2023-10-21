use iced_x86::FlowControl;
use crate::virtualize;
use crate::vm::machine::disassemble;

pub struct Disassembler {
    bytes: Vec<u8>,
}

const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;
const EXAMPLE_CODE_BITNESS: u32 = 64;
const EXAMPLE_CODE_RIP: u64 = 140001000;

impl Disassembler {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        // TODO detect bitness only allow x64 for now
        Self { bytes }
    }

    pub fn disassemble(&self) -> usize {
        use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

        let mut decoder =
            Decoder::with_ip(EXAMPLE_CODE_BITNESS, &self.bytes, 0, DecoderOptions::NONE);

        // Formatters: Masm*, Nasm*, Gas* (AT&T) and Intel* (XED).
        // For fastest code, see `SpecializedFormatter` which is ~3.3x faster. Use it if formatting
        // speed is more important than being able to re-assemble formatted instructions.
        let mut formatter = NasmFormatter::new();

        // Change some options, there are many more
        formatter.options_mut().set_digit_separator("`");
        formatter.options_mut().set_first_operand_char_index(10);

        // String implements FormatterOutput
        let mut output = String::new();

        // Initialize this outside the loop because decode_out() writes to every field
        let mut instruction = Instruction::default();

        let mut function_size = 0;

        // The decoder also implements Iterator/IntoIterator so you could use a for loop:
        //      for instruction in &mut decoder { /* ... */ }
        // or collect():
        //      let instructions: Vec<_> = decoder.into_iter().collect();
        // but can_decode()/decode_out() is a little faster:
        while decoder.can_decode() {
            // There's also a decode() method that returns an instruction but that also
            // means it copies an instruction (40 bytes):
            //     instruction = decoder.decode();
            decoder.decode_out(&mut instruction);

            // Format the instruction ("disassemble" it)
            output.clear();
            formatter.format(&instruction, &mut output);

            // Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
            print!("{:016X} ", instruction.ip());
            let start_index = (instruction.ip()) as usize;
            let instr_bytes = &self.bytes[start_index..start_index + instruction.len()];

             for b in instr_bytes.iter() {
                print!("{:02X}", b);
            }
            if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
                for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                    print!("  ");
                }
            }
            println!(" {}", output);


            match instruction.flow_control() {
                FlowControl::Return => {
                    // detect if its not real function end
                    function_size += instruction.len();

                    if self
                        .bytes
                        .get((instruction.ip()) as usize + 2)
                        .is_none()
                        || is_end_of_function(
                        self.bytes[(instruction.ip()) as usize + 1],
                        self.bytes[(instruction.ip()) as usize + 2],
                    )
                    {
                        break;
                    }
                }
                FlowControl::Interrupt => break,
                FlowControl::Exception => {
                    if instruction.is_invalid() {
                        break;
                    }
                }
                _ => function_size += instruction.len(),
            }

            //println!("{}", disassemble(&virtualize(instr_bytes)).unwrap());
        }

        function_size
    }
}

fn is_end_of_function(instr: u8, next_instr: u8) -> bool {
    instr == 0xCC
        || instr == 0xFF
        || (instr == 0x48
        || instr == 0x55
        || instr == 0x50
        || (instr == 0x41 && next_instr == 0x56)
        || (instr == 0x41 && next_instr == 0x57))
}
