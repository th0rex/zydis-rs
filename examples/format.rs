extern crate zydis;
use zydis::gen::*;
use zydis::*;

use std::os::raw::c_void;

#[cfg_attr(rustfmt, rustfmt_skip)]
static CODE: &'static [u8] = &[
    0x51, 0x8D, 0x45, 0xFF, 0x50, 0xFF, 0x75, 0x0C, 0xFF, 0x75, 0x08,
    0xFF, 0x15, 0xA0, 0xA5, 0x48, 0x76, 0x85, 0xC0, 0x0F, 0x88, 0xFC,
    0xDA, 0x02, 0x00u8,
];

fn wrapped_format_instruction(
    formatter: &Formatter,
    buffer: &mut Buffer,
    instruction: &ZydisDecodedInstruction,
    context: &mut (),
    original: ZydisFormatterFormatFunc,
) -> ZydisResult<()> {
    buffer.append("ABC")
}

fn main() {
    let mut formatter = Formatter::new(ZYDIS_FORMATTER_STYLE_INTEL).unwrap();
    formatter.set_wrapped_hook(Box::new(wrapped_format_instruction), ()).unwrap();

    let decoder = Decoder::new(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64).unwrap();

    for (mut instruction, ip) in decoder.instruction_iterator(CODE, 0) {
        let insn = formatter.format_instruction(&mut instruction, 200);
        println!("0x{:016X} {}", ip, insn.unwrap());
    }
}
