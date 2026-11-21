//! 指定アドレス範囲の逆アセンブリ（デバッグ用）。
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = &args[1];
    let base_v = u64::from_str_radix(&args[2], 16).unwrap();
    let start = u64::from_str_radix(&args[3], 16).unwrap();
    let end = u64::from_str_radix(&args[4], 16).unwrap();
    let data = std::fs::read(path).unwrap();
    let file_base = base_v;
    let be = args.get(5).map(String::as_str) == Some("be");
    let mut pc = start;
    while pc < end {
        let off = (pc - file_base) as usize;
        let w = if be {
            u16::from_be_bytes([data[off], data[off + 1]])
        } else {
            u16::from_le_bytes([data[off], data[off + 1]])
        };
        let s = polyisa_guest_superh::disasm_word(u128::from(w), 16)
            .unwrap_or_else(|| format!("??? {w:#06x}"));
        println!("{pc:#x}: {w:#06x}  {s}");
        pc += 2;
    }
}
