// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `polyisa` コマンド。実行の機構そのものは各クレートが持つ。

#![forbid(unsafe_code)]

pub mod run;

/// `run`、`cpus`、`disasm` のいずれか。引数の解析は後の段階で足す。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Command {
    Run,
    Cpus,
    Disasm,
    Help,
}

/// 最初の引き数から命令を決める。外部クレートを使わず手で解析する。
#[must_use]
pub fn parse_command(args: &[String]) -> Command {
    match args.first().map(String::as_str) {
        Some("run") => Command::Run,
        Some("cpus") => Command::Cpus,
        Some("disasm") => Command::Disasm,
        _ => Command::Help,
    }
}

/// 16進の1語を逆アセンブルする。長さは下位2ビットで判定する
///（`0b11` 以外は16ビット）。RISC-V のみ。
#[must_use]
pub fn disassemble_riscv(word: u128) -> Option<&'static str> {
    let len = if word & 0b11 == 0b11 { 32 } else { 16 };
    polyisa_guest_riscv::decode(word, len).map(polyisa_guest_riscv::disasm)
}

/// `disasm` の引数（16進文字列）を語に直す。`0x` 接頭辞の有無は問わない。
#[must_use]
pub fn parse_hex_word(s: &str) -> Option<u128> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.is_empty() || s.len() > 32 {
        return None;
    }
    let mut v = 0u128;
    for c in s.chars() {
        let d = c.to_digit(16)? as u128;
        v = v * 16 + d;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch() {
        let run = ["run".to_string()];
        assert_eq!(parse_command(&run), Command::Run);
        let empty: [String; 0] = [];
        assert_eq!(parse_command(&empty), Command::Help);
    }

    #[test]
    fn disasm_add_and_c_addi() {
        // add x1,x2,x3 と c.addi x1,1（llvm-mc の符号化と一致）。
        assert_eq!(
            disassemble_riscv(0x0031_00b3),
            Some("add {rd}, {rs1}, {rs2}")
        );
        assert_eq!(disassemble_riscv(0x0085), Some("c.addi {rd}, {imm}"));
        assert_eq!(disassemble_riscv(0xffff_ffff), None);
    }

    #[test]
    fn hex_parses() {
        assert_eq!(parse_hex_word("0x0085"), Some(0x85));
        assert_eq!(parse_hex_word("003100B3"), Some(0x0031_00b3));
        assert_eq!(parse_hex_word(""), None);
        assert_eq!(parse_hex_word("0xzz"), None);
    }
}
