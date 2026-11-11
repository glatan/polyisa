// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `polyisa` コマンド。実行の機構そのものは各クレートが持つ。

#![forbid(unsafe_code)]

pub mod run;
pub mod run_mips;
pub mod run_x86;

/// ELF を選んで実行する。`EI_CLASS` と `e_machine` で RISC-V、x86、MIPS を振り分ける。
/// 番号表の出典は各 `run_elf_*` 側にある。RV32 を含むそれ以外の組み合わせは
/// 未対応として拒否する（従来の `run_elf` も RV32 を受け付けない）。
pub fn run_path(path: &str, argv: &[String]) -> Result<u64, String> {
    use polyisa_loader::elf::{CLASS_32, CLASS_64, MAGIC};
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    if bytes.len() < 6 || bytes[0..4] != MAGIC {
        return Err(format!("{path} は ELF ではない"));
    }
    match bytes[4] {
        CLASS_32 => {
            let ehdr =
                polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
            // EM_386=3。Ref: SRC-LINUX (7.3).
            if ehdr.machine == 3 {
                run_x86::run_elf_x86(path, argv)
            } else if ehdr.machine == 8 {
                // EM_MIPS。Ref: SRC-LINUX (7.3)。アーキテクチャとエンディアンは ELF ヘッダから取る。
                run_mips::run_elf_mips(path, argv)
            } else {
                Err(format!("未対応の e_machine: {}", ehdr.machine))
            }
        }
        CLASS_64 => {
            let ehdr =
                polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
            // EM_RISCV=243。Ref: SPEC-RISCV-PSABI (v1.0).
            if ehdr.machine == 243 {
                run::run_elf(path, argv)
            } else if ehdr.machine == 62 {
                // EM_X86_64。Ref: SRC-LINUX (7.3)。
                run_x86::run_elf_x86_64(path, argv)
            } else {
                Err(format!("未対応の e_machine: {}", ehdr.machine))
            }
        }
        _ => Err(format!("{path} は未知の ELF クラスである")),
    }
}

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
