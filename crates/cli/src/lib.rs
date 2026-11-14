// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `polyisa` コマンド。実行の機構そのものは各クレートが持つ。

#![forbid(unsafe_code)]

#[cfg(feature = "guest-aarch64")]
pub mod run_aarch64;
#[cfg(feature = "guest-mips")]
pub mod run_mips;
#[cfg(feature = "guest-riscv")]
pub mod run_riscv;
#[cfg(feature = "guest-x86")]
pub mod run_x86;

/// ELF を選んで実行する。`EI_CLASS` と `e_machine` で RISC-V、x86、MIPS、
/// AArch64 を振り分ける。
/// 番号表の出典は各 `run_elf_*` 側にある。RV32 を含むそれ以外の組み合わせは
/// 未対応として拒否する（従来の `run_elf` も RV32 を受け付けない）。
pub fn run_path(path: &str, argv: &[String]) -> Result<u64, String> {
    run_path_with(path, argv, None)
}

/// `--cpu` の指定。文法は cpu-models.md の「実行時の選択」:
/// `<ISA ファミリ>:<CPU モデル>[,+<機能>][,-<機能>][,<パラメータ>=<値>]`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CpuSpec {
    pub family: String,
    pub model: String,
    pub add: Vec<String>,
    pub remove: Vec<String>,
    /// `パラメータ=値`。挙動パラメータの宣言はまだない（GAP-0027）。
    pub params: Vec<(String, String)>,
}

/// `--cpu` の値を解析する。`+機能`、`-機能`、`パラメータ=値` を列に分ける。
pub fn parse_cpu_spec(s: &str) -> Result<CpuSpec, String> {
    let Some((family, rest)) = s.split_once(':') else {
        return Err(format!("--cpu は <ファミリ>:<モデル> の形: {s}"));
    };
    let mut it = rest.split(',');
    let model = it.next().unwrap_or_default().to_string();
    let mut spec = CpuSpec {
        family: family.to_string(),
        model,
        add: Vec::new(),
        remove: Vec::new(),
        params: Vec::new(),
    };
    for item in it {
        if let Some(f) = item.strip_prefix('+') {
            spec.add.push(f.to_string());
        } else if let Some(f) = item.strip_prefix('-') {
            spec.remove.push(f.to_string());
        } else if let Some((k, v)) = item.split_once('=') {
            spec.params.push((k.to_string(), v.to_string()));
        } else {
            return Err(format!(
                "--cpu の項は +機能、-機能、パラメータ=値 の形: {item}"
            ));
        }
    }
    Ok(spec)
}

/// モデル名と機能の足し引きを、そのファミリの生成表で `CpuSel` に解決する。
#[cfg(any(
    feature = "guest-aarch64",
    feature = "guest-mips",
    feature = "guest-riscv",
    feature = "guest-x86"
))]
fn resolve_sel(
    family: &str,
    models: &[polyisa_isadl::select::ModelRow],
    features: &[polyisa_isadl::select::FeatureRow],
    feat_bits: &[(&str, u64)],
    spec: &CpuSpec,
) -> Result<polyisa_isadl::select::CpuSel, String> {
    if !spec.params.is_empty() {
        let (k, _) = &spec.params[0];
        return Err(format!("挙動パラメータ {k} は宣言されていない（GAP-0027）"));
    }
    let add: Vec<&str> = spec.add.iter().map(String::as_str).collect();
    let remove: Vec<&str> = spec.remove.iter().map(String::as_str).collect();
    polyisa_isadl::select::resolve(models, features, feat_bits, &spec.model, &add, &remove)
        .map_err(|e| format!("{family}: {e}"))
}

#[cfg(feature = "guest-x86")]
fn run_x86_32_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "x86",
                polyisa_guest_x86::MODEL_DEFS,
                polyisa_guest_x86::FEATURE_DEFS,
                polyisa_guest_x86::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_x86::run_elf_x86_32_sel(path, argv, sel.as_ref())
}

#[cfg(not(feature = "guest-x86"))]
fn run_x86_32_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は x86 ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-x86")]
fn run_x86_64_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "x86",
                polyisa_guest_x86::MODEL_DEFS,
                polyisa_guest_x86::FEATURE_DEFS,
                polyisa_guest_x86::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_x86::run_elf_x86_64_sel(path, argv, sel.as_ref())
}

#[cfg(not(feature = "guest-x86"))]
fn run_x86_64_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は x86 ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-mips")]
fn run_mips_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "mips",
                polyisa_guest_mips::MODEL_DEFS,
                polyisa_guest_mips::FEATURE_DEFS,
                polyisa_guest_mips::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_mips::run_elf_mips_sel(path, argv, sel.as_ref())
}

#[cfg(not(feature = "guest-mips"))]
fn run_mips_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は mips ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-aarch64")]
fn run_aarch64_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "aarch64",
                polyisa_guest_aarch64::MODEL_DEFS,
                polyisa_guest_aarch64::FEATURE_DEFS,
                polyisa_guest_aarch64::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_aarch64::run_elf_aarch64_sel(path, argv, sel.as_ref())
}

#[cfg(not(feature = "guest-aarch64"))]
fn run_aarch64_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は aarch64 ゲストなしでビルドされた".to_string())
}

#[cfg(feature = "guest-riscv")]
fn run_riscv_elf(path: &str, argv: &[String], spec: Option<&CpuSpec>) -> Result<u64, String> {
    let sel = spec
        .map(|s| {
            resolve_sel(
                "riscv",
                polyisa_guest_riscv::MODEL_DEFS,
                polyisa_guest_riscv::FEATURE_DEFS,
                polyisa_guest_riscv::FEAT_BITS,
                s,
            )
        })
        .transpose()?;
    run_riscv::run_elf_sel(path, argv, sel.as_ref())
}

#[cfg(not(feature = "guest-riscv"))]
fn run_riscv_elf(_path: &str, _argv: &[String], _spec: Option<&CpuSpec>) -> Result<u64, String> {
    Err("この polyisa は riscv ゲストなしでビルドされた".to_string())
}

/// `run_path` に `--cpu` の指定を加える。`cpu` は `parse_cpu_spec` の
/// 入力と同じ文字列。ファミリが ELF の `e_machine` と合わなければ拒否する。
pub fn run_path_with(path: &str, argv: &[String], cpu: Option<&str>) -> Result<u64, String> {
    use polyisa_loader::elf::{CLASS_32, CLASS_64, MAGIC};
    let spec = cpu.map(parse_cpu_spec).transpose()?;
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    if bytes.len() < 6 || bytes[0..4] != MAGIC {
        return Err(format!("{path} は ELF ではない"));
    }
    let check = |want: &str| match &spec {
        Some(s) if s.family != want => Err(format!(
            "--cpu のファミリ {} は ELF の {want} と合わない",
            s.family
        )),
        _ => Ok(()),
    };
    match bytes[4] {
        CLASS_32 => {
            let ehdr =
                polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
            // EM_386=3。Ref: SRC-LINUX (7.3).
            if ehdr.machine == 3 {
                check("x86")?;
                run_x86_32_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 8 {
                // EM_MIPS。Ref: SRC-LINUX (7.3)。アーキテクチャとエンディアンは ELF ヘッダから取る。
                check("mips")?;
                run_mips_elf(path, argv, spec.as_ref())
            } else {
                Err(format!("未対応の e_machine: {}", ehdr.machine))
            }
        }
        CLASS_64 => {
            let ehdr =
                polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
            // EM_RISCV=243。Ref: SPEC-RISCV-PSABI (v1.0).
            if ehdr.machine == 243 {
                check("riscv")?;
                run_riscv_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 62 {
                // EM_X86_64。Ref: SRC-LINUX (7.3)。
                check("x86")?;
                run_x86_64_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 8 {
                // EM_MIPS の 64 ビット（n64 ABI）。Ref: SRC-LINUX (7.3)。
                check("mips")?;
                run_mips_elf(path, argv, spec.as_ref())
            } else if ehdr.machine == 183 {
                // EM_AARCH64。Ref: SPEC-AARCH64-ELF（AAELF64）§4.2。
                check("aarch64")?;
                run_aarch64_elf(path, argv, spec.as_ref())
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
///（`0b11` 以外は16ビット）。RISC-V のみ。`guest-riscv` 機能で有効になる。
#[cfg(feature = "guest-riscv")]
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

    #[cfg(feature = "guest-riscv")]
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
    fn cpu_spec_parses() {
        let s = parse_cpu_spec("riscv:rv64gc,+zba,-d,foo=1").unwrap();
        assert_eq!(s.family, "riscv");
        assert_eq!(s.model, "rv64gc");
        assert_eq!(s.add, ["zba"]);
        assert_eq!(s.remove, ["d"]);
        assert_eq!(s.params, [("foo".to_string(), "1".to_string())]);
        assert!(parse_cpu_spec("nocolon").is_err());
        assert!(parse_cpu_spec("x86:generic32,bad").is_err());
    }

    #[test]
    fn hex_parses() {
        assert_eq!(parse_hex_word("0x0085"), Some(0x85));
        assert_eq!(parse_hex_word("003100B3"), Some(0x0031_00b3));
        assert_eq!(parse_hex_word(""), None);
        assert_eq!(parse_hex_word("0xzz"), None);
    }
}
