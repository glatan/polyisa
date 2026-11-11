// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS I、MIPS32 Release 2、Release 6 が同じ write/exit を返す（層7・program）。
//!
//! clang 23 の `-march=mips1` は、ロードの直後にその結果を使う命令を置かない。
//! そのため R3000 の 2 本も clang で作る。Release 6 のこのバイナリは addiu、
//! rs が 0 の aui（符号化は lui）、syscall だけを含む。
//!
//! 出典は TOOL-LLVM と SRC-LINUX (7.3) の o32 番号。

use std::path::{Path, PathBuf};
use std::process::Command;

use polyisa_cli::run_mips::{MipsModel, O32Io, run_elf_model};

const SRC: &str = r#"
const char msg[] __attribute__((used)) = "hi\n";

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "li $v0, 4004\n"
        "li $a0, 1\n"
        "lui $a1, %hi(msg)\n"
        "addiu $a1, $a1, %lo(msg)\n"
        "li $a2, 3\n"
        "syscall\n"
        "li $v0, 4001\n"
        "li $a0, 0\n"
        "syscall\n");
}
"#;

fn lld() -> PathBuf {
    let out = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .expect("rustc");
    let sysroot = String::from_utf8(out.stdout).expect("sysroot utf-8");
    PathBuf::from(sysroot.trim()).join("lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld")
}

fn compile(dir: &Path, target: &str, march: &str, lld: &Path) -> PathBuf {
    let src = dir.join(format!("{target}-{march}.c"));
    let elf = dir.join(format!("{target}-{march}.elf"));
    std::fs::write(&src, SRC).unwrap();
    let status = Command::new("clang")
        .args([
            &format!("--target={target}-linux-gnu"),
            &format!("-march={march}"),
            "-mabi=32",
            "-nostdlib",
            "-static",
            &format!("-fuse-ld={}", lld.display()),
            "-Wl,-e,_start",
            "-o",
        ])
        .arg(&elf)
        .arg(&src)
        .status()
        .expect("clang");
    assert!(status.success(), "clang {target} {march} failed");
    elf
}

#[test]
fn four_models_print_hi() {
    let lld = lld();
    assert!(
        lld.is_file(),
        "rust-lld が {} に必要。TOOL-RUST のリンカを使う。",
        lld.display()
    );
    let dir = std::env::temp_dir().join("polyisa-heavy-program-mips");
    std::fs::create_dir_all(&dir).unwrap();
    let cases = [
        ("mipsel", "mips1", MipsModel::mips1_le()),
        ("mips", "mips1", MipsModel::mips1_be()),
        ("mipsel", "mips32r2", MipsModel::mips32r2()),
        ("mipsel", "mips32r6", MipsModel::r6()),
    ];
    for (target, march, model) in cases {
        let elf = compile(&dir, target, march, &lld);
        let mut io = O32Io::default();
        let code = run_elf_model(elf.to_str().unwrap(), model, &mut io)
            .unwrap_or_else(|e| panic!("{target} {march}: {e}"));
        assert_eq!(code, 0, "{target} {march}");
        assert_eq!(io.stdout, b"hi\n", "{target} {march}");
    }
}
