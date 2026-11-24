// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ARM Semihosting 2.0 の静的 ELF が SYS_WRITE0/SYS_WRITE で stdout に
//! 書き SYS_EXIT で終わる（層7・program、S25-3）。
//!
//! clang で `-nostdlib -static` にコンパイルする。入口の規約は
//! ISA ごとに異なる:
//! - aarch64: `hlt #0xf000`（x0=演算、x1=パラメータ、返りは x0）
//! - arm A32: `svc #0x123456`（r0/r1、返りは r0）
//! - riscv64: `slli x0,x0,0x1f; ebreak; srai x0,x0,7`（a0/a1、返りは a0）
//!   出典は SPEC-ARM-SEMIHOST（演算の正本）と SPEC-RISCV-SEMIHOST（入口列）。

use std::path::{Path, PathBuf};
use std::process::Command;

/// AArch64。WRITE0 → WRITE({fd=1,ptr,len}) → EXIT({reason,code})。
const SRC_A64: &str = r#"
static const char m1[] __attribute__((used)) = "semi-hi\n";
static const char m2[] __attribute__((used)) = "semi-more\n";
static const unsigned long wblk[3] __attribute__((used)) = {1, (unsigned long)m2, 10};
static const unsigned long xblk[2] __attribute__((used)) = {0x20026, 3};

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "ldr x1, =m1\n"
        "mov x0, #4\n"
        "hlt #0xf000\n"
        "ldr x1, =wblk\n"
        "mov x0, #5\n"
        "hlt #0xf000\n"
        "ldr x1, =xblk\n"
        "mov x0, #0x18\n"
        "hlt #0xf000\n");
}
"#;

/// AArch32。WRITE0 → WRITE → EXIT_EXTENDED({reason,code})。
const SRC_A32: &str = r#"
static const char m1[] __attribute__((used)) = "semi-hi\n";
static const char m2[] __attribute__((used)) = "semi-more\n";
static const unsigned int wblk[3] __attribute__((used)) = {1, (unsigned int)m2, 10};
static const unsigned int xblk[2] __attribute__((used)) = {0x20026, 7};

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "ldr r1, =m1\n"
        "mov r0, #4\n"
        "svc #0x123456\n"
        "ldr r1, =wblk\n"
        "mov r0, #5\n"
        "svc #0x123456\n"
        "ldr r1, =xblk\n"
        "mov r0, #0x20\n"
        "svc #0x123456\n");
}
"#;

/// rv64。標識列は圧縮命令に潰されないよう `.option norvc` で囲む。
const SRC_RV64: &str = r#"
static const char m1[] __attribute__((used)) = "semi-hi\n";
static const char m2[] __attribute__((used)) = "semi-more\n";
static const unsigned long wblk[3] __attribute__((used)) = {1, (unsigned long)m2, 10};
static const unsigned long xblk[2] __attribute__((used)) = {0x20026, 5};

#define SEMI \
    "slli x0, x0, 0x1f\n" \
    "ebreak\n" \
    "srai x0, x0, 7\n"

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        ".option push\n"
        ".option norvc\n"
        "la a1, m1\n"
        "li a0, 4\n"
        SEMI
        "la a1, wblk\n"
        "li a0, 5\n"
        SEMI
        "la a1, xblk\n"
        "li a0, 0x18\n"
        SEMI
        ".option pop\n");
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

fn compile(dir: &Path, lld: &Path, name: &str, target: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    let elf = dir.join(format!("{name}.elf"));
    std::fs::write(&src, source).unwrap();
    let status = Command::new("clang")
        .args([
            &format!("--target={target}"),
            "-nostdlib",
            "-static",
            "-fno-stack-protector",
            &format!("-fuse-ld={}", lld.display()),
            "-Wl,-e,_start",
            "-o",
        ])
        .arg(&elf)
        .arg(&src)
        .status()
        .expect("clang");
    assert!(status.success(), "clang {target} failed");
    elf
}

fn workspace() -> (PathBuf, PathBuf) {
    let lld = lld();
    assert!(
        lld.is_file(),
        "rust-lld が {} に必要。TOOL-RUST のリンカを使う。",
        lld.display()
    );
    let dir = std::env::temp_dir().join("polyisa-heavy-program-semihost");
    std::fs::create_dir_all(&dir).unwrap();
    (lld, dir)
}

/// `hlt #0xf000` が SemiA64 の SYS_* 演算へ届き、WRITE0 と WRITE の
/// 出力が `io.stdout` に、EXIT の副番号が戻り値になる。インタプリタと
/// JIT の両経路を通す。
#[test]
fn aarch64_write_exit() {
    let (lld, dir) = workspace();
    let elf = compile(&dir, &lld, "a64-semi", "aarch64-linux-gnu", SRC_A64);
    let elf = elf.to_str().unwrap();

    let mut semi = polyisa_os_semihost::SemiA64::new("");
    let code = polyisa_cli::run_aarch64::run_elf_aarch64_semi(elf, &[], None, &mut semi, None)
        .unwrap_or_else(|e| panic!("a64 semi: {e}"));
    assert_eq!(code, 3);
    assert_eq!(semi.io.stdout, b"semi-hi\nsemi-more\n");

    let mut semi = polyisa_os_semihost::SemiA64::new("");
    let mut jit = polyisa_jit::Jit::new();
    let code = polyisa_cli::run_aarch64::run_elf_aarch64_semi_jit(
        elf,
        &[],
        None,
        &mut semi,
        None,
        &mut jit,
    )
    .unwrap_or_else(|e| panic!("a64 semi jit: {e}"));
    assert_eq!(code, 3);
    assert_eq!(semi.io.stdout, b"semi-hi\nsemi-more\n");
}

/// `svc #0x123456` が SemiA32 の SYS_* 演算へ届く。語幅は 32 ビットで
/// パラメータブロックも 4 バイト語。EXIT_EXTENDED の副番号が戻る。
#[test]
fn arm_write_exit() {
    let (lld, dir) = workspace();
    let elf = compile(&dir, &lld, "a32-semi", "armv7-linux-gnueabihf", SRC_A32);
    let elf = elf.to_str().unwrap();

    let mut semi = polyisa_os_semihost::SemiA32::new("");
    let code = polyisa_cli::run_arm::run_elf_arm_semi(elf, &[], None, &mut semi)
        .unwrap_or_else(|e| panic!("a32 semi: {e}"));
    assert_eq!(code, 7);
    assert_eq!(semi.io.stdout, b"semi-hi\nsemi-more\n");

    let mut semi = polyisa_os_semihost::SemiA32::new("");
    let mut jit = polyisa_jit::Jit::new();
    let code = polyisa_cli::run_arm::run_elf_arm_semi_jit(elf, &[], None, &mut semi, &mut jit)
        .unwrap_or_else(|e| panic!("a32 semi jit: {e}"));
    assert_eq!(code, 7);
    assert_eq!(semi.io.stdout, b"semi-hi\nsemi-more\n");
}

/// ebreak の標識列が SemiRv の SYS_* 演算へ届く。
#[test]
fn riscv_write_exit() {
    let (lld, dir) = workspace();
    let elf = compile(&dir, &lld, "rv64-semi", "riscv64-linux-gnu", SRC_RV64);
    let elf = elf.to_str().unwrap();

    let mut semi = polyisa_cli::run_riscv::SemiRv::new("", false);
    let code = polyisa_cli::run_riscv::run_elf_handler(elf, &[], None, &mut semi)
        .unwrap_or_else(|e| panic!("rv64 semi: {e}"));
    assert_eq!(code, 5);
    assert_eq!(semi.semi.io.stdout, b"semi-hi\nsemi-more\n");
}
