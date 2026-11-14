// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! AArch64 の静的 ELF が write/exit_group で "hi\n" を返す（層7・program）。
//!
//! clang の aarch64-linux-gnu ターゲットで `-nostdlib -static` にコンパイルする。
//! 出典は TOOL-LLVM と SRC-LINUX (7.3) の asm-generic 番号（write=64、
//! exit_group=94）。

use std::path::{Path, PathBuf};
use std::process::Command;

use polyisa_cli::run_aarch64::run_elf_aarch64_sys;
use polyisa_os_linux::aarch64::sys::Linux;

const SRC: &str = r#"
const char msg[] __attribute__((used)) = "hi\n";

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "mov x8, #64\n"
        "mov x0, #1\n"
        "adr x1, msg\n"
        "mov x2, #3\n"
        "svc #0\n"
        "mov x8, #94\n"
        "mov x0, #0\n"
        "svc #0\n");
}
"#;

/// 再帰呼び出し・条件分岐・スタック操作を使う版。fib(10)=55 を十進で書く。
/// `stp`/`ldp`/`bl`/`ret`/`b.cond`/`subs`/`cbz` 系を通す。
const SRC_FIB: &str = r#"
long fib(long n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

static int put(long n, char *p) {
    char tmp[24];
    int i = 0;
    if (n == 0) {
        *p++ = '0';
        return 1;
    }
    while (n) {
        tmp[i++] = '0' + (int)(n % 10);
        n /= 10;
    }
    int k = 0;
    while (i) *p++ = tmp[--i], k++;
    return k;
}

char buf[32];

void _start(void) {
    long v = fib(10);
    int n = put(v, buf);
    buf[n] = '\n';
    // %x0 の取り込みは先頭で行う（x8/x1 をあとで上書きするため）。
    __asm__ volatile(
        "mov x2, %x0\n"
        "mov x8, #64\n"
        "mov x0, #1\n"
        "adr x1, buf\n"
        "svc #0\n"
        "mov x8, #94\n"
        "mov x0, #0\n"
        "svc #0\n" ::"r"((long)(n + 1)));
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

fn compile(dir: &Path, lld: &Path, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    let elf = dir.join(format!("{name}.elf"));
    std::fs::write(&src, source).unwrap();
    let status = Command::new("clang")
        .args([
            "--target=aarch64-linux-gnu",
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
    assert!(status.success(), "clang aarch64 failed");
    elf
}

#[test]
fn generic_prints_hi() {
    let lld = lld();
    assert!(
        lld.is_file(),
        "rust-lld が {} に必要。TOOL-RUST のリンカを使う。",
        lld.display()
    );
    let dir = std::env::temp_dir().join("polyisa-heavy-program-aarch64");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "aarch64-hello", SRC);
    let mut sys = Linux::default();
    let code = run_elf_aarch64_sys(elf.to_str().unwrap(), &[], None, &mut sys)
        .unwrap_or_else(|e| panic!("aarch64: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"hi\n");
}

#[test]
fn fib_recursion_prints_55() {
    let lld = lld();
    assert!(lld.is_file(), "rust-lld が必要。TOOL-RUST のリンカを使う。");
    let dir = std::env::temp_dir().join("polyisa-heavy-program-aarch64");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir, &lld, "aarch64-fib", SRC_FIB);
    let mut sys = Linux::default();
    let code = run_elf_aarch64_sys(elf.to_str().unwrap(), &[], None, &mut sys)
        .unwrap_or_else(|e| panic!("aarch64 fib: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"55\n");
}
