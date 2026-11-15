// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 段階 9（IR と JIT）の差分試験。同じ ELF をインタプリタと JIT で
//! 実行し、終了コード・出力・走行したブロック数を比べる（層7・program）。
//!
//! 対象は AArch64・ARM・x86-64 の 3 ISA。`fib(10)=55` を十進で書く
//! 再帰・条件分岐・スタック・ロード/ストアを含むプログラムを使う。
//! JIT は `Jit::set_threshold(1)` で全ブロックを即コンパイルさせ、
//! x86-64 へのコード生成と生成コードの実行の両方を通す。

use std::path::{Path, PathBuf};
use std::process::Command;

const SRC_A64: &str = r#"
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

const SRC_ARM: &str = r#"
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
    // -nostdlib では __aeabi_idiv が無いので除算は反復減算で書く。
    while (n) {
        long q = 0, r = n;
        while (r >= 10) {
            r -= 10;
            q++;
        }
        tmp[i++] = '0' + (int)r;
        n = q;
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
    register int len __asm__("r2") = n + 1;
    __asm__ volatile(
        "mov r7, #4\n"
        "mov r0, #1\n"
        "ldr r1, =buf\n"
        "svc #0\n"
        "mov r7, #248\n"
        "mov r0, #0\n"
        "svc #0\n" ::"r"(len));
}
"#;

const SRC_X64: &str = r#"
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
    long n = put(v, buf);
    buf[n] = '\n';
    // write(1, buf, n+1); exit(0)。syscall 番号は x86-64 (write=1, exit=60)。
    __asm__ volatile(
        "mov %0, %%rdx\n"
        "mov $1, %%rax\n"
        "mov $1, %%rdi\n"
        "lea buf(%%rip), %%rsi\n"
        "syscall\n"
        "mov $60, %%rax\n"
        "xor %%edi, %%edi\n"
        "syscall\n" ::"r"(n + 1));
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

fn compile(
    dir: &Path,
    lld: &Path,
    name: &str,
    target: &str,
    extra: &[&str],
    source: &str,
) -> PathBuf {
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
        ])
        .args(extra)
        .arg("-o")
        .arg(&elf)
        .arg(&src)
        .status()
        .expect("clang");
    assert!(status.success(), "clang {target} failed");
    elf
}

fn test_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("polyisa-heavy-jit-diff");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// AArch64 の fib ELF をインタプリタと JIT で走らせて比べる。
/// `stp`/`ldp`/`bl`/`ret`/`b.cond`/`subs`/`cbz` 系を通る。
#[test]
fn aarch64_fib_interp_vs_jit() {
    use polyisa_cli::run_aarch64::{run_elf_aarch64_sys, run_elf_aarch64_sys_jit};
    use polyisa_os_linux::aarch64::sys::Linux;

    let lld = lld();
    assert!(lld.is_file(), "rust-lld が必要。TOOL-RUST のリンカを使う。");
    let elf = compile(
        &test_dir(),
        &lld,
        "a64-fib",
        "aarch64-linux-gnu",
        &[],
        SRC_A64,
    );
    let path = elf.to_str().unwrap();

    let mut sys = Linux::default();
    let code = run_elf_aarch64_sys(path, &[], None, &mut sys)
        .unwrap_or_else(|e| panic!("aarch64 interp: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"55\n");

    // threshold=1: 全ブロックを即コンパイル。機械語経路を確かめる。
    let mut jit = polyisa_jit::Jit::new();
    jit.set_threshold(1);
    let mut jsys = Linux::default();
    let jcode = run_elf_aarch64_sys_jit(path, &[], None, &mut jsys, &mut jit)
        .unwrap_or_else(|e| panic!("aarch64 jit: {e}"));
    assert_eq!(jcode, code, "終了コードが違う");
    assert_eq!(jsys.io.stdout, sys.io.stdout, "stdout が違う");
    assert_eq!(jsys.io.stderr, sys.io.stderr, "stderr が違う");
    let (ran, _) = jit.stats();
    assert!(jit.compiled() > 0, "コンパイル済みブロックが無い");
    assert!(ran > 0, "機械語で走ったブロックが無い");

    // 既定閾値: ホットになるまでは IR 解釈で走る経路を確かめる。
    let mut jit2 = polyisa_jit::Jit::new();
    let mut jsys2 = Linux::default();
    let jcode2 = run_elf_aarch64_sys_jit(path, &[], None, &mut jsys2, &mut jit2)
        .unwrap_or_else(|e| panic!("aarch64 jit(既定): {e}"));
    assert_eq!(jcode2, code, "終了コードが違う（既定閾値）");
    assert_eq!(jsys2.io.stdout, sys.io.stdout, "stdout が違う（既定閾値）");
    let (_, interp) = jit2.stats();
    assert!(interp > 0, "IR 解釈で走ったブロックが無い");
}

/// ARM（A32・EABI）の fib ELF の比較。cond 付き命令・ldm/stm を通る。
#[test]
fn arm_fib_interp_vs_jit() {
    use polyisa_cli::run_arm::{run_elf_arm_sys, run_elf_arm_sys_jit};
    use polyisa_os_linux::arm::sys::Linux;

    let lld = lld();
    assert!(lld.is_file(), "rust-lld が必要。TOOL-RUST のリンカを使う。");
    let elf = compile(
        &test_dir(),
        &lld,
        "arm-fib",
        "armv7-linux-gnueabihf",
        &["-marm"],
        SRC_ARM,
    );
    let path = elf.to_str().unwrap();

    let mut sys = Linux::new();
    let code =
        run_elf_arm_sys(path, &[], None, &mut sys).unwrap_or_else(|e| panic!("arm interp: {e}"));
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout, b"55\n");

    let mut jit = polyisa_jit::Jit::new();
    jit.set_threshold(1);
    let mut jsys = Linux::new();
    let jcode = run_elf_arm_sys_jit(path, &[], None, &mut jsys, &mut jit)
        .unwrap_or_else(|e| panic!("arm jit: {e}"));
    assert_eq!(jcode, code, "終了コードが違う");
    assert_eq!(jsys.io.stdout, sys.io.stdout, "stdout が違う");
    assert_eq!(jsys.io.stderr, sys.io.stderr, "stderr が違う");
    let (ran, _) = jit.stats();
    assert!(jit.compiled() > 0, "コンパイル済みブロックが無い");
    assert!(ran > 0, "機械語で走ったブロックが無い");

    let mut jit2 = polyisa_jit::Jit::new();
    let mut jsys2 = Linux::new();
    let jcode2 = run_elf_arm_sys_jit(path, &[], None, &mut jsys2, &mut jit2)
        .unwrap_or_else(|e| panic!("arm jit(既定): {e}"));
    assert_eq!(jcode2, code, "終了コードが違う（既定閾値）");
    assert_eq!(jsys2.io.stdout, sys.io.stdout, "stdout が違う（既定閾値）");
    let (_, interp) = jit2.stats();
    assert!(interp > 0, "IR 解釈で走ったブロックが無い");
}

/// x86-64 の fib ELF の比較。call/ret/jcc/push/pop を通る。
/// syscall 経路はブロックの境界としてインタプリタと同じ委譲を通る。
#[test]
fn x86_64_fib_interp_vs_jit() {
    use polyisa_cli::run_x86::{run_elf_x86_64_captured, run_elf_x86_64_captured_jit};

    let lld = lld();
    assert!(lld.is_file(), "rust-lld が必要。TOOL-RUST のリンカを使う。");
    let elf = compile(
        &test_dir(),
        &lld,
        "x64-fib",
        "x86_64-linux-gnu",
        &[],
        SRC_X64,
    );
    let path = elf.to_str().unwrap();

    let (code, out) =
        run_elf_x86_64_captured(path, &[]).unwrap_or_else(|e| panic!("x86-64 interp: {e}"));
    assert_eq!(code, 0);
    assert_eq!(out, b"55\n");

    let mut jit = polyisa_jit::Jit::new();
    jit.set_threshold(1);
    let (jcode, jout) = run_elf_x86_64_captured_jit(path, &[], &mut jit)
        .unwrap_or_else(|e| panic!("x86-64 jit: {e}"));
    assert_eq!(jcode, code, "終了コードが違う");
    assert_eq!(jout, out, "stdout が違う");
    let (ran, _) = jit.stats();
    assert!(jit.compiled() > 0, "コンパイル済みブロックが無い");
    assert!(ran > 0, "機械語で走ったブロックが無い");

    let mut jit2 = polyisa_jit::Jit::new();
    let (jcode2, jout2) = run_elf_x86_64_captured_jit(path, &[], &mut jit2)
        .unwrap_or_else(|e| panic!("x86-64 jit(既定): {e}"));
    assert_eq!(jcode2, code, "終了コードが違う（既定閾値）");
    assert_eq!(jout2, out, "stdout が違う（既定閾値）");
    let (_, interp) = jit2.stats();
    assert!(interp > 0, "IR 解釈で走ったブロックが無い");
}
