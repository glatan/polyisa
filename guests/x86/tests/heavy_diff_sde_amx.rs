// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Gap: GAP-0030
//! Intel SDE との AMX 実行差分（層: diff、E3）。
//!
//! AMX-INT8 の LDTILECFG→TILELOADD→TDPBSSD→TILESTORED を通る
//! 静的 ELF を作り、tilestored の 16 バイトを stdout に書く。
//! 同じ ELF を polyisa と `sde64 -future` で実行し、出力を比較する。
//! sde64 または clang がなければスキップする。

use std::path::{Path, PathBuf};
use std::process::Command;

const SRC: &str = r#"
typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned char u8;

static long sys3(long n, long a, long b, long c) {
    long r;
    asm volatile("syscall" : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

void _start(void) {
    // AMX は Linux の動的 xstate なので XTILECFG(17) と
    // XTILEDATA(18) を要求する。SDE 側でホストカーネルが拒否しても、
    // -future が命令を通す環境ではそのまま実行できるよう結果は見ない。
    (void)sys3(158, 0x1023, 17, 0); // ARCH_REQ_XCOMP_PERM
    (void)sys3(158, 0x1023, 18, 0);
    static u8 cfg[64] = {0};
    cfg[0] = 1;
    for (int i = 0; i < 3; i++) {
        cfg[16 + i * 2] = 8;
        cfg[48 + i] = 2;
    }
    static const u8 a[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    static const u8 b[16] = {1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1};
    static u32 dst[4] = {0};
    asm volatile(
        ".byte 0xC4,0xE2,0x78,0x49,0x00\n\t"       // ldtilecfg (%rax)
        ".byte 0xC4,0xE2,0x7B,0x4B,0x0C,0x3E\n\t" // tileloadd (%rsi,%rdi),tmm1
        "mov %4, %%rsi\n\t"
        ".byte 0xC4,0xE2,0x7B,0x4B,0x14,0x3E\n\t" // tileloadd (%rsi,%rdi),tmm2
        ".byte 0xC4,0xE2,0x6B,0x5E,0xC1\n\t"      // tdpbssd %tmm2,%tmm1,%tmm0
        ".byte 0xC4,0xE2,0x7A,0x4B,0x04,0x3B\n\t" // tilestored %tmm0,(%rbx,%rdi)
        :
        : "a"(cfg), "S"(a), "D"(8), "b"(dst), "r"(b)
        : "memory");
    (void)sys3(1, 1, (long)dst, 16);
    (void)sys3(60, 0, 0, 0);
    __builtin_unreachable();
}
"#;

fn compile(dir: &Path) -> PathBuf {
    let src = dir.join("amx.c");
    let elf = dir.join("amx");
    std::fs::write(&src, SRC).unwrap();
    let status = Command::new("clang")
        .args([
            "-O1",
            "-static",
            "-nostdlib",
            "-ffreestanding",
            "-fno-stack-protector",
            "-o",
        ])
        .arg(&elf)
        .arg(&src)
        .status()
        .expect("clang");
    assert!(status.success(), "clang failed");
    elf
}

fn sde_path() -> Option<String> {
    ["sde64", "/opt/sde/sde64", "/usr/bin/sde64"]
        .iter()
        .find(|c| {
            Command::new(c)
                .args(["-future", "--", "/bin/true"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .map(|s| s.to_string())
}

fn poly_run(bytes: &[u8], path: &str) -> (Vec<u8>, Option<u64>) {
    let sel = polyisa_isadl::select::resolve(
        polyisa_guest_x86::MODEL_DEFS,
        polyisa_guest_x86::FEATURE_DEFS,
        polyisa_guest_x86::FEAT_BITS,
        "x86_64_v4",
        &["amx_tile", "amx_int8"],
        &[],
    )
    .unwrap();
    let mut sys = polyisa_os_linux::x86::sys::Linux::x86_64();
    let captured = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    sys.capture_out = Some(std::rc::Rc::clone(&captured));
    let argv = vec![path.to_string()];
    let code =
        polyisa_cli::run_x86::run_image_x86_64_sel(bytes, path, &argv, &mut sys, Some(&sel), None);
    (captured.borrow().clone(), code.ok())
}

#[test]
fn diff_sde_amx_int8() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("clang がない。スキップ");
        return;
    }
    let Some(sde) = sde_path() else {
        eprintln!("sde64 がない。スキップ");
        return;
    };
    let dir = std::env::temp_dir().join(format!("polyisa-sde-amx-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir);
    let bytes = std::fs::read(&elf).unwrap();
    let out = Command::new(sde)
        .args(["-future", "--"])
        .arg(&elf)
        .current_dir(&dir)
        .output()
        .expect("sde64");
    assert!(out.status.success(), "sde status {:?}", out.status);
    let (poly, code) = poly_run(&bytes, elf.to_str().unwrap());
    assert_eq!(code, Some(0), "poly exit");
    assert_eq!(poly.len(), 16, "poly stdout len");
    assert_eq!(out.stdout.len(), 16, "sde stdout len");
    assert_eq!(poly, out.stdout, "tilestored bytes");
    let expect = [8u32, 10, 24, 26]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    assert_eq!(poly, expect, "known TDPBSSD result");
}
