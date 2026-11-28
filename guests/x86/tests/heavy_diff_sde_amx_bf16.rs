// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Intel SDE との AMX-BF16 数値差分（層: diff、E3）。
//!
//! TDPBF16PS の partial-sum 丸め・denormal flush・NaN/Inf 伝播を
//! 特殊値を混ぜた corpus で polyisa と `sde64 -future` の両方に通し、
//! tilestored 出力を比較する。sde64 または clang がなければスキップする。

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

// 3 tile とも colsb=16/rows=4。K=colsb/4=4 pair。
static u8 cfg[64] __attribute__((aligned(64))) = {0};
// A: 4 rows x 4 u32。u32 の lo/hi が even/odd の bf16。
// 1.0/-1.0、denormal、Inf、NaN、-Inf、大きい/小さな normal を混ぜる。
static u32 a[16] __attribute__((aligned(64))) = {
    0x3f803f80,0xbf80bf80,0x00010001,0x3f80bf80,
    0x7f807f80,0x3f803f80,0x00000000,0x3f000000,
    0x7fc00000,0x3f803f80,0x40004000,0xbf80bf80,
    0xff80ff80,0x00000000,0x00010000,0x3f803f80,
};
// B: 4 rows x 4 u32。column 1 は zero を混ぜて Inf*0 の NaN 生成を狙う。
static u32 b[16] __attribute__((aligned(64))) = {
    0x3f803f80,0x00000000,0x3f803f80,0x40004000,
    0x3f803f80,0x3f803f80,0x3f803f80,0x3f803f80,
    0x3f803f80,0x00003f80,0xbf803f80,0x3f803f80,
    0xbf803f80,0x3f803f80,0x3f80bf80,0x00010001,
};
// FP16 用 corpus。1.0/-1.0、denormal、Inf、NaN、-Inf、zero を混ぜる。
static u32 a16[16] __attribute__((aligned(64))) = {
    0x3c003c00,0xbc00bc00,0x00010001,0x3c00bc00,
    0x7c007c00,0x3c003c00,0x00000000,0x38003800,
    0x7e000000,0x3c003c00,0x40004000,0xbc00bc00,
    0xfc00fc00,0x00000000,0x00010000,0x3c003c00,
};
static u32 b16[16] __attribute__((aligned(64))) = {
    0x3c003c00,0x00000000,0x3c003c00,0x40004000,
    0x3c003c00,0x3c003c00,0x3c003c00,0x3c003c00,
    0x3c003c00,0x00003c00,0xbc003c00,0x3c003c00,
    0xbc003c00,0x3c003c00,0x3c00bc00,0x00010001,
};
static u32 dst[32] __attribute__((aligned(64))) = {0};

void _start(void) {
    (void)sys3(158, 0x1023, 17, 0); // ARCH_REQ_XCOMP_PERM XTILECFG
    (void)sys3(158, 0x1023, 18, 0); // XTILEDATA
    cfg[0] = 1;
    for (int i = 0; i < 3; i++) {
        cfg[16 + i * 2] = 16;
        cfg[48 + i] = 4;
    }
    // tile 命令の .byte encoding が rsi/rdi/rbx を固定的に使うため、
    // これらは pinned input にせず "r" input から asm 内でロードし、
    // clobber として宣言する。pinned input を asm 内で壊すと、asm 後に
    // コンパイラがそのレジスタを再利用する経路でアドレスがずれる。
    asm volatile(
        "mov %1, %%rsi\n\t"
        "mov %2, %%rdi\n\t"
        "mov %3, %%rbx\n\t"
        ".byte 0xC4,0xE2,0x78,0x49,0x00\n\t"       // ldtilecfg (%rax)
        ".byte 0xC4,0xE2,0x7B,0x4B,0x0C,0x3E\n\t" // tileloadd (%rsi,%rdi),tmm1
        "mov %4, %%rsi\n\t"
        ".byte 0xC4,0xE2,0x7B,0x4B,0x14,0x3E\n\t" // tileloadd (%rsi,%rdi),tmm2
        ".byte 0xC4,0xE2,0x6A,0x5C,0xC1\n\t"      // tdpbf16ps %tmm2,%tmm1,%tmm0
        ".byte 0xC4,0xE2,0x7A,0x4B,0x04,0x3B\n\t" // tilestored %tmm0,(%rbx,%rdi)
        // FP16 round。tmm0 をゼロへ戻し、a16/b16 で同じ形状を通す。
        ".byte 0xC4,0xE2,0x7B,0x49,0xC0\n\t"       // tilezero tmm0
        "mov %5, %%rsi\n\t"
        ".byte 0xC4,0xE2,0x7B,0x4B,0x0C,0x3E\n\t" // tileloadd (%rsi,%rdi),tmm1
        "mov %6, %%rsi\n\t"
        ".byte 0xC4,0xE2,0x7B,0x4B,0x14,0x3E\n\t" // tileloadd (%rsi,%rdi),tmm2
        ".byte 0xC4,0xE2,0x6B,0x5C,0xC1\n\t"      // tdpfp16ps %tmm2,%tmm1,%tmm0
        "add $64, %%rbx\n\t"
        ".byte 0xC4,0xE2,0x7A,0x4B,0x04,0x3B\n\t" // tilestored %tmm0,(%rbx,%rdi)
        :
        : "a"(cfg), "r"(a), "r"((u64)16), "r"(dst), "r"(b), "r"(a16), "r"(b16)
        : "memory", "rsi", "rdi", "rbx");
    (void)sys3(1, 1, (long)dst, 128);
    (void)sys3(60, 0, 0, 0);
    __builtin_unreachable();
}


"#;

fn compile(dir: &Path) -> PathBuf {
    let src = dir.join("amxbf16.c");
    let elf = dir.join("amxbf16");
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
        &["amx_tile", "amx_bf16", "amx_fp16"],
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
fn diff_sde_amx_bf16_numeric() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("clang がない。スキップ");
        return;
    }
    let Some(sde) = sde_path() else {
        eprintln!("sde64 がない。スキップ");
        return;
    };
    let dir = std::env::temp_dir().join(format!("polyisa-sde-amxbf16-{}", std::process::id()));
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
    assert_eq!(poly.len(), 128, "poly stdout len");
    assert_eq!(out.stdout.len(), 128, "sde stdout len");
    if poly != out.stdout {
        for i in 0..32 {
            let p = u32::from_le_bytes(poly[i * 4..i * 4 + 4].try_into().unwrap());
            let s = u32::from_le_bytes(out.stdout[i * 4..i * 4 + 4].try_into().unwrap());
            if p != s {
                eprintln!("mismatch dword{i}: poly={p:08x} sde={s:08x}");
            }
        }
        panic!("amx bf16 mismatch");
    }
}
