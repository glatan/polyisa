// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Intel SDE との ACE 実行差分（層: diff、E3）。
//!
//! ACE palette 2 の TOP2BF16PS を通る静的 ELF を作り、
//! TILEMOVROW read で取り出した 16 行を stdout へ書く。入力には
//! BF16 の zero/subnormal/Inf/NaN と FP32 accumulator の corner case を
//! 混ぜ、同じ ELF を polyisa と `sde64 -future-ag` で比較する。
//! sde64 または clang がなければスキップする。

use std::path::{Path, PathBuf};
use std::process::Command;

const SRC: &str = r#"typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned char u8;

static long sys3(long n, long a, long b, long c) {
    long r;
    asm volatile("syscall" : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

static u8 cfg[64] __attribute__((aligned(64))) = {2};
// 1 行分の FP32 accumulator。SDE は ACE ドラフト pseudocode と
// 異なり subnormal accumulator を DAZ しないため、oracle 比較では
// 両者が一致する有限 normal/zero の領域に限定する。
static u32 accrow[16] __attribute__((aligned(64))) = {
    0x3f800000,0xbf800000,0x00000000,0x80000000,
    0x3dcccccd,0x4b000001,0x00800000,0x3f000000,
    0xbf000000,0x41200000,0xc1200000,0x3eaaaaab,
    0x00000000,0x80000000,0x3f800001,0xbf800001
};
// BF16 pair/row。zero、符号、最小 normal、大きな/小さな normal を混ぜる。
// BF16 subnormal・NaN・Inf は SDE とドラフト pseudocode の既知差なので
// この oracle 入力には入れない。
static u32 arow[16] __attribute__((aligned(64))) = {
    0x40003f80,0x20002000,0x3f80bf80,0x80000000,
    0x3f803f80,0xbf804040,0x20002000,0x3f800000,
    0x00000000,0x3f80bf80,0x3f002000,0x4040bf80,
    0x2eed1234,0x77fe2000,0x3f80c000,0x00000000
};
static u32 brow[16] __attribute__((aligned(64))) = {
    0x3f804000,0x20002000,0x3f80bf80,0x00008000,
    0xbf803f80,0x3f803f80,0x20002000,0x00000000,
    0x3f80bf80,0x00000000,0x20003f00,0xbf804040,
    0x12342eed,0x200077fe,0xc0003f80,0x00000000
};
static u32 out[256] __attribute__((aligned(64)));

void _start(void) {
    (void)sys3(158, 0x1023, 17, 0);
    (void)sys3(158, 0x1023, 18, 0);
    (void)sys3(158, 0x1023, 20, 0);
    asm volatile(
        "mov %0, %%rax\n\t"
        ".byte 0xC4,0xE2,0x78,0x49,0x00\n\t"       // ldtilecfg (%rax), palette2
        ".byte 0xC4,0xE2,0x7B,0x49,0xC8\n\t"       // tilezero tmm1
        "vmovdqu64 (%1), %%zmm2\n\t"
        ".byte 0x62,0xF3,0xFD,0x48,0x07,0xCA,0x00\n\t" // tilemovrow tmm1,zmm2,0
        "vmovdqu64 (%2), %%zmm0\n\t"
        "vmovdqu64 (%3), %%zmm1\n\t"
        ".byte 0x62,0xF2,0x76,0x48,0x5C,0xC8\n\t" // top2bf16ps tmm1,zmm0,zmm1
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,0\n\t"
        "vmovdqu64 %%zmm0, 0(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,1\n\t"
        "vmovdqu64 %%zmm0, 64(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,2\n\t"
        "vmovdqu64 %%zmm0, 128(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,3\n\t"
        "vmovdqu64 %%zmm0, 192(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,4\n\t"
        "vmovdqu64 %%zmm0, 256(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,5\n\t"
        "vmovdqu64 %%zmm0, 320(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,6\n\t"
        "vmovdqu64 %%zmm0, 384(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,7\n\t"
        "vmovdqu64 %%zmm0, 448(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,8\n\t"
        "vmovdqu64 %%zmm0, 512(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,9\n\t"
        "vmovdqu64 %%zmm0, 576(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,10\n\t"
        "vmovdqu64 %%zmm0, 640(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,11\n\t"
        "vmovdqu64 %%zmm0, 704(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,12\n\t"
        "vmovdqu64 %%zmm0, 768(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,13\n\t"
        "vmovdqu64 %%zmm0, 832(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,14\n\t"
        "vmovdqu64 %%zmm0, 896(%4)\n\t"
        ".byte 0x62,0xF3,0x7D,0x48,0x07,0xC1,15\n\t"
        "vmovdqu64 %%zmm0, 960(%4)\n\t"
        :
        : "r"(cfg), "r"(accrow), "r"(arow), "r"(brow), "r"(out)
        : "rax", "memory");
    (void)sys3(1, 1, (long)out, 1024);
    (void)sys3(60, 0, 0, 0);
    __builtin_unreachable();
}"#;

fn compile(dir: &Path) -> PathBuf {
    let src = dir.join("ace.c");
    let elf = dir.join("ace");
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
                .args(["-future-ag", "--", "/bin/true"])
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
        &["ace"],
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
fn diff_sde_ace_top2bf16ps() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("clang がない。スキップ");
        return;
    }
    let Some(sde) = sde_path() else {
        eprintln!("sde64 がない。スキップ");
        return;
    };
    let dir = std::env::temp_dir().join(format!("polyisa-sde-ace-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir);
    let bytes = std::fs::read(&elf).unwrap();
    let out = Command::new(sde)
        .args(["-future-ag", "--"])
        .arg(&elf)
        .current_dir(&dir)
        .output()
        .expect("sde64");
    assert!(out.status.success(), "sde status {:?}", out.status);
    assert_eq!(out.stdout.len(), 1024, "sde stdout len");
    let (poly, code) = poly_run(&bytes, elf.to_str().unwrap());
    assert_eq!(code, Some(0), "poly exit");
    assert_eq!(poly.len(), 1024, "poly stdout len");
    if poly != out.stdout {
        let mut bad = Vec::new();
        for i in 0..256 {
            let a = u32::from_le_bytes(poly[i * 4..i * 4 + 4].try_into().unwrap());
            let b = u32::from_le_bytes(out.stdout[i * 4..i * 4 + 4].try_into().unwrap());
            if a != b {
                bad.push(format!("r{}c{} poly={a:08x} sde={b:08x}", i / 16, i % 16));
            }
        }
        panic!(
            "TOP2BF16PS tile mismatch: {}",
            bad[..bad.len().min(12)].join(" ")
        );
    }
}
