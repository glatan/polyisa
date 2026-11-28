// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Intel SDE との AVX10 実行差分（層: diff、E3）。
//!
//! AVX10.2 の conversion、min/max、FP16 dot product、整数 byte 変換を
//! 通る静的 ELF を作り、出力ベクトルと MXCSR を stdout へ書く。
//! 入力には zero、符号、denormal、Inf、NaN、丸め境界を混ぜ、同じ ELF を
//! polyisa と `sde64 -dmr` で比較する。sde64 または clang がなければ
//! スキップする。

use std::path::{Path, PathBuf};
use std::process::Command;

const SRC: &str = r#"typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

static long sys3(long n, long a, long b, long c) {
    long r;
    asm volatile("syscall" : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

// FP32 入力。zero、符号、Inf、NaN、denormal、大きな/小さな normal、
// FP16 への丸め境界を混ぜる。
static u32 ps_a[8] __attribute__((aligned(64))) = {
    0x3fc00000,0xc0100000,0x00000000,0x80000000,
    0x40490fdb,0x477fe000,0x00000001,0x7fc00001
};
static u32 ps_b[8] __attribute__((aligned(64))) = {
    0x40200000,0x7f800000,0xff800000,0x33800000,
    0x3f000000,0x7fc00000,0x4b000001,0x00800001
};
// HF8/FP16/BF16 入力。E4M3/E5M2 の zero、subnormal、normal、最大値、
// Inf/NaN 相当のビットパターンを固定で並べる。
static u8 hf8_in[16] __attribute__((aligned(64))) = {
    0x00,0x80,0x01,0x81,0x38,0xb8,0x3c,0xbc,
    0x7e,0xfe,0x7f,0xff,0x40,0xc0,0x55,0xaa
};
static u16 ph_in[16] __attribute__((aligned(64))) = {
    0x0000,0x8000,0x0001,0x8001,0x3c00,0xbc00,
    0x3e00,0xbe00,0x7bff,0xfbff,0x7c00,0xfc00,
    0x7e00,0x7c01,0x3555,0x4000
};
static u16 bf16_in[16] __attribute__((aligned(64))) = {
    0x0000,0x8000,0x0001,0x8001,0x3f80,0xbf80,
    0x3fc0,0xbfc0,0x7f7f,0xff7f,0x7f80,0xff80,
    0x7fc0,0x7f81,0x3f00,0x4000
};
// bias 入力は 0 を中心に、小さい正負のシフトも含める。
static u16 bias_in[16] __attribute__((aligned(64))) = {
    0,0,0,0,1,0xffff,2,0xfffe,
    0,0,0,0,4,0xfffc,8,0xfff8
};
static u32 mxcsr_init[1] __attribute__((aligned(64))) = {0x1f80};
static u32 out[1024] __attribute__((aligned(64)));

void _start(void) {
    asm volatile(
        "ldmxcsr (%10)\n\t"

        // FP32 二入力 -> FP16 packed conversion。
        "vmovdqu64 (%1), %%ymm1\n\t"
        "vmovdqu64 (%2), %%ymm2\n\t"
        ".byte 0x62,0xF2,0x75,0x28,0x67,0xC2\n\t" // vcvt2ps2phx ymm0,ymm1,ymm2
        "vmovdqu64 %%ymm0, 0(%0)\n\t"
        "vstmxcsr 32(%0)\n\t"

        // HF8 -> FP16。
        "ldmxcsr (%10)\n\t"
        "vmovdqu64 (%3), %%xmm1\n\t"
        ".byte 0x62,0xF5,0x7F,0x28,0x1E,0xC1\n\t" // vcvthf82ph ymm0,xmm1
        "vmovdqu64 %%ymm0, 64(%0)\n\t"
        "vstmxcsr 96(%0)\n\t"

        // FP16 + bias -> FP8。非飽和/飽和、BF8/HF8 の4形。
        "ldmxcsr (%10)\n\t"
        "vmovdqu64 (%4), %%ymm1\n\t"
        "vmovdqu64 (%5), %%ymm2\n\t"
        ".byte 0x62,0xF2,0x74,0x28,0x74,0xC2\n\t" // vcvtbiasph2bf8 xmm0,ymm1,ymm2
        ".byte 0x62,0xF5,0x74,0x28,0x74,0xDA\n\t" // vcvtbiasph2bf8s xmm3,ymm1,ymm2
        ".byte 0x62,0xF5,0x74,0x28,0x18,0xE2\n\t" // vcvtbiasph2hf8 xmm4,ymm1,ymm2
        ".byte 0x62,0xF5,0x74,0x28,0x1B,0xEA\n\t" // vcvtbiasph2hf8s xmm5,ymm1,ymm2
        "vmovdqu64 %%ymm0, 128(%0)\n\t"
        "vmovdqu64 %%ymm3, 192(%0)\n\t"
        "vmovdqu64 %%ymm4, 256(%0)\n\t"
        "vmovdqu64 %%ymm5, 320(%0)\n\t"
        "vstmxcsr 352(%0)\n\t"

        // BF16/FP16/FP32 -> integer byte。truncation/RNE と符号有無。
        "ldmxcsr (%10)\n\t"
        "vmovdqu64 (%6), %%xmm2\n\t"
        ".byte 0x62,0xF5,0x7F,0x28,0x68,0xC2\n\t" // vcvttbf162ibs xmm0,xmm2
        ".byte 0x62,0xF5,0x7F,0x28,0x69,0xDA\n\t" // vcvtbf162ibs xmm3,xmm2
        ".byte 0x62,0xF5,0x7F,0x28,0x6A,0xE2\n\t" // vcvttbf162iubs xmm4,xmm2
        ".byte 0x62,0xF5,0x7F,0x28,0x6B,0xEA\n\t" // vcvtbf162iubs xmm5,xmm2
        "vmovdqu64 %%ymm0, 384(%0)\n\t"
        "vmovdqu64 %%ymm3, 448(%0)\n\t"
        "vmovdqu64 %%ymm4, 512(%0)\n\t"
        "vmovdqu64 %%ymm5, 576(%0)\n\t"
        "vstmxcsr 608(%0)\n\t"

        "ldmxcsr (%10)\n\t"
        "vmovdqu64 (%5), %%ymm2\n\t"
        ".byte 0x62,0xF5,0x7C,0x28,0x68,0xC2\n\t" // vcvttph2ibs xmm0,ymm2
        ".byte 0x62,0xF5,0x7C,0x28,0x69,0xDA\n\t" // vcvtph2ibs xmm3,ymm2
        ".byte 0x62,0xF5,0x7C,0x28,0x6A,0xE2\n\t" // vcvttph2iubs xmm4,ymm2
        ".byte 0x62,0xF5,0x7C,0x28,0x6B,0xEA\n\t" // vcvtph2iubs xmm5,ymm2
        "vmovdqu64 %%ymm0, 640(%0)\n\t"
        "vmovdqu64 %%ymm3, 704(%0)\n\t"
        "vmovdqu64 %%ymm4, 768(%0)\n\t"
        "vmovdqu64 %%ymm5, 832(%0)\n\t"
        "vstmxcsr 864(%0)\n\t"

        "ldmxcsr (%10)\n\t"
        "vmovdqu64 (%1), %%ymm2\n\t"
        ".byte 0x62,0xF5,0x7D,0x28,0x68,0xC2\n\t" // vcvttps2ibs xmm0,ymm2
        ".byte 0x62,0xF5,0x7D,0x28,0x69,0xDA\n\t" // vcvtps2ibs xmm3,ymm2
        ".byte 0x62,0xF5,0x7D,0x28,0x6A,0xE2\n\t" // vcvttps2iubs xmm4,ymm2
        ".byte 0x62,0xF5,0x7D,0x28,0x6B,0xEA\n\t" // vcvtps2iubs xmm5,ymm2
        "vmovdqu64 %%ymm0, 896(%0)\n\t"
        "vmovdqu64 %%ymm3, 960(%0)\n\t"
        "vmovdqu64 %%ymm4, 1024(%0)\n\t"
        "vmovdqu64 %%ymm5, 1088(%0)\n\t"
        "vstmxcsr 1120(%0)\n\t"

        // VMINMAXPS の immediate 4形。signed zero/NaN を含む。
        "ldmxcsr (%10)\n\t"
        "vmovdqu64 (%1), %%ymm1\n\t"
        "vmovdqu64 (%2), %%ymm2\n\t"
        ".byte 0x62,0xF3,0x75,0x28,0x52,0xC2,0x00\n\t"
        "vmovdqu64 %%ymm0, 1152(%0)\n\t"
        "vmovdqu64 (%1), %%ymm1\n\t"
        "vmovdqu64 (%2), %%ymm2\n\t"
        ".byte 0x62,0xF3,0x75,0x28,0x52,0xC2,0x01\n\t"
        "vmovdqu64 %%ymm0, 1216(%0)\n\t"
        "vmovdqu64 (%1), %%ymm1\n\t"
        "vmovdqu64 (%2), %%ymm2\n\t"
        ".byte 0x62,0xF3,0x75,0x28,0x52,0xC2,0x02\n\t"
        "vmovdqu64 %%ymm0, 1280(%0)\n\t"
        "vmovdqu64 (%1), %%ymm1\n\t"
        "vmovdqu64 (%2), %%ymm2\n\t"
        ".byte 0x62,0xF3,0x75,0x28,0x52,0xC2,0x03\n\t"
        "vmovdqu64 %%ymm0, 1344(%0)\n\t"

        // FP16 pair dot product。acc + a0*b0 + a1*b1。
        "ldmxcsr (%10)\n\t"
        "vmovdqu64 (%5), %%ymm1\n\t"
        "vmovdqu64 (%6), %%ymm2\n\t"
        "vxorps %%ymm0,%%ymm0,%%ymm0\n\t"
        ".byte 0x62,0xF2,0x74,0x28,0x52,0xC2\n\t" // vdpphps ymm0,ymm1,ymm2
        "vmovdqu64 %%ymm0, 1408(%0)\n\t"
        "vstmxcsr 1440(%0)\n\t"
        :
        : "r"(out), "r"(ps_a), "r"(ps_b), "r"(hf8_in), "r"(bias_in), "r"(ph_in), "r"(bf16_in), "r"(0), "r"(0), "r"(0), "r"(mxcsr_init)
        : "rax", "memory");
    (void)sys3(1, 1, (long)out, 1472);
    (void)sys3(60, 0, 0, 0);
    __builtin_unreachable();
}"#;

fn compile(dir: &Path) -> PathBuf {
    let src = dir.join("avx10.c");
    let elf = dir.join("avx10");
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
                .args(["-dmr", "--", "/bin/true"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .map(|s| s.to_string())
}

fn poly_run(bytes: &[u8], path: &str) -> (Vec<u8>, Result<u64, String>) {
    let sel = polyisa_isadl::select::resolve(
        polyisa_guest_x86::MODEL_DEFS,
        polyisa_guest_x86::FEATURE_DEFS,
        polyisa_guest_x86::FEAT_BITS,
        "x86_64_v4",
        &["avx10_2"],
        &[],
    )
    .unwrap();
    let mut sys = polyisa_os_linux::x86::sys::Linux::x86_64();
    let captured = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    sys.capture_out = Some(std::rc::Rc::clone(&captured));
    let argv = vec![path.to_string()];
    let code =
        polyisa_cli::run_x86::run_image_x86_64_sel(bytes, path, &argv, &mut sys, Some(&sel), None);
    (captured.borrow().clone(), code)
}

#[test]
fn diff_sde_avx10_numeric_corpus() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("clang がない。スキップ");
        return;
    }
    let Some(sde) = sde_path() else {
        eprintln!("sde64 がない。スキップ");
        return;
    };
    let dir = std::env::temp_dir().join(format!("polyisa-sde-avx10-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir);
    let bytes = std::fs::read(&elf).unwrap();
    let out = Command::new(sde)
        .args(["-dmr", "--"])
        .arg(&elf)
        .current_dir(&dir)
        .output()
        .expect("sde64");
    assert!(out.status.success(), "sde status {:?}", out.status);
    assert_eq!(out.stdout.len(), 1472, "sde stdout len");
    let (poly, code) = poly_run(&bytes, elf.to_str().unwrap());
    assert_eq!(code, Ok(0), "poly exit");
    assert_eq!(poly.len(), 1472, "poly stdout len");
    if poly != out.stdout {
        let mut bad = Vec::new();
        for i in 0..368 {
            let a = u32::from_le_bytes(poly[i * 4..i * 4 + 4].try_into().unwrap());
            let b = u32::from_le_bytes(out.stdout[i * 4..i * 4 + 4].try_into().unwrap());
            if a != b {
                bad.push(format!("dword{i} poly={a:08x} sde={b:08x}"));
            }
        }
        panic!("avx10 mismatch: {}", bad[..bad.len().min(24)].join(" "));
    }
}
