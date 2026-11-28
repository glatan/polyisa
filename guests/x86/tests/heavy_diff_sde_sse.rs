// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Intel SDE との SSE 実行差分（層: diff、E3）。
//!
//! coverage 監査で証拠ゼロだった SSE conversion/shuffle/scalar-arith
//! 系を、adversarial な浮動小数入力で sde64 -future と比較する。
//! 命令は asm mnemonic で書けるものはそのまま書く（SSE2 までなら
//! clang がそのまま受け付ける）。denormal/zero/Inf/NaN/丸め境界を
//! 入力に含め、xmm 出力と movmsk/cvt 系の GPR 出力を stdout に出して
//! bit 比較する。sde64 または clang がなければスキップする。

use std::path::{Path, PathBuf};
use std::process::Command;

const SRC: &str = r#"
typedef unsigned long u64;
typedef unsigned int u32;

static long sys3(long n, long a, long b, long c) {
    long r;
    asm volatile("syscall" : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

// float x4: 1.5, -2.5, 最小 denormal, +Inf
static u32 fa[4] __attribute__((aligned(16))) =
    {0x3fc00000, 0xc0200000, 0x00000001, 0x7f800000};
// float x4: qNaN+payload, -0.0, 丸め境界の 16777216+1, 最大 normal
static u32 fb[4] __attribute__((aligned(16))) =
    {0x7fc00001, 0x80000000, 0x4b000001, 0x7f7fffff};
// double x2: pi 近似, 1e300
static u64 da[2] __attribute__((aligned(16))) =
    {0x400921fb54442d18UL, 0x7e37e43c8800759cUL};
// double x2: 最小 denormal, -Inf
static u64 db[2] __attribute__((aligned(16))) =
    {0x0000000000000001UL, 0xfff0000000000000UL};
// float の整数化入力: 1.5(偶への丸め), 2.5, -3.5, 2147483648.0(overflow)
static u32 fi[4] __attribute__((aligned(16))) =
    {0x3fc00000, 0x40200000, 0xc0600000, 0x4f000000};

static u32 out[256] __attribute__((aligned(16)));

void _start(void) {
    asm volatile(
        "movups (%1), %%xmm0\n\t"     // fa
        "movups (%2), %%xmm1\n\t"     // fb
        "movupd (%3), %%xmm4\n\t"     // da
        "movupd (%4), %%xmm5\n\t"     // db
        "movups (%5), %%xmm6\n\t"     // fi

        // --- conversion ---
        "mov $-12345, %%eax\n\t"
        "cvtsi2ss %%eax, %%xmm8\n\t"
        "movups %%xmm8, 0(%0)\n\t"
        "cvtss2si %%xmm6, %%ebx\n\t"  // 1.5 → RNE で 2
        "movl %%ebx, 16(%0)\n\t"
        "cvttss2si %%xmm6, %%ebx\n\t" // 1.5 → truncate で 1
        "movl %%ebx, 20(%0)\n\t"
        "cvtss2si 4(%5), %%ebx\n\t"    // 2.5 → RNE で 2（偶へ）
        "movl %%ebx, 24(%0)\n\t"
        "cvtss2si 12(%5), %%ebx\n\t"   // 2^31 → overflow indefinite
        "movl %%ebx, 28(%0)\n\t"
        "cvtsd2si %%xmm4, %%edx\n\t"
        "movl %%edx, 32(%0)\n\t"
        "cvtss2sd %%xmm0, %%xmm9\n\t"
        "movups %%xmm9, 48(%0)\n\t"
        "cvtsd2ss %%xmm4, %%xmm10\n\t"
        "movups %%xmm10, 64(%0)\n\t"
        "cvtps2pd %%xmm0, %%xmm11\n\t"
        "movups %%xmm11, 80(%0)\n\t"
        "cvtpd2ps %%xmm4, %%xmm12\n\t"
        "movups %%xmm12, 96(%0)\n\t"

        // --- shuffle / unpack / dup ---
        "movups %%xmm0, %%xmm2\n\t"
        "shufps $0x1b, %%xmm1, %%xmm2\n\t"
        "movups %%xmm2, 112(%0)\n\t"
        "movupd %%xmm4, %%xmm3\n\t"
        "shufpd $1, %%xmm5, %%xmm3\n\t"
        "movups %%xmm3, 128(%0)\n\t"
        "movups %%xmm0, %%xmm2\n\t"
        "unpcklps %%xmm1, %%xmm2\n\t"
        "movups %%xmm2, 144(%0)\n\t"
        "movups %%xmm0, %%xmm2\n\t"
        "unpckhps %%xmm1, %%xmm2\n\t"
        "movups %%xmm2, 160(%0)\n\t"
        "movupd %%xmm4, %%xmm3\n\t"
        "unpcklpd %%xmm5, %%xmm3\n\t"
        "movups %%xmm3, 176(%0)\n\t"
        "movupd %%xmm4, %%xmm3\n\t"
        "unpckhpd %%xmm5, %%xmm3\n\t"
        "movups %%xmm3, 192(%0)\n\t"
        "movshdup %%xmm0, %%xmm7\n\t"
        "movups %%xmm7, 208(%0)\n\t"
        "movsldup %%xmm1, %%xmm7\n\t"
        "movups %%xmm7, 224(%0)\n\t"
        "movddup %%xmm4, %%xmm7\n\t"
        "movups %%xmm7, 240(%0)\n\t"
        "movups %%xmm0, %%xmm2\n\t"
        "movhlps %%xmm1, %%xmm2\n\t"
        "movups %%xmm2, 256(%0)\n\t"
        "movups %%xmm0, %%xmm2\n\t"
        "movlhps %%xmm1, %%xmm2\n\t"
        "movups %%xmm2, 272(%0)\n\t"

        // --- scalar arith ---
        "movupd %%xmm4, %%xmm2\n\t"
        "divsd %%xmm5, %%xmm2\n\t"    // pi / denormal-min = +Inf
        "movups %%xmm2, 288(%0)\n\t"
        "movupd %%xmm4, %%xmm2\n\t"
        "minsd %%xmm5, %%xmm2\n\t"
        "movups %%xmm2, 304(%0)\n\t"
        "sqrtsd %%xmm4, %%xmm2\n\t"
        "movups %%xmm2, 320(%0)\n\t"

        // --- integer simd ---
        "pcmpeqb %%xmm2, %%xmm2\n\t"  // all-ones
        "psubb %%xmm1, %%xmm2\n\t"
        "movups %%xmm2, 336(%0)\n\t"
        "movups %%xmm0, %%xmm3\n\t"
        "pmaxub %%xmm1, %%xmm3\n\t"
        "movups %%xmm3, 352(%0)\n\t"

        // --- movmsk / pinsrw / pextrw ---
        "movmskps %%xmm0, %%eax\n\t"
        "movl %%eax, 368(%0)\n\t"
        "movmskpd %%xmm5, %%eax\n\t"
        "movl %%eax, 372(%0)\n\t"
        "pxor %%xmm2, %%xmm2\n\t"
        "pinsrw $3, %%ebx, %%xmm2\n\t"
        "movups %%xmm2, 384(%0)\n\t"
        "pextrw $7, %%xmm0, %%eax\n\t"
        "movl %%eax, 400(%0)\n\t"
        :
        : "r"(out), "r"(fa), "r"(fb), "r"(da), "r"(db), "r"(fi)
        : "eax", "ebx", "edx", "memory",
          "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
          "xmm8","xmm9","xmm10","xmm11","xmm12");
    (void)sys3(1, 1, (long)out, 416);
    (void)sys3(60, 0, 0, 0);
    __builtin_unreachable();
}
"#;

fn compile(dir: &Path) -> PathBuf {
    let src = dir.join("sse.c");
    let elf = dir.join("sse");
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
        &[],
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
fn diff_sde_sse() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("clang がない。スキップ");
        return;
    }
    let Some(sde) = sde_path() else {
        eprintln!("sde64 がない。スキップ");
        return;
    };
    let dir = std::env::temp_dir().join(format!("polyisa-sde-sse-{}", std::process::id()));
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
    assert_eq!(out.stdout.len(), 416, "sde stdout len");
    assert_eq!(poly.len(), 416, "poly stdout len");
    if poly != out.stdout {
        let mut bad = Vec::new();
        for i in 0..104 {
            let a = u32::from_le_bytes(poly[i * 4..i * 4 + 4].try_into().unwrap());
            let b = u32::from_le_bytes(out.stdout[i * 4..i * 4 + 4].try_into().unwrap());
            if a != b {
                bad.push(format!("d{} poly={a:08x} sde={b:08x}", i));
            }
        }
        panic!(
            "SSE mismatch ({} words): {}",
            bad.len(),
            bad[..bad.len().min(12)].join(" ")
        );
    }
}
