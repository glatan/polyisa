// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86-64 の xsave 系と AMX 許可、vsyscall を使うテストプログラム
//! （層7・program、ロードマップ S13-7、E4 の先）。
//!
//! 検証コンテナの clang（TOOL-CLANG）で `-nostdlib -static` に
//! ビルドし、polyisa の Linux パーソナリティで実行する。内容は
//! CPUID leaf D（xsave 領域サイズ）、arch_prctl の XCOMP 系
//! （SUPP/PERM/REQ）、XGETBV、XSAVE/XRSTOR の退避往復、
//! AMX タイル演算（許可取得後の TDPBSSD）、vsyscall ページ経由の
//! gettimeofday/time/getcpu で、出力をピンする。

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

static void puts_(const char *s, long n) { sys3(1, 1, (long)s, n); }

static void pnum(u64 v) {
    char b[24];
    int i = 24;
    if (v == 0) { puts_("0", 1); return; }
    while (v) { b[--i] = '0' + (v % 10); v /= 10; }
    puts_(&b[i], 24 - i);
}

static void phex(u64 v) {
    char b[20];
    int i = 20;
    if (v == 0) { b[--i] = '0'; }
    while (v) { int d = v & 15; b[--i] = d < 10 ? '0'+d : 'a'+d-10; v >>= 4; }
    b[--i] = 'x'; b[--i] = '0';
    puts_(&b[i], 20 - i);
}

static void lit(const char *s) { long n = 0; while (s[n]) n++; puts_(s, n); }

__attribute__((aligned(64))) static u8 xsave_area[4096];

struct timeval_x { u64 sec, usec; };

void _start(void) {
    lit("x86ext\n");
    // CPUID leaf D subleaf 0（xsave 領域サイズ）。
    {
        u32 a, b_, c, d;
        asm volatile("cpuid" : "=a"(a), "=b"(b_), "=c"(c), "=d"(d)
            : "a"(0xD), "c"(0) : "memory");
        lit("cpuidD ebx="); pnum(b_); lit(" ecx="); pnum(c); lit("\n");
    }
    // arch_prctl XCOMP。supp / perm。
    u64 supp = 0, perm = 0, r;
    r = sys3(158, 0x1021, (long)&supp, 0); // ARCH_GET_XCOMP_SUPP
    lit("xcomp_supp="); phex(supp); lit(" r="); pnum(r); lit("\n");
    r = sys3(158, 0x1022, (long)&perm, 0); // ARCH_GET_XCOMP_PERM
    lit("xcomp_perm="); phex(perm); lit(" r="); pnum(r); lit("\n");
    // XGETBV: XTILE 許可前の XCR0。
    u32 x0 = 0, x1 = 0;
    asm volatile("xgetbv" : "=a"(x0), "=d"(x1) : "c"(0) : "memory");
    lit("xcr0="); phex(x0); lit("\n");
    // XTILECFG(17) → XTILEDATA(18) の許可。
    r = sys3(158, 0x1023, 17, 0);
    lit("req17="); pnum(r); lit("\n");
    r = sys3(158, 0x1023, 18, 0);
    lit("req18="); pnum(r); lit("\n");
    asm volatile("xgetbv" : "=a"(x0), "=d"(x1) : "c"(0) : "memory");
    lit("xcr0_after="); phex(x0); lit("\n");
    // XSAVE/XRSTOR: xmm0 に印を置き、退避→消去→復元で往復。
    {
        u64 pat[2] __attribute__((aligned(16))) =
            {0x1122334455667788UL, 0x99AABBCCDDEEFF00UL};
        u64 out[2] __attribute__((aligned(16))) = {0, 0};
        asm volatile(
            "movdqa (%2), %%xmm0\n\t"
            "xsave64 %0\n\t"
            "pxor %%xmm0, %%xmm0\n\t"
            "xrstor64 %0\n\t"
            "movdqa %%xmm0, (%1)\n\t"
            : "=m"(xsave_area)
            : "r"(out), "r"(pat), "a"(7), "d"(0)
            : "xmm0", "memory");
        lit("xsave_rt=");
        pnum((out[0] == pat[0] && out[1] == pat[1]) ? 1 : 0);
        lit("\n");
    }
    // AMX: LDTILECFG → TILELOADD → TDPBSSD → TILESTORED。
    {
        // palette1: tmm0-2、rows=2・colsb=8。
        static u8 cfg[64] = {0};
        cfg[0] = 1;
        for (int i = 0; i < 3; i++) {
            cfg[16 + i * 2] = 8;   // colsb=8
            cfg[48 + i] = 2;       // rows=2
        }
        static const u8 a[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        // B は 4n+q インタリーブ（単位行列相当）。
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
        // dst[0..3] の dword（期待: 8,10,24,26）。
        lit("amx="); pnum(dst[0]); lit(","); pnum(dst[1]); lit(",");
        pnum(dst[2]); lit(","); pnum(dst[3]); lit("\n");
    }
    // vsyscall ページ: 0xff600000 +0 gettimeofday、+0x400 time、
    // +0x800 getcpu。
    {
        struct timeval_x tv = {0, 0};
        u64 (*gtod)(u64, u64) = (u64 (*)(u64, u64))(u64)0xff600000;
        u64 (*tm)(u64) = (u64 (*)(u64))(u64)0xff600400;
        u64 (*getcpu)(u64, u64, u64) = (u64 (*)(u64, u64, u64))(u64)0xff600800;
        gtod((u64)&tv, 0);
        lit("vsys_gtod="); pnum(tv.sec); lit("\n");
        u64 t = 0;
        tm((u64)&t);
        lit("vsys_time="); pnum(t); lit("\n");
        u64 cpu = 0xFF, node = 0xFF;
        getcpu((u64)&cpu, (u64)&node, 0);
        lit("vsys_cpu="); pnum(cpu); lit(" node="); pnum(node); lit("\n");
    }
    sys3(60, 42, 0, 0);
    __builtin_unreachable();
}
"#;

fn compile(dir: &Path) -> PathBuf {
    let src = dir.join("x86ext.c");
    let elf = dir.join("x86ext");
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
    let b = std::fs::read(&elf).unwrap();
    assert_eq!(b[4], 2, "ELFCLASS64");
    assert_eq!(&b[18..20], &[62, 0], "EM_X86_64");
    elf
}

/// AMX 許可・xsave・vsyscall を使うプログラム。
/// CPU モデルは `x86_64_v4` に `+amx_tile,+amx_int8` を足す。
#[test]
fn x86ext_xsave_amx_vsyscall() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("clang がない。スキップ");
        return;
    }
    let dir = std::env::temp_dir().join(format!("polyisa-x86ext-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf = compile(&dir);
    let bytes = std::fs::read(&elf).unwrap();
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
    let argv: Vec<String> = vec![elf.to_str().unwrap().to_string()];
    let code = polyisa_cli::run_x86::run_image_x86_64_sel(
        &bytes,
        elf.to_str().unwrap(),
        &argv,
        &mut sys,
        Some(&sel),
        None,
    )
    .unwrap_or_else(|e| panic!("run: {e}"));
    let captured_out = captured.borrow().clone();
    let out = String::from_utf8_lossy(&captured_out);
    // x86_64_v4 では AVX-512 成分も初期 XCR0 に入る。CPUID leaf D.0
    // の EBX は有効 XCR0=0xe7 に対応する 2688B、ECX は対応成分全体の
    // 最大 11008B。supp は XTILECFG|XTILEDATA を含む。
    let expect = concat!(
        "x86ext\n",
        "cpuidD ebx=2688 ecx=11008\n",
        "xcomp_supp=0x600e7 r=0\n",
        "xcomp_perm=0xe7 r=0\n",
        "xcr0=0xe7\n",
        "req17=0\n",
        "req18=0\n",
        "xcr0_after=0x600e7\n",
        "xsave_rt=1\n",
        "amx=8,10,24,26\n",
        "vsys_gtod=946688400\n",
        "vsys_time=946688400\n",
        "vsys_cpu=0 node=0\n",
    );
    assert_eq!(out, expect, "stdout");
    assert_eq!(code, 42, "exit code");
}
