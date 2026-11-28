// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Intel SDE との APX 正例実行差分（層: diff、E3）。
//!
//! coverage 監査で diff 証拠ゼロだった APX の正例経路（ccmp/ctest の
//! dfv 意味、push2/pop2/push2p/pop2p の往復、NF 指定の旗不変）を
//! `sde64 -dmr` と比較する。命令バイト列は bare_x86run の run64_apx
//! で検証済みのものを .byte で埋め込む（clang は APX mnemonic を
//! 知らない）。sde64 または clang がなければスキップする。

use std::path::{Path, PathBuf};
use std::process::Command;

const SRC: &str = r#"
typedef unsigned long u64;

static long sys3(long n, long a, long b, long c) {
    long r;
    asm volatile("syscall" : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

static u64 out[32] __attribute__((aligned(16)));

void _start(void) {
    asm volatile(
        "mov %0, %%rdi\n\t"
        "and $-16, %%rsp\n\t"

        // r25=1、r26=2（REX2 not/neg/inc の既知列）。
        ".byte 0xD5,0x19,0xF7,0xD1\n\t"   // notq %r25 → -1
        ".byte 0xD5,0x19,0xF7,0xD9\n\t"   // negq %r25 → 1
        ".byte 0xD5,0x19,0xF7,0xD2\n\t"   // notq %r26 → -1
        ".byte 0xD5,0x19,0xF7,0xDA\n\t"   // negq %r26 → 1
        ".byte 0xD5,0x19,0xFF,0xC2\n\t"   // incq %r26 → 2

        // ccmpf {dfv=zf} r25,r26: 条件偽 → 比較せず dfv の zf だけ立つ。
        "xor %%eax, %%eax\n\t"            // ZF=1 CF=0 SF=0 OF=0
        "cmp $1, %%eax\n\t"               // ZF=0 SF=1 CF=1（事前の旗を汚す）
        ".byte 0x62,0x4C,0x14,0x0B,0x39,0xD1\n\t"
        "pushfq\n\t"
        "pop %%rax\n\t"
        "mov %%rax, 0(%%rdi)\n\t"

        // ccmpt {dfv=zf} r25,r26: 条件真 → 1-2 を普通に比較。
        ".byte 0x62,0x4C,0x14,0x0A,0x39,0xD1\n\t"
        "pushfq\n\t"
        "pop %%rax\n\t"
        "mov %%rax, 8(%%rdi)\n\t"

        // ctestf {dfv=cf} r25,2: 偽 → dfv の cf のみ。
        "xor %%eax, %%eax\n\t"
        ".byte 0x62,0x4C,0x0C,0x0B,0xF7,0xC1,0x02,0x00,0x00,0x00\n\t"
        "pushfq\n\t"
        "pop %%rax\n\t"
        "mov %%rax, 16(%%rdi)\n\t"

        // ctestt {dfv=cf} r25,2: 真 → 1&2=0 の TEST。
        ".byte 0x62,0x4C,0x0C,0x0A,0xF7,0xC1,0x02,0x00,0x00,0x00\n\t"
        "pushfq\n\t"
        "pop %%rax\n\t"
        "mov %%rax, 24(%%rdi)\n\t"

        // NF: xor で ZF=1 にし、sub.nf では旗が不変のはず。
        "xor %%eax, %%eax\n\t"            // ZF=1
        ".byte 0x62,0x4C,0x3C,0x14,0x29,0xD1\n\t"  // sub.nf r24,r25,r26
        "pushfq\n\t"
        "pop %%rax\n\t"
        "mov %%rax, 32(%%rdi)\n\t"

        // push2/pop2 往復: r12=0x1111, r13=0x2222。
        "mov $0x1111, %%r12\n\t"
        "mov $0x2222, %%r13\n\t"
        ".byte 0x62,0xD4,0x1C,0x18,0xFF,0xF5\n\t"  // push2 %r13,%r12
        "mov $0, %%r12\n\t"
        "mov $0, %%r13\n\t"
        ".byte 0x62,0x54,0x14,0x18,0x8F,0xC4\n\t"  // pop2 %r12,%r13
        "mov %%r12, 40(%%rdi)\n\t"
        "mov %%r13, 48(%%rdi)\n\t"
        "mov %%rsp, 56(%%rdi)\n\t"

        // push2p/pop2p 往復（役割交換）。
        "mov $0x3333, %%r12\n\t"
        "mov $0x4444, %%r13\n\t"
        ".byte 0x62,0xD4,0x9C,0x18,0xFF,0xF5\n\t"  // push2p %r13,%r12
        "mov $0, %%r12\n\t"
        "mov $0, %%r13\n\t"
        ".byte 0x62,0x54,0x94,0x18,0x8F,0xC4\n\t"  // pop2p %r12,%r13
        "mov %%r12, 64(%%rdi)\n\t"
        "mov %%r13, 72(%%rdi)\n\t"
        "mov %%rsp, 80(%%rdi)\n\t"
        :
        : "r"(out)
        : "rax", "rdi", "r12", "r13", "memory");
    (void)sys3(1, 1, (long)out, 88);
    (void)sys3(60, 0, 0, 0);
    __builtin_unreachable();
}
"#;

fn compile(dir: &Path) -> PathBuf {
    let src = dir.join("apx.c");
    let elf = dir.join("apx");
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

fn poly_run(bytes: &[u8], path: &str) -> (Vec<u8>, Option<u64>) {
    let sel = polyisa_isadl::select::resolve(
        polyisa_guest_x86::MODEL_DEFS,
        polyisa_guest_x86::FEATURE_DEFS,
        polyisa_guest_x86::FEAT_BITS,
        "x86_64_v4",
        &["apx"],
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
fn diff_sde_apx() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("clang がない。スキップ");
        return;
    }
    let Some(sde) = sde_path() else {
        eprintln!("sde64 がない。スキップ");
        return;
    };
    let dir = std::env::temp_dir().join(format!("polyisa-sde-apx-{}", std::process::id()));
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
    let (poly, code) = poly_run(&bytes, elf.to_str().unwrap());
    assert_eq!(code, Some(0), "poly exit");
    assert_eq!(out.stdout.len(), 88, "sde stdout len");
    assert_eq!(poly.len(), 88, "poly stdout len");
    // q7/q10 は rsp のスナップショットで、生のスタックアドレスは
    // 環境依存なので比較できない（整列と往復の対称性は命令側で
    // 保証される）。両側を 0 にマスクしてから比較する。
    let mut poly = poly;
    let mut sde_out = out.stdout.clone();
    for i in [7usize, 10] {
        poly[i * 8..i * 8 + 8].fill(0);
        sde_out[i * 8..i * 8 + 8].fill(0);
    }
    if poly != sde_out {
        let mut bad = Vec::new();
        for i in 0..11 {
            let a = u64::from_le_bytes(poly[i * 8..i * 8 + 8].try_into().unwrap());
            let b = u64::from_le_bytes(sde_out[i * 8..i * 8 + 8].try_into().unwrap());
            if a != b {
                bad.push(format!("q{} poly={a:016x} sde={b:016x}", i));
            }
        }
        panic!(
            "APX mismatch ({} qwords): {}",
            bad.len(),
            bad[..bad.len().min(11)].join(" ")
        );
    }
}
