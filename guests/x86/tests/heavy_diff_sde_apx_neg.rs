// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Intel SDE との APX negative case 差分（層: diff、E3）。
//!
//! fault する命令列はプロセスを殺すので、正例のようなレジスタ
//! スナップショット比較はできない。ケースごとに最小の静的 ELF を
//! 作り、polyisa と `sde64 -dmr` の両方で実行し、
//! 終了シグナル（#UD→SIGILL、#GP→SIGSEGV）が一致することを比較する。
//! sde64 または clang がなければスキップする。

use std::path::{Path, PathBuf};
use std::process::Command;

// 各ケースは (名前, rsp を 16 非整列にするか, 命令バイト列)。
// 命令は push2/pop2 の既知エンコーディング（bare_x86run の
// run64_apx_push2pop2_exceptions と同じ）。
const CASES: &[(&str, bool, &[u8])] = &[
    // push2 %rsp,%r12: B が RSP で #UD。
    (
        "push2_rsp_operand_ud",
        false,
        &[0x62, 0xF4, 0x1C, 0x18, 0xFF, 0xF4],
    ),
    // push2 %r12,%rsp: V が RSP で #UD。
    (
        "push2_v_rsp_ud",
        false,
        &[0x62, 0xD4, 0x5C, 0x18, 0xFF, 0xF4],
    ),
    // pop2 %r12,%r12: 同一レジスタで #UD。
    (
        "pop2_duplicate_ud",
        false,
        &[0x62, 0xD4, 0x1C, 0x18, 0x8F, 0xC4],
    ),
    // push2 %r13,%r12 rsp 16 非整列で #GP。
    (
        "push2_misaligned_gp",
        true,
        &[0x62, 0xD4, 0x1C, 0x18, 0xFF, 0xF5],
    ),
];

const SRC_TMPL: &str = r#"typedef unsigned long u64;
static long sys3(long n, long a, long b, long c) {
    long r;
    asm volatile("syscall" : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}
void _start(void) {
    asm volatile(
        "and $-16, %%rsp\n\t"
        "sub $%0, %%rsp\n\t"   // 0 なら 16 整列、8 なら非整列
        "mov $0x1111, %%r12\n\t"
        "mov $0x2222, %%r13\n\t"
        "mov $0x3333, %%rbp\n\t"
        // fault 命令はリンク時にパッチする。ここでは 8 バイトの
        // スペースを NOP で確保する。
        ".byte 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90\n\t"
        ".global fault_insn\n"
        "fault_insn:\n\t"
        ".byte 0x90,0x90,0x90,0x90,0x90,0x90\n\t"
        :
        :
        : "r12", "r13", "memory");
    // fault で死ななければ exit(42)（fault しなかった印）。
    (void)sys3(60, 42, 0, 0);
    __builtin_unreachable();
}
"#;

fn build(dir: &Path, name: &str, misalign: bool, insn: &[u8]) -> PathBuf {
    let src = dir.join(format!("neg_{name}.c"));
    let elf = dir.join(format!("neg_{name}"));
    let sub = if misalign { 8 } else { 0 };
    std::fs::write(&src, SRC_TMPL.replace("%0", &sub.to_string())).unwrap();
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
    // fault_insn シンボルの位置へ命令バイト列をパッチする。
    // .byte で確保した 6 バイトの NOP 列を探す代わりに、nm で
    // シンボル位置を引く。
    let nm = Command::new("sh")
        .arg("-c")
        .arg(format!("nm {} | grep fault_insn", elf.display()))
        .output()
        .expect("nm");
    let out = String::from_utf8_lossy(&nm.stdout);
    let addr = out
        .split_whitespace()
        .next()
        .and_then(|a| u64::from_str_radix(a, 16).ok())
        .unwrap_or_else(|| panic!("nm output: {out}"));
    // ET_EXEC static なので file offset を program header から引く。
    // ここでは readelf ではなく、単純に .text がファイルの先頭近くに
    // ある構造を利用し、objdump ではなくバイナリを走査して
    // NOP 6 連を探すほうが確実。ただし NOP 列は他にもあるため、
    // fault_insn の VMA からオフセットを計算する。
    let mut bytes = std::fs::read(&elf).unwrap();
    // phdr を読んで .text を含むセグメントの vaddr/offset 対応を取る。
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    let mut patched = false;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(bytes[ph..ph + 4].try_into().unwrap());
        if p_type != 1 {
            continue;
        }
        let p_offset = u64::from_le_bytes(bytes[ph + 8..ph + 16].try_into().unwrap());
        let p_vaddr = u64::from_le_bytes(bytes[ph + 16..ph + 24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(bytes[ph + 32..ph + 40].try_into().unwrap());
        if addr >= p_vaddr && addr < p_vaddr + p_filesz {
            let off = (p_offset + (addr - p_vaddr)) as usize;
            bytes[off..off + insn.len()].copy_from_slice(insn);
            patched = true;
            break;
        }
    }
    assert!(patched, "fault_insn のパッチに失敗");
    std::fs::write(&elf, bytes).unwrap();
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

fn poly_run(bytes: &[u8], path: &str) -> Option<u64> {
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
    let argv = vec![path.to_string()];
    polyisa_cli::run_x86::run_image_x86_64_sel(bytes, path, &argv, &mut sys, Some(&sel), None).ok()
}

#[test]
fn diff_sde_apx_negative() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("clang がない。スキップ");
        return;
    }
    let Some(sde) = sde_path() else {
        eprintln!("sde64 がない。スキップ");
        return;
    };
    let dir = std::env::temp_dir().join(format!("polyisa-sde-apxneg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, misalign, insn) in CASES {
        let elf = build(&dir, name, *misalign, insn);
        let bytes = std::fs::read(&elf).unwrap();
        let sde_out = Command::new(&sde)
            .args(["-dmr", "--"])
            .arg(&elf)
            .current_dir(&dir)
            .output()
            .expect("sde64");
        // SDE 側: シグナル死なら status は signal()。unix wait status の
        // 下位 7bit がシグナル番号。exit(42) は fault 不発を意味する。
        use std::os::unix::process::ExitStatusExt as _;
        let sde_sig = sde_out.status.signal();
        let sde_code = sde_out.status.code();
        let poly = poly_run(&bytes, elf.to_str().unwrap());
        eprintln!("{name}: sde signal={sde_sig:?} code={sde_code:?} poly={poly:?}");
        // fault しなければ両方 exit(42)。fault すればシグナルで死ぬ。
        // #UD は SIGILL(4)、#GP は SIGSEGV(11)。polyisa は終了コードに
        // シグナル番号を乗せる。
        assert_ne!(
            poly,
            Some(42),
            "{name}: polyisa が fault せず exit(42) で抜けた"
        );
        let expect_sig = if name.ends_with("_ud") { 4 } else { 11 };
        // SDE はゲストのシグナル死を自プロセスの exit code
        // 128+signo で報告する。ただし PUSH2 の整列 #GP は、SDE が
        // エミュレーション上の致命診断（"#GP PUSH2: RSP must be 16
        // bytes aligned" を stderr に出して exit 1）として扱う。
        // 診断文はアーキテクチャの要件そのものなので、polyisa の #GP
        // （SIGSEGV 配送）と意味的に同じ fault として突き合わせる。
        let _ = sde_sig;
        if *name == "push2_misaligned_gp" {
            let stderr = String::from_utf8_lossy(&sde_out.stderr);
            assert_eq!(sde_code, Some(1), "{name}: SDE は診断で exit 1");
            assert!(
                stderr.contains("#GP"),
                "{name}: SDE の診断は #GP を明示するはず: {stderr}"
            );
        } else {
            assert_eq!(
                sde_code,
                Some(128 + expect_sig),
                "{name}: SDE は 128+{expect_sig} で死ぬはず"
            );
        }
        assert_eq!(
            poly,
            Some(expect_sig as u64),
            "{name}: polyisa も同じシグナルで死ぬはず"
        );
    }
}
