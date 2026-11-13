// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S4-1 の枠。台帳の BIN-DISTRO-I386（BusyBox 1.35.0、静的、i386、musl）で
//! 基本コマンド群を回し、終了コードと標準出力を見る。
//!
//! バイナリはリポジトリに含めない。ファイルが無いときは失敗する。

// Gap: GAP-0022（`--list` の全アプレット網羅は x86_64 版テストに及ばない。
// 対象は実用上の基本コマンドに限る）

use std::path::{Path, PathBuf};

fn busybox() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.join(".testdata/bin-distro-i386/busybox")
}

fn run(path: &Path, args: &[&str]) -> (u64, Vec<u8>) {
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    polyisa_cli::run_x86::run_elf_x86_32_captured(path.to_str().expect("utf-8 path"), &argv)
        .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")))
}

/// i386 musl が通る命令形と旧番号 syscall の固定。出力は仮想環境の値に合わせて pin する。
#[test]
fn basic_commands() {
    let path = busybox();
    assert!(
        path.is_file(),
        "BIN-DISTRO-I386 の BusyBox 1.35.0 を {} に置く。リポジトリには含めない。",
        path.display()
    );
    let pwd_expect = format!("{}\n", std::env::current_dir().expect("cwd").display()).into_bytes();
    let pinned: Vec<(&[&str], Vec<u8>)> = vec![
        (&["echo", "a", "b", "c"], b"a b c\n".to_vec()),
        (&["printf", "abc"], b"abc".to_vec()),
        (&["uname"], b"Linux\n".to_vec()),
        (
            &["uname", "-a"],
            b"Linux localhost 6.0.0 #1 x86_64 GNU/Linux\n".to_vec(),
        ),
        (&["id"], b"uid=0(root) gid=0(root) groups=0(root)\n".to_vec()),
        (&["sh", "-c", "echo shell-ok"], b"shell-ok\n".to_vec()),
        (&["date"], b"Sat Jan  1 01:00:00 UTC 2000\n".to_vec()),
        (&["pwd"], pwd_expect),
        (
            &["wc", "-l", "/proc/self/status"],
            b"7 /proc/self/status\n".to_vec(),
        ),
        (
            &["cat", "/proc/self/status"],
            b"Name:\tinit\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nPPid:\t0\nThreads:\t1\nCpus_allowed:\t1\nCpus_allowed_list:\t0\n"
                .to_vec(),
        ),
    ];
    for (args, expect) in &pinned {
        let (code, out) = run(&path, args);
        assert_eq!(code, 0, "{}", args.join(" "));
        assert_eq!(out.as_slice(), expect.as_slice(), "{}", args.join(" "));
    }
    let (code, _) = run(&path, &["true"]);
    assert_eq!(code, 0);
}

/// `ls` は statx が ENOSYS のとき stat64/getdents64 に退く経路を使う。
/// 一時ディレクトリを作って内容を pin する。
#[test]
fn ls_lists_directory() {
    let path = busybox();
    assert!(path.is_file());
    let dir = std::env::temp_dir().join(format!("polyisa-i386-ls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    std::fs::write(dir.join("a.txt"), b"a").expect("write a.txt");
    std::fs::write(dir.join("b.txt"), b"b").expect("write b.txt");
    let arg = dir.to_str().expect("utf-8 dir").to_string();
    let (code, out) = run(&path, &["ls", &arg]);
    assert_eq!(code, 0);
    assert_eq!(out.as_slice(), b"a.txt\nb.txt\n");
}
