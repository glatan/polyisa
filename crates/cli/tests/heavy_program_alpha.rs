// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S16-1 の枠。Alpha の ELF が `call_pal callsys` の Linux ABI で
//! 正しい出力を返す（層7・program）。
//!
//! LLVM は Alpha バックエンドを持たないので裸プログラムの
//! コンパイル経路は無く、配布物の BusyBox を走らせて終了コードと
//! 標準出力を固定値と照合する。
//!
//! 配布物は台帳 BIN-DISTRO-ALPHA（Debian-ports busybox-static、
//! 静的 glibc、LE）。バイナリはリポジトリに含めない。
//!
//! 通る道筋: ELF ロード（EM_ALPHA_EXP）・初期スタック・
//! `call_pal 0x83` の syscall ABI・rduniq/wruniq の TLS・
//! 8KiB ゲストページと 4KiB 裏ページ・getdents/stat/stat64・
//! 存在しないパスの ENOENT 返却を通る。
//!
//! 既知の外れ値:
//! - getdents64 は `.`/`..` を合成しない（GAP-0046）。
//!   `ls -a` のピン留め出力はドットエントリを含まない。
//! - 解釈実行なので対象は小さい入力に絞る。

use std::path::{Path, PathBuf};

use polyisa_cli::run_alpha::{run_elf_alpha_captured, run_elf_alpha_captured_in};

fn busybox(dir: &str, bin: &str) -> PathBuf {
    let real = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.testdata")
        .join(dir);
    let real = real.join(bin);
    assert!(real.is_file(), "{dir}/{bin} を {} に置く", real.display());
    real
}

fn run(path: &str, args: &[&str]) -> (u64, Vec<u8>) {
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    run_elf_alpha_captured(path, &argv).unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")))
}

/// (argv, 期待終了コード, 期待標準出力) の行。
type Case<'a> = (&'a [&'a str], u64, &'a [u8]);

fn pinned(path: &Path, cases: &[Case]) {
    let path = path.to_str().expect("utf-8 path");
    for (args, code, out) in cases {
        let (got_code, got_out) = run(path, args);
        assert_eq!(got_code, *code, "{}: 終了コード", args.join(" "));
        assert_eq!(
            got_out,
            *out,
            "{}: 標準出力 {:?}",
            args.join(" "),
            String::from_utf8_lossy(&got_out)
        );
    }
}

/// 台帳 BIN-DISTRO-ALPHA（Debian-ports busybox-static、静的 glibc、LE）。
/// `call_pal 0x83` ABI・rduniq/wruniq・8KiB ゲストページ・Alpha 独自の
/// errno/フラグ値・stat/stat64/statfs64 レイアウトを通る。
#[test]
fn alpha_distro_commands_static() {
    let bb = busybox("bin-distro-alpha", "busybox");
    let cases: Vec<Case> = vec![
        (&["true"], 0, b""),
        (&["false"], 1, b""),
        (&["echo", "hi"], 0, b"hi\n"),
        (&["echo", "-n", "hi"], 0, b"hi"),
        (&["printf", "x%d\n", "42"], 0, b"x42\n"),
        (
            &["uname", "-a"],
            0,
            b"Linux polyisa 7.3.0 #1 polyisa alpha GNU/Linux\n",
        ),
        (&["uname", "-m"], 0, b"alpha\n"),
        (&["hostname"], 0, b"polyisa\n"),
        (&["basename", "/a/b.c"], 0, b"b.c\n"),
        (&["dirname", "/a/b"], 0, b"/a\n"),
        (&["expr", "2", "+", "3"], 0, b"5\n"),
        (&["id"], 0, b"uid=0(root) gid=0(root)\n"),
        (&["whoami"], 0, b"root\n"),
        (&["env"], 0, b""),
        (&["tty"], 1, b"not a tty\n"),
        (&["test", "-n", "x"], 0, b""),
        (&["test", "-z", "x"], 1, b""),
        (&["find", "/dev/null"], 0, b"/dev/null\n"),
        (&["head", "-c", "0", "/dev/null"], 0, b""),
        (&["sort", "/dev/null"], 0, b""),
        (&["sleep", "0"], 0, b""),
        (&["wc", "-c", "/dev/null"], 0, b"0 /dev/null\n"),
        (&["ls", "/dev/null"], 0, b"/dev/null\n"),
        // ENOENT の返却（エラーメッセージは標準エラー側）。
        (&["ls", "/nonexistent"], 1, b""),
        (
            &["md5sum", "/dev/null"],
            0,
            b"d41d8cd98f00b204e9800998ecf8427e  /dev/null\n",
        ),
        (
            &["sha1sum", "/dev/null"],
            0,
            b"da39a3ee5e6b4b0d3255bfef95601890afd80709  /dev/null\n",
        ),
    ];
    pinned(&bb, &cases);
}

/// getdents64 の fd ごとの走査位置とソート出力を固定値と照合する。
/// `.`/`..` は合成しない（GAP-0046）ので `ls -a` も `a\nb\n` になる。
#[test]
fn alpha_ls_options_and_dents() {
    let dir = std::env::temp_dir().join("polyisa-heavy-alpha-ls");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a"), b"").unwrap();
    std::fs::write(dir.join("b"), b"").unwrap();
    let bb = busybox("bin-distro-alpha", "busybox");
    let bb = bb.to_str().unwrap();
    let d = dir.to_str().unwrap();
    for (args, out) in [
        (vec!["ls", "-1", d], b"a\nb\n".to_vec()),
        (vec!["ls", "-a", d], b"a\nb\n".to_vec()),
    ] {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, got) =
            run_elf_alpha_captured(bb, &argv).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        assert_eq!(code, 0, "{args:?}");
        assert_eq!(got, out, "{args:?}");
    }
    // -l はサイズ 0 の空ファイルが total 0 の行を出す。inode や
    // 日付は環境で揺れるので先頭行だけ固定する。
    let argv: Vec<String> = ["ls", "-l", d].iter().map(|s| (*s).to_string()).collect();
    let (code, got) = run_elf_alpha_captured(bb, &argv).unwrap();
    assert_eq!(code, 0);
    assert!(
        got.starts_with(b"total 0\n"),
        "ls -l の先頭行: {:?}",
        String::from_utf8_lossy(&got)
    );
}

/// 標準入力経由の読み取り。`wc -l` は改行の数を数える。
#[test]
fn alpha_stdin_commands_match() {
    let bb = busybox("bin-distro-alpha", "busybox");
    let bb = bb.to_str().unwrap();
    let argv: Vec<String> = ["wc", "-l"].iter().map(|s| (*s).to_string()).collect();
    let (code, out) = run_elf_alpha_captured_in(bb, &argv, b"a\nb\nc\n").unwrap();
    assert_eq!(code, 0);
    assert_eq!(out, b"3\n", "wc -l stdin");
}
