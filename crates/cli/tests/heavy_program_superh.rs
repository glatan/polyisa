// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S18-E の枠。`.testdata/bin-distro-sh4/busybox`（Debian-ports の
//! busybox-static 1.38、SH-4 リトルエンディアン・静的リンク glibc）
//! と `.testdata/bin-distro-sh4eb/busybox`（自前ビルド、SH-4A
//! ビッグエンディアン・静的リンク musl）の基本コマンド群をゲスト側で
//! 実行し、終了コードと標準出力を固定値と照合する。ホストは SH の
//! ELF を直接実行できないため、ホスト対照は行わない。バイナリは
//! リポジトリに含めない。ファイルが無いときは失敗する。
//!
//! 対象は「出力が決定的で、カーネル例外配送・スレッドを踏まない」
//! アプレットに限る。現状の既知の外れ値:
//! - `sh`/`ash` は fork/clone が ENOSYS のため `-c` の子シェル実行が
//!   走らない（GAP-0060）。
//! - `uname -m` は合成 utsname の固定値 "sh4" を出す。
//! - BE 側は musl で LE 側は glibc のため、エラーメッセージ文面や
//!   `ls` の並びなど libc 依存の部分はケースに含めない。

use std::path::{Path, PathBuf};

fn busybox_le() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    let p = p.join(".testdata/bin-distro-sh4/busybox");
    assert!(
        p.is_file(),
        "BIN-DISTRO-SH4 の busybox-static を {} に置く。リポジトリには含めない。",
        p.display()
    );
    p
}

fn busybox_be() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    let p = p.join(".testdata/bin-distro-sh4eb/busybox");
    assert!(
        p.is_file(),
        "BIN-DISTRO-SH4EB の busybox を {} に置く。リポジトリには含めない。",
        p.display()
    );
    p
}

/// (argv, 期待終了コード, 期待標準出力) の行。
type Case<'a> = (&'a [&'a str], u64, &'a [u8]);

/// (argv, 標準入力, 期待終了コード, 期待標準出力) の行。
type CaseIn<'a> = (&'a [&'a str], &'a [u8], u64, &'a [u8]);

fn run(path: &str, args: &[&str]) -> (u64, Vec<u8>) {
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    polyisa_cli::run_superh::run_elf_superh_captured(path, &argv)
        .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")))
}

fn run_in(path: &str, args: &[&str], input: &[u8]) -> (u64, Vec<u8>) {
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    polyisa_cli::run_superh::run_elf_superh_captured_in(path, &argv, input)
        .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")))
}

/// LE/BE 共通の決定的ケース。startup 時の libc 初期化（brk/
/// set_tid_address/set_robust_list/getrandom/readlinkat/mprotect/
/// prctl/clock_gettime64）を両 libc で踏む。
fn common_cases() -> &'static [Case<'static>] {
    &[
        (&["true"], 0, b""),
        (&["false"], 1, b""),
        (&["echo", "hi"], 0, b"hi\n"),
        (&["echo", "-n", "hi"], 0, b"hi"),
        (&["printf", "x%d\n", "42"], 0, b"x42\n"),
        (&["uname", "-s"], 0, b"Linux\n"),
        (&["uname", "-m"], 0, b"sh4\n"),
        (&["uname", "-r"], 0, b"6.1.0-polyisa\n"),
        (&["basename", "/a/b.c"], 0, b"b.c\n"),
        (&["dirname", "/a/b"], 0, b"/a\n"),
        (&["expr", "2", "+", "3"], 0, b"5\n"),
        (&["hostname"], 0, b"polyisa\n"),
        (&["env"], 0, b""),
        (&["id", "-u"], 0, b"0\n"),
        (&["id", "-g"], 0, b"0\n"),
        (&["test", "-n", "x"], 0, b""),
        (&["test", "-z", "x"], 1, b""),
        (&["ls", "/dev/null"], 0, b"/dev/null\n"),
        (&["find", "/dev/null"], 0, b"/dev/null\n"),
        (&["head", "-c", "0", "/dev/null"], 0, b""),
        (&["sort", "/dev/null"], 0, b""),
        (&["wc", "-c", "/dev/null"], 0, b"0 /dev/null\n"),
        // cat は sendfile64 を踏む（入力位置を進める経路の検査）。
        (&["cat", "/dev/null"], 0, b""),
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
        (
            &["date", "-u", "-d", "@0"],
            0,
            b"Thu Jan  1 00:00:00 UTC 1970\n",
        ),
    ]
}

fn common_stdin_cases() -> &'static [CaseIn<'static>] {
    &[
        (&["wc", "-c"], b"hello", 0, b"5\n"),
        (&["cat"], b"abc\n", 0, b"abc\n"),
        (&["head", "-n", "2"], b"a\nb\nc\n", 0, b"a\nb\n"),
        (&["sort"], b"b\na\n", 0, b"a\nb\n"),
    ]
}

fn run_pinned(path: &Path) {
    let path = path.to_str().expect("utf-8 path");
    for (args, want_code, want_out) in common_cases() {
        let (code, out) = run(path, args);
        assert_eq!(code, *want_code, "{}", args.join(" "));
        assert_eq!(out.as_slice(), *want_out, "{}", args.join(" "));
    }
}

fn run_pinned_stdin(path: &Path) {
    let path = path.to_str().expect("utf-8 path");
    for (args, input, want_code, want_out) in common_stdin_cases() {
        let (code, out) = run_in(path, args, input);
        assert_eq!(code, *want_code, "{}", args.join(" "));
        assert_eq!(out.as_slice(), *want_out, "{}", args.join(" "));
    }
}

/// ホストファイルを開く系。openat/read/getdents64/statx/sendfile64
/// （cat）、dirfd 相対解決（ls・fstatat64）、readlink（find）を踏む。
fn run_host_file_cases(path: &Path, tag: &str) {
    let path = path.to_str().expect("utf-8 path");
    // 並列テストが同一プロセス内で動くので tag でディレクトリを分ける。
    let dir = std::env::temp_dir().join(format!("polyisa-superh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"a\nb\nc\n").unwrap();
    let f = file.to_str().unwrap();
    let d = dir.to_str().unwrap();
    let cases: &[Case] = &[
        (&["cat", f], 0, b"a\nb\nc\n"),
        (&["wc", "-l", f], 0, b"3"),
        (&["head", "-n", "1", f], 0, b"a\n"),
        (&["tail", "-n", "1", f], 0, b"c\n"),
        (&["ls", d], 0, b"f\n"),
    ];
    for (args, want_code, want_out) in cases {
        let (code, out) = run(path, args);
        assert_eq!(code, *want_code, "{}", args.join(" "));
        // wc の出力は行数とパスを空白区切りで出すので前方一致で見る。
        if args[0] == "wc" {
            assert!(
                out.starts_with(want_out),
                "{}: {:?} に {:?} が先頭にない",
                args.join(" "),
                out,
                want_out
            );
        } else {
            assert_eq!(out.as_slice(), *want_out, "{}", args.join(" "));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn le_basic_commands_match_pinned() {
    run_pinned(&busybox_le());
}

#[test]
fn le_stdin_commands_match_pinned() {
    run_pinned_stdin(&busybox_le());
}

#[test]
fn le_guest_reads_host_files() {
    run_host_file_cases(&busybox_le(), "le");
}

#[test]
fn be_basic_commands_match_pinned() {
    run_pinned(&busybox_be());
}

#[test]
fn be_stdin_commands_match_pinned() {
    run_pinned_stdin(&busybox_be());
}

#[test]
fn be_guest_reads_host_files() {
    run_host_file_cases(&busybox_be(), "be");
}
