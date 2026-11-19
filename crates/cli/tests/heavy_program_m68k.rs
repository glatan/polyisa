// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S14-E2 の枠。`.testdata/bin-distro-m68k/busybox`
//! （Debian-ports の busybox-static 1.38、68020 向け静的リンク）の
//! 基本コマンド群をゲスト側で実行し、終了コードと標準出力を固定値と
//! 照合する。ホストは m68k ELF を直接実行できないため、ホスト対照は
//! 行わない。バイナリはリポジトリに含めない。ファイルが無いときは
//! 失敗する。
//!
//! 対象は「出力が決定的で、カーネル例外配送・FPU 算術を踏まない」
//! アプレットに限る。現状の既知の外れ値:
//! - 実機例外（divz・illegal・未補完の Line-F）の配送は SSP/ベクタ
//!   表をカーネルが持つ前提で、ユーザランド実行では Unimplemented
//!   に落ちる（od が該当）。
//! - FPU の補完は fmovem.x/fmovem.l/fmove.x の転送のみで、算術命令は
//!   対象外（seq が該当）。
//! - dirfd 相対のパス解決は未対応（statx の非空 path + 実 dirfd 等）。

use std::path::PathBuf;

fn busybox() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    let p = p.join(".testdata/bin-distro-m68k/busybox");
    assert!(
        p.is_file(),
        "BIN-DISTRO-M68K の busybox-static を {} に置く。リポジトリには含めない。",
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
    polyisa_cli::run_m68k::run_elf_m68k_captured(path, &argv)
        .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")))
}

#[test]
fn basic_commands_match_pinned() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let pinned: &[Case] = &[
        (&["true"], 0, b""),
        (&["false"], 1, b""),
        (&["echo", "hi"], 0, b"hi\n"),
        (&["echo", "-n", "hi"], 0, b"hi"),
        (&["printf", "x%d\n", "42"], 0, b"x42\n"),
        (&["uname", "-m"], 0, b"m68k\n"),
        (&["arch"], 0, b"m68k\n"),
        (&["basename", "/a/b.c"], 0, b"b.c\n"),
        (&["dirname", "/a/b"], 0, b"/a\n"),
        (&["expr", "2", "+", "3"], 0, b"5\n"),
        (&["hostname"], 0, b"polyisa\n"),
        (&["env"], 0, b""),
        (&["test", "-n", "x"], 0, b""),
        (&["test", "-z", "x"], 1, b""),
        (&["ls", "/dev/null"], 0, b"/dev/null\n"),
        (&["find", "/dev/null"], 0, b"/dev/null\n"),
        (&["head", "-c", "0", "/dev/null"], 0, b""),
        (&["sort", "/dev/null"], 0, b""),
        (&["wc", "-c", "/dev/null"], 0, b"0 /dev/null\n"),
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
    ];
    for (args, want_code, want_out) in pinned {
        let (code, out) = run(path, args);
        assert_eq!(code, *want_code, "{}", args.join(" "));
        assert_eq!(out.as_slice(), *want_out, "{}", args.join(" "));
    }
}

#[test]
fn stdin_commands_match_pinned() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let cases: &[CaseIn] = &[
        (&["wc", "-c"], b"hello", 0, b"5\n"),
        (&["cat"], b"abc\n", 0, b"abc\n"),
        (&["head", "-n", "2"], b"a\nb\nc\n", 0, b"a\nb\n"),
        (&["sort"], b"b\na\n", 0, b"a\nb\n"),
    ];
    for (args, input, want_code, want_out) in cases {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_m68k::run_elf_m68k_captured_in(path, &argv, input)
            .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
        assert_eq!(code, *want_code, "{}", args.join(" "));
        assert_eq!(out.as_slice(), *want_out, "{}", args.join(" "));
    }
}

#[test]
fn guest_reads_host_files() {
    let path = busybox();
    let path = path.to_str().expect("utf-8 path");
    let dir = std::env::temp_dir().join(format!("polyisa-m68k-{}", std::process::id()));
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
