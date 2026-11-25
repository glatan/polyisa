// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S19-1 の判定。`.testdata/bin-distro-loongarch`（Alpine 3.24
//! loongarch64 の動的リンク BusyBox 1.37 と musl ローダ）を
//! ゲストルートとして、基本コマンド群をゲスト側で実行し、
//! 終了コードと標準出力を固定値と照合する。ホストは LoongArch の
//! ELF を直接実行できないため、ホスト対照は行わない。
//! バイナリはリポジトリに含めない。ファイルが無いときは失敗する。
//!
//! 動的リンク ET_DYN + PT_INTERP のロード経路（GAP-0062 の
//! ローダ近似の主たる被験経路）と、musl が要求する LSX の
//! 部分集合（VLD/VST/VREPLGR2VR など）を踏む。対象は
//! 「出力が決定的で、fork/clone・スレッド・ネットワークを
//! 踏まない」アプレットに限る。現状の既知の外れ値:
//! - `sh`/`ash` は clone が ENOSYS のため `-c` が走らない
//! - `uname -m` は合成 utsname の固定値 "loongarch64" を出す。
//!   実機は "loongarch64"（`uname` のマシン名は CONFIG 由来で
//!   同じ綴り）と一致する。

use std::path::PathBuf;

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    let p = p.join(".testdata/bin-distro-loongarch");
    assert!(
        p.join("bin/busybox").is_file() && p.join("lib/ld-musl-loongarch64.so.1").is_file(),
        "BIN-DISTRO-LOONGARCH の Alpine ルートを {} に置く。\
         リポジトリには含めない。",
        p.display()
    );
    p
}

/// (argv, 期待終了コード, 期待標準出力) の行。
type Case<'a> = (&'a [&'a str], u64, &'a [u8]);

/// (argv, 標準入力, 期待終了コード, 期待標準出力) の行。
type CaseIn<'a> = (&'a [&'a str], &'a [u8], u64, &'a [u8]);

fn run(args: &[&str]) -> (u64, Vec<u8>) {
    run_in(args, &[])
}

fn run_in(args: &[&str], input: &[u8]) -> (u64, Vec<u8>) {
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let mut sys = polyisa_os_linux::loongarch::sys::Linux::new();
    sys.stdin_buf = input.to_vec();
    let root = root();
    let code = polyisa_cli::run_loongarch::run_elf_loongarch_sys_root(
        "/bin/busybox",
        &argv,
        None,
        &mut sys,
        Some(root.to_str().expect("utf-8 path")),
    )
    .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
    (code, sys.io.stdout)
}

/// 決定的ケース。startup 時の libc 初期化（brk/set_tid_address/
/// set_robust_list/rseq/getrandom/readlinkat/mprotect/prlimit64/
/// clock_gettime）を踏む。
fn common_cases() -> &'static [Case<'static>] {
    &[
        (&["true"], 0, b""),
        (&["false"], 1, b""),
        (&["echo", "hi"], 0, b"hi\n"),
        (&["echo", "-n", "hi"], 0, b"hi"),
        (&["printf", "x%d\n", "42"], 0, b"x42\n"),
        (&["uname", "-s"], 0, b"Linux\n"),
        (&["uname", "-m"], 0, b"loongarch64\n"),
        (&["basename", "/a/b.c"], 0, b"b.c\n"),
        (&["dirname", "/a/b"], 0, b"/a\n"),
        (&["expr", "2", "+", "3"], 0, b"5\n"),
        (&["test", "-n", "x"], 0, b""),
        (&["test", "-z", "x"], 1, b""),
        (&["ls", "/dev/null"], 0, b"/dev/null\n"),
        (&["wc", "-c", "/dev/null"], 0, b"0 /dev/null\n"),
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

#[test]
fn basic_commands_match_pinned() {
    for (args, want_code, want_out) in common_cases() {
        let (code, out) = run(args);
        assert_eq!(code, *want_code, "{}", args.join(" "));
        assert_eq!(out.as_slice(), *want_out, "{}", args.join(" "));
    }
}

#[test]
fn stdin_commands_match_pinned() {
    for (args, input, want_code, want_out) in common_stdin_cases() {
        let (code, out) = run_in(args, input);
        assert_eq!(code, *want_code, "{}", args.join(" "));
        assert_eq!(out.as_slice(), *want_out, "{}", args.join(" "));
    }
}

/// ゲストルート内のホストファイルを開く系。openat/read/
/// getdents64/statx（stat）、readlink（symlink 解決）を踏む。
/// 並列テストが同一プロセス内で動くのでテスト用の一時
/// ディレクトリを root 配下ではなくホスト側に作る訳ではない
/// — ゲストルート内のパスしか見えないため、root 内に作る。
#[test]
fn guest_reads_files_in_root() {
    let r = root();
    let dir = r
        .join("tmp")
        .join(format!("polyisa-la-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("f");
    std::fs::write(&file, b"a\nb\nc\n").unwrap();
    // ゲストから見えるのはゲスト名空間のパス。
    let gd = format!("/tmp/polyisa-la-{}", std::process::id());
    let gf = format!("{gd}/f");
    let cases: &[Case] = &[
        (&["cat", gf.as_str()], 0, b"a\nb\nc\n"),
        (&["wc", "-l", gf.as_str()], 0, b"3"),
        (&["head", "-n", "1", gf.as_str()], 0, b"a\n"),
        (&["tail", "-n", "1", gf.as_str()], 0, b"c\n"),
        (&["ls", gd.as_str()], 0, b"f\n"),
    ];
    for (args, want_code, want_out) in cases {
        let (code, out) = run(args);
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

/// ゲストルート内の絶対シンボリックリンクは root 内で解決する。
/// 実行パスに `/bin/echo`（→ /bin/busybox への絶対リンク）を
/// 与えると、ローダ側のリンク解決で正しく busybox に辿り着く。
/// またゲストの `readlink -f` もリンクを root 内で正規化する。
#[test]
fn absolute_symlink_stays_in_root() {
    // 実行パスが argv[0] になるので、引数は argv[1:] だけ渡す
    // （`busybox echo x` ではなく `/bin/echo x` の形）。
    let argv: Vec<String> = vec!["link-ok".to_string()];
    let mut sys = polyisa_os_linux::loongarch::sys::Linux::new();
    let r = root();
    let code = polyisa_cli::run_loongarch::run_elf_loongarch_sys_root(
        "/bin/echo",
        &argv,
        None,
        &mut sys,
        Some(r.to_str().expect("utf-8 path")),
    )
    .expect("/bin/echo 経由の実行");
    assert_eq!(code, 0);
    assert_eq!(sys.io.stdout.as_slice(), b"link-ok\n");

    let (code2, out2) = run(&["readlink", "-f", "/bin/echo"]);
    assert_eq!(code2, 0);
    assert_eq!(out2.as_slice(), b"/bin/busybox\n");
}
