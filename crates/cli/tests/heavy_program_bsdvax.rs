// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S25-2 の枠。`.testdata/bin-distro-bsd43reno`（4.3BSD-Reno の
//! VAX ユーザー空間、0413 ZMAGIC a.out）の基本コマンド群を BSD
//! パーソナリティ上で実行し、終了コードと標準出力を照合する。
//! ホストは VAX コードを直接実行できないためホスト対照は行わ
//! ない。バイナリはリポジトリに含めない。ファイルが無いときは
//! 失敗する。
//!
//! 対象は「単一プロセスで完結し、出力が決定的な」コマンドに限る
//! （`sh`/`fork` は単一プロセス近似の外、`date` は非決定的、
//! `ls <dir>` は readdir の順序に依存する）。ファイル内容をその
//! まま返すケース（cat・grep 等）の期待値はフィクスチャの
//! ファイルから導出する。

#![cfg(feature = "guest-vax")]

use std::path::PathBuf;

fn bsd_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    let p = p.join(".testdata/bin-distro-bsd43reno");
    assert!(
        p.is_dir(),
        "BIN-DISTRO-BSD43RENO を {} に展開する。リポジトリには含めない。",
        p.display()
    );
    p
}

/// root 内の実行ファイル。`bin` は "/bin/cat" のようなゲスト絶対パス。
fn bin_path(root: &std::path::Path, gpath: &str) -> PathBuf {
    let p = root.join(gpath.trim_start_matches('/'));
    assert!(
        p.is_file(),
        "BIN-DISTRO-BSD43RENO の {gpath} が {} に無い。",
        p.display()
    );
    p
}

/// (argv[1..], 標準入力) でゲストバイナリを走らせ、
/// (終了コード, stdout) を返す。
fn run_in(gpath: &str, args: &[&str], input: &[u8]) -> (u64, Vec<u8>) {
    let root = bsd_root();
    let path = bin_path(&root, gpath);
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    polyisa_cli::run_vax::run_aout_bsd_captured_in(
        path.to_str().unwrap(),
        &argv,
        root.to_str().unwrap(),
        input,
    )
    .unwrap_or_else(|e| panic!("{gpath} {}: {e}", args.join(" ")))
}

fn run(gpath: &str, args: &[&str]) -> (u64, Vec<u8>) {
    run_in(gpath, args, b"")
}

/// (ゲストパス, argv[1..], 期待終了コード, 期待標準出力) の行。
type Case<'a> = (&'a str, &'a [&'a str], u64, &'a [u8]);

#[test]
fn basic_commands_match_pinned() {
    // cal 1 1980 の整形はレイアウト込みで固定。
    let cal = b"    January 1980\n S  M  Tu W  Th F  S\n       1  2  3  4  5\n 6  7  8  9 10 11 12\n13 14 15 16 17 18 19\n20 21 22 23 24 25 26\n27 28 29 30 31\n\n";
    // BSD wc は %8d 3 連の幅で出す（fixture 由来の決定的値）。
    let wc_motd = b"       4      17      79 /etc/motd\n";
    let pinned: &[Case] = &[
        ("/bin/echo", &["hi", "there"], 0, b"hi there\n"),
        ("/bin/expr", &["2", "+", "3"], 0, b"5\n"),
        ("/bin/hostname", &[], 0, b"vax780\n"),
        ("/bin/pwd", &[], 0, b"/\n"),
        ("/usr/bin/basename", &["/a/b/c.txt", ".txt"], 0, b"c\n"),
        ("/bin/ls", &["/etc/motd"], 0, b"/etc/motd\n"),
        ("/usr/bin/wc", &["/etc/motd"], 0, wc_motd),
        ("/usr/bin/cal", &["1", "1980"], 0, cal),
        // マッチしない grep は終了コード 1・出力なし。
        ("/usr/bin/grep", &["nomatch", "/etc/passwd"], 1, b""),
        // exec 経路: nice は getpriority のあとプロセス内で
        // 差し替える。
        ("/usr/bin/nice", &["-5", "/bin/echo", "n_ok"], 0, b"n_ok\n"),
    ];
    for (bin, args, want_code, want_out) in pinned {
        let (code, out) = run(bin, args);
        assert_eq!(code, *want_code, "{bin} {}", args.join(" "));
        assert_eq!(out.as_slice(), *want_out, "{bin} {}", args.join(" "));
    }
}

/// ファイル内容を返す系はフィクスチャから期待値を導出する。
#[test]
fn file_content_commands_match() {
    let root = bsd_root();
    let motd = std::fs::read(root.join("etc/motd")).unwrap();
    let passwd = std::fs::read(root.join("etc/passwd")).unwrap();

    // cat は内容そのまま。
    let (code, out) = run("/bin/cat", &["/etc/motd"]);
    assert_eq!(code, 0);
    assert_eq!(out, motd);

    // grep root /etc/passwd —— "root" を含む行だけ。
    let mut want = Vec::new();
    for l in passwd.split(|&b| b == b'\n') {
        if l.windows(4).any(|w| w == b"root") {
            want.extend_from_slice(l);
            want.push(b'\n');
        }
    }
    let (code, out) = run("/usr/bin/grep", &["root", "/etc/passwd"]);
    assert_eq!(code, 0);
    assert_eq!(out, want);

    // ed は対話コマンドを stdin から読む: `1,$p` で全文、
    // `q` で終了。先頭は ed が出すファイルサイズ（79）。
    let input = b"1,$p\nq\n";
    let mut want = b"79\n".to_vec();
    want.extend_from_slice(&motd);
    let (code, out) = run_in("/bin/ed", &["/etc/motd"], input);
    assert_eq!(code, 0);
    assert_eq!(out, want);
}
