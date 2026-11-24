// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S25-1 の枠。`.testdata/bin-distro-unixv7`（Unix V7 の PDP-11
//! ユーザー空間、0407/0410/0411 a.out）の基本コマンド群を V7
//! パーソナリティ上で実行し、終了コードと標準出力を照合する。
//! ホストは PDP-11 コードを直接実行できないためホスト対照は行わ
//! ない。バイナリはリポジトリに含めない。ファイルが無いときは
//! 失敗する。
//!
//! 対象は「単一プロセスで完結し、出力が決定的な」コマンドに限る
//! （`sh`/`fork` は単一プロセス近似の外、`date` は非決定的）。
//! ファイル内容をそのまま返すケース（cat・sort・tail 等）の
//! 期待値はフィクスチャのファイルから導出する。

#![cfg(feature = "guest-pdp11")]

use std::path::PathBuf;

fn v7_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    let p = p.join(".testdata/bin-distro-unixv7");
    assert!(
        p.is_dir(),
        "BIN-DISTRO-UNIXV7 を {} に展開する。リポジトリには含めない。",
        p.display()
    );
    p
}

/// `bin` の実行ファイル（root 内の /bin/`bin`）があればそのパス。
fn bin_path(root: &std::path::Path, bin: &str) -> PathBuf {
    let p = root.join("bin").join(bin);
    assert!(
        p.is_file(),
        "BIN-DISTRO-UNIXV7 の /bin/{bin} が {} に無い。",
        p.display()
    );
    p
}

/// (argv[1..], 標準入力) で `bin` を走らせ、(終了コード, stdout) を返す。
fn run_in(bin: &str, args: &[&str], input: &[u8]) -> (u64, Vec<u8>) {
    let root = v7_root();
    // sort が使うテンポラリディレクトリ（V7 の dirtry は
    // /usr/tmp → /tmp の順に試す）。
    let _ = std::fs::create_dir_all(root.join("tmp"));
    let path = bin_path(&root, bin);
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    polyisa_cli::run_pdp11::run_aout_v7_captured_in(
        path.to_str().unwrap(),
        &argv,
        root.to_str().unwrap(),
        input,
    )
    .unwrap_or_else(|e| panic!("/bin/{bin} {}: {e}", args.join(" ")))
}

fn run(bin: &str, args: &[&str]) -> (u64, Vec<u8>) {
    run_in(bin, args, b"")
}

/// (argv[1..], 期待終了コード, 期待標準出力) の行。
type Case<'a> = (&'a str, &'a [&'a str], u64, &'a [u8]);

#[test]
fn basic_commands_match_pinned() {
    // cal 1 1980 の整形はレイアウト込みで固定。
    let cal = b"   January 1980\n S  M Tu  W Th  F  S\n       1  2  3  4  5\n 6  7  8  9 10 11 12\n13 14 15 16 17 18 19\n20 21 22 23 24 25 26\n27 28 29 30 31\n\n";
    let pinned: &[Case] = &[
        ("echo", &["hi", "there"], 0, b"hi there\n"),
        ("echo", &["-n", "hi"], 0, b"hi"),
        ("expr", &["2", "+", "3"], 0, b"5\n"),
        ("basename", &["/a/b/c.txt", ".txt"], 0, b"c\n"),
        ("pwd", &[], 0, b"/\n"),
        ("ls", &["/etc/passwd"], 0, b"/etc/passwd\n"),
        ("cal", &["1", "1980"], 0, cal),
        // マッチしない grep は終了コード 1・出力なし。
        ("grep", &["nomatch", "/etc/passwd"], 1, b""),
        // V7 の cat は open 失敗を stderr に出すだけで exit 0。
        ("cat", &["/nonexistent"], 0, b""),
        ("tail", &["/nonexistent"], 1, b""),
        // exec 経路: nice はプロセス内で差し替え、time は
        // fork(EAGAIN)→exece の順で子処理を済ませる。sh の
        // 単一コマンド -c も fork せず exec だけで走る。
        ("nice", &["-5", "/bin/echo", "exec_ok"], 0, b"exec_ok\n"),
        ("time", &["/bin/echo", "t_ok"], 0, b"t_ok\n"),
        ("sh", &["-c", "/bin/echo sh_ok"], 0, b"sh_ok\n"),
        ("sh", &["-c", "echo builtin_ok"], 0, b"builtin_ok\n"),
    ];
    for (bin, args, want_code, want_out) in pinned {
        let (code, out) = run(bin, args);
        assert_eq!(code, *want_code, "{bin} {}", args.join(" "));
        assert_eq!(out.as_slice(), *want_out, "{bin} {}", args.join(" "));
    }
}

/// /etc/passwd の内容を返す系はフィクスチャから期待値を導出する。
#[test]
fn file_content_commands_match() {
    let passwd = std::fs::read(v7_root().join("etc/passwd")).unwrap();
    let lines: Vec<&[u8]> = passwd.split(|&b| b == b'\n').collect();
    // 末尾の空要素（最終 \n の後ろ）を落とした行集合。
    let body: Vec<&[u8]> = lines[..lines.len() - 1].to_vec();

    // cat は内容そのまま。
    let (code, out) = run("cat", &["/etc/passwd"]);
    assert_eq!(code, 0);
    assert_eq!(out, passwd);

    // grep root /etc/passwd —— "root" を含む行だけ。
    let mut want = Vec::new();
    for l in &body {
        if l.windows(4).any(|w| w == b"root") {
            want.extend_from_slice(l);
            want.push(b'\n');
        }
    }
    let (code, out) = run("grep", &["root", "/etc/passwd"]);
    assert_eq!(code, 0);
    assert_eq!(out, want);

    // tail -2 は末尾 2 行。
    let mut want = Vec::new();
    for l in &body[body.len() - 2..] {
        want.extend_from_slice(l);
        want.push(b'\n');
    }
    let (code, out) = run("tail", &["-2", "/etc/passwd"]);
    assert_eq!(code, 0);
    assert_eq!(out, want);

    // sort は行の辞書順（-r は逆順）。
    let mut sorted = body.clone();
    sorted.sort();
    let mut want = Vec::new();
    for l in &sorted {
        want.extend_from_slice(l);
        want.push(b'\n');
    }
    let (code, out) = run("sort", &["/etc/passwd"]);
    assert_eq!(code, 0);
    assert_eq!(out, want);
    sorted.reverse();
    let mut want = Vec::new();
    for l in &sorted {
        want.extend_from_slice(l);
        want.push(b'\n');
    }
    let (code, out) = run("sort", &["-r", "/etc/passwd"]);
    assert_eq!(code, 0);
    assert_eq!(out, want);

    // wc —— 行・語・バイトを "%7ld%7ld %7ld" で揃えて出す。
    let nw = passwd
        .split(|&b| b == b' ' || b == b'\n' || b == b'\t')
        .filter(|w| !w.is_empty())
        .count();
    let nl = body.len();
    let want = format!("{nl:7}{nw:7} {:7} /etc/passwd\n", passwd.len()).into_bytes();
    let (code, out) = run("wc", &["/etc/passwd"]);
    assert_eq!(code, 0);
    assert_eq!(out, want);
}

/// 標準入力を読むコマンド（`sys.io.stdin` 供給）。
#[test]
fn stdin_commands_match_pinned() {
    type Case<'a> = (&'a str, &'a [&'a str], &'a [u8], u64, &'a [u8]);
    let cases: &[Case] = &[
        ("cat", &[], b"abc\n", 0, b"abc\n"),
        ("wc", &[], b"a b\nc\n", 0, b"      2      3       6\n"),
        ("tr", &["a-z", "A-Z"], b"abc z\n", 0, b"ABC Z\n"),
        ("uniq", &[], b"p\np\nq\n", 0, b"p\nq\n"),
        ("tail", &["-1"], b"x\ny\nz\n", 0, b"z\n"),
    ];
    for (bin, args, input, want_code, want_out) in cases {
        let (code, out) = run_in(bin, args, input);
        assert_eq!(code, *want_code, "{bin} {}", args.join(" "));
        assert_eq!(out.as_slice(), *want_out, "{bin} {}", args.join(" "));
    }
}
