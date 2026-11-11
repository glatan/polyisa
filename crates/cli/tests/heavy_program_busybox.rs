// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! BusyBox の一部アプレットの回帰（層7・program）。
//!
//! 対象は、コミットメッセージで exit 0 と記録され、再実行でも exit 0 だったものに限る。
//! `true`、`echo hi`、`uname -a`、`id`。`df` は ADR-0014 により対象外。
//! `sh -c 'echo hi'` は載せない。`_dl_get_origin` がパスの先頭を `/` とみなせず、
//! glibc が exit 127 で止まる。
//! この一覧はロードマップ S4-1 の `busybox --list` 全体ではない。
//!
//! バイナリは BusyBox 1.37.0 の静的リンク x86_64 である。台帳の BIN-DISTRO
//! （1.35.0）では `true` が未実装命令で止まるため、このテストには使わない。
//! リポジトリには含めない。ファイルが無いときは失敗する。

use std::path::PathBuf;

fn busybox() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.join(".testdata/busybox-1.37.0/busybox")
}

#[test]
fn recorded_applets_match_exit_and_output() {
    let path = busybox();
    assert!(
        path.is_file(),
        "BusyBox 1.37.0 の静的 x86_64 を {} に置く。リポジトリには含めない。台帳の BIN-DISTRO 1.35.0 は、この一覧が exit 0 にならない別バイナリである。",
        path.display()
    );
    let path = path.to_str().expect("utf-8 path");
    let cases: &[(&[&str], &[u8])] = &[
        (&["true"], b""),
        (&["echo", "hi"], b"hi\n"),
        (
            &["uname", "-a"],
            b"Linux localhost 6.0.0 #1 x86_64 GNU/Linux\n",
        ),
        (&["id"], b"uid=0(root) gid=0(root) groups=0(root)\n"),
    ];
    for (args, expect) in cases {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (code, out) = polyisa_cli::run_x86::run_elf_x86_64_captured(path, &argv)
            .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
        assert_eq!(code, 0, "{}", args.join(" "));
        assert_eq!(out.as_slice(), *expect, "{}", args.join(" "));
    }
}
