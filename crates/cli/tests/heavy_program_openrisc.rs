// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S20-1 の判定。`.testdata/bin-distro-or1k`（or1k 動的リンク
//! musl BusyBox と ld-musl-or1k.so.1、BIN-DISTRO-OR1K）を
//! ゲストルートとして、基本コマンド群をゲスト側で実行し、
//! 終了コードと標準出力を固定値と照合する。ホストは OpenRISC の
//! ELF を直接実行できないため、ホスト対照は行わない。
//! バイナリはリポジトリに含めない。ファイルが無いときは失敗する。
//!
//! 通る道筋: ELFCLASS32・BE・EM_OPENRISC=92 のロード、
//! PT_INTERP の ldso（ET_DYN バイアス・RELRO の mprotect・
//! mallocng の PROT_NONE ガード mmap）、auxv/argv/envp の BE
//! 初期スタック、遅延スロット（CPUCFGR[ND]=0）、l.sys の
//! Trap 経路、brk 前に画像直後ページを触る musl の heap VMA
//! 近似（遅延割付）、getdents64・statx→newfstatat 代替。

use std::path::PathBuf;

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    let p = p.join(".testdata/bin-distro-or1k");
    assert!(
        p.join("bin/busybox").is_file() && p.join("lib/ld-musl-or1k.so.1").is_file(),
        "BIN-DISTRO-OR1K のルートを {} に置く。\
         リポジトリには含めない。",
        p.display()
    );
    p
}

/// (argv, 期待終了コード, 期待標準出力) の行。
type Case<'a> = (&'a [&'a str], u64, &'a [u8]);

fn run(args: &[&str]) -> (u64, Vec<u8>) {
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let mut sys = polyisa_os_linux::openrisc::sys::Linux::new();
    let root = root();
    let code = polyisa_cli::run_openrisc::run_elf_openrisc_sys_root(
        "/bin/busybox",
        &argv,
        None,
        &mut sys,
        Some(root.to_str().expect("utf-8 path")),
    )
    .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
    (code, sys.io.stdout)
}

/// 決定的ケース。ldso の startup（set_tid_address・brk・
/// PROT_NONE ガード mmap・mprotect）と BusyBox 本体の
/// syscall（statx→newfstatat・ioctl・clock_gettime{,64}・
/// getdents64）を踏む。
fn common_cases() -> &'static [Case<'static>] {
    &[
        (&["true"], 0, b""),
        (&["false"], 1, b""),
        (&["echo", "hi"], 0, b"hi\n"),
        (&["echo", "-n", "hi"], 0, b"hi"),
        (&["printf", "x%d\n", "42"], 0, b"x42\n"),
        (&["uname", "-s"], 0, b"Linux\n"),
        (&["uname", "-m"], 0, b"or1k\n"),
        (&["basename", "/a/b.c"], 0, b"b.c\n"),
        (&["dirname", "/a/b"], 0, b"/a\n"),
        (&["expr", "2", "+", "3"], 0, b"5\n"),
        (&["test", "-n", "x"], 0, b""),
        (&["test", "-z", "x"], 1, b""),
        (
            &["head", "-1", "/etc/passwd"],
            0,
            b"root::0:0::/root:/bin/sh\n",
        ),
        (
            &["ls", "/"],
            0,
            b"bin\netc\ninit\nlib\nlinuxrc\nqemu-or1k-busybox-test.log\nsbin\ntmp\nusr\nvar\n",
        ),
    ]
}

#[test]
fn busybox_common_cases() {
    for (args, code, out) in common_cases() {
        let (c, o) = run(args);
        assert_eq!(c, *code, "{}: 終了コード", args.join(" "));
        assert_eq!(o.as_slice(), *out, "{}: 標準出力", args.join(" "));
    }
}
