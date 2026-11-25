// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! S22-1 の判定。`.testdata/bin-distro-hexagon`（Hexagon 動的リンク
//! musl BusyBox と ld-musl-hexagon.so.1、BIN-DISTRO-HEXAGON）を
//! ゲストルートとして、基本コマンド群をゲスト側で実行し、
//! 終了コードと標準出力を固定値と照合する。ホストは Hexagon の
//! ELF を直接実行できないため、ホスト対照は行わない。
//! バイナリはリポジトリに含めない。ファイルが無いときは失敗する。
//!
//! 通る道筋: ELFCLASS32・LE・EM_QDSP6=164 のロード、PT_INTERP の
//! ldso（ET_DYN バイアス・RELRO の mprotect・mallocng の
//! PROT_NONE ガード mmap）、auxv/argv/envp の LE 初期スタック、
//! trap0(#1) の Trap 経路、lazymap 窓の遅延割付、
//! statx/getdents64/mmap2 等の syscall パーソナリティ。
//!
//! 既知残課題: `decfloat` が使う convert_*df/
//! convert_*sf 系 FP 変換命令は未実装で %f 系（seq 等）は
//! 走らない。`__secs_to_tm` 系で remdays が異常に大きく残り
//! date / ls -l が時刻整形前に停止するケースがある。

use std::path::PathBuf;

fn root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    let p = p.join(".testdata/bin-distro-hexagon");
    assert!(
        p.join("bin/busybox").is_file() && p.join("lib/ld-musl-hexagon.so.1").is_file(),
        "BIN-DISTRO-HEXAGON のルートを {} に置く。\
         リポジトリには含めない。",
        p.display()
    );
    p
}

/// (argv, 期待終了コード, 期待標準出力) の行。
type Case<'a> = (&'a [&'a str], u64, &'a [u8]);

fn run(args: &[&str]) -> (u64, Vec<u8>) {
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let mut sys = polyisa_os_linux::hexagon::sys::Linux::new();
    let root = root();
    let code = polyisa_cli::run_hexagon::run_elf_hexagon_sys_root(
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
/// syscall（statx・ioctl・clock_gettime64・getdents64）を踏む。
fn common_cases() -> &'static [Case<'static>] {
    &[
        (&["true"], 0, b""),
        (&["false"], 1, b""),
        (&["echo", "hi"], 0, b"hi\n"),
        (&["echo", "-n", "hi"], 0, b"hi"),
        (&["printf", "x%d\n", "42"], 0, b"x42\n"),
        (&["uname", "-s"], 0, b"Linux\n"),
        (&["uname", "-m"], 0, b"hexagon\n"),
        (&["hostname"], 0, b"polyisa\n"),
        (&["pwd"], 0, b"/\n"),
        (&["basename", "/a/b.c"], 0, b"b.c\n"),
        (&["dirname", "/a/b"], 0, b"/a\n"),
        (&["expr", "2", "+", "3"], 0, b"5\n"),
        (&["test", "-n", "x"], 0, b""),
        (&["test", "-z", "x"], 1, b""),
        (&["id"], 0, b"uid=0(root) gid=0(root)\n"),
        (
            &["head", "-1", "/etc/passwd"],
            0,
            b"root:x:0:0:root:/root:/bin/sh\n",
        ),
        (&["cat", "/etc/hostname"], 0, b"buildroot\n"),
        (
            &["ls", "/"],
            0,
            b"bin\ndev\netc\nlib\nlib32\nlinuxrc\nmedia\nmnt\nopt\nproc\nroot\nrun\nsbin\nsys\ntmp\nusr\nvar\n",
        ),
        (&["wc", "-l", "/etc/passwd"], 0, b"9 /etc/passwd\n"),
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
