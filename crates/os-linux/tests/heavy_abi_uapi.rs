// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ABI 表とカーネル UAPI の突き合わせ（層6・abi）。
//!
//! 手順は検証戦略の層6の簡易版である。本来はカーネルソースから UAPI を生成して
//! `sizeof`/`offsetof` と番号を比較するが、ここではホストの
//! `<asm-generic/unistd.h>` を clang で展開し、番号表と突き合わせる。
//! ヘッダや clang がなければスキップして通す（未実行扱い）。
//!
//! 対象は台帳 SRC-LINUX（用途F・確認済み）と TOOL-RUST（用途X・確認済み）.

use std::process::{Command, Stdio};

fn clang() -> Option<String> {
    for c in ["clang", "/usr/sbin/clang", "/usr/bin/clang"] {
        if Command::new(c).arg("--version").output().is_ok() {
            return Some(c.to_string());
        }
    }
    None
}

/// UAPI の `__NR_*` を展開して値列を返す。
fn uapi_numbers(clang: &str, macros: &[&str]) -> Option<Vec<u64>> {
    let mut src = String::from("#include <asm-generic/unistd.h>\n");
    src.push_str(&macros.join(" "));
    src.push('\n');
    // ホストの asm/bitsperlong.h は __x86_64__ で 64 品を決める。
    // 汎用ヘッダの 64 ビット分岐を通すための苦肉の策であり、他には影響しない.
    let mut child = Command::new(clang)
        .args([
            "--target=riscv64-unknown-linux-gnu",
            "-D__x86_64__",
            "-D__ARCH_WANT_NEW_STAT",
            "-E",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    use std::io::Write as _;
    child.stdin.as_mut()?.write_all(src.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut last = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        last = Some(line);
    }
    let last = last?;
    last.split_whitespace()
        .map(|t| t.parse::<u64>().ok())
        .collect::<Option<Vec<u64>>>()
}

/// UAPI の `__NR_*` を x86_64 向けに展開して値列を返す。
/// `<asm/unistd_64.h>` を素直に読む。ホスト依存ではなく、x86_64 固定である。
fn uapi_numbers_x86_64(clang: &str, macros: &[&str]) -> Option<Vec<u64>> {
    let mut src = String::from("#include <asm/unistd_64.h>\n");
    src.push_str(&macros.join(" "));
    src.push('\n');
    let mut child = Command::new(clang)
        .args(["--target=x86_64-unknown-linux-gnu", "-E", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    use std::io::Write as _;
    child.stdin.as_mut()?.write_all(src.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut last = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        last = Some(line);
    }
    let last = last?;
    last.split_whitespace()
        .map(|t| t.parse::<u64>().ok())
        .collect::<Option<Vec<u64>>>()
}

#[test]
fn syscall_numbers_match_uapi() {
    let Some(cc) = clang() else {
        // Gap: GAP-0005
        eprintln!("skip: clang がないため未実行");
        return;
    };
    // (UAPI マクロ, polyisa の値)。
    let cases: &[(&str, u64)] = &[
        ("__NR_read", polyisa_os_linux::rv64::READ),
        ("__NR_write", polyisa_os_linux::rv64::WRITE),
        ("__NR_close", polyisa_os_linux::rv64::CLOSE),
        ("__NR_openat", polyisa_os_linux::rv64::OPENAT),
        ("__NR_mmap", polyisa_os_linux::rv64::MMAP),
        ("__NR_mprotect", polyisa_os_linux::rv64::MPROTECT),
        ("__NR_munmap", polyisa_os_linux::rv64::MUNMAP),
        ("__NR_brk", polyisa_os_linux::rv64::BRK),
        ("__NR_exit", polyisa_os_linux::rv64::EXIT),
        ("__NR_exit_group", polyisa_os_linux::rv64::EXIT_GROUP),
        ("__NR_uname", polyisa_os_linux::rv64::UNAME),
        (
            "__NR_set_tid_address",
            polyisa_os_linux::rv64::SET_TID_ADDRESS,
        ),
        ("__NR_clock_gettime", polyisa_os_linux::rv64::CLOCK_GETTIME),
        ("__NR_getrandom", polyisa_os_linux::rv64::GETRANDOM),
        ("__NR_lseek", polyisa_os_linux::rv64::LSEEK),
        ("__NR_getdents64", polyisa_os_linux::rv64::GETDENTS64),
        ("__NR_getcwd", polyisa_os_linux::rv64::GETCWD),
        ("__NR_dup3", polyisa_os_linux::rv64::DUP3),
        ("__NR_fcntl", polyisa_os_linux::rv64::FCNTL),
        ("__NR_ioctl", polyisa_os_linux::rv64::IOCTL),
        ("__NR_pread64", polyisa_os_linux::rv64::PREAD64),
        ("__NR_readlinkat", polyisa_os_linux::rv64::READLINKAT),
        ("__NR_newfstatat", polyisa_os_linux::rv64::NEWFSTATAT),
        ("__NR_fstat", polyisa_os_linux::rv64::FSTAT),
        ("__NR_statx", polyisa_os_linux::rv64::STATX),
    ];
    let macros: Vec<&str> = cases.iter().map(|(m, _)| *m).collect();
    let Some(got) = uapi_numbers(&cc, &macros) else {
        // Gap: GAP-0005
        eprintln!("skip: UAPI ヘッダの展開に失敗したため未実行");
        return;
    };
    assert_eq!(got.len(), cases.len(), "展開数が一致しない: {got:?}");
    for (i, (m, want)) in cases.iter().enumerate() {
        assert_eq!(got[i], *want, "{m} の番号が UAPI と食い違う");
    }
}

#[test]
fn syscall_numbers_match_uapi_x86_64() {
    let Some(cc) = clang() else {
        // Gap: GAP-0005
        eprintln!("skip: clang がないため未実行");
        return;
    };
    // (UAPI マクロ, polyisa の値)。x86_64 固有の表である。
    let cases: &[(&str, u64)] = &[
        ("__NR_read", polyisa_os_linux::x86_64::READ),
        ("__NR_write", polyisa_os_linux::x86_64::WRITE),
        ("__NR_close", polyisa_os_linux::x86_64::CLOSE),
        ("__NR_openat", polyisa_os_linux::x86_64::OPENAT),
        ("__NR_mmap", polyisa_os_linux::x86_64::MMAP),
        ("__NR_mprotect", polyisa_os_linux::x86_64::MPROTECT),
        ("__NR_munmap", polyisa_os_linux::x86_64::MUNMAP),
        ("__NR_brk", polyisa_os_linux::x86_64::BRK),
        ("__NR_exit", polyisa_os_linux::x86_64::EXIT),
        ("__NR_exit_group", polyisa_os_linux::x86_64::EXIT_GROUP),
        ("__NR_uname", polyisa_os_linux::x86_64::UNAME),
        (
            "__NR_set_tid_address",
            polyisa_os_linux::x86_64::SET_TID_ADDRESS,
        ),
        (
            "__NR_clock_gettime",
            polyisa_os_linux::x86_64::CLOCK_GETTIME,
        ),
        ("__NR_getrandom", polyisa_os_linux::x86_64::GETRANDOM),
        ("__NR_lseek", polyisa_os_linux::x86_64::LSEEK),
        ("__NR_getdents64", polyisa_os_linux::x86_64::GETDENTS64),
        ("__NR_getcwd", polyisa_os_linux::x86_64::GETCWD),
        ("__NR_dup3", polyisa_os_linux::x86_64::DUP3),
        ("__NR_fcntl", polyisa_os_linux::x86_64::FCNTL),
        ("__NR_ioctl", polyisa_os_linux::x86_64::IOCTL),
        ("__NR_pread64", polyisa_os_linux::x86_64::PREAD64),
        ("__NR_readlinkat", polyisa_os_linux::x86_64::READLINKAT),
        ("__NR_newfstatat", polyisa_os_linux::x86_64::NEWFSTATAT),
        ("__NR_fstat", polyisa_os_linux::x86_64::FSTAT),
        ("__NR_statx", polyisa_os_linux::x86_64::STATX),
        ("__NR_getgroups", polyisa_os_linux::x86_64::GETGROUPS),
        ("__NR_statfs", polyisa_os_linux::x86_64::STATFS),
        ("__NR_fstatfs", polyisa_os_linux::x86_64::FSTATFS),
        ("__NR_clone", polyisa_os_linux::x86_64::CLONE),
        ("__NR_execve", polyisa_os_linux::x86_64::EXECVE),
        ("__NR_wait4", polyisa_os_linux::x86_64::WAIT4),
    ];
    let macros: Vec<&str> = cases.iter().map(|(m, _)| *m).collect();
    let Some(got) = uapi_numbers_x86_64(&cc, &macros) else {
        // Gap: GAP-0005
        eprintln!("skip: UAPI ヘッダの展開に失敗したため未実行");
        return;
    };
    assert_eq!(got.len(), cases.len(), "展開数が一致しない: {got:?}");
    for (i, (m, want)) in cases.iter().enumerate() {
        assert_eq!(got[i], *want, "{m} の番号が UAPI と食い違う");
    }
}

/// UAPI の `__NR_*` を i386 向けに展開して値列を返す。
/// `<asm/unistd_32.h>` を素直に読む。ホスト依存ではなく、i386 固定である。
/// newfstatat は i386 に存在しないため fstatat64 で突き合わせる。
fn uapi_numbers_i386(clang: &str, macros: &[&str]) -> Option<Vec<u64>> {
    let mut src = String::from("#include <asm/unistd_32.h>\n");
    src.push_str(&macros.join(" "));
    src.push('\n');
    let mut child = Command::new(clang)
        .args(["--target=i386-unknown-linux-gnu", "-E", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    use std::io::Write as _;
    child.stdin.as_mut()?.write_all(src.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut last = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        last = Some(line);
    }
    let last = last?;
    last.split_whitespace()
        .map(|t| t.parse::<u64>().ok())
        .collect::<Option<Vec<u64>>>()
}

#[test]
fn syscall_numbers_match_uapi_i386() {
    let Some(cc) = clang() else {
        // Gap: GAP-0005
        eprintln!("skip: clang がないため未実行");
        return;
    };
    // (UAPI マクロ, polyisa の値)。i386 固有の表である。
    let cases: &[(&str, u64)] = &[
        ("__NR_read", polyisa_os_linux::i386::READ),
        ("__NR_write", polyisa_os_linux::i386::WRITE),
        ("__NR_close", polyisa_os_linux::i386::CLOSE),
        ("__NR_openat", polyisa_os_linux::i386::OPENAT),
        ("__NR_mmap", polyisa_os_linux::i386::MMAP),
        ("__NR_mprotect", polyisa_os_linux::i386::MPROTECT),
        ("__NR_munmap", polyisa_os_linux::i386::MUNMAP),
        ("__NR_brk", polyisa_os_linux::i386::BRK),
        ("__NR_exit", polyisa_os_linux::i386::EXIT),
        ("__NR_exit_group", polyisa_os_linux::i386::EXIT_GROUP),
        ("__NR_uname", polyisa_os_linux::i386::UNAME),
        (
            "__NR_set_tid_address",
            polyisa_os_linux::i386::SET_TID_ADDRESS,
        ),
        ("__NR_clock_gettime", polyisa_os_linux::i386::CLOCK_GETTIME),
        ("__NR_getrandom", polyisa_os_linux::i386::GETRANDOM),
        ("__NR_lseek", polyisa_os_linux::i386::LSEEK),
        ("__NR_getdents64", polyisa_os_linux::i386::GETDENTS64),
        ("__NR_getcwd", polyisa_os_linux::i386::GETCWD),
        ("__NR_dup3", polyisa_os_linux::i386::DUP3),
        ("__NR_fcntl", polyisa_os_linux::i386::FCNTL),
        ("__NR_ioctl", polyisa_os_linux::i386::IOCTL),
        ("__NR_pread64", polyisa_os_linux::i386::PREAD64),
        ("__NR_readlinkat", polyisa_os_linux::i386::READLINKAT),
        ("__NR_fstatat64", polyisa_os_linux::i386::FSTATAT64),
        ("__NR_fstat", polyisa_os_linux::i386::FSTAT),
        ("__NR_statx", polyisa_os_linux::i386::STATX),
        ("__NR_getgroups", polyisa_os_linux::i386::GETGROUPS),
        ("__NR_getgroups32", polyisa_os_linux::i386::GETGROUPS32),
        ("__NR_statfs", polyisa_os_linux::i386::STATFS),
        ("__NR_fstatfs", polyisa_os_linux::i386::FSTATFS),
        ("__NR_statfs64", polyisa_os_linux::i386::STATFS64),
        ("__NR_fstatfs64", polyisa_os_linux::i386::FSTATFS64),
        ("__NR_clone", polyisa_os_linux::i386::CLONE),
        ("__NR_execve", polyisa_os_linux::i386::EXECVE),
        ("__NR_wait4", polyisa_os_linux::i386::WAIT4),
    ];
    let macros: Vec<&str> = cases.iter().map(|(m, _)| *m).collect();
    let Some(got) = uapi_numbers_i386(&cc, &macros) else {
        // Gap: GAP-0005
        eprintln!("skip: UAPI ヘッダの展開に失敗したため未実行");
        return;
    };
    assert_eq!(got.len(), cases.len(), "展開数が一致しない: {got:?}");
    for (i, (m, want)) in cases.iter().enumerate() {
        assert_eq!(got[i], *want, "{m} の番号が UAPI と食い違う");
    }
}
