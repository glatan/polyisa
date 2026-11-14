// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! AArch64 ABI 表とカーネル UAPI の突き合わせ（層6・abi）。
//!
//! 手順は検証戦略の層6の簡易版である。aarch64 の `<asm/unistd.h>` は
//! `<asm-generic/unistd.h>` をそのまま取り込むので、ホストの汎用ヘッダを
//! clang で展開し、番号表と突き合わせる。
//! clang がなければ `devtool test:plan` がこのバイナリを実行対象から外す。
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

/// UAPI の `__NR_*` を aarch64 向けに展開して値列を返す。
/// aarch64 の syscall 番号は asm-generic の表そのものである。
fn uapi_numbers(clang: &str, macros: &[&str]) -> Option<Vec<u64>> {
    let mut src = String::from("#include <asm-generic/unistd.h>\n");
    src.push_str(&macros.join(" "));
    src.push('\n');
    // asm-generic の 64 ビット分岐を通す。汎用ヘッダを素直に読むための苦肉の策.
    let mut child = Command::new(clang)
        .args([
            "--target=aarch64-unknown-linux-gnu",
            "-D__x86_64__",
            "-D__ARCH_WANT_NEW_STAT",
            "-D__ARCH_WANT_RENAMEAT",
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

#[test]
fn syscall_numbers_match_uapi_aarch64() {
    let cc = clang().expect("clang がない（未実行の決定は devtool test:plan が担う）");
    // (UAPI マクロ, polyisa の値)。
    let cases: &[(&str, u64)] = &[
        ("__NR_read", polyisa_os_linux::aarch64::READ),
        ("__NR_write", polyisa_os_linux::aarch64::WRITE),
        ("__NR_readv", polyisa_os_linux::aarch64::READV),
        ("__NR_writev", polyisa_os_linux::aarch64::WRITEV),
        ("__NR_pread64", polyisa_os_linux::aarch64::PREAD64),
        ("__NR_pwrite64", polyisa_os_linux::aarch64::PWRITE64),
        ("__NR_openat", polyisa_os_linux::aarch64::OPENAT),
        ("__NR_close", polyisa_os_linux::aarch64::CLOSE),
        ("__NR_lseek", polyisa_os_linux::aarch64::LSEEK),
        ("__NR_dup", polyisa_os_linux::aarch64::DUP),
        ("__NR_dup3", polyisa_os_linux::aarch64::DUP3),
        ("__NR_fcntl", polyisa_os_linux::aarch64::FCNTL),
        ("__NR_ioctl", polyisa_os_linux::aarch64::IOCTL),
        ("__NR_flock", polyisa_os_linux::aarch64::FLOCK),
        ("__NR_pipe2", polyisa_os_linux::aarch64::PIPE2),
        ("__NR_getdents64", polyisa_os_linux::aarch64::GETDENTS64),
        ("__NR_getcwd", polyisa_os_linux::aarch64::GETCWD),
        ("__NR_readlinkat", polyisa_os_linux::aarch64::READLINKAT),
        ("__NR_newfstatat", polyisa_os_linux::aarch64::NEWFSTATAT),
        ("__NR_fstat", polyisa_os_linux::aarch64::FSTAT),
        ("__NR_statx", polyisa_os_linux::aarch64::STATX),
        ("__NR_statfs", polyisa_os_linux::aarch64::STATFS64),
        ("__NR_fstatfs", polyisa_os_linux::aarch64::FSTATFS64),
        ("__NR_faccessat", polyisa_os_linux::aarch64::FACCESSAT),
        ("__NR_faccessat2", polyisa_os_linux::aarch64::FACCESSAT2),
        ("__NR_mknodat", polyisa_os_linux::aarch64::MKNODAT),
        ("__NR_mkdirat", polyisa_os_linux::aarch64::MKDIRAT),
        ("__NR_unlinkat", polyisa_os_linux::aarch64::UNLINKAT),
        ("__NR_symlinkat", polyisa_os_linux::aarch64::SYMLINKAT),
        ("__NR_linkat", polyisa_os_linux::aarch64::LINKAT),
        ("__NR_renameat", polyisa_os_linux::aarch64::RENAMEAT),
        ("__NR_renameat2", polyisa_os_linux::aarch64::RENAMEAT2),
        ("__NR_umount2", polyisa_os_linux::aarch64::UMOUNT2),
        ("__NR_mount", polyisa_os_linux::aarch64::MOUNT),
        ("__NR_truncate", polyisa_os_linux::aarch64::TRUNCATE64),
        ("__NR_ftruncate", polyisa_os_linux::aarch64::FTRUNCATE64),
        ("__NR_chdir", polyisa_os_linux::aarch64::CHDIR),
        ("__NR_fchdir", polyisa_os_linux::aarch64::FCHDIR),
        ("__NR_fchmod", polyisa_os_linux::aarch64::FCHMOD),
        ("__NR_fchmodat", polyisa_os_linux::aarch64::FCHMODAT),
        ("__NR_fchownat", polyisa_os_linux::aarch64::FCHOWNAT),
        ("__NR_fchown", polyisa_os_linux::aarch64::FCHOWN),
        ("__NR_utimensat", polyisa_os_linux::aarch64::UTIMENSAT),
        ("__NR_mmap", polyisa_os_linux::aarch64::MMAP),
        ("__NR_munmap", polyisa_os_linux::aarch64::MUNMAP),
        ("__NR_mprotect", polyisa_os_linux::aarch64::MPROTECT),
        ("__NR_mremap", polyisa_os_linux::aarch64::MREMAP),
        ("__NR_msync", polyisa_os_linux::aarch64::MSYNC),
        ("__NR_mincore", polyisa_os_linux::aarch64::MINCORE),
        ("__NR_madvise", polyisa_os_linux::aarch64::MADVISE),
        ("__NR_brk", polyisa_os_linux::aarch64::BRK),
        ("__NR_exit", polyisa_os_linux::aarch64::EXIT),
        ("__NR_exit_group", polyisa_os_linux::aarch64::EXIT_GROUP),
        ("__NR_waitid", polyisa_os_linux::aarch64::WAITID),
        ("__NR_wait4", polyisa_os_linux::aarch64::WAIT4),
        ("__NR_uname", polyisa_os_linux::aarch64::UNAME),
        (
            "__NR_set_tid_address",
            polyisa_os_linux::aarch64::SET_TID_ADDRESS,
        ),
        ("__NR_futex", polyisa_os_linux::aarch64::FUTEX),
        (
            "__NR_set_robust_list",
            polyisa_os_linux::aarch64::SET_ROBUST_LIST,
        ),
        ("__NR_nanosleep", polyisa_os_linux::aarch64::NANOSLEEP),
        ("__NR_getitimer", polyisa_os_linux::aarch64::GETITIMER),
        ("__NR_setitimer", polyisa_os_linux::aarch64::SETITIMER),
        (
            "__NR_clock_gettime",
            polyisa_os_linux::aarch64::CLOCK_GETTIME,
        ),
        ("__NR_getrandom", polyisa_os_linux::aarch64::GETRANDOM),
        ("__NR_getpid", polyisa_os_linux::aarch64::GETPID),
        ("__NR_getppid", polyisa_os_linux::aarch64::GETPPID),
        ("__NR_getuid", polyisa_os_linux::aarch64::GETUID),
        ("__NR_geteuid", polyisa_os_linux::aarch64::GETEUID),
        ("__NR_getgid", polyisa_os_linux::aarch64::GETGID),
        ("__NR_getegid", polyisa_os_linux::aarch64::GETEGID),
        ("__NR_gettid", polyisa_os_linux::aarch64::GETTID),
        ("__NR_sysinfo", polyisa_os_linux::aarch64::SYSINFO),
        ("__NR_prlimit64", polyisa_os_linux::aarch64::PRLIMIT64),
        ("__NR_clone", polyisa_os_linux::aarch64::CLONE),
        ("__NR_execve", polyisa_os_linux::aarch64::EXECVE),
        ("__NR_sync", polyisa_os_linux::aarch64::SYNC),
        ("__NR_fsync", polyisa_os_linux::aarch64::FSYNC),
        ("__NR_fdatasync", polyisa_os_linux::aarch64::FDATASYNC),
        ("__NR_pselect6", polyisa_os_linux::aarch64::PSELECT6),
        ("__NR_ppoll", polyisa_os_linux::aarch64::PPOLL),
        ("__NR_sendfile", polyisa_os_linux::aarch64::SENDFILE),
        ("__NR_quotactl", polyisa_os_linux::aarch64::QUOTACTL),
        ("__NR_acct", polyisa_os_linux::aarch64::ACCT),
        ("__NR_personality", polyisa_os_linux::aarch64::PERSONALITY),
        ("__NR_init_module", polyisa_os_linux::aarch64::INIT_MODULE),
        ("__NR_swapon", polyisa_os_linux::aarch64::SWAPON),
        ("__NR_swapoff", polyisa_os_linux::aarch64::SWAPOFF),
        ("__NR_pivot_root", polyisa_os_linux::aarch64::PIVOT_ROOT),
        ("__NR_membarrier", polyisa_os_linux::aarch64::MEMBARRIER),
        ("__NR_rseq", polyisa_os_linux::aarch64::RSEQ),
    ];
    let macros: Vec<&str> = cases.iter().map(|(m, _)| *m).collect();
    let got = uapi_numbers(&cc, &macros).expect("UAPI ヘッダの展開に失敗");
    assert_eq!(got.len(), cases.len(), "展開数が一致しない: {got:?}");
    for (i, (m, want)) in cases.iter().enumerate() {
        assert_eq!(got[i], *want, "{m} の番号が UAPI と食い違う");
    }
}
