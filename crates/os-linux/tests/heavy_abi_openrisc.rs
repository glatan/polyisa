// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! openrisc の ABI 表とカーネル UAPI の突き合わせ（層6・abi、S20-2）。
//!
//! or1k はアーチ固有の tbl を持たず、共通表 `scripts/syscall.tbl`
//! からアーチ別の opt-in で `unistd_32.h` が生成される。or1k が使う
//! 行は abi ∈ {common, 32, or1k, time32, stat64, rlimit, renameat}
//! （`arch/openrisc/kernel/Makefile.syscalls` の
//! `syscall_abis_32 += or1k time32 stat64 rlimit renameat` が
//! common/32 と合わせて opt-in する）。同じ番号に 32 系と 64 系の
//! 行が並ぶときは 32 系を取る（25 は fcntl64、62 は llseek、
//! 79/80 は fstatat64/fstat64、222 は mmap2）。or1k 固有の
//! `or1k_atomic`(244) を含む。出典は `.testdata/uapi-openrisc`
//! （台帳 SRC-LINUX-OPENRISC-UAPI・用途T）。データがなければ
//! devtool test:plan が外す。

use std::collections::HashMap;
use std::path::PathBuf;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/uapi-openrisc")
}

/// `syscall.tbl` を番号→名に畳む。4 列は 番号・abi・名・入口点。
/// or1k は abi ∈ {common, 32, or1k, time32, stat64, rlimit, renameat}
/// の行だけを載せ、畳んだ表では番号が一意になる（同番号に 32 系と
/// 64 系が並ぶ行は 64 系が落ちる）。
fn tbl_names(path: &PathBuf) -> HashMap<u64, String> {
    const OR1K_ABIS: &[&str] = &[
        "common", "32", "or1k", "time32", "stat64", "rlimit", "renameat",
    ];
    let text = std::fs::read_to_string(path).expect("syscall.tbl を読む");
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut cols = line.split_whitespace();
        let (num, abi, name) = match (cols.next(), cols.next(), cols.next()) {
            (Some(n), Some(a), Some(nm)) => (n, a, nm),
            _ => panic!("tbl の行が読めない: {line:?}"),
        };
        if !OR1K_ABIS.contains(&abi) {
            continue;
        }
        let n: u64 = num
            .parse()
            .unwrap_or_else(|_| panic!("tbl の番号: {line:?}"));
        if let Some(prev) = map.insert(n, name.to_string()) {
            panic!("tbl で or1k の番号 {n} が重複する（{prev} と {name}）");
        }
    }
    map
}

/// `Makefile.syscalls` の opt-in を確認し、選択規則
/// {common, 32, or1k, time32, stat64, rlimit, renameat} の根拠を
/// 固定する。
#[test]
fn makefile_syscalls_selects_or1k_abis() {
    let mk = data_dir().join("Makefile.syscalls");
    assert!(
        mk.is_file(),
        "SRC-LINUX-OPENRISC-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let text = std::fs::read_to_string(&mk).expect("Makefile.syscalls を読む");
    assert!(
        text.contains("syscall_abis_32 += or1k time32 stat64 rlimit renameat"),
        "or1k の 32 ビット ABI opt-in が見えない"
    );
}

#[test]
fn syscall_numbers_match_uapi_openrisc() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-OPENRISC-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let names = tbl_names(&tbl);
    let want_nr = |name: &str| -> u64 {
        *names
            .iter()
            .find(|(_, v)| v.as_str() == name)
            .map(|(n, _)| n)
            .unwrap_or_else(|| panic!("tbl に {name} がない"))
    };
    use polyisa_os_linux::openrisc::nr as a;
    for (name, want) in [
        ("fcntl64", a::FCNTL),
        ("ioctl", a::IOCTL),
        ("faccessat", a::FACCESSAT),
        ("openat", a::OPENAT),
        ("close", a::CLOSE),
        ("getdents64", a::GETDENTS64),
        ("llseek", a::LLSEEK),
        ("read", a::READ),
        ("write", a::WRITE),
        ("readv", a::READV),
        ("writev", a::WRITEV),
        ("pread64", a::PREAD64),
        ("readlinkat", a::READLINKAT),
        ("fstatat64", a::FSTATAT64),
        ("fstat64", a::FSTAT64),
        ("exit", a::EXIT),
        ("exit_group", a::EXIT_GROUP),
        ("set_tid_address", a::SET_TID_ADDRESS),
        ("futex", a::FUTEX),
        ("set_robust_list", a::SET_ROBUST_LIST),
        ("nanosleep", a::NANOSLEEP),
        ("clock_gettime", a::CLOCK_GETTIME),
        ("rt_sigaction", a::RT_SIGACTION),
        ("rt_sigprocmask", a::RT_SIGPROCMASK),
        ("setregid", a::SETREGID),
        ("setgid", a::SETGID),
        ("setreuid", a::SETREUID),
        ("setuid", a::SETUID),
        ("setresuid", a::SETRESUID),
        ("setresgid", a::SETRESGID),
        ("setfsuid", a::SETFSUID),
        ("setfsgid", a::SETFSGID),
        ("uname", a::UNAME),
        ("getpid", a::GETPID),
        ("getppid", a::GETPPID),
        ("getuid", a::GETUID),
        ("geteuid", a::GETEUID),
        ("getgid", a::GETGID),
        ("getegid", a::GETEGID),
        ("gettid", a::GETTID),
        ("brk", a::BRK),
        ("munmap", a::MUNMAP),
        ("mmap2", a::MMAP2),
        ("mprotect", a::MPROTECT),
        ("or1k_atomic", a::OR1K_ATOMIC),
        ("prlimit64", a::PRLIMIT64),
        ("getrandom", a::GETRANDOM),
        ("statx", a::STATX),
        ("clock_gettime64", a::CLOCK_GETTIME64),
    ] {
        let got = want_nr(name);
        assert_eq!(got, want, "__NR_{name} の番号が UAPI と食い違う");
    }
}

#[test]
fn name_table_covers_uapi_openrisc() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-OPENRISC-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let names = tbl_names(&tbl);
    // 実装の全エントリが tbl の同じ番号の名と一致すること。
    for (nr, got) in polyisa_os_linux::openrisc::SYSCALLS {
        let Some(want) = names.get(nr) else {
            panic!("実装が or1k の UAPI にない番号 {nr}({got}) を持つ");
        };
        assert_eq!(got, want, "name({nr}) が UAPI と食い違う");
    }
    // tbl の or1k ABI 全集の全番号が実装に載っていること
    // （UAPI 側の漏れ検出）。
    for (nr, want) in &names {
        assert!(
            polyisa_os_linux::openrisc::name(*nr).is_some(),
            "UAPI の {nr}({want}) が実装にない"
        );
    }
    // UAPI の最大番号を超える実装エントリがないこと。
    let max = names.keys().copied().max().unwrap_or(0);
    assert_eq!(
        polyisa_os_linux::openrisc::SYSCALLS
            .iter()
            .map(|(n, _)| *n)
            .max(),
        Some(max),
        "実装表の最大番号が UAPI と食い違う"
    );
    assert!(
        polyisa_os_linux::openrisc::name(max + 1).is_none(),
        "UAPI の最大番号を超える実装エントリがある"
    );
}
