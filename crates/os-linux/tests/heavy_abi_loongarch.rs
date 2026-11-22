// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! loongarch の ABI 表とカーネル UAPI の突き合わせ（層6・abi、S19-2）。
//!
//! LoongArch はアーチ固有の tbl を持たず、共通表
//! `scripts/syscall.tbl` からアーチ別の opt-in で生成される。
//! la64 が使う行は abi ∈ {common, 64, memfd_secret}（memfd_secret は
//! `arch/loongarch/kernel/Makefile.syscalls` の
//! `syscall_abis_64 += memfd_secret` で opt-in）。同じ番号に
//! common と 64 の行が並ぶときは 64 の行を取る（generic 表では
//! 同番号に複数 abi が並ぶと個別名を持つ。例: 25 は common 行を
//! 持たず 64 行 `fcntl` を取る）。出典は
//! `.testdata/uapi-loongarch`（台帳 SRC-LINUX-LOONGARCH-UAPI・用途T）。
//! データがなければ devtool test:plan が外す。

use std::collections::HashMap;
use std::path::PathBuf;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/uapi-loongarch")
}

/// `syscall.tbl` を番号→名に畳む。4 列は 番号・abi・名・入口点。
/// la64 は abi が common と 64 と memfd_secret の行だけを載せる。
/// 同じ番号で common と 64 が両方ある場合は 64 の行が勝つ
/// （tbl は同番号を abi 別に並べ、64 固有の名を持つ行が後に来る）。
fn tbl_names(path: &PathBuf) -> HashMap<u64, String> {
    let text = std::fs::read_to_string(path).expect("syscall.tbl を読む");
    let mut map: HashMap<u64, (u8, String)> = HashMap::new();
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
        let n: u64 = num
            .parse()
            .unwrap_or_else(|_| panic!("tbl の番号: {line:?}"));
        // 優先度: memfd_secret/64 = 2、common = 1。その他の abi
        // 値（32/time32/stat64/他アーチ固有）は la64 に無関係。
        let (keep, prio) = match abi {
            "common" => (true, 1u8),
            "64" | "memfd_secret" => (true, 2u8),
            _ => (false, 0),
        };
        if !keep {
            continue;
        }
        match map.get(&n) {
            Some((p, _)) if *p >= prio => {}
            _ => {
                map.insert(n, (prio, name.to_string()));
            }
        }
    }
    map.into_iter().map(|(n, (_, v))| (n, v)).collect()
}

/// `Makefile.syscalls` の opt-in を確認し、選択規則 {common, 64,
/// memfd_secret} の根拠を固定する。
#[test]
fn makefile_syscalls_selects_memfd_secret() {
    let mk = data_dir().join("Makefile.syscalls");
    assert!(
        mk.is_file(),
        "SRC-LINUX-LOONGARCH-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let text = std::fs::read_to_string(&mk).expect("Makefile.syscalls を読む");
    assert!(
        text.contains("syscall_abis_64 += memfd_secret"),
        "la64 の memfd_secret opt-in が見えない"
    );
}

#[test]
fn syscall_numbers_match_uapi_loongarch() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-LOONGARCH-UAPI を {} に置く。リポジトリには含めない。",
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
    use polyisa_os_linux::loongarch::nr as a;
    for (name, want) in [
        ("getcwd", a::GETCWD),
        ("dup", a::DUP),
        ("dup3", a::DUP3),
        ("fcntl", a::FCNTL),
        ("ioctl", a::IOCTL),
        ("flock", a::FLOCK),
        ("mknodat", a::MKNODAT),
        ("mkdirat", a::MKDIRAT),
        ("unlinkat", a::UNLINKAT),
        ("symlinkat", a::SYMLINKAT),
        ("linkat", a::LINKAT),
        ("renameat2", a::RENAMEAT2),
        ("faccessat", a::FACCESSAT),
        ("chdir", a::CHDIR),
        ("openat", a::OPENAT),
        ("close", a::CLOSE),
        ("pipe2", a::PIPE2),
        ("getdents64", a::GETDENTS64),
        ("lseek", a::LSEEK),
        ("read", a::READ),
        ("write", a::WRITE),
        ("readv", a::READV),
        ("writev", a::WRITEV),
        ("pread64", a::PREAD64),
        ("pwrite64", a::PWRITE64),
        ("sendfile", a::SENDFILE),
        ("pselect6", a::PSELECT6),
        ("ppoll", a::PPOLL),
        ("readlinkat", a::READLINKAT),
        ("execve", a::EXECVE),
        ("mmap", a::MMAP),
        ("mprotect", a::MPROTECT),
        ("wait4", a::WAIT4),
        ("prlimit64", a::PRLIMIT64),
        ("getrandom", a::GETRANDOM),
        ("execveat", a::EXECVEAT),
        ("statx", a::STATX),
        ("rseq", a::RSEQ),
    ] {
        let got = want_nr(name);
        assert_eq!(got, want, "__NR_{name} の番号が UAPI と食い違う");
    }
}

#[test]
fn name_table_covers_uapi_loongarch() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-LOONGARCH-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let names = tbl_names(&tbl);
    // 実装の全エントリが tbl の同じ番号の名と一致すること。
    for (nr, got) in polyisa_os_linux::loongarch::SYSCALLS {
        let Some(want) = names.get(nr) else {
            panic!("実装が la64 の UAPI にない番号 {nr}({got}) を持つ");
        };
        assert_eq!(got, want, "name({nr}) が UAPI と食い違う");
    }
    // tbl の common・64・memfd_secret の全番号が実装に載っていること
    // （UAPI 側の漏れ検出）。
    for (nr, want) in &names {
        assert!(
            polyisa_os_linux::loongarch::name(*nr).is_some(),
            "UAPI の {nr}({want}) が実装にない"
        );
    }
    // UAPI の最大番号を超える実装エントリがないこと。
    let max = names.keys().copied().max().unwrap_or(0);
    assert_eq!(
        polyisa_os_linux::loongarch::SYSCALLS
            .iter()
            .map(|(n, _)| *n)
            .max(),
        Some(max),
        "実装表の最大番号が UAPI と食い違う"
    );
    assert!(
        polyisa_os_linux::loongarch::name(max + 1).is_none(),
        "UAPI の最大番号を超える実装エントリがある"
    );
}
