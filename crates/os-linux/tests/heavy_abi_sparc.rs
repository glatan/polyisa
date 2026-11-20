// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! sparc32/sparc64 ABI 表とカーネル UAPI の突き合わせ（層6・abi、S15-2）。
//!
//! SPARC の UAPI 番号は `arch/sparc/kernel/syscalls/syscall.tbl` が正本。
//! abi 列は common・32・64 で、同じ番号でも 32 側は compat 名
//! （`lchown32` 等）、64 側は素の名に分かれる行がある。UAPI が
//! `_newselect` 等と呼ぶものを実装は glibc 名（`newselect`）で保持する。
//! 出典は `.testdata/uapi-sparc`（台帳 SRC-LINUX-SPARC-UAPI・用途T）。
//! データがなければ devtool test:plan が外す。

use std::collections::HashMap;
use std::path::PathBuf;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/uapi-sparc")
}

/// `syscall.tbl` を番号→(32 側の名, 64 側の名) に畳む。common 行は
/// 両側に入る。32・64 どちらかにしかない行は片側だけ Some になる。
fn tbl_names(path: &PathBuf) -> HashMap<u64, (Option<String>, Option<String>)> {
    let text = std::fs::read_to_string(path).expect("syscall.tbl を読む");
    let mut map: HashMap<u64, (Option<String>, Option<String>)> = HashMap::new();
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
        let e = map.entry(n).or_default();
        match abi {
            "common" => {
                e.0 = Some(name.to_string());
                e.1 = Some(name.to_string());
            }
            "32" => e.0 = Some(name.to_string()),
            "64" => e.1 = Some(name.to_string()),
            _ => panic!("tbl の abi 列が読めない: {line:?}"),
        }
    }
    map
}

/// UAPI の `_` 始まりの名を実装側の正準名へ写す。
/// `_newselect`→`newselect`、`_llseek`→`llseek`、`_sysctl`→`sysctl`。
fn canon(name: &str) -> &str {
    name.strip_prefix('_').unwrap_or(name)
}

#[test]
fn syscall_numbers_match_uapi_sparc() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-SPARC-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let names = tbl_names(&tbl);
    let want_nr = |name: &str| -> u64 {
        *names
            .iter()
            .find_map(|(n, (a, b))| {
                [a.as_ref(), b.as_ref()]
                    .into_iter()
                    .flatten()
                    .any(|u| canon(u) == name)
                    .then_some(n)
            })
            .unwrap_or_else(|| panic!("tbl に {name} がない"))
    };
    use polyisa_os_linux::sparc::nr as a;
    for (name, want) in [
        ("exit", a::EXIT),
        ("fork", a::FORK),
        ("read", a::READ),
        ("write", a::WRITE),
        ("open", a::OPEN),
        ("close", a::CLOSE),
        ("wait4", a::WAIT4),
        ("execv", a::EXECV),
        ("chown", a::CHOWN),
        ("brk", a::BRK),
        ("perfctr", a::PERFCTR),
        ("getpid", a::GETPID),
        ("setuid", a::SETUID),
        ("getuid", a::GETUID),
        ("vmsplice", a::VMSPLICE),
        ("sigaltstack", a::SIGALTSTACK),
        ("lchown32", a::LCHOWN32),
        ("getuid32", a::GETUID32),
        ("chown32", a::CHOWN32),
        ("stat", a::STAT),
        ("sendfile", a::SENDFILE),
        ("lstat", a::LSTAT),
        ("dup", a::DUP),
        ("pipe", a::PIPE),
        ("memory_ordering", a::MEMORY_ORDERING),
        ("getgid32", a::GETGID32),
        ("ioctl", a::IOCTL),
        ("reboot", a::REBOOT),
        ("mmap2", a::MMAP2),
        ("execve", a::EXECVE),
        ("fstat", a::FSTAT),
        ("fstat64", a::FSTAT64),
        ("getpagesize", a::GETPAGESIZE),
        ("vfork", a::VFORK),
        ("pread64", a::PREAD64),
        ("pwrite64", a::PWRITE64),
        ("mmap", a::MMAP),
        ("munmap", a::MUNMAP),
        ("mprotect", a::MPROTECT),
        ("truncate64", a::TRUNCATE64),
        ("getgroups", a::GETGROUPS),
        ("setresuid", a::SETRESUID),
        ("getresuid", a::GETRESUID),
        ("getgroups32", a::GETGROUPS32),
        ("fcntl64", a::FCNTL64),
        ("utrap_install", a::UTRAP_INSTALL),
        ("personality", a::PERSONALITY),
        ("newselect", a::NEWSELECT),
        ("llseek", a::LLSEEK),
        ("sysctl", a::SYSCTL),
        ("clock_gettime", a::CLOCK_GETTIME),
        ("statx", a::STATX),
        ("getrandom", a::GETRANDOM),
        ("semtimedop", a::SEMTIMEDOP),
        ("clock_gettime64", a::CLOCK_GETTIME64),
        ("futex_time64", a::FUTEX_TIME64),
        ("clone3", a::CLONE3),
        ("openat2", a::OPENAT2),
        ("fchmodat2", a::FCHMODAT2),
        ("map_shadow_stack", a::MAP_SHADOW_STACK),
        ("statmount", a::STATMOUNT),
        ("mseal", a::MSEAL),
        ("setxattrat", a::SETXATTRAT),
        ("open_tree_attr", a::OPEN_TREE_ATTR),
        ("file_getattr", a::FILE_GETATTR),
        ("listns", a::LISTNS),
        ("fchroot", a::FCHROOT),
    ] {
        let got = want_nr(name);
        assert_eq!(got, want, "__NR_{name} の番号が UAPI と食い違う");
    }
}

#[test]
fn name_table_covers_uapi_sparc() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-SPARC-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let names = tbl_names(&tbl);
    // 実装の全エントリが tbl の同じ番号の abi 名（またはその正準名）と
    // 一致すること。name() は番号ごとに正準名を一つ返す。
    for nr in 0..=472u64 {
        let Some(got) = polyisa_os_linux::sparc::name(nr) else {
            continue;
        };
        let Some((n32, n64)) = names.get(&nr) else {
            panic!("実装が UAPI にない番号 {nr}({got}) を持つ");
        };
        let ok = [n32.as_ref(), n64.as_ref()]
            .into_iter()
            .flatten()
            .any(|u| u == got || canon(u) == got);
        assert!(ok, "name({nr})={got} は UAPI {names:?} と食い違う");
    }
    // tbl の全番号が実装に載っていること（UAPI 側の漏れ検出）。
    for (nr, pair) in &names {
        assert!(
            polyisa_os_linux::sparc::name(*nr).is_some(),
            "UAPI の {nr}{pair:?} が実装にない"
        );
    }
    // 0..=472 の範囲走査に依存しないよう、実装が 472 を超える番号を
    // 持たないことも確認する。
    assert!(
        polyisa_os_linux::sparc::name(473).is_none(),
        "UAPI の最大番号を超える実装エントリがある"
    );
}
