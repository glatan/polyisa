// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! s390x ABI 表とカーネル UAPI の突き合わせ（層6・abi、S11-2）。
//!
//! s390 の UAPI 番号は `arch/s390/kernel/syscalls/syscall.tbl` が正本。
//! s390x は abi 列が `common`・`64` の行を使う（`32` 行は 31 ビット
//! compat 専用で s390x ユーザには出ない）。
//! 出典は `.testdata/uapi-s390`（台帳 SRC-LINUX-S390-UAPI・用途T）。
//! データがなければ devtool test:plan が外す。

use std::path::PathBuf;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/uapi-s390")
}

/// `syscall.tbl` の（common|64）行を name→番号に畳む。`32` 行は捨てる。
fn tbl_numbers(path: &PathBuf) -> std::collections::HashMap<String, u64> {
    let text = std::fs::read_to_string(path).expect("syscall.tbl を読む");
    let mut map = std::collections::HashMap::new();
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
        if abi == "32" {
            continue;
        }
        let n: u64 = num
            .parse()
            .unwrap_or_else(|_| panic!("tbl の番号: {line:?}"));
        map.insert(name.to_string(), n);
    }
    map
}

#[test]
fn syscall_numbers_match_uapi_s390x() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-S390-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let nums = tbl_numbers(&tbl);
    use polyisa_os_linux::s390 as a;
    for (name, want) in [
        ("exit", a::EXIT),
        ("read", a::READ),
        ("write", a::WRITE),
        ("open", a::OPEN),
        ("close", a::CLOSE),
        ("creat", a::CREAT),
        ("link", a::LINK),
        ("unlink", a::UNLINK),
        ("execve", a::EXECVE),
        ("chdir", a::CHDIR),
        ("mknod", a::MKNOD),
        ("chmod", a::CHMOD),
        ("lseek", a::LSEEK),
        ("getpid", a::GETPID),
        ("access", a::ACCESS),
        ("sync", a::SYNC),
        ("kill", a::KILL),
        ("rename", a::RENAME),
        ("mkdir", a::MKDIR),
        ("rmdir", a::RMDIR),
        ("dup", a::DUP),
        ("pipe", a::PIPE),
        ("times", a::TIMES),
        ("brk", a::BRK),
        ("ioctl", a::IOCTL),
        ("fcntl", a::FCNTL),
        ("umask", a::UMASK),
        ("dup2", a::DUP2),
        ("getppid", a::GETPPID),
        ("getrusage", a::GETRUSAGE),
        ("gettimeofday", a::GETTIMEOFDAY),
        ("mmap", a::MMAP),
        ("munmap", a::MUNMAP),
        ("ftruncate", a::FTRUNCATE),
        ("stat", a::STAT),
        ("lstat", a::LSTAT),
        ("fstat", a::FSTAT),
        ("wait4", a::WAIT4),
        ("sysinfo", a::SYSINFO),
        ("fsync", a::FSYNC),
        ("clone", a::CLONE),
        ("uname", a::UNAME),
        ("mprotect", a::MPROTECT),
        ("personality", a::PERSONALITY),
        ("getdents", a::GETDENTS),
        ("select", a::SELECT),
        ("readv", a::READV),
        ("writev", a::WRITEV),
        ("sched_yield", a::SCHED_YIELD),
        ("nanosleep", a::NANOSLEEP),
        ("poll", a::POLL),
        ("prctl", a::PRCTL),
        ("rt_sigaction", a::RT_SIGACTION),
        ("rt_sigprocmask", a::RT_SIGPROCMASK),
        ("pread64", a::PREAD64),
        ("pwrite64", a::PWRITE64),
        ("getcwd", a::GETCWD),
        ("vfork", a::VFORK),
        ("getrlimit", a::GETRLIMIT),
        ("getuid", a::GETUID),
        ("getgid", a::GETGID),
        ("geteuid", a::GETEUID),
        ("getegid", a::GETEGID),
        ("madvise", a::MADVISE),
        ("getdents64", a::GETDENTS64),
        ("futex", a::FUTEX),
        ("sched_getaffinity", a::SCHED_GETAFFINITY),
        ("exit_group", a::EXIT_GROUP),
        ("set_tid_address", a::SET_TID_ADDRESS),
        ("clock_gettime", a::CLOCK_GETTIME),
        ("clock_nanosleep", a::CLOCK_NANOSLEEP),
        ("openat", a::OPENAT),
        ("mkdirat", a::MKDIRAT),
        ("newfstatat", a::NEWFSTATAT),
        ("unlinkat", a::UNLINKAT),
        ("readlinkat", a::READLINKAT),
        ("faccessat", a::FACCESSAT),
        ("pselect6", a::PSELECT6),
        ("ppoll", a::PPOLL),
        ("set_robust_list", a::SET_ROBUST_LIST),
        ("getcpu", a::GETCPU),
        ("eventfd2", a::EVENTFD2),
        ("pipe2", a::PIPE2),
        ("dup3", a::DUP3),
        ("prlimit64", a::PRLIMIT64),
        ("getrandom", a::GETRANDOM),
        ("memfd_create", a::MEMFD_CREATE),
        ("statx", a::STATX),
        ("rseq", a::RSEQ),
        ("clone3", a::CLONE3),
        ("openat2", a::OPENAT2),
    ] {
        let got = nums
            .get(name)
            .unwrap_or_else(|| panic!("tbl に {name} がない"));
        assert_eq!(*got, want, "__NR_{name} の番号が UAPI と食い違う");
    }
}
