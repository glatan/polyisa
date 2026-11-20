// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! alpha の ABI 表とカーネル UAPI の突き合わせ（層6・abi、S16-2）。
//!
//! Alpha の UAPI 番号は `arch/alpha/kernel/syscalls/syscall.tbl` が正本。
//! abi 列は常に common で、OSF 由来の予約番号（`osf_*` 名の行）は
//! `sys_ni_syscall` に落ちる欠番として残っている。出典は
//! `.testdata/uapi-alpha`（台帳 SRC-LINUX-ALPHA-UAPI・用途T）。
//! データがなければ devtool test:plan が外す。

use std::collections::HashMap;
use std::path::PathBuf;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/uapi-alpha")
}

/// `syscall.tbl` を番号→名に畳む。4 列は 番号・abi・名・入口点。
fn tbl_names(path: &PathBuf) -> HashMap<u64, String> {
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
        assert_eq!(abi, "common", "alpha の abi 列は常に common: {line:?}");
        let n: u64 = num
            .parse()
            .unwrap_or_else(|_| panic!("tbl の番号: {line:?}"));
        map.insert(n, name.to_string());
    }
    map
}

#[test]
fn syscall_numbers_match_uapi_alpha() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-ALPHA-UAPI を {} に置く。リポジトリには含めない。",
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
    use polyisa_os_linux::alpha::nr as a;
    for (name, want) in [
        ("exit", a::EXIT),
        ("fork", a::FORK),
        ("read", a::READ),
        ("write", a::WRITE),
        ("close", a::CLOSE),
        ("link", a::LINK),
        ("unlink", a::UNLINK),
        ("chdir", a::CHDIR),
        ("fchdir", a::FCHDIR),
        ("mknod", a::MKNOD),
        ("chmod", a::CHMOD),
        ("chown", a::CHOWN),
        ("brk", a::BRK),
        ("lseek", a::LSEEK),
        ("getxpid", a::GETXPID),
        ("setuid", a::SETUID),
        ("getxuid", a::GETXUID),
        ("ptrace", a::PTRACE),
        ("access", a::ACCESS),
        ("sync", a::SYNC),
        ("kill", a::KILL),
        ("setpgid", a::SETPGID),
        ("dup", a::DUP),
        ("pipe", a::PIPE),
        ("osf_set_program_attributes", a::OSF_SET_PROGRAM_ATTRIBUTES),
        ("open", a::OPEN),
        ("getxgid", a::GETXGID),
        ("sigpending", a::SIGPENDING),
        ("ioctl", a::IOCTL),
        ("symlink", a::SYMLINK),
        ("readlink", a::READLINK),
        ("execve", a::EXECVE),
        ("umask", a::UMASK),
        ("getpgrp", a::GETPGRP),
        ("getpagesize", a::GETPAGESIZE),
        ("vfork", a::VFORK),
        ("stat", a::STAT),
        ("lstat", a::LSTAT),
        ("mmap", a::MMAP),
        ("munmap", a::MUNMAP),
        ("mprotect", a::MPROTECT),
        ("madvise", a::MADVISE),
        ("getgroups", a::GETGROUPS),
        ("gethostname", a::GETHOSTNAME),
        ("getdtablesize", a::GETDTABLESIZE),
        ("dup2", a::DUP2),
        ("fstat", a::FSTAT),
        ("fcntl", a::FCNTL),
        ("poll", a::POLL),
        ("fsync", a::FSYNC),
        ("sigsuspend", a::SIGSUSPEND),
        ("osf_gettimeofday", a::OSF_GETTIMEOFDAY),
        ("readv", a::READV),
        ("writev", a::WRITEV),
        ("fchown", a::FCHOWN),
        ("fchmod", a::FCHMOD),
        ("setreuid", a::SETREUID),
        ("setregid", a::SETREGID),
        ("rename", a::RENAME),
        ("truncate", a::TRUNCATE),
        ("ftruncate", a::FTRUNCATE),
        ("setgid", a::SETGID),
        ("mkdir", a::MKDIR),
        ("rmdir", a::RMDIR),
        ("getrlimit", a::GETRLIMIT),
        ("setrlimit", a::SETRLIMIT),
        ("setsid", a::SETSID),
        ("sigaction", a::SIGACTION),
        ("getpgid", a::GETPGID),
        ("getsid", a::GETSID),
        ("sigaltstack", a::SIGALTSTACK),
        ("osf_getsysinfo", a::OSF_GETSYSINFO),
        ("osf_setsysinfo", a::OSF_SETSYSINFO),
        ("getdents", a::GETDENTS),
        ("clone", a::CLONE),
        ("mlock", a::MLOCK),
        ("munlock", a::MUNLOCK),
        ("mlockall", a::MLOCKALL),
        ("munlockall", a::MUNLOCKALL),
        ("sysinfo", a::SYSINFO),
        ("times", a::TIMES),
        ("personality", a::PERSONALITY),
        ("setfsuid", a::SETFSUID),
        ("setfsgid", a::SETFSGID),
        ("statfs", a::STATFS),
        ("fstatfs", a::FSTATFS),
        ("sched_setparam", a::SCHED_SETPARAM),
        ("sched_getparam", a::SCHED_GETPARAM),
        ("sched_setscheduler", a::SCHED_SETSCHEDULER),
        ("sched_getscheduler", a::SCHED_GETSCHEDULER),
        ("sched_yield", a::SCHED_YIELD),
        ("sched_get_priority_max", a::SCHED_GET_PRIORITY_MAX),
        ("sched_get_priority_min", a::SCHED_GET_PRIORITY_MIN),
        ("sched_rr_get_interval", a::SCHED_RR_GET_INTERVAL),
        ("uname", a::UNAME),
        ("nanosleep", a::NANOSLEEP),
        ("mremap", a::MREMAP),
        ("setresuid", a::SETRESUID),
        ("getresuid", a::GETRESUID),
        ("prctl", a::PRCTL),
        ("pread64", a::PREAD64),
        ("pwrite64", a::PWRITE64),
        ("rt_sigreturn", a::RT_SIGRETURN),
        ("rt_sigaction", a::RT_SIGACTION),
        ("rt_sigprocmask", a::RT_SIGPROCMASK),
        ("rt_sigpending", a::RT_SIGPENDING),
        ("rt_sigsuspend", a::RT_SIGSUSPEND),
        ("select", a::SELECT),
        ("gettimeofday", a::GETTIMEOFDAY),
        ("settimeofday", a::SETTIMEOFDAY),
        ("getitimer", a::GETITIMER),
        ("setitimer", a::SETITIMER),
        ("utimes", a::UTIMES),
        ("getrusage", a::GETRUSAGE),
        ("wait4", a::WAIT4),
        ("getcwd", a::GETCWD),
        ("capget", a::CAPGET),
        ("capset", a::CAPSET),
        ("sendfile", a::SENDFILE),
        ("setresgid", a::SETRESGID),
        ("getresgid", a::GETRESGID),
        ("mincore", a::MINCORE),
        ("getdents64", a::GETDENTS64),
        ("gettid", a::GETTID),
        ("readahead", a::READAHEAD),
        ("tkill", a::TKILL),
        ("futex", a::FUTEX),
        ("exit_group", a::EXIT_GROUP),
        ("set_tid_address", a::SET_TID_ADDRESS),
        ("restart_syscall", a::RESTART_SYSCALL),
        ("fadvise64", a::FADVISE64),
        ("clock_gettime", a::CLOCK_GETTIME),
        ("clock_getres", a::CLOCK_GETRES),
        ("clock_nanosleep", a::CLOCK_NANOSLEEP),
        ("tgkill", a::TGKILL),
        ("stat64", a::STAT64),
        ("lstat64", a::LSTAT64),
        ("fstat64", a::FSTAT64),
        ("waitid", a::WAITID),
        ("ioprio_set", a::IOPRIO_SET),
        ("ioprio_get", a::IOPRIO_GET),
        ("fdatasync", a::FDATASYNC),
        ("openat", a::OPENAT),
        ("mkdirat", a::MKDIRAT),
        ("mknodat", a::MKNODAT),
        ("fchownat", a::FCHOWNAT),
        ("futimesat", a::FUTIMESAT),
        ("fstatat64", a::FSTATAT64),
        ("unlinkat", a::UNLINKAT),
        ("renameat", a::RENAMEAT),
        ("linkat", a::LINKAT),
        ("symlinkat", a::SYMLINKAT),
        ("readlinkat", a::READLINKAT),
        ("fchmodat", a::FCHMODAT),
        ("faccessat", a::FACCESSAT),
        ("pselect6", a::PSELECT6),
        ("ppoll", a::PPOLL),
        ("set_robust_list", a::SET_ROBUST_LIST),
        ("get_robust_list", a::GET_ROBUST_LIST),
        ("getcpu", a::GETCPU),
        ("utimensat", a::UTIMENSAT),
        ("eventfd", a::EVENTFD),
        ("dup3", a::DUP3),
        ("pipe2", a::PIPE2),
        ("preadv", a::PREADV),
        ("pwritev", a::PWRITEV),
        ("prlimit64", a::PRLIMIT64),
        ("getrandom", a::GETRANDOM),
        ("memfd_create", a::MEMFD_CREATE),
        ("statx", a::STATX),
        ("statfs64", a::STATFS64),
        ("fstatfs64", a::FSTATFS64),
        ("getegid", a::GETEGID),
        ("geteuid", a::GETEUID),
        ("getppid", a::GETPPID),
    ] {
        let got = want_nr(name);
        assert_eq!(got, want, "__NR_{name} の番号が UAPI と食い違う");
    }
}

#[test]
fn name_table_covers_uapi_alpha() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-ALPHA-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let names = tbl_names(&tbl);
    // 実装の全エントリが tbl の同じ番号の名と一致すること。
    for nr in 0..=582u64 {
        let Some(got) = polyisa_os_linux::alpha::name(nr) else {
            continue;
        };
        let Some(want) = names.get(&nr) else {
            panic!("実装が UAPI にない番号 {nr}({got}) を持つ");
        };
        assert_eq!(got, want, "name({nr}) が UAPI と食い違う");
    }
    // tbl の全番号が実装に載っていること（UAPI 側の漏れ検出）。
    for (nr, want) in &names {
        assert!(
            polyisa_os_linux::alpha::name(*nr).is_some(),
            "UAPI の {nr}({want}) が実装にない"
        );
    }
    // UAPI の最大番号を超える実装エントリがないこと。
    assert!(
        polyisa_os_linux::alpha::name(583).is_none(),
        "UAPI の最大番号を超える実装エントリがある"
    );
}
