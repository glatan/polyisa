// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! superh の ABI 表とカーネル UAPI の突き合わせ（層6・abi、S18-2）。
//!
//! SH の UAPI 番号は `arch/sh/kernel/syscalls/syscall.tbl` が正本。
//! abi 列は全行 common（sh は 32 ビットのみ）。出典は
//! `.testdata/uapi-sh`（台帳 SRC-LINUX-SH-UAPI・用途T）。
//! データがなければ devtool test:plan が外す。

use std::collections::HashMap;
use std::path::PathBuf;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/uapi-sh")
}

/// `syscall.tbl` を番号→名に畳む。4 列は 番号・abi・名・入口点。
/// sh の abi 列は全行 common。
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
        let n: u64 = num
            .parse()
            .unwrap_or_else(|_| panic!("tbl の番号: {line:?}"));
        match abi {
            "common" => {
                map.insert(n, name.to_string());
            }
            _ => panic!("tbl の abi 列が読めない: {line:?}"),
        }
    }
    map
}

#[test]
fn syscall_numbers_match_uapi_sh() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-SH-UAPI を {} に置く。リポジトリには含めない。",
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
    use polyisa_os_linux::superh::nr as a;
    for (name, want) in [
        ("restart_syscall", a::RESTART_SYSCALL),
        ("exit", a::EXIT),
        ("fork", a::FORK),
        ("read", a::READ),
        ("write", a::WRITE),
        ("open", a::OPEN),
        ("close", a::CLOSE),
        ("waitpid", a::WAITPID),
        ("creat", a::CREAT),
        ("link", a::LINK),
        ("unlink", a::UNLINK),
        ("execve", a::EXECVE),
        ("chdir", a::CHDIR),
        ("time", a::TIME),
        ("mknod", a::MKNOD),
        ("chmod", a::CHMOD),
        ("lchown", a::LCHOWN),
        ("lseek", a::LSEEK),
        ("getpid", a::GETPID),
        ("mount", a::MOUNT),
        ("umount", a::UMOUNT),
        ("setuid", a::SETUID),
        ("getuid", a::GETUID),
        ("stime", a::STIME),
        ("ptrace", a::PTRACE),
        ("alarm", a::ALARM),
        ("pause", a::PAUSE),
        ("utime", a::UTIME),
        ("access", a::ACCESS),
        ("nice", a::NICE),
        ("sync", a::SYNC),
        ("kill", a::KILL),
        ("rename", a::RENAME),
        ("mkdir", a::MKDIR),
        ("rmdir", a::RMDIR),
        ("dup", a::DUP),
        ("pipe", a::PIPE),
        ("times", a::TIMES),
        ("brk", a::BRK),
        ("setgid", a::SETGID),
        ("getgid", a::GETGID),
        ("geteuid", a::GETEUID),
        ("getegid", a::GETEGID),
        ("acct", a::ACCT),
        ("umount2", a::UMOUNT2),
        ("ioctl", a::IOCTL),
        ("fcntl", a::FCNTL),
        ("setpgid", a::SETPGID),
        ("umask", a::UMASK),
        ("chroot", a::CHROOT),
        ("ustat", a::USTAT),
        ("dup2", a::DUP2),
        ("getppid", a::GETPPID),
        ("getpgrp", a::GETPGRP),
        ("setsid", a::SETSID),
        ("sigaction", a::SIGACTION),
        ("setrlimit", a::SETRLIMIT),
        ("getrusage", a::GETRUSAGE),
        ("gettimeofday", a::GETTIMEOFDAY),
        ("settimeofday", a::SETTIMEOFDAY),
        ("getgroups", a::GETGROUPS),
        ("setgroups", a::SETGROUPS),
        ("symlink", a::SYMLINK),
        ("readlink", a::READLINK),
        ("uselib", a::USELIB),
        ("swapon", a::SWAPON),
        ("reboot", a::REBOOT),
        ("mmap", a::MMAP),
        ("munmap", a::MUNMAP),
        ("truncate", a::TRUNCATE),
        ("ftruncate", a::FTRUNCATE),
        ("fchmod", a::FCHMOD),
        ("fchown", a::FCHOWN),
        ("getpriority", a::GETPRIORITY),
        ("setpriority", a::SETPRIORITY),
        ("statfs", a::STATFS),
        ("fstatfs", a::FSTATFS),
        ("socketcall", a::SOCKETCALL),
        ("syslog", a::SYSLOG),
        ("setitimer", a::SETITIMER),
        ("getitimer", a::GETITIMER),
        ("stat", a::STAT),
        ("lstat", a::LSTAT),
        ("fstat", a::FSTAT),
        ("vhangup", a::VHANGUP),
        ("wait4", a::WAIT4),
        ("swapoff", a::SWAPOFF),
        ("sysinfo", a::SYSINFO),
        ("fsync", a::FSYNC),
        ("sigreturn", a::SIGRETURN),
        ("clone", a::CLONE),
        ("setdomainname", a::SETDOMAINNAME),
        ("uname", a::UNAME),
        ("cacheflush", a::CACHEFLUSH),
        ("adjtimex", a::ADJTIMEX),
        ("mprotect", a::MPROTECT),
        ("sigprocmask", a::SIGPROCMASK),
        ("init_module", a::INIT_MODULE),
        ("delete_module", a::DELETE_MODULE),
        ("quotactl", a::QUOTACTL),
        ("getpgid", a::GETPGID),
        ("fchdir", a::FCHDIR),
        ("bdflush", a::BDFLUSH),
        ("sysfs", a::SYSFS),
        ("personality", a::PERSONALITY),
        ("setfsuid", a::SETFSUID),
        ("setfsgid", a::SETFSGID),
        ("getrlimit", a::GETRLIMIT),
        ("_llseek", a::_LLSEEK),
        ("getdents", a::GETDENTS),
        ("_newselect", a::_NEWSELECT),
        ("flock", a::FLOCK),
        ("msync", a::MSYNC),
        ("readv", a::READV),
        ("writev", a::WRITEV),
        ("getsid", a::GETSID),
        ("fdatasync", a::FDATASYNC),
        ("_sysctl", a::_SYSCTL),
        ("mlock", a::MLOCK),
        ("munlock", a::MUNLOCK),
        ("mlockall", a::MLOCKALL),
        ("munlockall", a::MUNLOCKALL),
        ("sched_setparam", a::SCHED_SETPARAM),
        ("sched_getparam", a::SCHED_GETPARAM),
        ("sched_setscheduler", a::SCHED_SETSCHEDULER),
        ("sched_getscheduler", a::SCHED_GETSCHEDULER),
        ("sched_yield", a::SCHED_YIELD),
        ("sched_get_priority_max", a::SCHED_GET_PRIORITY_MAX),
        ("sched_get_priority_min", a::SCHED_GET_PRIORITY_MIN),
        ("sched_rr_get_interval", a::SCHED_RR_GET_INTERVAL),
        ("nanosleep", a::NANOSLEEP),
        ("mremap", a::MREMAP),
        ("setresuid", a::SETRESUID),
        ("getresuid", a::GETRESUID),
        ("poll", a::POLL),
        ("nfsservctl", a::NFSSERVCTL),
        ("setresgid", a::SETRESGID),
        ("getresgid", a::GETRESGID),
        ("prctl", a::PRCTL),
        ("rt_sigreturn", a::RT_SIGRETURN),
        ("rt_sigaction", a::RT_SIGACTION),
        ("rt_sigprocmask", a::RT_SIGPROCMASK),
        ("rt_sigpending", a::RT_SIGPENDING),
        ("rt_sigtimedwait", a::RT_SIGTIMEDWAIT),
        ("rt_sigqueueinfo", a::RT_SIGQUEUEINFO),
        ("rt_sigsuspend", a::RT_SIGSUSPEND),
        ("pread64", a::PREAD64),
        ("pwrite64", a::PWRITE64),
        ("chown", a::CHOWN),
        ("getcwd", a::GETCWD),
        ("capget", a::CAPGET),
        ("capset", a::CAPSET),
        ("sigaltstack", a::SIGALTSTACK),
        ("sendfile", a::SENDFILE),
        ("vfork", a::VFORK),
        ("ugetrlimit", a::UGETRLIMIT),
        ("mmap2", a::MMAP2),
        ("truncate64", a::TRUNCATE64),
        ("ftruncate64", a::FTRUNCATE64),
        ("stat64", a::STAT64),
        ("lstat64", a::LSTAT64),
        ("fstat64", a::FSTAT64),
        ("lchown32", a::LCHOWN32),
        ("getuid32", a::GETUID32),
        ("getgid32", a::GETGID32),
        ("geteuid32", a::GETEUID32),
        ("getegid32", a::GETEGID32),
        ("setreuid32", a::SETREUID32),
        ("setregid32", a::SETREGID32),
        ("getgroups32", a::GETGROUPS32),
        ("setgroups32", a::SETGROUPS32),
        ("fchown32", a::FCHOWN32),
        ("setresuid32", a::SETRESUID32),
        ("getresuid32", a::GETRESUID32),
        ("setresgid32", a::SETRESGID32),
        ("getresgid32", a::GETRESGID32),
        ("chown32", a::CHOWN32),
        ("setuid32", a::SETUID32),
        ("setgid32", a::SETGID32),
        ("setfsuid32", a::SETFSUID32),
        ("setfsgid32", a::SETFSGID32),
        ("pivot_root", a::PIVOT_ROOT),
        ("mincore", a::MINCORE),
        ("madvise", a::MADVISE),
        ("getdents64", a::GETDENTS64),
        ("fcntl64", a::FCNTL64),
        ("gettid", a::GETTID),
        ("readahead", a::READAHEAD),
        ("setxattr", a::SETXATTR),
        ("getxattr", a::GETXATTR),
        ("tkill", a::TKILL),
        ("sendfile64", a::SENDFILE64),
        ("futex", a::FUTEX),
        ("sched_setaffinity", a::SCHED_SETAFFINITY),
        ("sched_getaffinity", a::SCHED_GETAFFINITY),
        ("exit_group", a::EXIT_GROUP),
        ("clock_gettime", a::CLOCK_GETTIME),
        ("clock_getres", a::CLOCK_GETRES),
        ("statfs64", a::STATFS64),
        ("fstatfs64", a::FSTATFS64),
        ("tgkill", a::TGKILL),
        ("utimes", a::UTIMES),
        ("fadvise64_64", a::FADVISE64_64),
        ("io_setup", a::IO_SETUP),
        ("fadvise64", a::FADVISE64),
        ("epoll_create", a::EPOLL_CREATE),
        ("remap_file_pages", a::REMAP_FILE_PAGES),
        ("set_tid_address", a::SET_TID_ADDRESS),
        ("openat", a::OPENAT),
        ("fstatat64", a::FSTATAT64),
        ("unlinkat", a::UNLINKAT),
        ("set_robust_list", a::SET_ROBUST_LIST),
        ("splice", a::SPLICE),
        ("getcpu", a::GETCPU),
        ("eventfd", a::EVENTFD),
    ] {
        let got = want_nr(name);
        assert_eq!(got, want, "__NR_{name} の番号が UAPI と食い違う");
    }
}

#[test]
fn name_table_covers_uapi_sh() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-SH-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let names = tbl_names(&tbl);
    // 実装の全エントリが tbl の同じ番号の名と一致すること。
    for nr in 0..=472u64 {
        let Some(got) = polyisa_os_linux::superh::name(nr) else {
            continue;
        };
        let Some(want) = names.get(&nr) else {
            panic!("実装が sh の UAPI にない番号 {nr}({got}) を持つ");
        };
        assert_eq!(got, want, "name({nr}) が UAPI と食い違う");
    }
    // tbl の全番号が実装に載っていること（UAPI 側の漏れ検出）。
    for (nr, want) in &names {
        assert!(
            polyisa_os_linux::superh::name(*nr).is_some(),
            "UAPI の {nr}({want}) が実装にない"
        );
    }
    // UAPI の最大番号を超える実装エントリがないこと。
    assert!(
        polyisa_os_linux::superh::name(473).is_none(),
        "UAPI の最大番号を超える実装エントリがある"
    );
}
