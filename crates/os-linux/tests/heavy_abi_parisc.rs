// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! parisc の ABI 表とカーネル UAPI の突き合わせ（層6・abi、S17-2）。
//!
//! PA-RISC の UAPI 番号は `arch/parisc/kernel/syscalls/syscall.tbl` が正本。
//! abi 列は common・32・64 で、hppa32 が使うのは common と 32 の行。
//! 同じ番号に 32 と 64 の行が並ぶときは 32 の行を取る（現行 tbl では
//! 同名）。64 の行だけを持つ番号は hppa32 の表に入らない。出典は
//! `.testdata/uapi-hppa`（台帳 SRC-LINUX-HPPA-UAPI・用途T）。
//! データがなければ devtool test:plan が外す。

use std::collections::HashMap;
use std::path::PathBuf;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/uapi-hppa")
}

/// `syscall.tbl` を番号→名に畳む。4 列は 番号・abi・名・入口点。
/// hppa32 の表なので abi が common と 32 の行だけを載せる。
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
            "common" | "32" => {
                map.insert(n, name.to_string());
            }
            "64" => {}
            _ => panic!("tbl の abi 列が読めない: {line:?}"),
        }
    }
    map
}

#[test]
fn syscall_numbers_match_uapi_parisc() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-HPPA-UAPI を {} に置く。リポジトリには含めない。",
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
    use polyisa_os_linux::parisc::nr as a;
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
        ("stat", a::STAT),
        ("lseek", a::LSEEK),
        ("getpid", a::GETPID),
        ("mount", a::MOUNT),
        ("setuid", a::SETUID),
        ("getuid", a::GETUID),
        ("stime", a::STIME),
        ("ptrace", a::PTRACE),
        ("alarm", a::ALARM),
        ("fstat", a::FSTAT),
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
        ("signal", a::SIGNAL),
        ("geteuid", a::GETEUID),
        ("getegid", a::GETEGID),
        ("acct", a::ACCT),
        ("umount2", a::UMOUNT2),
        ("ioctl", a::IOCTL),
        ("fcntl", a::FCNTL),
        ("setpgid", a::SETPGID),
        ("uname", a::UNAME),
        ("umask", a::UMASK),
        ("chroot", a::CHROOT),
        ("ustat", a::USTAT),
        ("dup2", a::DUP2),
        ("getppid", a::GETPPID),
        ("getpgrp", a::GETPGRP),
        ("setsid", a::SETSID),
        ("pivot_root", a::PIVOT_ROOT),
        ("sgetmask", a::SGETMASK),
        ("ssetmask", a::SSETMASK),
        ("setreuid", a::SETREUID),
        ("setregid", a::SETREGID),
        ("mincore", a::MINCORE),
        ("sigpending", a::SIGPENDING),
        ("sethostname", a::SETHOSTNAME),
        ("setrlimit", a::SETRLIMIT),
        ("getrlimit", a::GETRLIMIT),
        ("getrusage", a::GETRUSAGE),
        ("gettimeofday", a::GETTIMEOFDAY),
        ("settimeofday", a::SETTIMEOFDAY),
        ("getgroups", a::GETGROUPS),
        ("setgroups", a::SETGROUPS),
        ("symlink", a::SYMLINK),
        ("lstat", a::LSTAT),
        ("readlink", a::READLINK),
        ("uselib", a::USELIB),
        ("swapon", a::SWAPON),
        ("reboot", a::REBOOT),
        ("mmap2", a::MMAP2),
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
        ("stat64", a::STAT64),
        ("syslog", a::SYSLOG),
        ("setitimer", a::SETITIMER),
        ("getitimer", a::GETITIMER),
        ("capget", a::CAPGET),
        ("capset", a::CAPSET),
        ("pread64", a::PREAD64),
        ("pwrite64", a::PWRITE64),
        ("getcwd", a::GETCWD),
        ("vhangup", a::VHANGUP),
        ("fstat64", a::FSTAT64),
        ("vfork", a::VFORK),
        ("wait4", a::WAIT4),
        ("swapoff", a::SWAPOFF),
        ("sysinfo", a::SYSINFO),
        ("fsync", a::FSYNC),
        ("madvise", a::MADVISE),
        ("clone", a::CLONE),
        ("setdomainname", a::SETDOMAINNAME),
        ("sendfile", a::SENDFILE),
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
        ("sigaltstack", a::SIGALTSTACK),
        ("poll", a::POLL),
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
        ("chown", a::CHOWN),
        ("lstat64", a::LSTAT64),
        ("truncate64", a::TRUNCATE64),
        ("ftruncate64", a::FTRUNCATE64),
        ("getdents64", a::GETDENTS64),
        ("fcntl64", a::FCNTL64),
        ("gettid", a::GETTID),
        ("readahead", a::READAHEAD),
        ("tkill", a::TKILL),
        ("sendfile64", a::SENDFILE64),
        ("futex", a::FUTEX),
        ("sched_setaffinity", a::SCHED_SETAFFINITY),
        ("sched_getaffinity", a::SCHED_GETAFFINITY),
        ("exit_group", a::EXIT_GROUP),
        ("epoll_create", a::EPOLL_CREATE),
        ("remap_file_pages", a::REMAP_FILE_PAGES),
        ("waitid", a::WAITID),
        ("fadvise64_64", a::FADVISE64_64),
        ("set_tid_address", a::SET_TID_ADDRESS),
        ("setxattr", a::SETXATTR),
        ("lsetxattr", a::LSETXATTR),
        ("fsetxattr", a::FSETXATTR),
        ("getxattr", a::GETXATTR),
        ("lgetxattr", a::LGETXATTR),
        ("fgetxattr", a::FGETXATTR),
        ("listxattr", a::LISTXATTR),
        ("llistxattr", a::LLISTXATTR),
        ("flistxattr", a::FLISTXATTR),
        ("removexattr", a::REMOVEXATTR),
        ("lremovexattr", a::LREMOVEXATTR),
        ("fremovexattr", a::FREMOVEXATTR),
        ("clock_settime", a::CLOCK_SETTIME),
        ("clock_gettime", a::CLOCK_GETTIME),
        ("clock_getres", a::CLOCK_GETRES),
        ("clock_nanosleep", a::CLOCK_NANOSLEEP),
        ("tgkill", a::TGKILL),
        ("ioprio_set", a::IOPRIO_SET),
        ("ioprio_get", a::IOPRIO_GET),
        ("pselect6", a::PSELECT6),
        ("ppoll", a::PPOLL),
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
        ("set_robust_list", a::SET_ROBUST_LIST),
        ("get_robust_list", a::GET_ROBUST_LIST),
        ("sync_file_range", a::SYNC_FILE_RANGE),
        ("getcpu", a::GETCPU),
        ("statfs64", a::STATFS64),
        ("fstatfs64", a::FSTATFS64),
        ("utimensat", a::UTIMENSAT),
        ("fallocate", a::FALLOCATE),
        ("dup3", a::DUP3),
        ("pipe2", a::PIPE2),
        ("rt_tgsigqueueinfo", a::RT_TGSIGQUEUEINFO),
        ("prlimit64", a::PRLIMIT64),
        ("clock_adjtime", a::CLOCK_ADJTIME),
        ("syncfs", a::SYNCFS),
        ("utimes", a::UTIMES),
        ("renameat2", a::RENAMEAT2),
        ("getrandom", a::GETRANDOM),
        ("execveat", a::EXECVEAT),
        ("mlock2", a::MLOCK2),
        ("statx", a::STATX),
        ("rseq", a::RSEQ),
        ("cacheflush", a::CACHEFLUSH),
        ("clock_gettime64", a::CLOCK_GETTIME64),
        ("clock_settime64", a::CLOCK_SETTIME64),
        ("clock_adjtime64", a::CLOCK_ADJTIME64),
        ("clock_getres_time64", a::CLOCK_GETRES_TIME64),
        ("clock_nanosleep_time64", a::CLOCK_NANOSLEEP_TIME64),
        ("utimensat_time64", a::UTIMENSAT_TIME64),
        ("pselect6_time64", a::PSELECT6_TIME64),
        ("ppoll_time64", a::PPOLL_TIME64),
        ("futex_time64", a::FUTEX_TIME64),
        (
            "sched_rr_get_interval_time64",
            a::SCHED_RR_GET_INTERVAL_TIME64,
        ),
        ("clone3", a::CLONE3),
        ("faccessat2", a::FACCESSAT2),
    ] {
        let got = want_nr(name);
        assert_eq!(got, want, "__NR_{name} の番号が UAPI と食い違う");
    }
}

#[test]
fn name_table_covers_uapi_parisc() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-HPPA-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let names = tbl_names(&tbl);
    // 実装の全エントリが tbl の同じ番号の名と一致すること。
    for nr in 0..=472u64 {
        let Some(got) = polyisa_os_linux::parisc::name(nr) else {
            continue;
        };
        let Some(want) = names.get(&nr) else {
            panic!("実装が hppa32 の UAPI にない番号 {nr}({got}) を持つ");
        };
        assert_eq!(got, want, "name({nr}) が UAPI と食い違う");
    }
    // tbl の common・32 の全番号が実装に載っていること（UAPI 側の漏れ検出）。
    for (nr, want) in &names {
        assert!(
            polyisa_os_linux::parisc::name(*nr).is_some(),
            "UAPI の {nr}({want}) が実装にない"
        );
    }
    // UAPI の最大番号を超える実装エントリがないこと。
    assert!(
        polyisa_os_linux::parisc::name(473).is_none(),
        "UAPI の最大番号を超える実装エントリがある"
    );
}
