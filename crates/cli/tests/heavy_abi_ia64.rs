// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ia64 の ABI 表とカーネル UAPI の突き合わせ（層6・abi、S21-2 の
//! 機械的証拠）。
//!
//! ia64 はアーチ固有の `arch/ia64/kernel/syscalls/syscall.tbl` を
//! 持ち、専用の Makefile が `syscallhdr.sh --emit-nr --offset
//! __NR_Linux` で `include/generated/uapi/asm/unistd_64.h` を生成
//! する（`uapi/asm/unistd.h` は `__NR_Linux`=1024 を定義して
//! `asm/unistd_64.h` を include する）。表の番号に 1024 を足した
//! ものが実際の syscall 番号で、abi 列は全行 common、表番号は
//! 0–452（435 clone3・447 memfd_secret は ia64 では予約の穴）。
//! 実装側は `ia64::SYSCALLS` が表番号（0 起点）の名表を持ち、
//! `ia64::NR_BASE` が 1024、`r15 - NR_BASE` が表番号になる。
//! 出典は `.testdata/uapi-ia64`（台帳 SRC-LINUX-IA64-UAPI・用途T）。
//! データがなければ devtool test:plan が外す。

use std::collections::HashMap;
use std::path::PathBuf;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/uapi-ia64")
}

/// `syscall.tbl` を表番号→名に畳む。4 列は 表番号・abi・名・入口点。
/// ia64 は abi が全行 common で、表番号に `NR_BASE`(1024) を足した
/// ものが実番号になる。コメント行の「# N reserved for ...」は
/// 予約の穴で表には載らない。
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
        assert_eq!(abi, "common", "ia64 の abi は全行 common: {line:?}");
        let n: u64 = num
            .parse()
            .unwrap_or_else(|_| panic!("tbl の番号: {line:?}"));
        if let Some(prev) = map.insert(n, name.to_string()) {
            panic!("tbl で番号 {n} が重複する（{prev} と {name}）");
        }
    }
    map
}

/// +1024 規約の生成経路を固定する: `syscalls-Makefile` が
/// `syscallhdr.sh --emit-nr --offset __NR_Linux` を呼び、
/// `uapi/asm/unistd.h` が `__NR_Linux` を 1024 と定義すること。
/// 実装の `NR_BASE`・`NR_SYSCALLS`（表番号の上限 + 1）がその値と
/// 一致することを併せて見る。
#[test]
fn nr_base_rule_matches_uapi_ia64() {
    let mk = data_dir().join("kernel/syscalls-Makefile");
    assert!(
        mk.is_file(),
        "SRC-LINUX-IA64-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let text = std::fs::read_to_string(&mk).expect("syscalls-Makefile を読む");
    assert!(
        text.contains("--emit-nr --offset __NR_Linux"),
        "ia64 の unistd_64.h 生成が --offset __NR_Linux ではない"
    );
    let uh = data_dir().join("uapi-asm/unistd.h");
    let text = std::fs::read_to_string(&uh).expect("uapi-asm/unistd.h を読む");
    assert!(
        text.contains("__NR_Linux      1024"),
        "uapi-asm/unistd.h の __NR_Linux が 1024 ではない"
    );
    assert_eq!(
        polyisa_os_linux::ia64::NR_BASE,
        1024,
        "NR_BASE が __NR_Linux=1024 と食い違う"
    );
    let names = tbl_names(&data_dir().join("syscall.tbl"));
    let max = names.keys().copied().max().unwrap_or(0);
    assert_eq!(
        polyisa_os_linux::ia64::NR_SYSCALLS,
        max + 1,
        "NR_SYSCALLS が表番号の上限 + 1 と食い違う"
    );
}

#[test]
fn syscall_numbers_match_uapi_ia64() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-IA64-UAPI を {} に置く。リポジトリには含めない。",
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
    use polyisa_os_linux::ia64::nr as a;
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
        ("fchdir", a::FCHDIR),
        ("utimes", a::UTIMES),
        ("mknod", a::MKNOD),
        ("chmod", a::CHMOD),
        ("chown", a::CHOWN),
        ("lseek", a::LSEEK),
        ("getpid", a::GETPID),
        ("getppid", a::GETPPID),
        ("setuid", a::SETUID),
        ("getuid", a::GETUID),
        ("geteuid", a::GETEUID),
        ("ptrace", a::PTRACE),
        ("access", a::ACCESS),
        ("sync", a::SYNC),
        ("fsync", a::FSYNC),
        ("fdatasync", a::FDATASYNC),
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
        ("getegid", a::GETEGID),
        ("ioctl", a::IOCTL),
        ("fcntl", a::FCNTL),
        ("umask", a::UMASK),
        ("dup2", a::DUP2),
        ("setreuid", a::SETREUID),
        ("setregid", a::SETREGID),
        ("getresuid", a::GETRESUID),
        ("getresgid", a::GETRESGID),
        ("getgroups", a::GETGROUPS),
        ("setgroups", a::SETGROUPS),
        ("getpgid", a::GETPGID),
        ("setpgid", a::SETPGID),
        ("setsid", a::SETSID),
        ("getsid", a::GETSID),
        ("sethostname", a::SETHOSTNAME),
        ("setrlimit", a::SETRLIMIT),
        ("getrlimit", a::GETRLIMIT),
        ("getrusage", a::GETRUSAGE),
        ("gettimeofday", a::GETTIMEOFDAY),
        ("select", a::SELECT),
        ("poll", a::POLL),
        ("symlink", a::SYMLINK),
        ("readlink", a::READLINK),
        ("truncate", a::TRUNCATE),
        ("ftruncate", a::FTRUNCATE),
        ("fchmod", a::FCHMOD),
        ("fchown", a::FCHOWN),
        ("getpriority", a::GETPRIORITY),
        ("setpriority", a::SETPRIORITY),
        ("statfs", a::STATFS),
        ("fstatfs", a::FSTATFS),
        ("gettid", a::GETTID),
        ("syslog", a::SYSLOG),
        ("setitimer", a::SETITIMER),
        ("getitimer", a::GETITIMER),
        ("vhangup", a::VHANGUP),
        ("lchown", a::LCHOWN),
        ("wait4", a::WAIT4),
        ("sysinfo", a::SYSINFO),
        ("clone", a::CLONE),
        ("uname", a::UNAME),
        ("setdomainname", a::SETDOMAINNAME),
        ("adjtimex", a::ADJTIMEX),
        ("personality", a::PERSONALITY),
        ("getdents", a::GETDENTS),
        ("flock", a::FLOCK),
        ("readv", a::READV),
        ("writev", a::WRITEV),
        ("pread64", a::PREAD64),
        ("pwrite64", a::PWRITE64),
        ("mmap", a::MMAP),
        ("munmap", a::MUNMAP),
        ("mlock", a::MLOCK),
        ("mlockall", a::MLOCKALL),
        ("mprotect", a::MPROTECT),
        ("mremap", a::MREMAP),
        ("msync", a::MSYNC),
        ("munlock", a::MUNLOCK),
        ("munlockall", a::MUNLOCKALL),
        ("sched_getparam", a::SCHED_GETPARAM),
        ("sched_setparam", a::SCHED_SETPARAM),
        ("sched_getscheduler", a::SCHED_GETSCHEDULER),
        ("sched_setscheduler", a::SCHED_SETSCHEDULER),
        ("sched_yield", a::SCHED_YIELD),
        ("sched_get_priority_max", a::SCHED_GET_PRIORITY_MAX),
        ("sched_get_priority_min", a::SCHED_GET_PRIORITY_MIN),
        ("sched_rr_get_interval", a::SCHED_RR_GET_INTERVAL),
        ("nanosleep", a::NANOSLEEP),
        ("prctl", a::PRCTL),
        ("old_getpagesize", a::OLD_GETPAGESIZE),
        ("mmap2", a::MMAP2),
        ("perfmonctl", a::PERFMONCTL),
        ("sigaltstack", a::SIGALTSTACK),
        ("rt_sigaction", a::RT_SIGACTION),
        ("rt_sigpending", a::RT_SIGPENDING),
        ("rt_sigprocmask", a::RT_SIGPROCMASK),
        ("rt_sigqueueinfo", a::RT_SIGQUEUEINFO),
        ("rt_sigreturn", a::RT_SIGRETURN),
        ("rt_sigsuspend", a::RT_SIGSUSPEND),
        ("rt_sigtimedwait", a::RT_SIGTIMEDWAIT),
        ("getcwd", a::GETCWD),
        ("capget", a::CAPGET),
        ("capset", a::CAPSET),
        ("sendfile", a::SENDFILE),
        ("mincore", a::MINCORE),
        ("madvise", a::MADVISE),
        ("stat", a::STAT),
        ("lstat", a::LSTAT),
        ("fstat", a::FSTAT),
        ("clone2", a::CLONE2),
        ("getdents64", a::GETDENTS64),
        ("getunwind", a::GETUNWIND),
        ("readahead", a::READAHEAD),
        ("setxattr", a::SETXATTR),
        ("getxattr", a::GETXATTR),
        ("listxattr", a::LISTXATTR),
        ("removexattr", a::REMOVEXATTR),
        ("tkill", a::TKILL),
        ("futex", a::FUTEX),
        ("sched_setaffinity", a::SCHED_SETAFFINITY),
        ("sched_getaffinity", a::SCHED_GETAFFINITY),
        ("set_tid_address", a::SET_TID_ADDRESS),
        ("fadvise64", a::FADVISE64),
        ("tgkill", a::TGKILL),
        ("exit_group", a::EXIT_GROUP),
        ("io_setup", a::IO_SETUP),
        ("epoll_create", a::EPOLL_CREATE),
        ("epoll_ctl", a::EPOLL_CTL),
        ("epoll_wait", a::EPOLL_WAIT),
        ("restart_syscall", a::RESTART_SYSCALL),
        ("clock_settime", a::CLOCK_SETTIME),
        ("clock_gettime", a::CLOCK_GETTIME),
        ("clock_getres", a::CLOCK_GETRES),
        ("clock_nanosleep", a::CLOCK_NANOSLEEP),
        ("fstatfs64", a::FSTATFS64),
        ("statfs64", a::STATFS64),
        ("waitid", a::WAITID),
        ("ioprio_set", a::IOPRIO_SET),
        ("ioprio_get", a::IOPRIO_GET),
        ("inotify_init", a::INOTIFY_INIT),
        ("openat", a::OPENAT),
        ("mkdirat", a::MKDIRAT),
        ("mknodat", a::MKNODAT),
        ("fchownat", a::FCHOWNAT),
        ("futimesat", a::FUTIMESAT),
        ("newfstatat", a::NEWFSTATAT),
        ("unlinkat", a::UNLINKAT),
        ("renameat", a::RENAMEAT),
        ("linkat", a::LINKAT),
        ("symlinkat", a::SYMLINKAT),
        ("readlinkat", a::READLINKAT),
        ("fchmodat", a::FCHMODAT),
        ("faccessat", a::FACCESSAT),
        ("pselect6", a::PSELECT6),
        ("ppoll", a::PPOLL),
        ("unshare", a::UNSHARE),
        ("splice", a::SPLICE),
        ("set_robust_list", a::SET_ROBUST_LIST),
        ("sync_file_range", a::SYNC_FILE_RANGE),
        ("fallocate", a::FALLOCATE),
        ("getcpu", a::GETCPU),
        ("epoll_pwait", a::EPOLL_PWAIT),
        ("utimensat", a::UTIMENSAT),
        ("timerfd_create", a::TIMERFD_CREATE),
        ("epoll_create1", a::EPOLL_CREATE1),
        ("dup3", a::DUP3),
        ("pipe2", a::PIPE2),
        ("inotify_init1", a::INOTIFY_INIT1),
        ("preadv", a::PREADV),
        ("pwritev", a::PWRITEV),
        ("prlimit64", a::PRLIMIT64),
        ("process_vm_readv", a::PROCESS_VM_READV),
        ("process_vm_writev", a::PROCESS_VM_WRITEV),
        ("accept4", a::ACCEPT4),
        ("renameat2", a::RENAMEAT2),
        ("getrandom", a::GETRANDOM),
        ("memfd_create", a::MEMFD_CREATE),
        ("execveat", a::EXECVEAT),
        ("mlock2", a::MLOCK2),
        ("copy_file_range", a::COPY_FILE_RANGE),
        ("statx", a::STATX),
        ("seccomp", a::SECCOMP),
        ("rseq", a::RSEQ),
        ("close_range", a::CLOSE_RANGE),
        ("openat2", a::OPENAT2),
        ("faccessat2", a::FACCESSAT2),
    ] {
        let got = want_nr(name);
        assert_eq!(got, want, "__NR_{name} の番号が UAPI と食い違う");
    }
}

#[test]
fn name_table_covers_uapi_ia64() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-IA64-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let names = tbl_names(&tbl);
    // 実装の全エントリが tbl の同じ番号の名と一致すること。
    for (nr, got) in polyisa_os_linux::ia64::SYSCALLS {
        let Some(want) = names.get(nr) else {
            panic!("実装が ia64 の UAPI にない番号 {nr}({got}) を持つ");
        };
        assert_eq!(got, want, "name({nr}) が UAPI と食い違う");
    }
    // tbl の全番号が実装に載っていること（UAPI 側の漏れ検出）。
    for (nr, want) in &names {
        assert!(
            polyisa_os_linux::ia64::name(*nr).is_some(),
            "UAPI の {nr}({want}) が実装にない"
        );
    }
    // 予約の穴（435 clone3・447 memfd_secret）が実装にもないこと。
    for hole in [435u64, 447] {
        assert!(
            !names.contains_key(&hole) && polyisa_os_linux::ia64::name(hole).is_none(),
            "予約番号 {hole} が実装か tbl にある"
        );
    }
    // UAPI の最大番号を超える実装エントリがないこと。
    let max = names.keys().copied().max().unwrap_or(0);
    assert_eq!(
        polyisa_os_linux::ia64::SYSCALLS
            .iter()
            .map(|(n, _)| *n)
            .max(),
        Some(max),
        "実装表の最大番号が UAPI と食い違う"
    );
    assert!(
        polyisa_os_linux::ia64::name(max + 1).is_none(),
        "UAPI の最大番号を超える実装エントリがある"
    );
}
