// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Power（ppc64）ABI 表とカーネル UAPI の突き合わせ（層6・abi、S8-2）。
//!
//! powerpc の UAPI 番号は `arch/powerpc/kernel/syscalls/syscall.tbl`
//! が正本である。ppc64 は abi 列が `common`・`nospu`・`64` の行を使う
//! （`32`・`spu` 行は compat/SPU 専用で ppc64 ユーザには出ない）。
//! 出典は `.testdata/uapi-powerpc`（台帳 SRC-LINUX-POWERPC-UAPI・用途T）。
//! データがなければ devtool test:plan が外す。

use std::path::PathBuf;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/uapi-powerpc")
}

/// `syscall.tbl` の（common|nospu|64）行を name→番号に畳む。
/// `32`・`spu` 行は ppc64 ユーザが使わないので捨てる。
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
        if abi == "32" || abi == "spu" {
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
fn syscall_numbers_match_uapi_powerpc64() {
    let tbl = data_dir().join("syscall.tbl");
    assert!(
        tbl.is_file(),
        "SRC-LINUX-POWERPC-UAPI を {} に置く。リポジトリには含めない。",
        data_dir().display()
    );
    let nums = tbl_numbers(&tbl);
    use polyisa_os_linux::power as a;
    // (tbl の名, polyisa の番号)。powerpc 固有の別名:
    //   _llseek/_newselect/_sysctl は先頭に '_' がつく。
    //   getrlimit(76) は 64 ビットで ni-syscall。実装が使うのは
    //   ugetrlimit(190) で、musl の SYS_getrlimit はこちらを指す。
    //   sync_file_range は ppc64 では sync_file_range2(308)。
    // truncate64/ftruncate64/fcntl64 は 32 行のみ（ppc32 compat）なので
    // ppc64 の突き合わせ対象から外す。
    for (name, want) in [
        ("exit", a::EXIT),
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
        ("setuid", a::SETUID),
        ("getuid", a::GETUID),
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
        ("dup2", a::DUP2),
        ("getppid", a::GETPPID),
        ("getpgrp", a::GETPGRP),
        ("setsid", a::SETSID),
        ("setreuid", a::SETREUID),
        ("setregid", a::SETREGID),
        ("sethostname", a::SETHOSTNAME),
        ("setrlimit", a::SETRLIMIT),
        ("getrusage", a::GETRUSAGE),
        ("gettimeofday", a::GETTIMEOFDAY),
        ("settimeofday", a::SETTIMEOFDAY),
        ("getgroups", a::GETGROUPS),
        ("setgroups", a::SETGROUPS),
        ("select", a::SELECT),
        ("symlink", a::SYMLINK),
        ("readlink", a::READLINK),
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
        ("ipc", a::IPC),
        ("fsync", a::FSYNC),
        ("clone", a::CLONE),
        ("setdomainname", a::SETDOMAINNAME),
        ("uname", a::UNAME),
        ("adjtimex", a::ADJTIMEX),
        ("mprotect", a::MPROTECT),
        ("init_module", a::INIT_MODULE),
        ("delete_module", a::DELETE_MODULE),
        ("quotactl", a::QUOTACTL),
        ("getpgid", a::GETPGID),
        ("fchdir", a::FCHDIR),
        ("sysfs", a::SYSFS),
        ("personality", a::PERSONALITY),
        ("setfsuid", a::SETFSUID),
        ("setfsgid", a::SETFSGID),
        ("_llseek", a::LLSEEK),
        ("getdents", a::GETDENTS),
        ("_newselect", a::NEWSELECT),
        ("flock", a::FLOCK),
        ("msync", a::MSYNC),
        ("readv", a::READV),
        ("writev", a::WRITEV),
        ("getsid", a::GETSID),
        ("fdatasync", a::FDATASYNC),
        ("_sysctl", a::SYSCTL),
        ("mlock", a::MLOCK),
        ("munlock", a::MUNLOCK),
        ("mlockall", a::MLOCKALL),
        ("munlockall", a::MUNLOCKALL),
        ("sched_yield", a::SCHED_YIELD),
        ("nanosleep", a::NANOSLEEP),
        ("mremap", a::MREMAP),
        ("setresuid", a::SETRESUID),
        ("getresuid", a::GETRESUID),
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
        ("pread64", a::PREAD64),
        ("pwrite64", a::PWRITE64),
        ("chown", a::CHOWN),
        ("getcwd", a::GETCWD),
        ("capget", a::CAPGET),
        ("capset", a::CAPSET),
        ("sigaltstack", a::SIGALTSTACK),
        ("sendfile", a::SENDFILE),
        ("vfork", a::VFORK),
        ("ugetrlimit", a::GETRLIMIT),
        ("readahead", a::READAHEAD),
        ("getdents64", a::GETDENTS64),
        ("pivot_root", a::PIVOT_ROOT),
        ("madvise", a::MADVISE),
        ("mincore", a::MINCORE),
        ("gettid", a::GETTID),
        ("tkill", a::TKILL),
        ("futex", a::FUTEX),
        ("sched_setaffinity", a::SCHED_SETAFFINITY),
        ("sched_getaffinity", a::SCHED_GETAFFINITY),
        ("io_setup", a::IO_SETUP),
        ("io_destroy", a::IO_DESTROY),
        ("io_getevents", a::IO_GETEVENTS),
        ("io_submit", a::IO_SUBMIT),
        ("io_cancel", a::IO_CANCEL),
        ("set_tid_address", a::SET_TID_ADDRESS),
        ("fadvise64", a::FADVISE64),
        ("exit_group", a::EXIT_GROUP),
        ("epoll_create", a::EPOLL_CREATE),
        ("epoll_ctl", a::EPOLL_CTL),
        ("epoll_wait", a::EPOLL_WAIT),
        ("clock_settime", a::CLOCK_SETTIME),
        ("clock_gettime", a::CLOCK_GETTIME),
        ("clock_getres", a::CLOCK_GETRES),
        ("clock_nanosleep", a::CLOCK_NANOSLEEP),
        ("tgkill", a::TGKILL),
        ("statfs64", a::STATFS64),
        ("fstatfs64", a::FSTATFS64),
        ("waitid", a::WAITID),
        ("inotify_init", a::INOTIFY_INIT),
        ("pselect6", a::PSELECT6),
        ("ppoll", a::PPOLL),
        ("splice", a::SPLICE),
        ("tee", a::TEE),
        ("vmsplice", a::VMSPLICE),
        ("openat", a::OPENAT),
        ("mkdirat", a::MKDIRAT),
        ("mknodat", a::MKNODAT),
        ("fchownat", a::FCHOWNAT),
        ("newfstatat", a::NEWFSTATAT),
        ("unlinkat", a::UNLINKAT),
        ("renameat", a::RENAMEAT),
        ("linkat", a::LINKAT),
        ("symlinkat", a::SYMLINKAT),
        ("readlinkat", a::READLINKAT),
        ("fchmodat", a::FCHMODAT),
        ("faccessat", a::FACCESSAT),
        ("set_robust_list", a::SET_ROBUST_LIST),
        ("getcpu", a::GETCPU),
        ("epoll_pwait", a::EPOLL_PWAIT),
        ("utimensat", a::UTIMENSAT),
        ("signalfd", a::SIGNALFD),
        ("timerfd_create", a::TIMERFD_CREATE),
        ("eventfd", a::EVENTFD),
        ("sync_file_range2", a::SYNC_FILE_RANGE),
        ("fallocate", a::FALLOCATE),
        ("timerfd_settime", a::TIMERFD_SETTIME),
        ("timerfd_gettime", a::TIMERFD_GETTIME),
        ("signalfd4", a::SIGNALFD4),
        ("eventfd2", a::EVENTFD2),
        ("epoll_create1", a::EPOLL_CREATE1),
        ("dup3", a::DUP3),
        ("pipe2", a::PIPE2),
        ("inotify_init1", a::INOTIFY_INIT1),
        ("perf_event_open", a::PERF_EVENT_OPEN),
        ("prlimit64", a::PRLIMIT64),
        ("renameat2", a::RENAMEAT2),
        ("seccomp", a::SECCOMP),
        ("getrandom", a::GETRANDOM),
        ("memfd_create", a::MEMFD_CREATE),
        ("membarrier", a::MEMBARRIER),
        ("mlock2", a::MLOCK2),
        ("copy_file_range", a::COPY_FILE_RANGE),
        ("statx", a::STATX),
        ("rseq", a::RSEQ),
    ] {
        let got = nums
            .get(name)
            .unwrap_or_else(|| panic!("tbl に {name} がない"));
        assert_eq!(*got, want, "__NR_{name} の番号が UAPI と食い違う");
    }
}
