// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ARM（EABI）ABI 表とカーネル UAPI の突き合わせ（層6・abi、S7-2）。
//!
//! arm の UAPI 番号は `arch/arm/tools/syscall.tbl` と
//! `arch/arm/include/uapi/asm/unistd.h`（__ARM_NR_* 帯）が正本である。
//! 生成ヘッダ（unistd-eabi.h 等）は配布物に含まれないので、両者を
//! `.testdata/uapi-arm`（台帳 SRC-LINUX-ARM-UAPI・用途T）から読み、
//! 番号表と突き合わせる。データがなければ devtool test:plan が外す。

use std::path::PathBuf;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.testdata/uapi-arm")
}

/// `syscall.tbl` の（common|eabi）行を name→番号に畳む。
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
        if abi == "oabi" {
            continue; // EABI では使われない行だけを捨てる。
        }
        let n: u64 = num
            .parse()
            .unwrap_or_else(|_| panic!("tbl の番号: {line:?}"));
        assert!(map.insert(name.to_string(), n).is_none(), "重複: {name}");
    }
    map
}

/// `unistd.h` の `__ARM_NR_x (__ARM_NR_BASE+k)` を x→番号に畳む。
fn arm_private_numbers(path: &PathBuf) -> std::collections::HashMap<String, u64> {
    let text = std::fs::read_to_string(path).expect("unistd.h を読む");
    const BASE: u64 = 0xf0000; // __ARM_NR_BASE（EABI の __NR_SYSCALL_BASE=0）
    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("#define __ARM_NR_") else {
            continue;
        };
        let mut cols = rest.split_whitespace();
        let name = cols.next().expect("ARM_NR 名");
        if name == "BASE" {
            continue;
        }
        let expr = cols
            .next()
            .expect("ARM_NR 式")
            .trim_matches(|c| c == '(' || c == ')');
        let k: u64 = expr
            .strip_prefix("__ARM_NR_BASE+")
            .and_then(|t| t.parse().ok())
            .unwrap_or_else(|| panic!("ARM_NR の式が読めない: {line:?}"));
        map.insert(name.to_string(), BASE + k);
    }
    map
}

#[test]
fn syscall_numbers_match_uapi_arm() {
    let dir = data_dir();
    let tbl = dir.join("syscall.tbl");
    let unistd = dir.join("asm/unistd.h");
    assert!(
        tbl.is_file() && unistd.is_file(),
        "SRC-LINUX-ARM-UAPI を {} に置く（syscall.tbl と asm/unistd.h）。リポジトリには含めない。",
        dir.display()
    );
    let nums = tbl_numbers(&tbl);
    let arm_priv = arm_private_numbers(&unistd);
    use polyisa_os_linux::arm as a;
    // (tbl の名, polyisa の番号)。tbl の名は syscall 名（__NR_ を除く）。
    for (name, want) in [
        ("restart_syscall", a::RESTART_SYSCALL),
        ("exit", a::EXIT),
        ("exit_group", a::EXIT_GROUP),
        ("read", a::READ),
        ("write", a::WRITE),
        ("readv", a::READV),
        ("writev", a::WRITEV),
        ("pread64", a::PREAD64),
        ("pwrite64", a::PWRITE64),
        ("open", a::OPEN),
        ("openat", a::OPENAT),
        ("close", a::CLOSE),
        ("creat", a::CREAT),
        ("link", a::LINK),
        ("unlink", a::UNLINK),
        ("execve", a::EXECVE),
        ("chdir", a::CHDIR),
        ("fchdir", a::FCHDIR),
        ("mknod", a::MKNOD),
        ("chmod", a::CHMOD),
        ("lchown", a::LCHOWN),
        ("lseek", a::LSEEK),
        ("_llseek", a::LLSEEK),
        ("getpid", a::GETPID),
        ("getppid", a::GETPPID),
        ("mount", a::MOUNT),
        ("umount2", a::UMOUNT2),
        ("setuid", a::SETUID),
        ("getuid", a::GETUID),
        ("ptrace", a::PTRACE),
        ("access", a::ACCESS),
        ("sync", a::SYNC),
        ("kill", a::KILL),
        ("rename", a::RENAME),
        ("mkdir", a::MKDIR),
        ("rmdir", a::RMDIR),
        ("dup", a::DUP),
        ("dup2", a::DUP2),
        ("dup3", a::DUP3),
        ("pipe", a::PIPE),
        ("pipe2", a::PIPE2),
        ("times", a::TIMES),
        ("brk", a::BRK),
        ("setgid", a::SETGID),
        ("getgid", a::GETGID),
        ("geteuid", a::GETEUID),
        ("getegid", a::GETEGID),
        ("acct", a::ACCT),
        ("ioctl", a::IOCTL),
        ("fcntl", a::FCNTL),
        ("fcntl64", a::FCNTL64),
        ("setpgid", a::SETPGID),
        ("umask", a::UMASK),
        ("chroot", a::CHROOT),
        ("ustat", a::USTAT),
        ("getpgrp", a::GETPGRP),
        ("setsid", a::SETSID),
        ("sethostname", a::SETHOSTNAME),
        ("setrlimit", a::SETRLIMIT),
        ("getrusage", a::GETRUSAGE),
        ("gettimeofday", a::GETTIMEOFDAY),
        ("settimeofday", a::SETTIMEOFDAY),
        ("getgroups", a::GETGROUPS),
        ("setgroups", a::SETGROUPS),
        ("symlink", a::SYMLINK),
        ("readlink", a::READLINK),
        ("reboot", a::REBOOT),
        ("munmap", a::MUNMAP),
        ("truncate", a::TRUNCATE),
        ("ftruncate", a::FTRUNCATE),
        ("fchmod", a::FCHMOD),
        ("fchown", a::FCHOWN),
        ("getpriority", a::GETPRIORITY),
        ("setpriority", a::SETPRIORITY),
        ("statfs", a::STATFS),
        ("fstatfs", a::FSTATFS),
        ("statfs64", a::STATFS64),
        ("fstatfs64", a::FSTATFS64),
        ("syslog", a::SYSLOG),
        ("setitimer", a::SETITIMER),
        ("getitimer", a::GETITIMER),
        ("stat", a::STAT),
        ("lstat", a::LSTAT),
        ("fstat", a::FSTAT),
        ("vhangup", a::VHANGUP),
        ("wait4", a::WAIT4),
        ("sysinfo", a::SYSINFO),
        ("clone", a::CLONE),
        ("uname", a::UNAME),
        ("adjtimex", a::ADJTIMEX),
        ("mprotect", a::MPROTECT),
        ("mremap", a::MREMAP),
        ("msync", a::MSYNC),
        ("mlock", a::MLOCK),
        ("munlock", a::MUNLOCK),
        ("mlockall", a::MLOCKALL),
        ("munlockall", a::MUNLOCKALL),
        ("getpgid", a::GETPGID),
        ("bdflush", a::BDFLUSH),
        ("personality", a::PERSONALITY),
        ("getdents", a::GETDENTS),
        ("_newselect", a::NEWSELECT),
        ("flock", a::FLOCK),
        ("getsid", a::GETSID),
        ("fdatasync", a::FDATASYNC),
        ("sched_setparam", a::SCHED_SETPARAM),
        ("sched_getparam", a::SCHED_GETPARAM),
        ("sched_setscheduler", a::SCHED_SETSCHEDULER),
        ("sched_getscheduler", a::SCHED_GETSCHEDULER),
        ("sched_yield", a::SCHED_YIELD),
        ("sched_get_priority_max", a::SCHED_GET_PRIORITY_MAX),
        ("sched_get_priority_min", a::SCHED_GET_PRIORITY_MIN),
        ("sched_rr_get_interval", a::SCHED_RR_GET_INTERVAL),
        ("nanosleep", a::NANOSLEEP),
        ("getresuid", a::GETRESUID),
        ("getresgid", a::GETRESGID),
        ("poll", a::POLL),
        ("sigaction", a::SIGACTION),
        ("sigprocmask", a::SIGPROCMASK),
        ("sigpending", a::SIGPENDING),
        ("sigsuspend", a::SIGSUSPEND),
        ("rt_sigaction", a::RT_SIGACTION),
        ("rt_sigprocmask", a::RT_SIGPROCMASK),
        ("rt_sigpending", a::RT_SIGPENDING),
        ("rt_sigsuspend", a::RT_SIGSUSPEND),
        ("chown", a::CHOWN),
        ("getcwd", a::GETCWD),
        ("capget", a::CAPGET),
        ("capset", a::CAPSET),
        ("sendfile", a::SENDFILE),
        ("sendfile64", a::SENDFILE64),
        ("vfork", a::VFORK),
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
        ("getdents64", a::GETDENTS64),
        ("pivot_root", a::PIVOT_ROOT),
        ("mincore", a::MINCORE),
        ("madvise", a::MADVISE),
        ("gettid", a::GETTID),
        ("tkill", a::TKILL),
        ("futex", a::FUTEX),
        ("sched_setaffinity", a::SCHED_SETAFFINITY),
        ("sched_getaffinity", a::SCHED_GETAFFINITY),
        ("set_tid_address", a::SET_TID_ADDRESS),
        ("timer_create", a::TIMER_CREATE),
        ("clock_settime", a::CLOCK_SETTIME),
        ("clock_gettime", a::CLOCK_GETTIME),
        ("clock_getres", a::CLOCK_GETRES),
        ("clock_nanosleep", a::CLOCK_NANOSLEEP),
        ("tgkill", a::TGKILL),
        ("utimes", a::UTIMES),
        ("arm_fadvise64_64", a::FADVISE64),
        ("mq_open", a::MQ_OPEN),
        ("waitid", a::WAITID),
        ("socket", a::SOCKET),
        ("bind", a::BIND),
        ("connect", a::CONNECT),
        ("listen", a::LISTEN),
        ("accept", a::ACCEPT),
        ("getsockname", a::GETSOCKNAME),
        ("getpeername", a::GETPEERNAME),
        ("socketpair", a::SOCKETPAIR),
        ("send", a::SEND),
        ("sendto", a::SENDTO),
        ("recv", a::RECV),
        ("recvfrom", a::RECVFROM),
        ("shutdown", a::SHUTDOWN),
        ("setsockopt", a::SETSOCKOPT),
        ("getsockopt", a::GETSOCKOPT),
        ("sendmsg", a::SENDMSG),
        ("recvmsg", a::RECVMSG),
        ("semop", a::SEMOP),
        ("semget", a::SEMGET),
        ("semctl", a::SEMCTL),
        ("msgsnd", a::MSGSND),
        ("msgrcv", a::MSGRCV),
        ("msgget", a::MSGGET),
        ("msgctl", a::MSGCTL),
        ("shmat", a::SHMAT),
        ("shmdt", a::SHMDT),
        ("shmget", a::SHMGET),
        ("shmctl", a::SHMCTL),
        ("ioprio_set", a::IOPRIO_SET),
        ("ioprio_get", a::IOPRIO_GET),
        ("inotify_init", a::INOTIFY_INIT),
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
        ("unshare", a::UNSHARE),
        ("set_robust_list", a::SET_ROBUST_LIST),
        ("get_robust_list", a::GET_ROBUST_LIST),
        ("splice", a::SPLICE),
        ("arm_sync_file_range", a::SYNC_FILE_RANGE2),
        ("tee", a::TEE),
        ("vmsplice", a::VMSPLICE),
        ("getcpu", a::GETCPU),
        ("epoll_pwait", a::EPOLL_PWAIT),
        ("utimensat", a::UTIMENSAT),
        ("signalfd", a::SIGNALFD),
        ("timerfd_create", a::TIMERFD_CREATE),
        ("eventfd", a::EVENTFD),
        ("fallocate", a::FALLOCATE),
        ("timerfd_settime", a::TIMERFD_SETTIME),
        ("timerfd_gettime", a::TIMERFD_GETTIME),
        ("signalfd4", a::SIGNALFD4),
        ("eventfd2", a::EVENTFD2),
        ("epoll_create1", a::EPOLL_CREATE1),
        ("preadv", a::PREADV),
        ("pwritev", a::PWRITEV),
        ("prlimit64", a::PRLIMIT64),
        ("name_to_handle_at", a::NAME_TO_HANDLE_AT),
        ("open_by_handle_at", a::OPEN_BY_HANDLE_AT),
        ("clock_adjtime", a::CLOCK_ADJTIME),
        ("syncfs", a::SYNCFS),
        ("sendmmsg", a::SENDMMSG),
        ("setns", a::SETNS),
        ("process_vm_readv", a::PROCESS_VM_READV),
        ("process_vm_writev", a::PROCESS_VM_WRITEV),
        ("kcmp", a::KCMP),
        ("finit_module", a::FINIT_MODULE),
        ("sched_setattr", a::SCHED_SETATTR),
        ("sched_getattr", a::SCHED_GETATTR),
        ("renameat2", a::RENAMEAT2),
        ("seccomp", a::SECCOMP),
        ("getrandom", a::GETRANDOM),
        ("memfd_create", a::MEMFD_CREATE),
        ("bpf", a::BPF),
        ("execveat", a::EXECVEAT),
        ("userfaultfd", a::USERFAULTFD),
        ("membarrier", a::MEMBARRIER),
        ("mlock2", a::MLOCK2),
        ("copy_file_range", a::COPY_FILE_RANGE),
        ("preadv2", a::PREADV2),
        ("pwritev2", a::PWRITEV2),
        ("statx", a::STATX),
        ("rseq", a::RSEQ),
        ("migrate_pages", a::MIGRATE_PAGES),
        ("clock_gettime64", a::CLOCK_GETTIME64),
        ("clock_settime64", a::CLOCK_SETTIME64),
        ("clock_adjtime64", a::CLOCK_ADJTIME64),
        ("clock_getres_time64", a::CLOCK_GETRES_TIME64),
        ("clock_nanosleep_time64", a::CLOCK_NANOSLEEP_TIME64),
        ("timer_gettime64", a::TIMER_GETTIME64),
        ("timer_settime64", a::TIMER_SETTIME64),
        ("timerfd_gettime64", a::TIMERFD_GETTIME64),
        ("timerfd_settime64", a::TIMERFD_SETTIME64),
        ("utimensat_time64", a::UTIMENSAT_TIME64),
        ("pselect6_time64", a::PSELECT6_TIME64),
        ("ppoll_time64", a::PPOLL_TIME64),
        ("recvmmsg_time64", a::RECVMMSG_TIME64),
        ("semtimedop_time64", a::SEMTIMEDOP_TIME64),
        ("rt_sigtimedwait_time64", a::RT_SIGTIMEDWAIT_TIME64),
        ("futex_time64", a::FUTEX_TIME64),
        (
            "sched_rr_get_interval_time64",
            a::SCHED_RR_GET_INTERVAL_TIME64,
        ),
        ("pidfd_send_signal", a::PIDFD_SEND_SIGNAL),
        ("io_uring_setup", a::IO_URING_SETUP),
        ("open_tree", a::OPEN_TREE),
        ("move_mount", a::MOVE_MOUNT),
        ("fsopen", a::FSOPEN),
        ("pidfd_open", a::PIDFD_OPEN),
        ("clone3", a::CLONE3),
        ("close_range", a::CLOSE_RANGE),
        ("openat2", a::OPENAT2),
        ("pidfd_getfd", a::PIDFD_GETFD),
        ("faccessat2", a::FACCESSAT2),
        ("process_madvise", a::PROCESS_MADVISE),
        ("epoll_pwait2", a::EPOLL_PWAIT2),
        ("mount_setattr", a::MOUNT_SETATTR),
        ("futex_waitv", a::FUTEX_WAITV),
    ] {
        let got = nums
            .get(name)
            .unwrap_or_else(|| panic!("tbl に {name} がない"));
        assert_eq!(*got, want, "__NR_{name} の番号が UAPI と食い違う");
    }
    // __ARM_NR_* 帯（unistd.h 正本）。
    for (name, want) in [
        ("breakpoint", a::ARM_NR_BREAKPOINT),
        ("cacheflush", a::ARM_NR_CACHEFLUSH),
        ("usr26", a::ARM_NR_USR26),
        ("usr32", a::ARM_NR_USR32),
        ("set_tls", a::ARM_NR_SET_TLS),
        ("get_tls", a::ARM_NR_GET_TLS),
    ] {
        let got = arm_priv
            .get(name)
            .unwrap_or_else(|| panic!("unistd.h に __ARM_NR_{name} がない"));
        assert_eq!(*got, want, "__ARM_NR_{name} の番号が UAPI と食い違う");
    }
    // cmpxchg はカーネル内部ヘッダの値（__ARM_NR_BASE+0xfff0）。
    assert_eq!(a::ARM_NR_CMPXCHG, 0xffff0);
}
