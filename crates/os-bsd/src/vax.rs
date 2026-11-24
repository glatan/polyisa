// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAX の 4.3BSD-Reno ABI 共通部。
//!
//! 規約: システムコールは `chmk` 命令（0xbc＋コード指定子）で
//! 発行する。sem がコードをスタックに積み、ハンドラは [sp] から
//! 取り出して sp を戻す。引数は `calls`/`callg` の枠の 4(ap)
//! から 32 ビットずつ並ぶ。成功は PSL.C=0 で r0 が戻り値、
//! 失敗は PSL.C=1 で r0 が errno。64 ビットの戻り値は r0/r1。
//! CRT0 の初期スタックは [argc][argv...][0][envp...][0]。
//! Ref: SPEC-BSD-43（システムコールの節と a.out(5)）.

/// syscall の実装。
pub mod sys;

/// 4.3BSD の errno。
pub mod errno {
    pub const EPERM: u32 = 1;
    pub const ENOENT: u32 = 2;
    pub const ESRCH: u32 = 3;
    pub const EINTR: u32 = 4;
    pub const EIO: u32 = 5;
    pub const ENXIO: u32 = 6;
    pub const E2BIG: u32 = 7;
    pub const ENOEXEC: u32 = 8;
    pub const EBADF: u32 = 9;
    pub const ECHILD: u32 = 10;
    pub const EDEADLK: u32 = 11;
    pub const ENOMEM: u32 = 12;
    pub const EACCES: u32 = 13;
    pub const EFAULT: u32 = 14;
    pub const ENOTBLK: u32 = 15;
    pub const EBUSY: u32 = 16;
    pub const EEXIST: u32 = 17;
    pub const EXDEV: u32 = 18;
    pub const ENODEV: u32 = 19;
    pub const ENOTDIR: u32 = 20;
    pub const EISDIR: u32 = 21;
    pub const EINVAL: u32 = 22;
    pub const ENFILE: u32 = 23;
    pub const EMFILE: u32 = 24;
    pub const ENOTTY: u32 = 25;
    pub const ETXTBSY: u32 = 26;
    pub const EFBIG: u32 = 27;
    pub const ENOSPC: u32 = 28;
    pub const ESPIPE: u32 = 29;
    pub const EROFS: u32 = 30;
    pub const EMLINK: u32 = 31;
    pub const EPIPE: u32 = 32;
    pub const EDOM: u32 = 33;
    pub const ERANGE: u32 = 34;
    /// EWOULDBLOCK と同じ値。
    pub const EAGAIN: u32 = 35;
    pub const ENAMETOOLONG: u32 = 63;
}

/// 4.3BSD のシグナル番号。
pub mod sig {
    pub const HUP: u8 = 1;
    pub const INT: u8 = 2;
    pub const QUIT: u8 = 3;
    pub const ILL: u8 = 4;
    pub const TRAP: u8 = 5;
    pub const IOT: u8 = 6;
    pub const EMT: u8 = 7;
    pub const FPE: u8 = 8;
    pub const KILL: u8 = 9;
    pub const BUS: u8 = 10;
    pub const SEGV: u8 = 11;
    pub const SYS: u8 = 12;
    pub const PIPE: u8 = 13;
    pub const ALRM: u8 = 14;
    pub const TERM: u8 = 15;
    pub const URG: u8 = 16;
    pub const STOP: u8 = 17;
    pub const TSTP: u8 = 18;
    pub const CONT: u8 = 19;
    pub const CHLD: u8 = 20;
    pub const TTIN: u8 = 21;
    pub const TTOU: u8 = 22;
    pub const IO: u8 = 23;
    pub const XCPU: u8 = 24;
    pub const XFSZ: u8 = 25;
    pub const VTALRM: u8 = 26;
    pub const PROF: u8 = 27;
    pub const WINCH: u8 = 28;
    pub const LOST: u8 = 29;
    pub const USR1: u8 = 30;
    pub const USR2: u8 = 31;
    /// コアを吐いて死んだことを示す、終了状態の旗。
    pub const CORE: u32 = 0o200;
}

/// 番号→名前（トレースの表示用。実装の有無は `sys` の振り分け）。
// Ref: SPEC-BSD-43（4.3BSD-Reno のシステムコール表）.
#[rustfmt::skip]
pub const NAMES: &[&str] = &[
    "indir", "exit", "fork", "read", "write", "open", "close", "wait4",
    "creat", "link", "unlink", "execv", "chdir", "fchdir", "mknod", "chmod",
    "chown", "break", "getfsstat", "lseek", "getpid", "mount", "umount",
    "setuid", "getuid", "stime", "ptrace", "alarm", "ostat", "pause",
    "utime", "stty", "gtty", "access", "nice", "ftime", "sync", "kill",
    "stat", "setpgrp", "lstat", "dup", "pipe", "times", "profil", "-",
    "setgid", "getgid", "ssig", "-", "-", "acct", "-", "-", "ioctl",
    "reboot", "-", "symlink", "readlink", "execve", "umask", "chroot",
    "fstat", "getkerninfo", "getpagesize", "msync", "vfork", "vread",
    "vwrite", "sbrk", "sstk", "mmap", "ovadvise", "munmap", "mprotect",
    "madvise", "vhangup", "-", "mincore", "getgroups", "setgroups",
    "getpgrp", "setpgrp", "setitimer", "wait", "swapon", "getitimer",
    "gethostname", "sethostname", "getdtablesize", "dup2", "getdopt",
    "fcntl", "select", "setdopt", "fsync", "setpriority", "socket",
    "connect", "accept", "getpriority", "send", "recv", "sigreturn",
    "bind", "setsockopt", "listen", "vtimes", "sigvec", "sigblock",
    "sigsetmask", "sigsuspend", "sigstack", "recvmsg", "sendmsg", "-",
    "gettimeofday", "getrusage", "getsockopt", "resuba", "readv",
    "writev", "settimeofday", "fchown", "fchmod", "recvfrom",
    "setreuid", "setregid", "rename", "truncate", "ftruncate", "flock",
    "msexec", "sendto", "shutdown", "socketpair", "mkdir", "rmdir",
    "utimes", "sigcleanup", "adjtime", "getpeername", "gethostid",
    "sethostid", "getrlimit", "setrlimit", "killpg", "-", "setquota",
    "quota", "getsockname", "getdirentries", "vhangup2", "-", "-",
];
