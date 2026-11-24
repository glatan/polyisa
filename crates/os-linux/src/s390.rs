// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! s390x Linux のシステムコール番号と ABI 定数。
//!
//! 番号は `arch/s390/kernel/syscalls/syscall.tbl` の UAPI 表由来の
//! 事実である（`.testdata/uapi-s390/syscall.tbl` も参照）。s390x は
//! `64`/`common` の列だけを使い、31 ビット互換の分岐は持たない。
//! システムコールの規約: `svc 0`（オペコード 0x0a）、番号は r1、
//! 引数は r2–r7、戻り値は r2、エラーは r2 に負の errno を直接返す。
//! Ref: SRC-LINUX (7.3), SPEC-S390-ABI.

/// syscall 実装。番号表は機能なしでも使えるが、`sys` の実装が
/// `polyisa-guest-s390` のレジスタ定義を使うので機能フラグで切る。
#[cfg(feature = "guest-s390")]
pub mod sys;

/// 実バイナリで必要になる番号（common/64 の列から）。
pub const EXIT: u64 = 1;
pub const READ: u64 = 3;
pub const WRITE: u64 = 4;
pub const OPEN: u64 = 5;
pub const CLOSE: u64 = 6;
pub const CREAT: u64 = 8;
pub const LINK: u64 = 9;
pub const UNLINK: u64 = 10;
pub const EXECVE: u64 = 11;
pub const CHDIR: u64 = 12;
pub const MKNOD: u64 = 14;
pub const CHMOD: u64 = 15;
pub const LSEEK: u64 = 19;
pub const GETPID: u64 = 20;
pub const ACCESS: u64 = 33;
pub const SYNC: u64 = 36;
pub const KILL: u64 = 37;
pub const RENAME: u64 = 38;
pub const MKDIR: u64 = 39;
pub const RMDIR: u64 = 40;
pub const DUP: u64 = 41;
pub const PIPE: u64 = 42;
pub const TIMES: u64 = 43;
pub const BRK: u64 = 45;
pub const IOCTL: u64 = 54;
pub const FCNTL: u64 = 55;
pub const UMASK: u64 = 60;
pub const DUP2: u64 = 63;
pub const GETPPID: u64 = 64;
pub const GETRUSAGE: u64 = 77;
pub const GETTIMEOFDAY: u64 = 78;
// ソケット系。旧 ABI の socketcall と s390x の直番号の両方。
pub const SOCKETCALL: u64 = 102;
pub const SOCKET: u64 = 359;
pub const SOCKETPAIR: u64 = 360;
pub const BIND: u64 = 361;
pub const CONNECT: u64 = 362;
pub const LISTEN: u64 = 363;
pub const ACCEPT4: u64 = 364;
pub const GETSOCKOPT: u64 = 365;
pub const SETSOCKOPT: u64 = 366;
pub const GETSOCKNAME: u64 = 367;
pub const GETPEERNAME: u64 = 368;
pub const SENDTO: u64 = 369;
pub const SENDMSG: u64 = 370;
pub const RECVFROM: u64 = 371;
pub const RECVMSG: u64 = 372;
pub const SHUTDOWN: u64 = 373;
pub const MMAP: u64 = 90;
pub const MUNMAP: u64 = 91;
pub const FTRUNCATE: u64 = 93;
pub const STAT: u64 = 106;
pub const LSTAT: u64 = 107;
pub const FSTAT: u64 = 108;
pub const WAIT4: u64 = 114;
pub const SYSINFO: u64 = 116;
pub const FSYNC: u64 = 118;
pub const CLONE: u64 = 120;
pub const UNAME: u64 = 122;
pub const MPROTECT: u64 = 125;
pub const PERSONALITY: u64 = 136;
pub const GETDENTS: u64 = 141;
pub const SELECT: u64 = 142;
pub const READV: u64 = 145;
pub const WRITEV: u64 = 146;
pub const SCHED_YIELD: u64 = 158;
pub const NANOSLEEP: u64 = 162;
pub const POLL: u64 = 168;
pub const PRCTL: u64 = 172;
pub const RT_SIGACTION: u64 = 174;
pub const RT_SIGPROCMASK: u64 = 175;
pub const PREAD64: u64 = 180;
pub const PWRITE64: u64 = 181;
pub const GETCWD: u64 = 183;
pub const VFORK: u64 = 190;
pub const GETRLIMIT: u64 = 191;
pub const MMAP2: u64 = 192;
pub const GETUID: u64 = 199;
pub const GETGID: u64 = 200;
pub const GETEUID: u64 = 201;
pub const GETEGID: u64 = 202;
pub const MADVISE: u64 = 219;
pub const GETDENTS64: u64 = 220;
pub const FUTEX: u64 = 238;
pub const SCHED_GETAFFINITY: u64 = 240;
pub const EXIT_GROUP: u64 = 248;
pub const SET_TID_ADDRESS: u64 = 252;
pub const CLOCK_GETTIME: u64 = 260;
pub const CLOCK_NANOSLEEP: u64 = 262;
pub const OPENAT: u64 = 288;
pub const MKDIRAT: u64 = 289;
pub const NEWFSTATAT: u64 = 293;
pub const UNLINKAT: u64 = 294;
pub const READLINKAT: u64 = 298;
pub const FACCESSAT: u64 = 300;
pub const EPOLL_CREATE: u64 = 249;
pub const EPOLL_CTL: u64 = 250;
pub const EPOLL_WAIT: u64 = 251;
pub const PSELECT6: u64 = 301;
pub const PPOLL: u64 = 302;
pub const SET_ROBUST_LIST: u64 = 304;
pub const EPOLL_PWAIT: u64 = 312;
pub const EVENTFD: u64 = 318;
pub const TIMERFD_CREATE: u64 = 319;
pub const TIMERFD_SETTIME: u64 = 320;
pub const TIMERFD_GETTIME: u64 = 321;
pub const GETCPU: u64 = 311;
pub const EVENTFD2: u64 = 323;
pub const PIPE2: u64 = 325;
pub const DUP3: u64 = 326;
pub const EPOLL_CREATE1: u64 = 327;
pub const PRLIMIT64: u64 = 334;
pub const GETRANDOM: u64 = 349;
pub const MEMFD_CREATE: u64 = 350;
pub const STATX: u64 = 379;
pub const RSEQ: u64 = 383;
pub const CLONE3: u64 = 435;
pub const OPENAT2: u64 = 437;
pub const EPOLL_PWAIT2: u64 = 441;

/// 番号の表示名。デバッグ出力とトレースに使う。
#[must_use]
pub fn name(nr: u64) -> Option<&'static str> {
    Some(match nr {
        EXIT => "exit",
        READ => "read",
        WRITE => "write",
        OPEN => "open",
        CLOSE => "close",
        EXECVE => "execve",
        LSEEK => "lseek",
        GETPID => "getpid",
        ACCESS => "access",
        RENAME => "rename",
        MKDIR => "mkdir",
        RMDIR => "rmdir",
        DUP => "dup",
        BRK => "brk",
        IOCTL => "ioctl",
        FCNTL => "fcntl",
        UMASK => "umask",
        DUP2 => "dup2",
        GETPPID => "getppid",
        GETTIMEOFDAY => "gettimeofday",
        MMAP => "mmap",
        MUNMAP => "munmap",
        STAT => "stat",
        FSTAT => "fstat",
        UNAME => "uname",
        MPROTECT => "mprotect",
        READV => "readv",
        WRITEV => "writev",
        NANOSLEEP => "nanosleep",
        SELECT => "select",
        POLL => "poll",
        PRCTL => "prctl",
        RT_SIGACTION => "rt_sigaction",
        RT_SIGPROCMASK => "rt_sigprocmask",
        PREAD64 => "pread64",
        PWRITE64 => "pwrite64",
        GETCWD => "getcwd",
        GETRLIMIT => "getrlimit",
        MMAP2 => "mmap2",
        GETUID => "getuid",
        GETGID => "getgid",
        GETEUID => "geteuid",
        GETEGID => "getegid",
        MADVISE => "madvise",
        GETDENTS64 => "getdents64",
        FUTEX => "futex",
        SCHED_GETAFFINITY => "sched_getaffinity",
        EXIT_GROUP => "exit_group",
        SET_TID_ADDRESS => "set_tid_address",
        CLOCK_GETTIME => "clock_gettime",
        OPENAT => "openat",
        NEWFSTATAT => "newfstatat",
        UNLINKAT => "unlinkat",
        READLINKAT => "readlinkat",
        FACCESSAT => "faccessat",
        PSELECT6 => "pselect6",
        PPOLL => "ppoll",
        EPOLL_CREATE => "epoll_create",
        EPOLL_CTL => "epoll_ctl",
        EPOLL_WAIT => "epoll_wait",
        EPOLL_PWAIT => "epoll_pwait",
        EPOLL_CREATE1 => "epoll_create1",
        EPOLL_PWAIT2 => "epoll_pwait2",
        EVENTFD => "eventfd",
        EVENTFD2 => "eventfd2",
        TIMERFD_CREATE => "timerfd_create",
        TIMERFD_SETTIME => "timerfd_settime",
        TIMERFD_GETTIME => "timerfd_gettime",
        SET_ROBUST_LIST => "set_robust_list",
        GETCPU => "getcpu",
        PRLIMIT64 => "prlimit64",
        GETRANDOM => "getrandom",
        MEMFD_CREATE => "memfd_create",
        STATX => "statx",
        RSEQ => "rseq",
        SOCKETCALL => "socketcall",
        SOCKET => "socket",
        SOCKETPAIR => "socketpair",
        BIND => "bind",
        CONNECT => "connect",
        LISTEN => "listen",
        ACCEPT4 => "accept4",
        GETSOCKOPT => "getsockopt",
        SETSOCKOPT => "setsockopt",
        GETSOCKNAME => "getsockname",
        GETPEERNAME => "getpeername",
        SENDTO => "sendto",
        SENDMSG => "sendmsg",
        RECVFROM => "recvfrom",
        RECVMSG => "recvmsg",
        SHUTDOWN => "shutdown",
        _ => return None,
    })
}

/// errno（asm-generic 値）。
pub mod errno {
    pub const EPERM: u32 = 1;
    pub const ENOENT: u32 = 2;
    pub const EINTR: u32 = 4;
    pub const EIO: u32 = 5;
    pub const EBADF: u32 = 9;
    pub const EAGAIN: u32 = 11;
    pub const ENOMEM: u32 = 12;
    pub const EFAULT: u32 = 14;
    pub const EEXIST: u32 = 17;
    pub const ENODEV: u32 = 19;
    pub const ENOTDIR: u32 = 20;
    pub const EISDIR: u32 = 21;
    pub const EINVAL: u32 = 22;
    pub const ENFILE: u32 = 23;
    pub const EMFILE: u32 = 24;
    pub const ENOTTY: u32 = 25;
    pub const EFBIG: u32 = 27;
    pub const ENOSPC: u32 = 28;
    pub const ESPIPE: u32 = 29;
    pub const EROFS: u32 = 30;
    pub const ERANGE: u32 = 34;
    pub const ENOSYS: u32 = 38;
    pub const ENOTEMPTY: u32 = 39;
    pub const ELOOP: u32 = 40;
}
