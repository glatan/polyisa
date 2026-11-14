// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! AArch64 Linux のシステムコール番号と ABI 定数。
//!
//! 番号は asm-generic の UAPI 表由来の事実である。AArch64 は o32/n32/n64 の
//! ような ABI 分岐がなく、LP64 の一系統だけを持つ。
//! Ref: SRC-LINUX (7.3) の `include/uapi/asm-generic/unistd.h`。

// ---- 番号（asm-generic）----
pub const GETCWD: u64 = 17;
pub const DUP: u64 = 23;
pub const DUP3: u64 = 24;
pub const FCNTL: u64 = 25;
pub const IOCTL: u64 = 29;
pub const FLOCK: u64 = 32;
pub const MKNODAT: u64 = 33;
pub const MKDIRAT: u64 = 34;
pub const UNLINKAT: u64 = 35;
pub const SYMLINKAT: u64 = 36;
pub const LINKAT: u64 = 37;
pub const RENAMEAT: u64 = 38;
pub const UMOUNT2: u64 = 39;
pub const MOUNT: u64 = 40;
pub const PIVOT_ROOT: u64 = 41;
pub const STATFS64: u64 = 43;
pub const FSTATFS64: u64 = 44;
pub const TRUNCATE64: u64 = 45;
pub const FTRUNCATE64: u64 = 46;
pub const FACCESSAT: u64 = 48;
pub const CHDIR: u64 = 49;
pub const FCHDIR: u64 = 50;
pub const FCHMOD: u64 = 52;
pub const FCHMODAT: u64 = 53;
pub const FCHOWNAT: u64 = 54;
pub const FCHOWN: u64 = 55;
pub const OPENAT: u64 = 56;
pub const CLOSE: u64 = 57;
pub const PIPE2: u64 = 59;
pub const QUOTACTL: u64 = 60;
pub const GETDENTS64: u64 = 61;
pub const LSEEK: u64 = 62;
pub const READ: u64 = 63;
pub const WRITE: u64 = 64;
pub const READV: u64 = 65;
pub const WRITEV: u64 = 66;
pub const PREAD64: u64 = 67;
pub const PWRITE64: u64 = 68;
pub const SENDFILE: u64 = 71;
pub const PSELECT6: u64 = 72;
pub const PPOLL: u64 = 73;
pub const READLINKAT: u64 = 78;
pub const NEWFSTATAT: u64 = 79;
pub const FSTAT: u64 = 80;
pub const SYNC: u64 = 81;
pub const FSYNC: u64 = 82;
pub const FDATASYNC: u64 = 83;
pub const UTIMENSAT: u64 = 88;
pub const ACCT: u64 = 89;
pub const PERSONALITY: u64 = 92;
pub const EXIT: u64 = 93;
pub const EXIT_GROUP: u64 = 94;
pub const WAITID: u64 = 95;
pub const SET_TID_ADDRESS: u64 = 96;
pub const FUTEX: u64 = 98;
pub const SET_ROBUST_LIST: u64 = 99;
pub const NANOSLEEP: u64 = 101;
pub const GETITIMER: u64 = 102;
pub const SETITIMER: u64 = 103;
pub const INIT_MODULE: u64 = 105;
pub const DELETE_MODULE: u64 = 106;
pub const CLOCK_GETTIME: u64 = 113;
pub const CLOCK_GETRES: u64 = 114;
pub const CLOCK_NANOSLEEP: u64 = 115;
pub const SYSLOG: u64 = 116;
pub const PTRACE: u64 = 117;
pub const SCHED_SETAFFINITY: u64 = 122;
pub const SCHED_GETAFFINITY: u64 = 123;
pub const SCHED_YIELD: u64 = 124;
pub const KILL: u64 = 129;
pub const TKILL: u64 = 130;
pub const TGKILL: u64 = 131;
pub const SIGALTSTACK: u64 = 132;
pub const RT_SIGACTION: u64 = 134;
pub const RT_SIGPROCMASK: u64 = 135;
pub const RT_SIGPENDING: u64 = 136;
pub const RT_SIGRETURN: u64 = 139;
pub const REBOOT: u64 = 142;
pub const TIMES: u64 = 153;
pub const SETPGID: u64 = 154;
pub const GETPGID: u64 = 155;
pub const GETSID: u64 = 156;
pub const SETSID: u64 = 157;
pub const GETGROUPS: u64 = 158;
pub const SETGROUPS: u64 = 159;
pub const UNAME: u64 = 160;
pub const SETHOSTNAME: u64 = 161;
pub const GETRLIMIT: u64 = 163;
pub const SETRLIMIT: u64 = 164;
pub const GETRUSAGE: u64 = 165;
pub const UMASK: u64 = 166;
pub const PRCTL: u64 = 167;
pub const GETCPU: u64 = 168;
pub const GETTIMEOFDAY: u64 = 169;
pub const GETPID: u64 = 172;
pub const GETPPID: u64 = 173;
pub const GETUID: u64 = 174;
pub const GETEUID: u64 = 175;
pub const GETGID: u64 = 176;
pub const GETEGID: u64 = 177;
pub const GETTID: u64 = 178;
pub const SYSINFO: u64 = 179;
pub const BRK: u64 = 214;
pub const MUNMAP: u64 = 215;
pub const MREMAP: u64 = 216;
pub const CLONE: u64 = 220;
pub const EXECVE: u64 = 221;
pub const MMAP: u64 = 222;
pub const SWAPON: u64 = 224;
pub const SWAPOFF: u64 = 225;
pub const MPROTECT: u64 = 226;
pub const MSYNC: u64 = 227;
pub const MINCORE: u64 = 232;
pub const MADVISE: u64 = 233;
pub const WAIT4: u64 = 260;
pub const PRLIMIT64: u64 = 261;
pub const RENAMEAT2: u64 = 276;
pub const GETRANDOM: u64 = 278;
pub const MEMBARRIER: u64 = 283;
pub const STATX: u64 = 291;
pub const RSEQ: u64 = 293;
pub const FACCESSAT2: u64 = 439;

/// 汎用 errno（asm-generic はホストと同じ値）。負で返す。
// Ref: SRC-LINUX (7.3) `include/uapi/asm-generic/errno*.h`。
pub mod errno {
    pub const EPERM: u32 = 1;
    pub const ENOENT: u32 = 2;
    pub const ESRCH: u32 = 3;
    pub const EINTR: u32 = 4;
    pub const EIO: u32 = 5;
    pub const ENOEXEC: u32 = 8;
    pub const EBADF: u32 = 9;
    pub const ECHILD: u32 = 10;
    pub const EAGAIN: u32 = 11;
    pub const ENOMEM: u32 = 12;
    pub const EACCES: u32 = 13;
    pub const EFAULT: u32 = 14;
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
    pub const EFBIG: u32 = 27;
    pub const ENOSPC: u32 = 28;
    pub const ESPIPE: u32 = 29;
    pub const EROFS: u32 = 30;
    pub const EMLINK: u32 = 31;
    pub const EPIPE: u32 = 32;
    pub const ERANGE: u32 = 34;
    pub const ENOSYS: u32 = 38;
    pub const ENAMETOOLONG: u32 = 36;
    pub const ELOOP: u32 = 40;
    pub const EOPNOTSUPP: u32 = 95;
    pub const EOVERFLOW: u32 = 75;
}

/// `openat` 等の `O_*`（asm-generic = 汎用値）。
pub mod oflag {
    pub const CREAT: u64 = 0o100;
    pub const EXCL: u64 = 0o200;
    pub const NOCTTY: u64 = 0o400;
    pub const TRUNC: u64 = 0o1000;
    pub const APPEND: u64 = 0o2000;
    pub const NONBLOCK: u64 = 0o4000;
    pub const DSYNC: u64 = 0o10000;
    pub const DIRECT: u64 = 0o40000;
    pub const LARGEFILE: u64 = 0o100000;
    pub const DIRECTORY: u64 = 0o200000;
    pub const NOFOLLOW: u64 = 0o400000;
    pub const NOATIME: u64 = 0o1000000;
    pub const CLOEXEC: u64 = 0o2000000;
    pub const SYNC: u64 = 0o4010000;
}

/// `mmap` のフラグ（汎用値）。
pub mod mflag {
    pub const SHARED: u64 = 1;
    pub const PRIVATE: u64 = 2;
    pub const FIXED: u64 = 0x10;
    pub const ANONYMOUS: u64 = 0x20;
}

/// `ioctl` の要求番号（汎用値）。
pub mod ioc {
    pub const TCGETS: u64 = 0x5401;
    pub const TCSETS: u64 = 0x5402;
    pub const TIOCGWINSZ: u64 = 0x5413;
    pub const FIONREAD: u64 = 0x541b;
    pub const TIOCNOTTY: u64 = 0x5422;
}

/// 番号から名前を引く。
#[must_use]
pub fn name(nr: u64) -> Option<&'static str> {
    Some(match nr {
        GETCWD => "getcwd",
        DUP => "dup",
        DUP3 => "dup3",
        FCNTL => "fcntl",
        IOCTL => "ioctl",
        FLOCK => "flock",
        MKNODAT => "mknodat",
        MKDIRAT => "mkdirat",
        UNLINKAT => "unlinkat",
        SYMLINKAT => "symlinkat",
        LINKAT => "linkat",
        RENAMEAT => "renameat",
        UMOUNT2 => "umount2",
        MOUNT => "mount",
        PIVOT_ROOT => "pivot_root",
        STATFS64 => "statfs64",
        FSTATFS64 => "fstatfs64",
        TRUNCATE64 => "truncate64",
        FTRUNCATE64 => "ftruncate64",
        FACCESSAT => "faccessat",
        CHDIR => "chdir",
        FCHDIR => "fchdir",
        FCHMOD => "fchmod",
        FCHMODAT => "fchmodat",
        FCHOWNAT => "fchownat",
        FCHOWN => "fchown",
        OPENAT => "openat",
        CLOSE => "close",
        PIPE2 => "pipe2",
        QUOTACTL => "quotactl",
        GETDENTS64 => "getdents64",
        LSEEK => "lseek",
        READ => "read",
        WRITE => "write",
        READV => "readv",
        WRITEV => "writev",
        PREAD64 => "pread64",
        PWRITE64 => "pwrite64",
        SENDFILE => "sendfile",
        PSELECT6 => "pselect6",
        PPOLL => "ppoll",
        READLINKAT => "readlinkat",
        NEWFSTATAT => "newfstatat",
        FSTAT => "fstat",
        SYNC => "sync",
        FSYNC => "fsync",
        FDATASYNC => "fdatasync",
        UTIMENSAT => "utimensat",
        ACCT => "acct",
        PERSONALITY => "personality",
        EXIT => "exit",
        EXIT_GROUP => "exit_group",
        WAITID => "waitid",
        SET_TID_ADDRESS => "set_tid_address",
        FUTEX => "futex",
        SET_ROBUST_LIST => "set_robust_list",
        NANOSLEEP => "nanosleep",
        GETITIMER => "getitimer",
        SETITIMER => "setitimer",
        INIT_MODULE => "init_module",
        DELETE_MODULE => "delete_module",
        CLOCK_GETTIME => "clock_gettime",
        CLOCK_GETRES => "clock_getres",
        CLOCK_NANOSLEEP => "clock_nanosleep",
        SYSLOG => "syslog",
        PTRACE => "ptrace",
        SCHED_SETAFFINITY => "sched_setaffinity",
        SCHED_GETAFFINITY => "sched_getaffinity",
        SCHED_YIELD => "sched_yield",
        KILL => "kill",
        TKILL => "tkill",
        TGKILL => "tgkill",
        SIGALTSTACK => "sigaltstack",
        RT_SIGACTION => "rt_sigaction",
        RT_SIGPROCMASK => "rt_sigprocmask",
        RT_SIGPENDING => "rt_sigpending",
        RT_SIGRETURN => "rt_sigreturn",
        REBOOT => "reboot",
        TIMES => "times",
        SETPGID => "setpgid",
        GETPGID => "getpgid",
        GETSID => "getsid",
        SETSID => "setsid",
        GETGROUPS => "getgroups",
        SETGROUPS => "setgroups",
        UNAME => "uname",
        SETHOSTNAME => "sethostname",
        GETRLIMIT => "getrlimit",
        SETRLIMIT => "setrlimit",
        GETRUSAGE => "getrusage",
        UMASK => "umask",
        PRCTL => "prctl",
        GETCPU => "getcpu",
        GETTIMEOFDAY => "gettimeofday",
        GETPID => "getpid",
        GETPPID => "getppid",
        GETUID => "getuid",
        GETEUID => "geteuid",
        GETGID => "getgid",
        GETEGID => "getegid",
        GETTID => "gettid",
        SYSINFO => "sysinfo",
        BRK => "brk",
        MUNMAP => "munmap",
        MREMAP => "mremap",
        CLONE => "clone",
        EXECVE => "execve",
        MMAP => "mmap",
        SWAPON => "swapon",
        SWAPOFF => "swapoff",
        MPROTECT => "mprotect",
        MSYNC => "msync",
        MINCORE => "mincore",
        MADVISE => "madvise",
        WAIT4 => "wait4",
        PRLIMIT64 => "prlimit64",
        RENAMEAT2 => "renameat2",
        GETRANDOM => "getrandom",
        MEMBARRIER => "membarrier",
        STATX => "statx",
        RSEQ => "rseq",
        FACCESSAT2 => "faccessat2",
        _ => return None,
    })
}

/// AArch64 Linux の syscall 処理。`guest-aarch64` 機能で有効になる。
#[cfg(feature = "guest-aarch64")]
pub mod sys;
