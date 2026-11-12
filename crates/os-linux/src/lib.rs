// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Linux パーソナリティ。仮想カーネルの上で Linux の規約を実装する.
//!
//! 番号表は Linux カーネルの UAPI 由来の事実を自前表現で書く。
//! 条文・コードの複製はしない.

// Ref: SRC-LINUX (7.3).

#![forbid(unsafe_code)]

/// ゲストの ABI。システムコール番号の表を選ぶときに使う。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GuestAbi {
    Unknown,
    Rv64Linux,
    X86_64Linux,
    I386Linux,
    MipsO32,
}

/// MIPS o32 のシステムコール番号。基準 4000 に表の通し番号を足した値。
/// exit は 1、write は 4。
// Ref: SRC-LINUX (7.3).
pub mod mips_o32 {
    pub const EXIT: u64 = 4001;
    pub const WRITE: u64 = 4004;
}

/// RISC-V（asm-generic）のシステムコール番号。
/// 値はカーネルの UAPI 表由来の事実である。
pub mod rv64 {
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const CLOSE: u64 = 57;
    pub const MMAP: u64 = 222;
    pub const MPROTECT: u64 = 226;
    pub const MUNMAP: u64 = 215;
    pub const BRK: u64 = 214;
    pub const EXIT: u64 = 93;
    pub const EXIT_GROUP: u64 = 94;
    pub const UNAME: u64 = 160;
    pub const SET_TID_ADDRESS: u64 = 96;
    pub const GETTID: u64 = 178;
    pub const GETPID: u64 = 172;
    pub const TGKILL: u64 = 131;
    pub const GETUID: u64 = 174;
    pub const GETEUID: u64 = 175;
    pub const GETGID: u64 = 176;
    pub const GETEGID: u64 = 177;
    pub const RT_SIGACTION: u64 = 134;
    pub const RT_SIGPROCMASK: u64 = 135;
    pub const CLOCK_GETTIME: u64 = 113;
    pub const GETRANDOM: u64 = 278;
    pub const OPENAT: u64 = 56;
    // 段階2（ファイル操作・動的リンク）。
    pub const LSEEK: u64 = 62;
    pub const GETDENTS64: u64 = 61;
    pub const GETCWD: u64 = 17;
    pub const DUP3: u64 = 24;
    pub const FCNTL: u64 = 25;
    pub const IOCTL: u64 = 29;
    pub const PREAD64: u64 = 67;
    pub const READLINKAT: u64 = 78;
    pub const NEWFSTATAT: u64 = 79;
    pub const FSTAT: u64 = 80;
    pub const STATX: u64 = 291;
    pub const READV: u64 = 65;
    pub const WRITEV: u64 = 66;
    pub const SENDFILE: u64 = 71;
    pub const CLOCK_NANOSLEEP: u64 = 115;
}

/// x86_64（Linux・64ビット）のシステムコール番号。
/// 値はカーネルの UAPI 由来の事実であり、`heavy_abi_uapi` で突き合わせる。
// Ref: SRC-LINUX (7.3).
pub mod x86_64 {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const CLOSE: u64 = 3;
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const MUNMAP: u64 = 11;
    pub const BRK: u64 = 12;
    pub const EXIT: u64 = 60;
    pub const EXIT_GROUP: u64 = 231;
    pub const UNAME: u64 = 63;
    pub const SET_TID_ADDRESS: u64 = 218;
    pub const GETTID: u64 = 186;
    pub const GETPID: u64 = 39;
    pub const TGKILL: u64 = 234;
    pub const GETUID: u64 = 102;
    pub const GETGID: u64 = 104;
    pub const GETEUID: u64 = 107;
    pub const GETEGID: u64 = 108;
    pub const RT_SIGACTION: u64 = 13;
    pub const RT_SIGPROCMASK: u64 = 14;
    pub const CLOCK_GETTIME: u64 = 228;
    pub const GETRANDOM: u64 = 318;
    pub const OPENAT: u64 = 257;
    pub const OPEN: u64 = 2;
    // 段階2相当（ファイル操作）。
    pub const LSEEK: u64 = 8;
    pub const GETDENTS64: u64 = 217;
    pub const GETCWD: u64 = 79;
    pub const CHDIR: u64 = 80;
    pub const DUP3: u64 = 292;
    pub const FCNTL: u64 = 72;
    pub const IOCTL: u64 = 16;
    pub const PREAD64: u64 = 17;
    pub const READLINKAT: u64 = 267;
    pub const READLINK: u64 = 89;
    pub const NEWFSTATAT: u64 = 262;
    pub const FSTAT: u64 = 5;
    pub const STAT: u64 = 4;
    pub const LSTAT: u64 = 6;
    pub const STATX: u64 = 332;
    pub const ARCH_PRCTL: u64 = 158;
    pub const SET_ROBUST_LIST: u64 = 273;
    pub const RSEQ: u64 = 334;
    pub const PRLIMIT64: u64 = 302;
    pub const READV: u64 = 19;
    pub const WRITEV: u64 = 20;
    pub const SENDFILE: u64 = 40;
    pub const TIME: u64 = 201;
    pub const NANOSLEEP: u64 = 35;
    pub const CLOCK_NANOSLEEP: u64 = 230;
    pub const SCHED_GETAFFINITY: u64 = 204;
    pub const GETGROUPS: u64 = 115;
    pub const MKDIR: u64 = 83;
    pub const RMDIR: u64 = 84;
    pub const MKNOD: u64 = 133;
    pub const UNLINK: u64 = 87;
    pub const ACCESS: u64 = 21;
    pub const UTIMENSAT: u64 = 280;
    pub const DUP: u64 = 32;
    pub const DUP2: u64 = 33;
    pub const MKDIRAT: u64 = 258;
    pub const UNLINKAT: u64 = 263;
    pub const FACCESSAT: u64 = 269;
    pub const CHMOD: u64 = 90;
    pub const FCHMOD: u64 = 91;
    pub const CHOWN: u64 = 92;
    pub const FCHOWN: u64 = 93;
    pub const LCHOWN: u64 = 94;
    pub const FCHMODAT: u64 = 268;
    pub const UMASK: u64 = 95;
    pub const FTRUNCATE: u64 = 77;
    pub const FALLOCATE: u64 = 285;
    pub const RENAME: u64 = 82;
    pub const SYMLINK: u64 = 88;
    pub const LINK: u64 = 86;
    pub const SYNC: u64 = 162;
    pub const CLONE: u64 = 56;
    pub const FORK: u64 = 57;
    pub const EXECVE: u64 = 59;
    pub const WAIT4: u64 = 61;
    pub const KILL: u64 = 62;
    pub const SETPGID: u64 = 109;
    pub const SETSID: u64 = 112;
    pub const GETPGID: u64 = 121;
    pub const GETPRIORITY: u64 = 140;
    pub const SETPRIORITY: u64 = 141;
    pub const PERSONALITY: u64 = 135;
    pub const SCHED_SETAFFINITY: u64 = 203;
    pub const IOPRIO_SET: u64 = 251;
    pub const IOPRIO_GET: u64 = 252;
    pub const FSYNC: u64 = 74;
    pub const FDATASYNC: u64 = 75;
    pub const UNSHARE: u64 = 272;
    pub const FCHDIR: u64 = 81;
    pub const SETGROUPS: u64 = 116;
    pub const CHROOT: u64 = 161;
    pub const GETPPID: u64 = 110;
    pub const SYSINFO: u64 = 99;
    pub const REBOOT: u64 = 169;
    pub const SYSLOG: u64 = 103;
    pub const SCHED_SETPARAM: u64 = 142;
    pub const SCHED_GETPARAM: u64 = 143;
    pub const SCHED_SETSCHEDULER: u64 = 144;
    pub const SCHED_GETSCHEDULER: u64 = 145;
    pub const SCHED_GET_PRIORITY_MAX: u64 = 146;
    pub const SCHED_GET_PRIORITY_MIN: u64 = 147;
    pub const PIPE2: u64 = 293;
    pub const PIPE: u64 = 22;
    // Gap: GAP-0004
    // statfs 系。busybox の `df` が呼ぶ。
    // Ref: SRC-LINUX (7.3).
    pub const STATFS: u64 = 137;
    pub const FSTATFS: u64 = 138;
}

/// i386（Linux・32ビット）のシステムコール番号。
/// 値はカーネルの UAPI 由来の事実である。新旧 stat 系は i386 の実態に合わせ、
/// newfstatat（i386 に存在しない）の代わりに fstatat64 を持つ。
// Ref: SRC-LINUX (7.3).
pub mod i386 {
    pub const READ: u64 = 3;
    pub const WRITE: u64 = 4;
    pub const CLOSE: u64 = 6;
    pub const MMAP: u64 = 90;
    pub const MPROTECT: u64 = 125;
    pub const MUNMAP: u64 = 91;
    pub const BRK: u64 = 45;
    pub const EXIT: u64 = 1;
    pub const EXIT_GROUP: u64 = 252;
    pub const UNAME: u64 = 122;
    pub const SET_TID_ADDRESS: u64 = 258;
    pub const GETTID: u64 = 224;
    pub const GETPID: u64 = 20;
    pub const TGKILL: u64 = 270;
    pub const GETUID: u64 = 24;
    pub const GETGID: u64 = 47;
    pub const GETEUID: u64 = 49;
    pub const GETEGID: u64 = 50;
    pub const RT_SIGACTION: u64 = 174;
    pub const RT_SIGPROCMASK: u64 = 175;
    pub const CLOCK_GETTIME: u64 = 265;
    pub const GETRANDOM: u64 = 355;
    pub const OPENAT: u64 = 295;
    pub const READV: u64 = 145;
    pub const WRITEV: u64 = 146;
    // 段階2相当（ファイル操作）。
    pub const LSEEK: u64 = 19;
    pub const GETDENTS64: u64 = 220;
    pub const GETCWD: u64 = 183;
    pub const DUP3: u64 = 330;
    pub const FCNTL: u64 = 55;
    pub const IOCTL: u64 = 54;
    pub const PREAD64: u64 = 180;
    pub const READLINKAT: u64 = 305;
    pub const READLINK: u64 = 85;
    pub const FSTATAT64: u64 = 300;
    pub const FSTAT: u64 = 108;
    pub const STATX: u64 = 383;
    pub const SENDFILE: u64 = 187;
    pub const TIME: u64 = 13;
    pub const NANOSLEEP: u64 = 162;
    pub const GETGROUPS: u64 = 80;
    pub const GETGROUPS32: u64 = 205;
    pub const MKDIR: u64 = 39;
    pub const RMDIR: u64 = 40;
    pub const UNLINK: u64 = 10;
    pub const ACCESS: u64 = 33;
    pub const UTIMENSAT: u64 = 320;
    pub const DUP: u64 = 41;
    pub const DUP2: u64 = 63;
    pub const MKDIRAT: u64 = 296;
    pub const UNLINKAT: u64 = 301;
    pub const FACCESSAT: u64 = 307;
    pub const CHMOD: u64 = 15;
    pub const FCHMOD: u64 = 94;
    pub const FCHMODAT: u64 = 306;
    pub const UMASK: u64 = 60;
    pub const FTRUNCATE: u64 = 93;
    pub const RENAME: u64 = 38;
    pub const SYMLINK: u64 = 83;
    // Gap: GAP-0004
    // statfs 系。busybox の `df` が呼ぶ。statfs/fstatfs (99/100) と
    // 64 系 (268/269) を持つ。GETGROUPS=80 と区別する.
    // Ref: SRC-LINUX (7.3).
    pub const STATFS: u64 = 99;
    pub const FSTATFS: u64 = 100;
    pub const STATFS64: u64 = 268;
    pub const FSTATFS64: u64 = 269;
    // 番号だけを置く。実行のテストは x86_64 にある。
    pub const CLONE: u64 = 120;
    pub const EXECVE: u64 = 11;
    pub const WAIT4: u64 = 114;
    pub const PIPE2: u64 = 331;
    pub const SETPGID: u64 = 57;
    pub const GETPGID: u64 = 132;
    pub const CHDIR: u64 = 12;
    pub const KILL: u64 = 37;
}

/// Linux の `clone` フラグ。アドレス空間の共有はプロセス生成では使わない。
// Ref: SRC-LINUX (7.3).
pub mod clone_flag {
    pub const VM: u64 = 0x100;
    pub const THREAD: u64 = 0x0001_0000;
}

/// 正常終了の wait ステータス。終了コードは 8–15 ビットに置く。
#[must_use]
pub fn exited_wait_status(code: u32) -> u32 {
    (code & 0xff) << 8
}

/// ABI と番号から名前を引く。
#[must_use]
pub fn syscall_name(abi: GuestAbi, nr: u64) -> Option<&'static str> {
    match abi {
        GuestAbi::Rv64Linux => match nr {
            rv64::READ => Some("read"),
            rv64::WRITE => Some("write"),
            rv64::CLOSE => Some("close"),
            rv64::MMAP => Some("mmap"),
            rv64::MPROTECT => Some("mprotect"),
            rv64::MUNMAP => Some("munmap"),
            rv64::BRK => Some("brk"),
            rv64::EXIT => Some("exit"),
            rv64::EXIT_GROUP => Some("exit_group"),
            rv64::UNAME => Some("uname"),
            rv64::SET_TID_ADDRESS => Some("set_tid_address"),
            rv64::GETTID => Some("gettid"),
            rv64::GETPID => Some("getpid"),
            rv64::TGKILL => Some("tgkill"),
            rv64::GETUID => Some("getuid"),
            rv64::GETEUID => Some("geteuid"),
            rv64::GETGID => Some("getgid"),
            rv64::GETEGID => Some("getegid"),
            rv64::RT_SIGACTION => Some("rt_sigaction"),
            rv64::RT_SIGPROCMASK => Some("rt_sigprocmask"),
            rv64::CLOCK_GETTIME => Some("clock_gettime"),
            rv64::GETRANDOM => Some("getrandom"),
            rv64::OPENAT => Some("openat"),
            rv64::LSEEK => Some("lseek"),
            rv64::GETDENTS64 => Some("getdents64"),
            rv64::GETCWD => Some("getcwd"),
            rv64::DUP3 => Some("dup3"),
            rv64::FCNTL => Some("fcntl"),
            rv64::IOCTL => Some("ioctl"),
            rv64::PREAD64 => Some("pread64"),
            rv64::READLINKAT => Some("readlinkat"),
            rv64::NEWFSTATAT => Some("newfstatat"),
            rv64::FSTAT => Some("fstat"),
            rv64::STATX => Some("statx"),
            rv64::READV => Some("readv"),
            rv64::WRITEV => Some("writev"),
            rv64::SENDFILE => Some("sendfile"),
            rv64::CLOCK_NANOSLEEP => Some("clock_nanosleep"),
            _ => None,
        },
        GuestAbi::I386Linux => match nr {
            i386::READ => Some("read"),
            i386::WRITE => Some("write"),
            i386::CLOSE => Some("close"),
            i386::MMAP => Some("mmap"),
            i386::MPROTECT => Some("mprotect"),
            i386::MUNMAP => Some("munmap"),
            i386::BRK => Some("brk"),
            i386::EXIT => Some("exit"),
            i386::EXIT_GROUP => Some("exit_group"),
            i386::UNAME => Some("uname"),
            i386::SET_TID_ADDRESS => Some("set_tid_address"),
            i386::GETTID => Some("gettid"),
            i386::GETPID => Some("getpid"),
            i386::TGKILL => Some("tgkill"),
            i386::GETUID => Some("getuid"),
            i386::GETEUID => Some("geteuid"),
            i386::GETGID => Some("getgid"),
            i386::GETEGID => Some("getegid"),
            i386::RT_SIGACTION => Some("rt_sigaction"),
            i386::RT_SIGPROCMASK => Some("rt_sigprocmask"),
            i386::CLOCK_GETTIME => Some("clock_gettime"),
            i386::GETRANDOM => Some("getrandom"),
            i386::OPENAT => Some("openat"),
            i386::LSEEK => Some("lseek"),
            i386::GETDENTS64 => Some("getdents64"),
            i386::GETCWD => Some("getcwd"),
            i386::DUP3 => Some("dup3"),
            i386::FCNTL => Some("fcntl"),
            i386::IOCTL => Some("ioctl"),
            i386::PREAD64 => Some("pread64"),
            i386::READLINKAT => Some("readlinkat"),
            i386::READLINK => Some("readlink"),
            i386::FSTATAT64 => Some("fstatat64"),
            i386::FSTAT => Some("fstat"),
            i386::STATX => Some("statx"),
            i386::READV => Some("readv"),
            i386::WRITEV => Some("writev"),
            i386::SENDFILE => Some("sendfile"),
            i386::TIME => Some("time"),
            i386::NANOSLEEP => Some("nanosleep"),
            i386::GETGROUPS => Some("getgroups"),
            i386::GETGROUPS32 => Some("getgroups32"),
            i386::MKDIR => Some("mkdir"),
            i386::RMDIR => Some("rmdir"),
            i386::UNLINK => Some("unlink"),
            i386::ACCESS => Some("access"),
            i386::UTIMENSAT => Some("utimensat"),
            i386::DUP => Some("dup"),
            i386::DUP2 => Some("dup2"),
            i386::MKDIRAT => Some("mkdirat"),
            i386::UNLINKAT => Some("unlinkat"),
            i386::FACCESSAT => Some("faccessat"),
            i386::CHMOD => Some("chmod"),
            i386::FCHMOD => Some("fchmod"),
            i386::FCHMODAT => Some("fchmodat"),
            i386::UMASK => Some("umask"),
            i386::FTRUNCATE => Some("ftruncate"),
            i386::RENAME => Some("rename"),
            i386::SYMLINK => Some("symlink"),
            i386::STATFS => Some("statfs"),
            i386::FSTATFS => Some("fstatfs"),
            i386::STATFS64 => Some("statfs64"),
            i386::FSTATFS64 => Some("fstatfs64"),
            i386::CLONE => Some("clone"),
            i386::EXECVE => Some("execve"),
            i386::WAIT4 => Some("wait4"),
            i386::PIPE2 => Some("pipe2"),
            i386::SETPGID => Some("setpgid"),
            i386::GETPGID => Some("getpgid"),
            i386::CHDIR => Some("chdir"),
            i386::KILL => Some("kill"),
            _ => None,
        },
        GuestAbi::X86_64Linux => match nr {
            x86_64::READ => Some("read"),
            x86_64::WRITE => Some("write"),
            x86_64::CLOSE => Some("close"),
            x86_64::MMAP => Some("mmap"),
            x86_64::MPROTECT => Some("mprotect"),
            x86_64::MUNMAP => Some("munmap"),
            x86_64::BRK => Some("brk"),
            x86_64::EXIT => Some("exit"),
            x86_64::EXIT_GROUP => Some("exit_group"),
            x86_64::UNAME => Some("uname"),
            x86_64::SET_TID_ADDRESS => Some("set_tid_address"),
            x86_64::GETTID => Some("gettid"),
            x86_64::GETPID => Some("getpid"),
            x86_64::TGKILL => Some("tgkill"),
            x86_64::GETUID => Some("getuid"),
            x86_64::GETEUID => Some("geteuid"),
            x86_64::GETGID => Some("getgid"),
            x86_64::GETEGID => Some("getegid"),
            x86_64::RT_SIGACTION => Some("rt_sigaction"),
            x86_64::RT_SIGPROCMASK => Some("rt_sigprocmask"),
            x86_64::CLOCK_GETTIME => Some("clock_gettime"),
            x86_64::GETRANDOM => Some("getrandom"),
            x86_64::OPENAT => Some("openat"),
            x86_64::OPEN => Some("open"),
            x86_64::LSEEK => Some("lseek"),
            x86_64::GETDENTS64 => Some("getdents64"),
            x86_64::GETCWD => Some("getcwd"),
            x86_64::DUP3 => Some("dup3"),
            x86_64::FCNTL => Some("fcntl"),
            x86_64::IOCTL => Some("ioctl"),
            x86_64::PREAD64 => Some("pread64"),
            x86_64::READLINKAT => Some("readlinkat"),
            x86_64::READLINK => Some("readlink"),
            x86_64::NEWFSTATAT => Some("newfstatat"),
            x86_64::FSTAT => Some("fstat"),
            x86_64::STAT => Some("stat"),
            x86_64::LSTAT => Some("lstat"),
            x86_64::STATX => Some("statx"),
            x86_64::READV => Some("readv"),
            x86_64::WRITEV => Some("writev"),
            x86_64::SENDFILE => Some("sendfile"),
            x86_64::TIME => Some("time"),
            x86_64::NANOSLEEP => Some("nanosleep"),
            x86_64::CLOCK_NANOSLEEP => Some("clock_nanosleep"),
            x86_64::SCHED_GETAFFINITY => Some("sched_getaffinity"),
            x86_64::GETGROUPS => Some("getgroups"),
            x86_64::MKDIR => Some("mkdir"),
            x86_64::RMDIR => Some("rmdir"),
            x86_64::MKNOD => Some("mknod"),
            x86_64::UNLINK => Some("unlink"),
            x86_64::ACCESS => Some("access"),
            x86_64::UTIMENSAT => Some("utimensat"),
            x86_64::DUP => Some("dup"),
            x86_64::DUP2 => Some("dup2"),
            x86_64::MKDIRAT => Some("mkdirat"),
            x86_64::UNLINKAT => Some("unlinkat"),
            x86_64::FACCESSAT => Some("faccessat"),
            x86_64::CHMOD => Some("chmod"),
            x86_64::FCHMOD => Some("fchmod"),
            x86_64::CHOWN => Some("chown"),
            x86_64::FCHOWN => Some("fchown"),
            x86_64::LCHOWN => Some("lchown"),
            x86_64::FCHMODAT => Some("fchmodat"),
            x86_64::UMASK => Some("umask"),
            x86_64::FTRUNCATE => Some("ftruncate"),
            x86_64::FALLOCATE => Some("fallocate"),
            x86_64::RENAME => Some("rename"),
            x86_64::SYMLINK => Some("symlink"),
            x86_64::LINK => Some("link"),
            x86_64::SYNC => Some("sync"),
            x86_64::ARCH_PRCTL => Some("arch_prctl"),
            x86_64::SET_ROBUST_LIST => Some("set_robust_list"),
            x86_64::RSEQ => Some("rseq"),
            x86_64::PRLIMIT64 => Some("prlimit64"),
            x86_64::STATFS => Some("statfs"),
            x86_64::FSTATFS => Some("fstatfs"),
            x86_64::CLONE => Some("clone"),
            x86_64::FORK => Some("fork"),
            x86_64::EXECVE => Some("execve"),
            x86_64::WAIT4 => Some("wait4"),
            x86_64::PIPE2 => Some("pipe2"),
            x86_64::PIPE => Some("pipe"),
            x86_64::SETPGID => Some("setpgid"),
            x86_64::SETSID => Some("setsid"),
            x86_64::GETPGID => Some("getpgid"),
            x86_64::GETPRIORITY => Some("getpriority"),
            x86_64::SETPRIORITY => Some("setpriority"),
            x86_64::PERSONALITY => Some("personality"),
            x86_64::SCHED_SETAFFINITY => Some("sched_setaffinity"),
            x86_64::IOPRIO_SET => Some("ioprio_set"),
            x86_64::IOPRIO_GET => Some("ioprio_get"),
            x86_64::FSYNC => Some("fsync"),
            x86_64::FDATASYNC => Some("fdatasync"),
            x86_64::UNSHARE => Some("unshare"),
            x86_64::FCHDIR => Some("fchdir"),
            x86_64::SETGROUPS => Some("setgroups"),
            x86_64::CHROOT => Some("chroot"),
            x86_64::GETPPID => Some("getppid"),
            x86_64::SYSINFO => Some("sysinfo"),
            x86_64::REBOOT => Some("reboot"),
            x86_64::SYSLOG => Some("syslog"),
            x86_64::SCHED_SETPARAM => Some("sched_setparam"),
            x86_64::SCHED_GETPARAM => Some("sched_getparam"),
            x86_64::SCHED_SETSCHEDULER => Some("sched_setscheduler"),
            x86_64::SCHED_GETSCHEDULER => Some("sched_getscheduler"),
            x86_64::SCHED_GET_PRIORITY_MAX => Some("sched_get_priority_max"),
            x86_64::SCHED_GET_PRIORITY_MIN => Some("sched_get_priority_min"),
            x86_64::CHDIR => Some("chdir"),
            x86_64::KILL => Some("kill"),
            _ => None,
        },
        GuestAbi::MipsO32 => match nr {
            mips_o32::EXIT => Some("exit"),
            mips_o32::WRITE => Some("write"),
            _ => None,
        },
        GuestAbi::Unknown => None,
    }
}

/// 初期スタックの写像を作る。`top` はスタック上端（16B整列）で、戻り値は
/// （配置するバイト列，初期SP）である。引数・環境はNUL終端文字列として置く。
/// 配置の規約は psABI と Linux の慣行に従う.
// Ref: SPEC-RISCV-PSABI (v1.0).
#[must_use]
pub fn build_initial_stack(
    top: u64,
    args: &[Vec<u8>],
    env: &[Vec<u8>],
    auxv: &[(u64, u64)],
) -> (Vec<u8>, u64) {
    fn w64(out: &mut [u8], off: usize, v: u64) {
        out[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    let strings_len: usize = args.iter().map(|a| a.len() + 1).sum::<usize>()
        + env.iter().map(|e| e.len() + 1).sum::<usize>();
    // AT_EXECFN を args[0] 向けに1件足す（args 空では付けない）。
    let execfn_extra: usize = if args.is_empty() { 0 } else { 16 };
    let arrays_len: usize =
        8 * (1 + (args.len() + 1) + (env.len() + 1)) + 16 * (auxv.len() + 1) + execfn_extra;
    let total = arrays_len + strings_len;
    let aligned = total.next_multiple_of(16);
    let sp = top - aligned as u64;
    let mut img = vec![0u8; aligned];
    let str_base = sp + (aligned - strings_len) as u64;
    // 文字列を詰める。
    let mut pos = 0usize;
    let mut addrs = Vec::new();
    for s in args.iter().chain(env.iter()) {
        let addr = str_base + pos as u64;
        img[aligned - strings_len + pos..aligned - strings_len + pos + s.len()].copy_from_slice(s);
        pos += s.len() + 1; // NUL は vec 初期値の 0 のまま.
        addrs.push(addr);
    }
    // 配列部。
    let mut off = 0usize;
    w64(&mut img, off, args.len() as u64);
    off += 8;
    for addr in addrs.iter().take(args.len()) {
        w64(&mut img, off, *addr);
        off += 8;
    }
    off += 8; // argv NULL.
    for i in 0..env.len() {
        w64(&mut img, off, addrs[args.len() + i]);
        off += 8;
    }
    off += 8; // envp NULL.
    for (k, v) in auxv {
        w64(&mut img, off, *k);
        w64(&mut img, off + 8, *v);
        off += 16;
    }
    // AT_EXECFN (31) は args[0] の番地を指す。静的 glibc の _dl_get_origin が参照する.
    // args が空の単体テストでは付けない.
    if !args.is_empty() {
        const AT_EXECFN: u64 = 31;
        w64(&mut img, off, AT_EXECFN);
        w64(&mut img, off + 8, addrs[0]);
        off += 16;
    }
    // AT_NULL 終端は img のゼロ初期化で表す.
    let _ = (off, pos);
    (img, sp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rv64_stage1_numbers() {
        // 代表的な番号が asm-generic と一致する。
        assert_eq!(rv64::WRITE, 64);
        assert_eq!(rv64::EXIT_GROUP, 94);
        assert_eq!(rv64::MMAP, 222);
        assert_eq!(rv64::BRK, 214);
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 64), Some("write"));
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 291), Some("statx"));
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 61), Some("getdents64"));
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 9999), None);
        assert_eq!(rv64::SENDFILE, 71);
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 71), Some("sendfile"));
        assert_eq!(rv64::CLOCK_NANOSLEEP, 115);
        assert_eq!(
            syscall_name(GuestAbi::Rv64Linux, 115),
            Some("clock_nanosleep")
        );
    }

    #[test]
    fn x86_64_stage1_numbers() {
        // 代表的な番号が x86_64 の UAPI と一致する（全体は層6で突合せ）。
        assert_eq!(x86_64::WRITE, 1);
        assert_eq!(x86_64::EXIT_GROUP, 231);
        assert_eq!(x86_64::MMAP, 9);
        assert_eq!(x86_64::BRK, 12);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 1), Some("write"));
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 332), Some("statx"));
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 217), Some("getdents64"));
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 64), None);
        assert_eq!(x86_64::SENDFILE, 40);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 40), Some("sendfile"));
        assert_eq!(x86_64::TIME, 201);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 201), Some("time"));
        assert_eq!(x86_64::NANOSLEEP, 35);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 35), Some("nanosleep"));
        assert_eq!(x86_64::SCHED_GETAFFINITY, 204);
        assert_eq!(
            syscall_name(GuestAbi::X86_64Linux, 204),
            Some("sched_getaffinity")
        );
        assert_eq!(x86_64::CLOCK_NANOSLEEP, 230);
        assert_eq!(
            syscall_name(GuestAbi::X86_64Linux, 230),
            Some("clock_nanosleep")
        );
        assert_eq!(x86_64::GETGROUPS, 115);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 115), Some("getgroups"));
        assert_eq!(x86_64::STATFS, 137);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 137), Some("statfs"));
        assert_eq!(x86_64::FSTATFS, 138);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 138), Some("fstatfs"));
        assert_eq!(x86_64::STAT, 4);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 4), Some("stat"));
        assert_eq!(x86_64::LSTAT, 6);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 6), Some("lstat"));
        assert_eq!(x86_64::ARCH_PRCTL, 158);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 158), Some("arch_prctl"));
        assert_eq!(x86_64::SET_ROBUST_LIST, 273);
        assert_eq!(
            syscall_name(GuestAbi::X86_64Linux, 273),
            Some("set_robust_list")
        );
        assert_eq!(x86_64::RSEQ, 334);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 334), Some("rseq"));
        assert_eq!(x86_64::PRLIMIT64, 302);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 302), Some("prlimit64"));
        assert_eq!(x86_64::LINK, 86);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 86), Some("link"));
        assert_eq!(x86_64::SYNC, 162);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 162), Some("sync"));
    }

    #[test]
    fn i386_stage1_numbers() {
        // 代表的な番号が i386 の UAPI と一致する（全体は層6で突合せ）。
        // newfstatat は i386 に存在しないため fstatat64 を持つ。
        assert_eq!(i386::WRITE, 4);
        assert_eq!(i386::EXIT_GROUP, 252);
        assert_eq!(i386::MMAP, 90);
        assert_eq!(i386::BRK, 45);
        assert_eq!(syscall_name(GuestAbi::I386Linux, 4), Some("write"));
        assert_eq!(syscall_name(GuestAbi::I386Linux, 383), Some("statx"));
        assert_eq!(syscall_name(GuestAbi::I386Linux, 300), Some("fstatat64"));
        assert_eq!(syscall_name(GuestAbi::I386Linux, 220), Some("getdents64"));
        assert_eq!(syscall_name(GuestAbi::I386Linux, 64), None);
        assert_eq!(i386::SENDFILE, 187);
        assert_eq!(syscall_name(GuestAbi::I386Linux, 187), Some("sendfile"));
        assert_eq!(i386::TIME, 13);
        assert_eq!(syscall_name(GuestAbi::I386Linux, 13), Some("time"));
        assert_eq!(i386::NANOSLEEP, 162);
        assert_eq!(syscall_name(GuestAbi::I386Linux, 162), Some("nanosleep"));
        assert_eq!(i386::GETGROUPS, 80);
        assert_eq!(syscall_name(GuestAbi::I386Linux, 80), Some("getgroups"));
        assert_eq!(i386::GETGROUPS32, 205);
        assert_eq!(syscall_name(GuestAbi::I386Linux, 205), Some("getgroups32"));
        assert_eq!(i386::STATFS, 99);
        assert_eq!(syscall_name(GuestAbi::I386Linux, 99), Some("statfs"));
        assert_eq!(i386::FSTATFS, 100);
        assert_eq!(syscall_name(GuestAbi::I386Linux, 100), Some("fstatfs"));
        assert_eq!(i386::STATFS64, 268);
        assert_eq!(syscall_name(GuestAbi::I386Linux, 268), Some("statfs64"));
        assert_eq!(i386::FSTATFS64, 269);
        assert_eq!(syscall_name(GuestAbi::I386Linux, 269), Some("fstatfs64"));
    }

    #[test]
    fn initial_stack_layout() {
        let top = 0x7fff_0000u64;
        let args = [b"prog".to_vec(), b"hi".to_vec()];
        let env: [Vec<u8>; 0] = [];
        let (img, sp) = build_initial_stack(top, &args, &env, &[(6, 0x1000)]);
        assert_eq!(sp % 16, 0);
        let r64 = |off: usize| u64::from_le_bytes(img[off..off + 8].try_into().unwrap());
        assert_eq!(r64(0), 2);
        let a0 = r64(8);
        let a1 = r64(16);
        assert_eq!(r64(24), 0);
        assert_eq!(r64(32), 0);
        // auxv: (6,0x1000) + AT_EXECFN(31,args[0]) + AT_NULL.
        assert_eq!(r64(40), 6);
        assert_eq!(r64(48), 0x1000);
        assert_eq!(r64(56), 31);
        assert_eq!(r64(64), a0);
        assert_eq!(r64(72), 0);
        assert_eq!(r64(80), 0);
        // 文字列の解決。
        let at = |addr: u64| (addr - sp) as usize;
        assert_eq!(&img[at(a0)..at(a0) + 4], b"prog");
        assert_eq!(&img[at(a1)..at(a1) + 2], b"hi");
        assert_eq!(syscall_name(GuestAbi::Unknown, 64), None);
    }

    #[test]
    fn mips_o32_numbers() {
        assert_eq!(mips_o32::EXIT, 4001);
        assert_eq!(mips_o32::WRITE, 4004);
        assert_eq!(
            syscall_name(GuestAbi::MipsO32, mips_o32::WRITE),
            Some("write")
        );
        assert_eq!(
            syscall_name(GuestAbi::MipsO32, mips_o32::EXIT),
            Some("exit")
        );
        assert_eq!(syscall_name(GuestAbi::MipsO32, 4000), None);
    }
}
