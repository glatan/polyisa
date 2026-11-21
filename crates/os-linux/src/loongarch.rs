// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! LoongArch（LA64/LA32）の Linux ゲスト ABI 共通部。
//!
//! 規約：syscall 番号は $a7（$r11）、引数は $a0–$a5（$r4–$r9）、
//! 戻り値は $a0（$r4）、失敗は $a0 = -errno。発行点は
//! `syscall`（慣例の即値 0）。番号表は asm-generic
//! （include/uapi/asm-generic/unistd.h）そのまま。
//! Ref: SRC-LINUX — arch/loongarch/kernel/entry.S,
//! include/uapi/asm-generic/unistd.h.

/// LoongArch の Linux syscall 処理。`guest-loongarch` 機能で有効になる。
#[cfg(feature = "guest-loongarch")]
pub mod sys;

/// syscall 番号定数（asm-generic）。
/// Ref: SRC-LINUX — include/uapi/asm-generic/unistd.h.
pub mod nr {
    pub const GETCWD: u64 = 17;
    pub const DUP: u64 = 23;
    pub const DUP3: u64 = 24;
    pub const FCNTL: u64 = 25;
    pub const IOCTL: u64 = 29;
    pub const MKDIRAT: u64 = 34;
    pub const UNLINKAT: u64 = 35;
    pub const LINKAT: u64 = 37;
    pub const FACCESSAT: u64 = 48;
    pub const CHDIR: u64 = 49;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const PIPE2: u64 = 59;
    pub const GETDENTS64: u64 = 61;
    pub const LSEEK: u64 = 62;
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const READV: u64 = 65;
    pub const WRITEV: u64 = 66;
    pub const PREAD64: u64 = 67;
    pub const PWRITE64: u64 = 68;
    pub const SENDFILE: u64 = 71;
    pub const PPOLL: u64 = 73;
    pub const READLINKAT: u64 = 78;
    pub const NEWFSTATAT: u64 = 79;
    pub const FSTAT: u64 = 80;
    pub const FSYNC: u64 = 82;
    pub const EXIT: u64 = 93;
    pub const EXIT_GROUP: u64 = 94;
    pub const SET_TID_ADDRESS: u64 = 96;
    pub const FUTEX: u64 = 98;
    pub const SET_ROBUST_LIST: u64 = 99;
    pub const NANOSLEEP: u64 = 101;
    pub const CLOCK_GETTIME: u64 = 113;
    pub const CLOCK_GETRES: u64 = 114;
    pub const SCHED_GETAFFINITY: u64 = 123;
    pub const SCHED_YIELD: u64 = 124;
    pub const RT_SIGACTION: u64 = 134;
    pub const RT_SIGPROCMASK: u64 = 135;
    pub const RT_SIGRETURN: u64 = 139;
    pub const UTSNAME: u64 = 160;
    pub const GETRUSAGE: u64 = 165;
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
    pub const CLONE: u64 = 220;
    pub const EXECVE: u64 = 221;
    pub const MMAP: u64 = 222;
    pub const MPROTECT: u64 = 226;
    pub const PRLIMIT64: u64 = 261;
    pub const GETRANDOM: u64 = 278;
    pub const STATX: u64 = 291;
    pub const RSEQ: u64 = 293;
}

/// syscall 番号から名前を引く（診断用）。
#[must_use]
pub fn name(nr: u64) -> Option<&'static str> {
    SYSCALLS
        .binary_search_by_key(&nr, |(n, _)| *n)
        .ok()
        .map(|i| SYSCALLS[i].1)
}

/// `name` の引き表。asm-generic のよく使う範囲。
const SYSCALLS: &[(u64, &str)] = &[
    (17, "getcwd"),
    (23, "dup"),
    (24, "dup3"),
    (25, "fcntl"),
    (29, "ioctl"),
    (34, "mkdirat"),
    (35, "unlinkat"),
    (37, "linkat"),
    (48, "faccessat"),
    (49, "chdir"),
    (56, "openat"),
    (57, "close"),
    (59, "pipe2"),
    (61, "getdents64"),
    (62, "lseek"),
    (63, "read"),
    (64, "write"),
    (65, "readv"),
    (66, "writev"),
    (67, "pread64"),
    (68, "pwrite64"),
    (71, "sendfile"),
    (73, "ppoll"),
    (78, "readlinkat"),
    (79, "newfstatat"),
    (80, "fstat"),
    (82, "fsync"),
    (93, "exit"),
    (94, "exit_group"),
    (96, "set_tid_address"),
    (98, "futex"),
    (99, "set_robust_list"),
    (101, "nanosleep"),
    (113, "clock_gettime"),
    (114, "clock_getres"),
    (123, "sched_getaffinity"),
    (124, "sched_yield"),
    (134, "rt_sigaction"),
    (135, "rt_sigprocmask"),
    (139, "rt_sigreturn"),
    (160, "uname"),
    (165, "getrusage"),
    (167, "prctl"),
    (168, "getcpu"),
    (169, "gettimeofday"),
    (172, "getpid"),
    (173, "getppid"),
    (174, "getuid"),
    (175, "geteuid"),
    (176, "getgid"),
    (177, "getegid"),
    (178, "gettid"),
    (179, "sysinfo"),
    (214, "brk"),
    (215, "munmap"),
    (220, "clone"),
    (221, "execve"),
    (222, "mmap"),
    (226, "mprotect"),
    (261, "prlimit64"),
    (278, "getrandom"),
    (291, "statx"),
    (293, "rseq"),
];
