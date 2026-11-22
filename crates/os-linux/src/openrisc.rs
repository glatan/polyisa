// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OpenRISC（or1k）の Linux ゲスト ABI 共通部。
//!
//! 規約: syscall 番号は r11、引数は r3-r8、戻り値は r11、
//! 失敗は r11 = -errno。発行点は `l.sys`（例外ベクタ 0xc00）。
//! 番号表は asm-generic（arch/openrisc/include/uapi/asm/unistd.h が
//! asm-generic/unistd.h を引く）に or1k_atomic=244 を加えたもの。
//! Ref: SRC-LINUX-OPENRISC-UAPI — arch/openrisc/include/uapi/asm/unistd.h,
//! arch/openrisc/kernel/entry.S（l.sys 発行点と r3-r8/r11 規約）.

/// OpenRISC Linux の syscall 処理。`guest-openrisc` 機能で有効になる。
#[cfg(feature = "guest-openrisc")]
pub mod sys;

/// syscall 番号定数（asm-generic + or1k_atomic）。
/// Ref: SRC-LINUX-OPENRISC-UAPI.
pub mod nr {
    pub const IOCTL: u64 = 29;
    pub const FCNTL: u64 = 25;
    pub const GETDENTS64: u64 = 61;
    pub const CLOCK_GETTIME64: u64 = 403;
    pub const FACCESSAT: u64 = 48;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const LSEEK: u64 = 62;
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const READV: u64 = 65;
    pub const WRITEV: u64 = 66;
    pub const PREAD64: u64 = 67;
    pub const READLINKAT: u64 = 78;
    pub const NEWFSTATAT: u64 = 79;
    pub const FSTAT: u64 = 80;
    pub const EXIT: u64 = 93;
    pub const EXIT_GROUP: u64 = 94;
    pub const SET_TID_ADDRESS: u64 = 96;
    pub const FUTEX: u64 = 98;
    pub const SET_ROBUST_LIST: u64 = 99;
    pub const NANOSLEEP: u64 = 101;
    pub const CLOCK_GETTIME: u64 = 113;
    pub const RT_SIGACTION: u64 = 134;
    pub const RT_SIGPROCMASK: u64 = 135;
    pub const UNAME: u64 = 160;
    pub const GETPID: u64 = 172;
    pub const GETPPID: u64 = 173;
    pub const GETUID: u64 = 174;
    pub const GETEUID: u64 = 175;
    pub const GETGID: u64 = 176;
    pub const GETEGID: u64 = 177;
    pub const GETTID: u64 = 178;
    pub const BRK: u64 = 214;
    pub const MUNMAP: u64 = 215;
    pub const MMAP: u64 = 222;
    pub const MPROTECT: u64 = 226;
    pub const OR1K_ATOMIC: u64 = 244;
    pub const PRLIMIT64: u64 = 261;
    pub const GETRANDOM: u64 = 278;
    pub const STATX: u64 = 291;
}
