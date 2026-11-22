// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OpenRISC（or1k）の Linux ゲスト ABI 共通部。
//!
//! 規約: syscall 番号は r11、引数は r3-r8、戻り値は r11、
//! 失敗は r11 = -errno。発行点は `l.sys`（例外ベクタ 0xc00）。
//! 番号表は asm-generic の 32 ビット系（`scripts/syscall.tbl` を
//! `arch/openrisc/kernel/Makefile.syscalls` の
//! `syscall_abis_32 += or1k time32 stat64 rlimit renameat` で畳んだ
//! `unistd_32.h`）である。32 ビット系のため nr62 は `sys_llseek`
//! （結果ポインタ規約）、nr222 は `sys_mmap2`（pgoff 単位）、
//! nr79/80 は `fstatat64`/`fstat64`（asm-generic `struct stat64`
//! の time32 レイアウト）である。
//! Ref: SRC-LINUX-OPENRISC-UAPI — scripts/syscall.tbl,
//! arch/openrisc/kernel/Makefile.syscalls,
//! arch/openrisc/kernel/entry.S（l.sys 発行点と r3-r8/r11 規約）.

/// OpenRISC Linux の syscall 処理。`guest-openrisc` 機能で有効になる。
#[cfg(feature = "guest-openrisc")]
pub mod sys;

/// syscall 番号定数（`scripts/syscall.tbl` の or1k 32 ビット ABI
/// 畳み込み。定数名は tbl の entry 名に揃える）。
/// Ref: SRC-LINUX-OPENRISC-UAPI.
pub mod nr {
    pub const IOCTL: u64 = 29;
    pub const FCNTL: u64 = 25;
    pub const GETDENTS64: u64 = 61;
    pub const CLOCK_GETTIME64: u64 = 403;
    pub const FACCESSAT: u64 = 48;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    /// `62 32 llseek sys_llseek` — (fd, off_hi, off_lo, result*, whence)。
    pub const LLSEEK: u64 = 62;
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const READV: u64 = 65;
    pub const WRITEV: u64 = 66;
    /// `pread64(fd, buf, len, pos)` — pos は r6:r7 の 64 ビット対（BE）。
    pub const PREAD64: u64 = 67;
    pub const READLINKAT: u64 = 78;
    /// `79 stat64 fstatat64 sys_fstatat64` — stat64 構造体（time32）。
    pub const FSTATAT64: u64 = 79;
    /// `80 stat64 fstat64 sys_fstat64` — stat64 構造体（time32）。
    pub const FSTAT64: u64 = 80;
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
    pub const SETREGID: u64 = 143;
    pub const SETGID: u64 = 144;
    pub const SETREUID: u64 = 145;
    pub const SETUID: u64 = 146;
    pub const SETRESUID: u64 = 147;
    pub const SETRESGID: u64 = 149;
    pub const SETFSUID: u64 = 151;
    pub const SETFSGID: u64 = 152;
    pub const GETPID: u64 = 172;
    pub const GETPPID: u64 = 173;
    pub const GETUID: u64 = 174;
    pub const GETEUID: u64 = 175;
    pub const GETGID: u64 = 176;
    pub const GETEGID: u64 = 177;
    pub const GETTID: u64 = 178;
    pub const BRK: u64 = 214;
    pub const MUNMAP: u64 = 215;
    /// `222 32 mmap2 sys_mmap2` — offset 引数は 4KiB ページ単位。
    pub const MMAP2: u64 = 222;
    pub const MPROTECT: u64 = 226;
    pub const OR1K_ATOMIC: u64 = 244;
    pub const PRLIMIT64: u64 = 261;
    pub const GETRANDOM: u64 = 278;
    pub const STATX: u64 = 291;
}
