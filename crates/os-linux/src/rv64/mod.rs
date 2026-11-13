// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! RISC-V（asm-generic）のシステムコール番号。
//! 値はカーネルの UAPI 表由来の事実である。
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

/// o32 相当の RISC-V Linux の syscall 処理。`riscv` 機能で有効になる。
#[cfg(feature = "riscv")]
pub mod sys;
