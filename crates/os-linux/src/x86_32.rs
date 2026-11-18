// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 の 32ビット（Linux の i386 ABI、EM_386）のシステムコール番号。
//! 値はカーネルの UAPI 由来の事実である。新旧 stat 系は 32ビットの実態に合わせ、
//! newfstatat（32ビットに存在しない）の代わりに fstatat64 を持つ。
// Ref: SRC-LINUX (7.3).

pub const READ: u64 = 3;
pub const WRITE: u64 = 4;
pub const CLOSE: u64 = 6;
pub const MMAP: u64 = 90;
/// mmap2/mmap_pgoff。offset はページ単位（musl i386 はこちらを使う）。
pub const MMAP_PG: u64 = 192;
pub const MPROTECT: u64 = 125;
pub const MUNMAP: u64 = 91;
pub const BRK: u64 = 45;
pub const EXIT: u64 = 1;
pub const EXIT_GROUP: u64 = 252;
pub const UNAME: u64 = 122;
pub const SET_THREAD_AREA: u64 = 243;
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
pub const RT_SIGRETURN: u64 = 173;
pub const PAUSE: u64 = 29;
pub const RT_SIGPENDING: u64 = 176;
pub const RT_SIGTIMEDWAIT: u64 = 177;
pub const RT_SIGSUSPEND: u64 = 179;
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
pub const SETGROUPS32: u64 = 206;
pub const FCHDIR: u64 = 133;
pub const SYSINFO: u64 = 116;
pub const PERSONALITY: u64 = 136;
pub const SETSID: u64 = 66;
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
// i386 musl が使う旧番号・32系・time64 の番号。
pub const OPEN: u64 = 5;
pub const FORK: u64 = 2;
pub const VFORK: u64 = 190;
pub const PIPE: u64 = 42;
pub const GETPPID: u64 = 64;
pub const GETTIMEOFDAY: u64 = 78;
pub const GETCPU: u64 = 318;
pub const LLSEEK: u64 = 140;
pub const STAT64: u64 = 195;
pub const LSTAT64: u64 = 196;
pub const FSTAT64: u64 = 197;
pub const GETUID32: u64 = 199;
pub const GETGID32: u64 = 200;
pub const GETEUID32: u64 = 201;
pub const GETEGID32: u64 = 202;
pub const SETUID32: u64 = 213;
pub const SETGID32: u64 = 214;
pub const FCNTL64: u64 = 221;
pub const CLOCK_GETTIME64: u64 = 403;
