// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PDP-11 の Unix V7 ABI 共通部。
//!
//! 規約: システムコールは `trap` 命令（0104nn。下位 8 ビットが
//! 番号）で発行する。引数が 1 個以下の呼出しは直接形で、第 1
//! 引数は r0 に置く。引数が 2 個以上の呼出しは `sys indir`
//! （010400）形で、trap の次の語はデータ空間の呼出しテンプレ
//! （`sys n` の語と引数語の並び）を指す。成功は PSW.C=0 で
//! r0 が戻り値、失敗は PSW.C=1 で r0 が errno。32 ビット値は
//! PDP-11 の語順（上位語が先）で運ばれる。
//! Ref: SPEC-UNIX-V7（システムコールの節と a.out(5)）.

/// syscall の実装。
pub mod sys;

/// V7 の errno。
pub mod errno {
    pub const EPERM: u16 = 1;
    pub const ENOENT: u16 = 2;
    pub const ESRCH: u16 = 3;
    pub const EINTR: u16 = 4;
    pub const EIO: u16 = 5;
    pub const ENXIO: u16 = 6;
    pub const E2BIG: u16 = 7;
    pub const ENOEXEC: u16 = 8;
    pub const EBADF: u16 = 9;
    pub const ECHILD: u16 = 10;
    pub const EAGAIN: u16 = 11;
    pub const ENOMEM: u16 = 12;
    pub const EACCES: u16 = 13;
    pub const EFAULT: u16 = 14;
    pub const ENOTBLK: u16 = 15;
    pub const EBUSY: u16 = 16;
    pub const EEXIST: u16 = 17;
    pub const EXDEV: u16 = 18;
    pub const ENODEV: u16 = 19;
    pub const ENOTDIR: u16 = 20;
    pub const EISDIR: u16 = 21;
    pub const EINVAL: u16 = 22;
    pub const ENFILE: u16 = 23;
    pub const EMFILE: u16 = 24;
    pub const ENOTTY: u16 = 25;
    pub const ETXTBSY: u16 = 26;
    pub const EFBIG: u16 = 27;
    pub const ENOSPC: u16 = 28;
    pub const ESPIPE: u16 = 29;
    pub const EROFS: u16 = 30;
    pub const EMLINK: u16 = 31;
    pub const EPIPE: u16 = 32;
}

/// V7 のシグナル番号。
pub mod sig {
    pub const HUP: u8 = 1;
    pub const INT: u8 = 2;
    pub const QUIT: u8 = 3;
    pub const ILL: u8 = 4;
    pub const TRACE: u8 = 5;
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
    /// コアを吐いて死んだことを示す、終了状態の旗。
    pub const CORE: u32 = 0o200;
}

/// システムコールの表項目。`args` は `sys` の語の後に続く
/// `u.u_arg` 語の数（直接形では trap の次の語、indir では
/// テンプレの次の語 —— `mov 4(r5),0f` 系のスタブが貼る語数）。
/// レジスタで運ばれる引数（fd 系の r0 や dup の r1）はここに
/// 数えない —— 実装側が `r_get` で読む。
#[derive(Clone, Copy, Debug)]
pub struct SysEnt {
    pub name: &'static str,
    pub args: u8,
}

/// `sysent[n]` = 番号 n の項目。実装の有無は `sys` 側の振り分け。
// Ref: SPEC-UNIX-V7 §2（各システムコールの引数の並び）.
#[rustfmt::skip]
pub const SYSENT: [SysEnt; 64] = [
    SysEnt { name: "indir",  args: 0 }, //  0
    SysEnt { name: "exit",   args: 0 }, //  1
    SysEnt { name: "fork",   args: 0 }, //  2
    SysEnt { name: "read",   args: 2 }, //  3
    SysEnt { name: "write",  args: 2 }, //  4
    SysEnt { name: "open",   args: 2 }, //  5
    SysEnt { name: "close",  args: 0 }, //  6
    SysEnt { name: "wait",   args: 0 }, //  7
    SysEnt { name: "creat",  args: 2 }, //  8
    SysEnt { name: "link",   args: 2 }, //  9
    SysEnt { name: "unlink", args: 1 }, // 10
    SysEnt { name: "exec",   args: 3 }, // 11
    SysEnt { name: "chdir",  args: 1 }, // 12
    SysEnt { name: "time",   args: 0 }, // 13
    SysEnt { name: "mknod",  args: 3 }, // 14
    SysEnt { name: "chmod",  args: 2 }, // 15
    SysEnt { name: "chown",  args: 3 }, // 16
    SysEnt { name: "sbreak", args: 1 }, // 17
    SysEnt { name: "stat",   args: 2 }, // 18
    SysEnt { name: "seek",   args: 3 }, // 19 — fd・off(long=2語)・whence
    SysEnt { name: "getpid", args: 0 }, // 20
    SysEnt { name: "mount",  args: 3 }, // 21
    SysEnt { name: "umount", args: 1 }, // 22
    SysEnt { name: "setuid", args: 0 }, // 23
    SysEnt { name: "getuid", args: 0 }, // 24
    SysEnt { name: "stime",  args: 0 }, // 25
    SysEnt { name: "ptrace", args: 3 }, // 26
    SysEnt { name: "alarm",  args: 0 }, // 27
    SysEnt { name: "fstat",  args: 1 }, // 28
    SysEnt { name: "pause",  args: 0 }, // 29
    SysEnt { name: "utime",  args: 2 }, // 30
    SysEnt { name: "nosys",  args: 1 }, // 31 — 旧 stty
    SysEnt { name: "nosys",  args: 1 }, // 32 — 旧 gtty
    SysEnt { name: "access", args: 3 }, // 33
    SysEnt { name: "nice",   args: 0 }, // 34
    SysEnt { name: "ftime",  args: 1 }, // 35
    SysEnt { name: "sync",   args: 0 }, // 36
    SysEnt { name: "kill",   args: 1 }, // 37
    SysEnt { name: "nosys",  args: 0 }, // 38
    SysEnt { name: "nosys",  args: 0 }, // 39
    SysEnt { name: "tell",   args: 0 }, // 40
    SysEnt { name: "dup",    args: 0 }, // 41
    SysEnt { name: "pipe",   args: 0 }, // 42
    SysEnt { name: "times",  args: 1 }, // 43
    SysEnt { name: "profil", args: 4 }, // 44
    SysEnt { name: "nosys",  args: 0 }, // 45
    SysEnt { name: "setgid", args: 0 }, // 46
    SysEnt { name: "getgid", args: 0 }, // 47
    SysEnt { name: "signal", args: 2 }, // 48
    SysEnt { name: "nosys",  args: 0 }, // 49
    SysEnt { name: "nosys",  args: 0 }, // 50
    SysEnt { name: "acct",   args: 1 }, // 51
    SysEnt { name: "phys",   args: 3 }, // 52
    SysEnt { name: "lock",   args: 1 }, // 53
    SysEnt { name: "ioctl",  args: 3 }, // 54
    SysEnt { name: "nosys",  args: 0 }, // 55
    SysEnt { name: "mpx",    args: 2 }, // 56
    SysEnt { name: "nosys",  args: 0 }, // 57
    SysEnt { name: "nosys",  args: 0 }, // 58
    SysEnt { name: "exece",  args: 3 }, // 59
    SysEnt { name: "umask",  args: 1 }, // 60
    SysEnt { name: "chroot", args: 1 }, // 61
    SysEnt { name: "nosys",  args: 0 }, // 62
    SysEnt { name: "nosys",  args: 0 }, // 63
];
