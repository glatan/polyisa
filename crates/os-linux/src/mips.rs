// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS の Linux ゲスト ABI 共通部。o32・n32・n64 が分かれる値と、
//! 三 ABI で共通の値をここに置く。実装は `sys` モジュール。
//!
//! MIPS は errno・シグナル番号・`O_*`/`MAP_*` の値が asm-generic と異なる。
//! 値はカーネル 6.19 の `arch/mips/include/uapi/asm/*.h` 由来の事実であり、
//! `heavy_abi_uapi` で突き合わせる。
// Ref: SRC-LINUX (7.3).

/// MIPS の Linux syscall 処理。`guest-mips` 機能で有効になる。
/// 設計の依存規則（`docs/design/workspace.md` の「依存規則」）が
/// `os-linux` の `guests/*` 依存を機能フラグ付きで認めている。
#[cfg(feature = "guest-mips")]
pub mod sys;

/// MIPS の errno。asm-generic とは 35 以降が違う。
/// `ERRNO_BASE`（1–34）は asm-generic と同じなので表に含めない。
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
    pub const EMFILE: u32 = 24;
    pub const ENOTTY: u32 = 25;
    pub const EFBIG: u32 = 27;
    pub const ENOSPC: u32 = 28;
    pub const ESPIPE: u32 = 29;
    pub const EROFS: u32 = 30;
    pub const EMLINK: u32 = 31;
    pub const EPIPE: u32 = 32;
    pub const EDOM: u32 = 33;
    pub const ERANGE: u32 = 34;
    pub const ENOMSG: u32 = 35;
    pub const EIDRM: u32 = 36;
    pub const EDEADLK: u32 = 45;
    pub const ENOLCK: u32 = 46;
    pub const ENOSTR: u32 = 60;
    pub const ENODATA: u32 = 61;
    pub const ETIME: u32 = 62;
    pub const ENOSR: u32 = 63;
    pub const ENOLINK: u32 = 67;
    pub const EPROTO: u32 = 71;
    pub const EMULTIHOP: u32 = 74;
    pub const EBADMSG: u32 = 77;
    pub const ENAMETOOLONG: u32 = 78;
    pub const EOVERFLOW: u32 = 79;
    pub const EILSEQ: u32 = 88;
    pub const ENOSYS: u32 = 89;
    pub const ELOOP: u32 = 90;
    pub const ERESTART: u32 = 91;
    pub const ENOTEMPTY: u32 = 93;
    pub const EUSERS: u32 = 94;
    pub const ENOTSOCK: u32 = 95;
    pub const EDESTADDRREQ: u32 = 96;
    pub const EMSGSIZE: u32 = 97;
    pub const EPROTOTYPE: u32 = 98;
    pub const ENOPROTOOPT: u32 = 99;
    pub const EPROTONOSUPPORT: u32 = 120;
    pub const ESOCKTNOSUPPORT: u32 = 121;
    pub const EOPNOTSUPP: u32 = 122;
    pub const EAFNOSUPPORT: u32 = 124;
    pub const EADDRINUSE: u32 = 125;
    pub const ECONNRESET: u32 = 131;
    pub const ENOBUFS: u32 = 132;
    pub const EISCONN: u32 = 133;
    pub const ENOTCONN: u32 = 134;
    pub const ETIMEDOUT: u32 = 145;
    pub const ECONNREFUSED: u32 = 146;
    pub const EINPROGRESS: u32 = 150;
    pub const ESTALE: u32 = 151;
    pub const ECANCELED: u32 = 158;
    pub const EOWNERDEAD: u32 = 165;
    pub const ENOTRECOVERABLE: u32 = 166;
    pub const EDQUOT: u32 = 1133;
}

/// ホスト（asm-generic）の errno を MIPS の値へ写す。
/// 1–34 は両者で同じ値なので表にない。`e` が表にない場合はそのまま返す。
#[rustfmt::skip]
#[must_use]
pub fn host_to_mips_errno(e: u32) -> u32 {
    // (asm-generic, MIPS)
    const MAP: &[(u32, u32)] = &[
        (35, errno::EDEADLK),
        (36, errno::ENAMETOOLONG),
        (37, errno::ENOLCK),
        (38, errno::ENOSYS),
        (39, errno::ENOTEMPTY),
        (40, errno::ELOOP),
        (42, errno::ENOMSG),
        (43, errno::EIDRM),
        (44, 37),  // ECHRNG
        (45, 38),  // EL2NSYNC
        (46, 39),  // EL3HLT
        (47, 40),  // EL3RST
        (48, 41),  // ELNRNG
        (49, 42),  // EUNATCH
        (50, 43),  // ENOCSI
        (51, 44),  // EL2HLT
        (52, 50),  // EBADE
        (53, 51),  // EBADR
        (54, 52),  // EXFULL
        (55, 53),  // ENOANO
        (56, 54),  // EBADRQC
        (57, 55),  // EBADSLT
        (60, errno::ENOSTR),
        (61, errno::ENODATA),
        (62, errno::ETIME),
        (63, errno::ENOSR),
        (64, 64),  // ENONET
        (65, 65),  // ENOPKG
        (66, 66),  // EREMOTE
        (67, errno::ENOLINK),
        (68, 68),  // EADV
        (69, 69),  // ESRMNT
        (70, 70),  // ECOMM
        (71, errno::EPROTO),
        (72, errno::EMULTIHOP),
        (73, 73),  // EDOTDOT
        (74, errno::EBADMSG),
        (75, errno::EOVERFLOW),
        (76, 80),  // ENOTUNIQ
        (77, 81),  // EBADFD
        (78, 82),  // EREMCHG
        (79, 83),  // ELIBACC
        (80, 84),  // ELIBBAD
        (81, 85),  // ELIBSCN
        (82, 86),  // ELIBMAX
        (83, 87),  // ELIBEXEC
        (84, errno::EILSEQ),
        (85, errno::ERESTART),
        (86, 92),  // ESTRPIPE
        (87, errno::EUSERS),
        (88, errno::ENOTSOCK),
        (89, errno::EDESTADDRREQ),
        (90, errno::EMSGSIZE),
        (91, errno::EPROTOTYPE),
        (92, errno::ENOPROTOOPT),
        (93, 120), // EPROTONOSUPPORT
        (94, 121), // ESOCKTNOSUPPORT
        (95, errno::EOPNOTSUPP),
        (96, 123), // EPFNOSUPPORT
        (97, errno::EAFNOSUPPORT),
        (98, 125), // EADDRINUSE
        (99, 126), // EADDRNOTAVAIL
        (100, 127), // ENETDOWN
        (101, 128), // ENETUNREACH
        (102, 129), // ENETRESET
        (103, 130), // ECONNABORTED
        (104, errno::ECONNRESET),
        (105, errno::ENOBUFS),
        (106, errno::EISCONN),
        (107, errno::ENOTCONN),
        (108, 143), // ESHUTDOWN
        (109, 144), // ETOOMANYREFS
        (110, errno::ETIMEDOUT),
        (111, errno::ECONNREFUSED),
        (112, 147), // EHOSTDOWN
        (113, 148), // EHOSTUNREACH
        (114, 149), // EALREADY
        (115, errno::EINPROGRESS),
        (116, errno::ESTALE),
        (117, 135), // EUCLEAN
        (118, 137), // ENOTNAM
        (119, 138), // ENAVAIL
        (120, 139), // EISNAM
        (121, 140), // EREMOTEIO
        (122, errno::EDQUOT),
        (123, 159), // ENOMEDIUM
        (124, 160), // EMEDIUMTYPE
        (125, errno::ECANCELED),
        (126, 161), // ENOKEY
        (127, 162), // EKEYEXPIRED
        (128, 163), // EKEYREVOKED
        (129, 164), // EKEYREJECTED
        (130, errno::EOWNERDEAD),
        (131, errno::ENOTRECOVERABLE),
        (132, 167), // ERFKILL
        (133, 168), // EHWPOISON
    ];
    MAP.iter().find(|(host, _)| *host == e).map_or(e, |(_, m)| *m)
}

/// MIPS のシグナル番号。USR1/USR2/CHLD/PWR/WINCH/URG/IO/STOP/TSTP/CONT/TTIN/TTOU
/// が asm-generic とずれている。
pub mod signal {
    pub const SIGHUP: u32 = 1;
    pub const SIGINT: u32 = 2;
    pub const SIGQUIT: u32 = 3;
    pub const SIGILL: u32 = 4;
    pub const SIGTRAP: u32 = 5;
    pub const SIGABRT: u32 = 6;
    pub const SIGEMT: u32 = 7;
    pub const SIGFPE: u32 = 8;
    pub const SIGKILL: u32 = 9;
    pub const SIGBUS: u32 = 10;
    pub const SIGSEGV: u32 = 11;
    pub const SIGSYS: u32 = 12;
    pub const SIGPIPE: u32 = 13;
    pub const SIGALRM: u32 = 14;
    pub const SIGTERM: u32 = 15;
    pub const SIGUSR1: u32 = 16;
    pub const SIGUSR2: u32 = 17;
    pub const SIGCHLD: u32 = 18;
    pub const SIGPWR: u32 = 19;
    pub const SIGWINCH: u32 = 20;
    pub const SIGURG: u32 = 21;
    pub const SIGIO: u32 = 22;
    pub const SIGSTOP: u32 = 23;
    pub const SIGTSTP: u32 = 24;
    pub const SIGCONT: u32 = 25;
    pub const SIGTTIN: u32 = 26;
    pub const SIGTTOU: u32 = 27;
    pub const SIGVTALRM: u32 = 28;
    pub const SIGPROF: u32 = 29;
    pub const SIGXCPU: u32 = 30;
    pub const SIGXFSZ: u32 = 31;
    pub const SIGRTMIN: u32 = 32;
    /// `_NSIG`。sigset は 128 ビット。
    pub const NSIG: u32 = 128;
}

/// MIPS の `O_*`。asm-generic と値が違う。
pub mod oflag {
    pub const APPEND: u32 = 0x0008;
    pub const DSYNC: u32 = 0x0010;
    pub const NONBLOCK: u32 = 0x0080;
    pub const CREAT: u32 = 0x0100;
    pub const TRUNC: u32 = 0x0200;
    pub const EXCL: u32 = 0x0400;
    pub const NOCTTY: u32 = 0x0800;
    pub const LARGEFILE: u32 = 0x2000;
    pub const DIRECT: u32 = 0x8000;
    pub const SYNC: u32 = 0x4000 | DSYNC;
    /// ホストへ渡せるフラグの和。ここにないビットは捨てる。
    pub const KNOWN: u32 =
        APPEND | DSYNC | NONBLOCK | CREAT | TRUNC | EXCL | NOCTTY | LARGEFILE | DIRECT | SYNC;
}

/// MIPS の `MAP_*`。`MAP_ANONYMOUS` が 0x0800（asm-generic は 0x20）。
pub mod mflag {
    pub const SHARED: u32 = 0x0001;
    pub const PRIVATE: u32 = 0x0002;
    pub const FIXED: u32 = 0x0010;
    pub const ANONYMOUS: u32 = 0x0800;
    pub const NORESERVE: u32 = 0x0400;
    pub const GROWSDOWN: u32 = 0x1000;
    pub const DENYWRITE: u32 = 0x2000;
    pub const EXECUTABLE: u32 = 0x4000;
    pub const LOCKED: u32 = 0x8000;
    pub const STACK: u32 = 0x40000;
    pub const HUGETLB: u32 = 0x80000;
}

/// ioctl の番号。MIPS は TCGETS が 0x540d（asm-generic は 0x5401）。
pub mod ioc {
    pub const TCGETS: u64 = 0x540d;
    pub const TCSETS: u64 = 0x540e;
    pub const TIOCGWINSZ: u64 = 0x4008_7468; // _IOR('t', 104, winsize) MIPS 版
    pub const FIONREAD: u64 = 0x467f;
    pub const TIOCNOTTY: u64 = 0x5471;
}
