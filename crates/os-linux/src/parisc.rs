// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PA-RISC（hppa32）Linux のシステムコール番号と ABI 定数。
//!
//! 番号は `arch/parisc/kernel/syscalls/syscall.tbl` 由来の事実。
//! hppa は asm-generic ではなく独自の連番を持つ（レガシ系）。errno
//! は 1–34 が asm-generic/errno-base.h と同値で 35 以上は HP-UX 系の
//! 独自値、O_*/MAP_* も独自値を持つ。syscall の発行点は
//! ページゼロのゲートウェイ `ble 0x100(%sr2,%r0)`、番号は `r20`、引数は
//! `r26`（arg0）から `r21`（arg5）へ降順、戻り値は `r28`（エラーは
//! 負の errno）、戻り番地は `r31`。
//! Ref: SRC-LINUX (7.3).

/// ページゼロのゲートウェイ入口。実行ループは `iaoq_f & !3` が
/// 0x1000 未満のとき、その番地を `handle_trap` の code に載せる。
/// Ref: SRC-LINUX (7.3) — arch/parisc gateway page.
pub mod gate {
    /// ヌルポインタ呼び出し（off 0x00）。
    pub const NULL_PTR: u32 = 0x00;
    /// 軽量 syscall（LWS-CAS。off 0xb0）。
    pub const LWS: u32 = 0xb0;
    /// set_thread_pointer（off 0xe0。実行ループが内蔵処理する）。
    pub const STP: u32 = 0xe0;
    /// 通常の syscall（off 0x100）。
    pub const SYSCALL: u32 = 0x100;
}

/// LWS（軽量 syscall）の副番号。`r20` が番号、`r26`=adr、結果は
/// `r28`、状態は `r21`（0/-errno）。`r25`/`r24`/`r23` の意味は
/// which ごとに異なる（各 const の doc）。
/// カーネルの `lws_table` は 5 エントリ（`__NR_lws_entries`=5）。
/// Ref: SRC-LINUX — arch/parisc/kernel/syscall.S `lws_table`・`lws_*`.
pub mod lws {
    /// `__NR_lws_entries`（5）。which>=5 は `comiclr,>>` で
    /// `lws_exit_nosys` に先行分岐するため r28 は不変。
    pub const ENTRIES: u64 = 5;
    /// `lws_table` のカーネル番地の代表値。`lws_start` は which<5
    /// のディスパッチ前に `r28` をこの番地で破壊する（"Scratch use
    /// of r28"）。ユーザに意味を持たないカーネル空間番地。
    pub const TABLE_ADDR: u64 = 0x1010_0000;
    /// CAS: `old` と `*adr` が等しければ `new` を書く。`r28` に元値、
    /// `r21` に 0/-errno（compare_and_swap32、ELF32 用入口）。
    pub const CAS: u64 = 0;
    /// ELF64 用入口（compare_and_swap64）。32 ビットカーネルでは
    /// `lws_exit_nosys` に分岐するため ENOSYS が正しい応答。
    pub const CAS64: u64 = 1;
    /// 新 CAS（`r25`/`r24`=old/new へのポインタ、`r23`=サイズ
    /// コード 0/1/2/3 → 8/16/32/64 ビット）。`r28` に成否（0=成功）、
    /// `r21` に 0/-errno（compare_and_swap_2）。
    pub const CAS2: u64 = 2;
    /// 不可分交換（atomic_xchg。`r25`=サイズコード、
    /// `r24`=new 値へのポインタ、`r23`=旧値の書き戻し先）。
    pub const XCHG: u64 = 3;
    /// 不可分ストア（atomic_store。`r25`=サイズコード、
    /// `r24`=値へのポインタ）。
    pub const STORE: u64 = 4;
}

/// hppa の errno。1–34 は `asm-generic/errno-base.h` と同値、35 以上は
/// `uapi/asm/errno.h` の独自表（HP-UX 系の値。ENOTEMPTY=247・
/// ENAMETOOLONG=248・ELOOP=249・ENOSYS=251、ソケット系は 216–245）。
/// 負で `r28` に返す。
// Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/errno.h
// と asm-generic/errno-base.h.
pub mod errno {
    // ---- asm-generic/errno-base.h と同値（1–34）----
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
    pub const ENOTBLK: u32 = 15;
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
    pub const ETXTBSY: u32 = 26;
    pub const EFBIG: u32 = 27;
    pub const ENOSPC: u32 = 28;
    pub const ESPIPE: u32 = 29;
    pub const EROFS: u32 = 30;
    pub const EMLINK: u32 = 31;
    pub const EPIPE: u32 = 32;
    pub const EDOM: u32 = 33;
    pub const ERANGE: u32 = 34;
    // ---- uapi/asm/errno.h の独自表（35 以上）----
    pub const ENOMSG: u32 = 35;
    pub const EIDRM: u32 = 36;
    pub const ECHRNG: u32 = 37;
    pub const EL2NSYNC: u32 = 38;
    pub const EL3HLT: u32 = 39;
    pub const EL3RST: u32 = 40;
    pub const ELNRNG: u32 = 41;
    pub const EUNATCH: u32 = 42;
    pub const ENOCSI: u32 = 43;
    pub const EL2HLT: u32 = 44;
    pub const EDEADLK: u32 = 45;
    pub const ENOLCK: u32 = 46;
    pub const EILSEQ: u32 = 47;
    pub const ENONET: u32 = 50;
    pub const ENODATA: u32 = 51;
    pub const ETIME: u32 = 52;
    pub const ENOSR: u32 = 53;
    pub const ENOSTR: u32 = 54;
    pub const ENOPKG: u32 = 55;
    pub const ENOLINK: u32 = 57;
    pub const EADV: u32 = 58;
    pub const ESRMNT: u32 = 59;
    pub const ECOMM: u32 = 60;
    pub const EPROTO: u32 = 61;
    pub const EMULTIHOP: u32 = 64;
    pub const EDOTDOT: u32 = 66;
    pub const EBADMSG: u32 = 67;
    pub const EUSERS: u32 = 68;
    pub const EDQUOT: u32 = 69;
    pub const ESTALE: u32 = 70;
    pub const EREMOTE: u32 = 71;
    pub const EOVERFLOW: u32 = 72;
    pub const EBADE: u32 = 160;
    pub const EBADR: u32 = 161;
    pub const EXFULL: u32 = 162;
    pub const ENOANO: u32 = 163;
    pub const EBADRQC: u32 = 164;
    pub const EBADSLT: u32 = 165;
    pub const EBFONT: u32 = 166;
    pub const ENOTUNIQ: u32 = 167;
    pub const EBADFD: u32 = 168;
    pub const EREMCHG: u32 = 169;
    pub const ELIBACC: u32 = 170;
    pub const ELIBBAD: u32 = 171;
    pub const ELIBSCN: u32 = 172;
    pub const ELIBMAX: u32 = 173;
    pub const ELIBEXEC: u32 = 174;
    pub const ERESTART: u32 = 175;
    pub const ESTRPIPE: u32 = 176;
    pub const EUCLEAN: u32 = 177;
    pub const ENOTNAM: u32 = 178;
    pub const ENAVAIL: u32 = 179;
    pub const EISNAM: u32 = 180;
    pub const EREMOTEIO: u32 = 181;
    pub const ENOMEDIUM: u32 = 182;
    pub const EMEDIUMTYPE: u32 = 183;
    pub const ENOKEY: u32 = 184;
    pub const EKEYEXPIRED: u32 = 185;
    pub const EKEYREVOKED: u32 = 186;
    pub const EKEYREJECTED: u32 = 187;
    pub const ENOTSOCK: u32 = 216;
    pub const EDESTADDRREQ: u32 = 217;
    pub const EMSGSIZE: u32 = 218;
    pub const EPROTOTYPE: u32 = 219;
    pub const ENOPROTOOPT: u32 = 220;
    pub const EPROTONOSUPPORT: u32 = 221;
    pub const ESOCKTNOSUPPORT: u32 = 222;
    pub const EOPNOTSUPP: u32 = 223;
    pub const EPFNOSUPPORT: u32 = 224;
    pub const EAFNOSUPPORT: u32 = 225;
    pub const EADDRINUSE: u32 = 226;
    pub const EADDRNOTAVAIL: u32 = 227;
    pub const ENETDOWN: u32 = 228;
    pub const ENETUNREACH: u32 = 229;
    pub const ENETRESET: u32 = 230;
    pub const ECONNABORTED: u32 = 231;
    pub const ECONNRESET: u32 = 232;
    pub const ENOBUFS: u32 = 233;
    pub const EISCONN: u32 = 234;
    pub const ENOTCONN: u32 = 235;
    pub const ESHUTDOWN: u32 = 236;
    pub const ETOOMANYREFS: u32 = 237;
    pub const ETIMEDOUT: u32 = 238;
    pub const ECONNREFUSED: u32 = 239;
    pub const EHOSTDOWN: u32 = 241;
    pub const EHOSTUNREACH: u32 = 242;
    pub const EALREADY: u32 = 244;
    pub const EINPROGRESS: u32 = 245;
    pub const ENOTEMPTY: u32 = 247;
    pub const ENAMETOOLONG: u32 = 248;
    pub const ELOOP: u32 = 249;
    pub const ENOSYS: u32 = 251;
    pub const ECANCELLED: u32 = 253;
    pub const EOWNERDEAD: u32 = 254;
    pub const ENOTRECOVERABLE: u32 = 255;
    pub const ERFKILL: u32 = 256;
    pub const EHWPOISON: u32 = 257;
    /// EFTYPE（generic 134 の hppa 値。hppa errno 表の末尾）。
    pub const EFTYPE: u32 = 258;
}

/// `mmap`/`mprotect` の prot と flags。hppa の MAP_FIXED=0x04 と
/// MAP_ANONYMOUS=0x10 は asm-generic（0x10/0x20）と異なる独自値。
/// PROT_* と MAP_SHARED/MAP_PRIVATE（linux/mman.h）は汎用と同じ。
// Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/mman.h.
pub mod mman {
    pub const PROT_READ: u32 = 1;
    pub const PROT_WRITE: u32 = 2;
    pub const PROT_EXEC: u32 = 4;
    pub const MAP_SHARED: u32 = 1;
    pub const MAP_PRIVATE: u32 = 2;
    pub const MAP_FIXED: u32 = 0x04;
    pub const MAP_ANONYMOUS: u32 = 0x10;
}

/// `open`/`openat` の O_*。hppa は独自のビット位置に置く。
/// ACCMODE/TRUNC など arch 側に定義のないものは asm-generic/fcntl.h
/// の値（ACCMODE=3 は読み書きモードの下位 2 ビット）。
// Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/fcntl.h
// と include/uapi/asm-generic/fcntl.h.
pub mod oflag {
    /// アクセスモードのマスク（0=RDONLY/1=WRONLY/2=RDWR、汎用値）。
    pub const ACCMODE: u64 = 0o3;
    pub const CREAT: u64 = 0o400; // 1 << 8
    pub const EXCL: u64 = 0o2000; // 1 << 10
    pub const TRUNC: u64 = 0o1000; // 1 << 9（asm-generic）
    pub const APPEND: u64 = 0o10; // 1 << 3
    pub const NONBLOCK: u64 = 0o200000; // 1 << 16
    pub const DIRECTORY: u64 = 0o10000; // 1 << 12
    pub const NOFOLLOW: u64 = 0o200; // 1 << 7
    /// O_DIRECT（1<<14。hppa は定義しないので asm-generic の値）。
    pub const DIRECT: u64 = 0o40000;
    pub const CLOEXEC: u64 = 0o1000_0000; // 1 << 21
    /// O_NOATIME（1<<20。hppa 定義。F_SETFL で変更可能）。
    pub const NOATIME: u64 = 0o4000_0000;
    /// O_LARGEFILE（1<<11。64 ビットサイズは常時受理するので解釈は不要）。
    pub const LARGEFILE: u64 = 0o4000;
    /// O_PATH（1<<22。fd はパス保持のみ）。
    pub const PATH: u64 = 0o2000_0000;
}

/// *at 系 syscall の dirfd とフラグ（汎用 UAPI）。
// Ref: SRC-LINUX (7.3) — include/uapi/linux/fcntl.h.
pub mod at {
    /// AT_FDCWD（現在の作業ディレクトリを指す dirfd）。
    pub const FDCWD: i64 = -100;
    /// AT_SYMLINK_NOFOLLOW。シンボリックリンクをたどらない。
    pub const SYMLINK_NOFOLLOW: u64 = 0x100;
    /// AT_REMOVEDIR（unlinkat でディレクトリを消す）。
    pub const REMOVEDIR: u64 = 0x200;
    /// AT_EACCESS（faccessat2 で実効 uid ではなく実 uid で検査）。
    /// AT_REMOVEDIR と同じ 0x200 のビットを共有する（呼び出しごとに
    /// 意味が異なる UAPI）。
    pub const EACCESS: u64 = 0x200;
    /// AT_EMPTY_PATH。空のパスは dirfd 自身を対象にする。
    pub const EMPTY_PATH: u64 = 0x1000;
    /// AT_NO_AUTOMOUNT（statx 等で受理される）。
    pub const NO_AUTOMOUNT: u64 = 0x800;
    /// AT_STATX_SYNC_TYPE（statx の同期モード指定の許容 mask）。
    pub const STATX_SYNC_TYPE: u64 = 0x6000;
}

/// `fcntl`/`fcntl64` のコマンド。hppa は 8–14 を独自値に変え
/// （GETLK64=8/SETLK64=9/SETLKW64=10/GETOWN=11/SETOWN=12/
/// SETSIG=13/GETSIG=14。asm-generic ではこの区間は
/// SETOWN/GETOWN/SETSIG/GETSIG/GETLK64/SETLK64/SETLKW64）、
/// 0–7 と 15 以降は asm-generic/fcntl.h の汎用値。
/// flock の l_type（F_RDLCK=1/F_WRLCK=2/F_UNLCK=3）も hppa 独自。
// Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/fcntl.h
// と include/uapi/asm-generic/fcntl.h.
pub mod fcntl {
    pub const DUPFD: u32 = 0;
    pub const GETFD: u32 = 1;
    pub const SETFD: u32 = 2;
    pub const GETFL: u32 = 3;
    pub const SETFL: u32 = 4;
    pub const GETLK: u32 = 5;
    pub const SETLK: u32 = 6;
    pub const SETLKW: u32 = 7;
    // ---- hppa 独自（asm/fcntl.h）----
    pub const GETLK64: u32 = 8;
    pub const SETLK64: u32 = 9;
    pub const SETLKW64: u32 = 10;
    pub const GETOWN: u32 = 11;
    pub const SETOWN: u32 = 12;
    pub const SETSIG: u32 = 13;
    pub const GETSIG: u32 = 14;
    // ---- asm-generic ----
    pub const SETOWN_EX: u32 = 15;
    pub const GETOWN_EX: u32 = 16;
    pub const GETOWNER_UIDS: u32 = 17;
    /// OFD ロック（asm-generic。flock64 形）。
    pub const OFD_GETLK: u32 = 36;
    pub const OFD_SETLK: u32 = 37;
    pub const OFD_SETLKW: u32 = 38;
    /// F_LINUX_SPECIFIC_BASE=1024 からの相対値。
    pub const SETLEASE: u32 = 1024;
    pub const GETLEASE: u32 = 1025;
    pub const NOTIFY: u32 = 1026;
    pub const DUPFD_QUERY: u32 = 1027;
    pub const CREATED_QUERY: u32 = 1028;
    pub const DUPFD_CLOEXEC: u32 = 1030;
    pub const SETPIPE_SZ: u32 = 1031;
    pub const GETPIPE_SZ: u32 = 1032;
    pub const GET_RW_HINT: u32 = 1035;
    pub const SET_RW_HINT: u32 = 1036;
    pub const GET_FILE_RW_HINT: u32 = 1037;
    pub const SET_FILE_RW_HINT: u32 = 1038;
    /// flock の l_type（hppa は 1/2/3 — generic の 0/1/2 とずれる）。
    pub const RDLCK: u16 = 1;
    pub const WRLCK: u16 = 2;
    pub const UNLCK: u16 = 3;
    /// F_SETFL が変更を許すビット（SETFL_MASK）。
    /// hppa の O_NDELAY は O_NONBLOCK と同値。
    pub const SETFL_MASK: u64 = super::oflag::APPEND
        | super::oflag::NONBLOCK
        | super::oflag::DIRECT
        | super::oflag::NOATIME;
    /// FD_CLOEXEC（F_GETFD/F_SETFD のビット）。
    pub const FD_CLOEXEC: u64 = 1;
    /// DN_MULTISHOT（F_NOTIFY の arg から除いて有効判定）。
    pub const DN_MULTISHOT: u64 = 0x8000_0000;
    /// 既定のパイプ容量（F_GETPIPE_SZ の応答）。
    pub const PIPE_SIZE: u64 = 65536;
    /// f_owner_ex の type（F_OWNER_TID/PID/PGRP）。
    pub const OWNER_PGRP: u32 = 2;
    /// rw_hint の上限（RWH_WRITE_LIFE_MAX）。
    pub const RW_HINT_MAX: u64 = 5;
}

/// hppa のシグナル番号。`uapi/asm/signal.h` は汎用でなく HP-UX 系の
/// 独自並び（USR1=16、PWR=19、IO=22、WINCH=23、URG=29、SYS=31）。
/// 1–15 は汎用と同じ。
// Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/signal.h.
pub mod sig {
    /// SIGKILL（9。1–15 は汎用と同値。ブロック不可）。
    pub const KILL: u32 = 9;
    pub const USR1: u32 = 16;
    pub const USR2: u32 = 17;
    pub const CHLD: u32 = 18;
    pub const PWR: u32 = 19;
    pub const VTALRM: u32 = 20;
    pub const PROF: u32 = 21;
    pub const IO: u32 = 22;
    pub const WINCH: u32 = 23;
    pub const STOP: u32 = 24;
    pub const TSTP: u32 = 25;
    pub const CONT: u32 = 26;
    pub const TTIN: u32 = 27;
    pub const TTOU: u32 = 28;
    pub const URG: u32 = 29;
    pub const XFSZ: u32 = 30;
    pub const SYS: u32 = 31;

    /// シグナル番号（1–64）→ sigset_t のビット。1<<(n-1)。
    /// カーネルの sigmask() と同じ定義。
    #[inline]
    pub const fn bit(n: u32) -> u64 {
        1u64 << (n - 1)
    }
}

/// rlimit の資源番号（asm-generic/resource.h。hppa は汎用の並び）。
// Ref: SRC-LINUX (7.3) — include/uapi/asm-generic/resource.h.
pub mod res {
    pub const CPU: u64 = 0;
    pub const FSIZE: u64 = 1;
    pub const DATA: u64 = 2;
    pub const STACK: u64 = 3;
    pub const CORE: u64 = 4;
    pub const RSS: u64 = 5;
    pub const NPROC: u64 = 6;
    pub const NOFILE: u64 = 7;
    pub const MEMLOCK: u64 = 8;
    pub const AS: u64 = 9;
    /// hppa32 の `struct rlimit`（u32×2）での無限値。
    pub const RLIM_INFINITY: u64 = 0xffff_ffff;
    /// `prlimit64` の `struct rlimit64`（u64×2）での無限値。
    pub const RLIM64_INFINITY: u64 = 0xffff_ffff_ffff_ffff;
    /// RLIM_NLIMITS（16。これ以上の資源番号は EINVAL）。
    pub const NLIMITS: u64 = 16;
}

// ---- 番号（syscall.tbl。実装で使う分を名前付き定数に）----
pub mod nr {
    pub const RESTART_SYSCALL: u64 = 0;
    pub const EXIT: u64 = 1;
    pub const FORK: u64 = 2;
    pub const READ: u64 = 3;
    pub const WRITE: u64 = 4;
    pub const OPEN: u64 = 5;
    pub const CLOSE: u64 = 6;
    pub const WAITPID: u64 = 7;
    pub const CREAT: u64 = 8;
    pub const LINK: u64 = 9;
    pub const UNLINK: u64 = 10;
    pub const EXECVE: u64 = 11;
    pub const CHDIR: u64 = 12;
    pub const TIME: u64 = 13;
    pub const MKNOD: u64 = 14;
    pub const CHMOD: u64 = 15;
    pub const LCHOWN: u64 = 16;
    pub const STAT: u64 = 18;
    pub const LSEEK: u64 = 19;
    pub const GETPID: u64 = 20;
    pub const MOUNT: u64 = 21;
    pub const SETUID: u64 = 23;
    pub const GETUID: u64 = 24;
    pub const STIME: u64 = 25;
    pub const PTRACE: u64 = 26;
    pub const ALARM: u64 = 27;
    pub const FSTAT: u64 = 28;
    pub const PAUSE: u64 = 29;
    pub const UTIME: u64 = 30;
    pub const ACCESS: u64 = 33;
    pub const NICE: u64 = 34;
    pub const SYNC: u64 = 36;
    pub const KILL: u64 = 37;
    pub const RENAME: u64 = 38;
    pub const MKDIR: u64 = 39;
    pub const RMDIR: u64 = 40;
    pub const DUP: u64 = 41;
    pub const PIPE: u64 = 42;
    pub const TIMES: u64 = 43;
    pub const BRK: u64 = 45;
    pub const SETGID: u64 = 46;
    pub const GETGID: u64 = 47;
    pub const SIGNAL: u64 = 48;
    pub const GETEUID: u64 = 49;
    pub const GETEGID: u64 = 50;
    pub const ACCT: u64 = 51;
    pub const UMOUNT2: u64 = 52;
    pub const IOCTL: u64 = 54;
    pub const FCNTL: u64 = 55;
    pub const SETPGID: u64 = 57;
    pub const UNAME: u64 = 59;
    pub const UMASK: u64 = 60;
    pub const CHROOT: u64 = 61;
    pub const USTAT: u64 = 62;
    pub const DUP2: u64 = 63;
    pub const GETPPID: u64 = 64;
    pub const GETPGRP: u64 = 65;
    pub const SETSID: u64 = 66;
    pub const PIVOT_ROOT: u64 = 67;
    pub const SGETMASK: u64 = 68;
    pub const SSETMASK: u64 = 69;
    pub const SETREUID: u64 = 70;
    pub const SETREGID: u64 = 71;
    pub const MINCORE: u64 = 72;
    pub const SIGPENDING: u64 = 73;
    pub const SETHOSTNAME: u64 = 74;
    pub const SETRLIMIT: u64 = 75;
    pub const GETRLIMIT: u64 = 76;
    pub const GETRUSAGE: u64 = 77;
    pub const GETTIMEOFDAY: u64 = 78;
    pub const SETTIMEOFDAY: u64 = 79;
    pub const GETGROUPS: u64 = 80;
    pub const SETGROUPS: u64 = 81;
    pub const SYMLINK: u64 = 83;
    pub const LSTAT: u64 = 84;
    pub const READLINK: u64 = 85;
    pub const USELIB: u64 = 86;
    pub const SWAPON: u64 = 87;
    pub const REBOOT: u64 = 88;
    pub const MMAP2: u64 = 89;
    pub const MMAP: u64 = 90;
    pub const MUNMAP: u64 = 91;
    pub const TRUNCATE: u64 = 92;
    pub const FTRUNCATE: u64 = 93;
    pub const FCHMOD: u64 = 94;
    pub const FCHOWN: u64 = 95;
    pub const GETPRIORITY: u64 = 96;
    pub const SETPRIORITY: u64 = 97;
    pub const STATFS: u64 = 99;
    pub const FSTATFS: u64 = 100;
    pub const STAT64: u64 = 101;
    pub const SYSLOG: u64 = 103;
    pub const SETITIMER: u64 = 104;
    pub const GETITIMER: u64 = 105;
    pub const CAPGET: u64 = 106;
    pub const CAPSET: u64 = 107;
    pub const PREAD64: u64 = 108;
    pub const PWRITE64: u64 = 109;
    pub const GETCWD: u64 = 110;
    pub const VHANGUP: u64 = 111;
    pub const FSTAT64: u64 = 112;
    pub const VFORK: u64 = 113;
    pub const WAIT4: u64 = 114;
    pub const SWAPOFF: u64 = 115;
    pub const SYSINFO: u64 = 116;
    pub const FSYNC: u64 = 118;
    pub const MADVISE: u64 = 119;
    pub const CLONE: u64 = 120;
    pub const SETDOMAINNAME: u64 = 121;
    pub const SENDFILE: u64 = 122;
    pub const ADJTIMEX: u64 = 124;
    pub const MPROTECT: u64 = 125;
    pub const SIGPROCMASK: u64 = 126;
    pub const INIT_MODULE: u64 = 128;
    pub const DELETE_MODULE: u64 = 129;
    pub const QUOTACTL: u64 = 131;
    pub const GETPGID: u64 = 132;
    pub const FCHDIR: u64 = 133;
    pub const BDFLUSH: u64 = 134;
    pub const SYSFS: u64 = 135;
    pub const PERSONALITY: u64 = 136;
    pub const SETFSUID: u64 = 138;
    pub const SETFSGID: u64 = 139;
    pub const _LLSEEK: u64 = 140;
    pub const GETDENTS: u64 = 141;
    pub const _NEWSELECT: u64 = 142;
    pub const FLOCK: u64 = 143;
    pub const MSYNC: u64 = 144;
    pub const READV: u64 = 145;
    pub const WRITEV: u64 = 146;
    pub const GETSID: u64 = 147;
    pub const FDATASYNC: u64 = 148;
    pub const _SYSCTL: u64 = 149;
    pub const MLOCK: u64 = 150;
    pub const MUNLOCK: u64 = 151;
    pub const MLOCKALL: u64 = 152;
    pub const MUNLOCKALL: u64 = 153;
    pub const SCHED_SETPARAM: u64 = 154;
    pub const SCHED_GETPARAM: u64 = 155;
    pub const SCHED_SETSCHEDULER: u64 = 156;
    pub const SCHED_GETSCHEDULER: u64 = 157;
    pub const SCHED_YIELD: u64 = 158;
    pub const SCHED_GET_PRIORITY_MAX: u64 = 159;
    pub const SCHED_GET_PRIORITY_MIN: u64 = 160;
    pub const SCHED_RR_GET_INTERVAL: u64 = 161;
    pub const NANOSLEEP: u64 = 162;
    pub const MREMAP: u64 = 163;
    pub const SETRESUID: u64 = 164;
    pub const GETRESUID: u64 = 165;
    pub const SIGALTSTACK: u64 = 166;
    pub const POLL: u64 = 168;
    pub const SETRESGID: u64 = 170;
    pub const GETRESGID: u64 = 171;
    pub const PRCTL: u64 = 172;
    pub const RT_SIGRETURN: u64 = 173;
    pub const RT_SIGACTION: u64 = 174;
    pub const RT_SIGPROCMASK: u64 = 175;
    pub const RT_SIGPENDING: u64 = 176;
    pub const RT_SIGTIMEDWAIT: u64 = 177;
    pub const RT_SIGQUEUEINFO: u64 = 178;
    pub const RT_SIGSUSPEND: u64 = 179;
    pub const CHOWN: u64 = 180;
    pub const LSTAT64: u64 = 198;
    pub const TRUNCATE64: u64 = 199;
    pub const FTRUNCATE64: u64 = 200;
    pub const GETDENTS64: u64 = 201;
    pub const FCNTL64: u64 = 202;
    pub const GETTID: u64 = 206;
    pub const READAHEAD: u64 = 207;
    pub const TKILL: u64 = 208;
    pub const SENDFILE64: u64 = 209;
    pub const FUTEX: u64 = 210;
    pub const SCHED_SETAFFINITY: u64 = 211;
    pub const SCHED_GETAFFINITY: u64 = 212;
    pub const EXIT_GROUP: u64 = 222;
    pub const EPOLL_CREATE: u64 = 224;
    pub const REMAP_FILE_PAGES: u64 = 227;
    pub const WAITID: u64 = 235;
    pub const FADVISE64_64: u64 = 236;
    pub const SET_TID_ADDRESS: u64 = 237;
    pub const SETXATTR: u64 = 238;
    pub const LSETXATTR: u64 = 239;
    pub const FSETXATTR: u64 = 240;
    pub const GETXATTR: u64 = 241;
    pub const LGETXATTR: u64 = 242;
    pub const FGETXATTR: u64 = 243;
    pub const LISTXATTR: u64 = 244;
    pub const LLISTXATTR: u64 = 245;
    pub const FLISTXATTR: u64 = 246;
    pub const REMOVEXATTR: u64 = 247;
    pub const LREMOVEXATTR: u64 = 248;
    pub const FREMOVEXATTR: u64 = 249;
    pub const CLOCK_SETTIME: u64 = 255;
    pub const CLOCK_GETTIME: u64 = 256;
    pub const CLOCK_GETRES: u64 = 257;
    pub const CLOCK_NANOSLEEP: u64 = 258;
    pub const TGKILL: u64 = 259;
    pub const IOPRIO_SET: u64 = 267;
    pub const IOPRIO_GET: u64 = 268;
    pub const PSELECT6: u64 = 273;
    pub const PPOLL: u64 = 274;
    pub const OPENAT: u64 = 275;
    pub const MKDIRAT: u64 = 276;
    pub const MKNODAT: u64 = 277;
    pub const FCHOWNAT: u64 = 278;
    pub const FUTIMESAT: u64 = 279;
    pub const FSTATAT64: u64 = 280;
    pub const UNLINKAT: u64 = 281;
    pub const RENAMEAT: u64 = 282;
    pub const LINKAT: u64 = 283;
    pub const SYMLINKAT: u64 = 284;
    pub const READLINKAT: u64 = 285;
    pub const FCHMODAT: u64 = 286;
    pub const FACCESSAT: u64 = 287;
    pub const SET_ROBUST_LIST: u64 = 289;
    pub const GET_ROBUST_LIST: u64 = 290;
    pub const SYNC_FILE_RANGE: u64 = 292;
    pub const GETCPU: u64 = 296;
    pub const STATFS64: u64 = 298;
    pub const FSTATFS64: u64 = 299;
    pub const UTIMENSAT: u64 = 301;
    pub const FALLOCATE: u64 = 305;
    pub const DUP3: u64 = 312;
    pub const PIPE2: u64 = 313;
    pub const RT_TGSIGQUEUEINFO: u64 = 317;
    pub const PRLIMIT64: u64 = 321;
    pub const CLOCK_ADJTIME: u64 = 324;
    pub const SYNCFS: u64 = 327;
    pub const UTIMES: u64 = 336;
    pub const RENAMEAT2: u64 = 337;
    pub const GETRANDOM: u64 = 339;
    pub const EXECVEAT: u64 = 342;
    pub const MLOCK2: u64 = 345;
    pub const STATX: u64 = 349;
    pub const RSEQ: u64 = 354;
    pub const CACHEFLUSH: u64 = 356;
    pub const CLOCK_GETTIME64: u64 = 403;
    pub const CLOCK_SETTIME64: u64 = 404;
    pub const CLOCK_ADJTIME64: u64 = 405;
    pub const CLOCK_GETRES_TIME64: u64 = 406;
    pub const CLOCK_NANOSLEEP_TIME64: u64 = 407;
    pub const UTIMENSAT_TIME64: u64 = 412;
    pub const PSELECT6_TIME64: u64 = 413;
    pub const PPOLL_TIME64: u64 = 414;
    pub const FUTEX_TIME64: u64 = 422;
    pub const SCHED_RR_GET_INTERVAL_TIME64: u64 = 423;
    pub const CLONE3: u64 = 435;
    pub const FACCESSAT2: u64 = 439;
}

/// `syscall.tbl` の common 列（32 ビット列と同名）。報告と
/// ディスパッチの名前引きに使う。
// Ref: SRC-LINUX (7.3) — arch/parisc/kernel/syscalls/syscall.tbl.
pub const SYSCALLS: &[(u64, &str)] = &[
    (0, "restart_syscall"),
    (1, "exit"),
    (2, "fork"),
    (3, "read"),
    (4, "write"),
    (5, "open"),
    (6, "close"),
    (7, "waitpid"),
    (8, "creat"),
    (9, "link"),
    (10, "unlink"),
    (11, "execve"),
    (12, "chdir"),
    (13, "time"),
    (14, "mknod"),
    (15, "chmod"),
    (16, "lchown"),
    (17, "socket"),
    (18, "stat"),
    (19, "lseek"),
    (20, "getpid"),
    (21, "mount"),
    (22, "bind"),
    (23, "setuid"),
    (24, "getuid"),
    (25, "stime"),
    (26, "ptrace"),
    (27, "alarm"),
    (28, "fstat"),
    (29, "pause"),
    (30, "utime"),
    (31, "connect"),
    (32, "listen"),
    (33, "access"),
    (34, "nice"),
    (35, "accept"),
    (36, "sync"),
    (37, "kill"),
    (38, "rename"),
    (39, "mkdir"),
    (40, "rmdir"),
    (41, "dup"),
    (42, "pipe"),
    (43, "times"),
    (44, "getsockname"),
    (45, "brk"),
    (46, "setgid"),
    (47, "getgid"),
    (48, "signal"),
    (49, "geteuid"),
    (50, "getegid"),
    (51, "acct"),
    (52, "umount2"),
    (53, "getpeername"),
    (54, "ioctl"),
    (55, "fcntl"),
    (56, "socketpair"),
    (57, "setpgid"),
    (58, "send"),
    (59, "uname"),
    (60, "umask"),
    (61, "chroot"),
    (62, "ustat"),
    (63, "dup2"),
    (64, "getppid"),
    (65, "getpgrp"),
    (66, "setsid"),
    (67, "pivot_root"),
    (68, "sgetmask"),
    (69, "ssetmask"),
    (70, "setreuid"),
    (71, "setregid"),
    (72, "mincore"),
    (73, "sigpending"),
    (74, "sethostname"),
    (75, "setrlimit"),
    (76, "getrlimit"),
    (77, "getrusage"),
    (78, "gettimeofday"),
    (79, "settimeofday"),
    (80, "getgroups"),
    (81, "setgroups"),
    (82, "sendto"),
    (83, "symlink"),
    (84, "lstat"),
    (85, "readlink"),
    (86, "uselib"),
    (87, "swapon"),
    (88, "reboot"),
    (89, "mmap2"),
    (90, "mmap"),
    (91, "munmap"),
    (92, "truncate"),
    (93, "ftruncate"),
    (94, "fchmod"),
    (95, "fchown"),
    (96, "getpriority"),
    (97, "setpriority"),
    (98, "recv"),
    (99, "statfs"),
    (100, "fstatfs"),
    (101, "stat64"),
    (103, "syslog"),
    (104, "setitimer"),
    (105, "getitimer"),
    (106, "capget"),
    (107, "capset"),
    (108, "pread64"),
    (109, "pwrite64"),
    (110, "getcwd"),
    (111, "vhangup"),
    (112, "fstat64"),
    (113, "vfork"),
    (114, "wait4"),
    (115, "swapoff"),
    (116, "sysinfo"),
    (117, "shutdown"),
    (118, "fsync"),
    (119, "madvise"),
    (120, "clone"),
    (121, "setdomainname"),
    (122, "sendfile"),
    (123, "recvfrom"),
    (124, "adjtimex"),
    (125, "mprotect"),
    (126, "sigprocmask"),
    (128, "init_module"),
    (129, "delete_module"),
    (131, "quotactl"),
    (132, "getpgid"),
    (133, "fchdir"),
    (134, "bdflush"),
    (135, "sysfs"),
    (136, "personality"),
    (138, "setfsuid"),
    (139, "setfsgid"),
    (140, "_llseek"),
    (141, "getdents"),
    (142, "_newselect"),
    (143, "flock"),
    (144, "msync"),
    (145, "readv"),
    (146, "writev"),
    (147, "getsid"),
    (148, "fdatasync"),
    (149, "_sysctl"),
    (150, "mlock"),
    (151, "munlock"),
    (152, "mlockall"),
    (153, "munlockall"),
    (154, "sched_setparam"),
    (155, "sched_getparam"),
    (156, "sched_setscheduler"),
    (157, "sched_getscheduler"),
    (158, "sched_yield"),
    (159, "sched_get_priority_max"),
    (160, "sched_get_priority_min"),
    (161, "sched_rr_get_interval"),
    (162, "nanosleep"),
    (163, "mremap"),
    (164, "setresuid"),
    (165, "getresuid"),
    (166, "sigaltstack"),
    (168, "poll"),
    (170, "setresgid"),
    (171, "getresgid"),
    (172, "prctl"),
    (173, "rt_sigreturn"),
    (174, "rt_sigaction"),
    (175, "rt_sigprocmask"),
    (176, "rt_sigpending"),
    (177, "rt_sigtimedwait"),
    (178, "rt_sigqueueinfo"),
    (179, "rt_sigsuspend"),
    (180, "chown"),
    (181, "setsockopt"),
    (182, "getsockopt"),
    (183, "sendmsg"),
    (184, "recvmsg"),
    (185, "semop"),
    (186, "semget"),
    (187, "semctl"),
    (188, "msgsnd"),
    (189, "msgrcv"),
    (190, "msgget"),
    (191, "msgctl"),
    (192, "shmat"),
    (193, "shmdt"),
    (194, "shmget"),
    (195, "shmctl"),
    (198, "lstat64"),
    (199, "truncate64"),
    (200, "ftruncate64"),
    (201, "getdents64"),
    (202, "fcntl64"),
    (206, "gettid"),
    (207, "readahead"),
    (208, "tkill"),
    (209, "sendfile64"),
    (210, "futex"),
    (211, "sched_setaffinity"),
    (212, "sched_getaffinity"),
    (215, "io_setup"),
    (216, "io_destroy"),
    (217, "io_getevents"),
    (218, "io_submit"),
    (219, "io_cancel"),
    (222, "exit_group"),
    (223, "lookup_dcookie"),
    (224, "epoll_create"),
    (225, "epoll_ctl"),
    (226, "epoll_wait"),
    (227, "remap_file_pages"),
    (228, "semtimedop"),
    (229, "mq_open"),
    (230, "mq_unlink"),
    (231, "mq_timedsend"),
    (232, "mq_timedreceive"),
    (233, "mq_notify"),
    (234, "mq_getsetattr"),
    (235, "waitid"),
    (236, "fadvise64_64"),
    (237, "set_tid_address"),
    (238, "setxattr"),
    (239, "lsetxattr"),
    (240, "fsetxattr"),
    (241, "getxattr"),
    (242, "lgetxattr"),
    (243, "fgetxattr"),
    (244, "listxattr"),
    (245, "llistxattr"),
    (246, "flistxattr"),
    (247, "removexattr"),
    (248, "lremovexattr"),
    (249, "fremovexattr"),
    (250, "timer_create"),
    (251, "timer_settime"),
    (252, "timer_gettime"),
    (253, "timer_getoverrun"),
    (254, "timer_delete"),
    (255, "clock_settime"),
    (256, "clock_gettime"),
    (257, "clock_getres"),
    (258, "clock_nanosleep"),
    (259, "tgkill"),
    (260, "mbind"),
    (261, "get_mempolicy"),
    (262, "set_mempolicy"),
    (264, "add_key"),
    (265, "request_key"),
    (266, "keyctl"),
    (267, "ioprio_set"),
    (268, "ioprio_get"),
    (269, "inotify_init"),
    (270, "inotify_add_watch"),
    (271, "inotify_rm_watch"),
    (272, "migrate_pages"),
    (273, "pselect6"),
    (274, "ppoll"),
    (275, "openat"),
    (276, "mkdirat"),
    (277, "mknodat"),
    (278, "fchownat"),
    (279, "futimesat"),
    (280, "fstatat64"),
    (281, "unlinkat"),
    (282, "renameat"),
    (283, "linkat"),
    (284, "symlinkat"),
    (285, "readlinkat"),
    (286, "fchmodat"),
    (287, "faccessat"),
    (288, "unshare"),
    (289, "set_robust_list"),
    (290, "get_robust_list"),
    (291, "splice"),
    (292, "sync_file_range"),
    (293, "tee"),
    (294, "vmsplice"),
    (295, "move_pages"),
    (296, "getcpu"),
    (297, "epoll_pwait"),
    (298, "statfs64"),
    (299, "fstatfs64"),
    (300, "kexec_load"),
    (301, "utimensat"),
    (302, "signalfd"),
    (304, "eventfd"),
    (305, "fallocate"),
    (306, "timerfd_create"),
    (307, "timerfd_settime"),
    (308, "timerfd_gettime"),
    (309, "signalfd4"),
    (310, "eventfd2"),
    (311, "epoll_create1"),
    (312, "dup3"),
    (313, "pipe2"),
    (314, "inotify_init1"),
    (315, "preadv"),
    (316, "pwritev"),
    (317, "rt_tgsigqueueinfo"),
    (318, "perf_event_open"),
    (319, "recvmmsg"),
    (320, "accept4"),
    (321, "prlimit64"),
    (322, "fanotify_init"),
    (323, "fanotify_mark"),
    (324, "clock_adjtime"),
    (325, "name_to_handle_at"),
    (326, "open_by_handle_at"),
    (327, "syncfs"),
    (328, "setns"),
    (329, "sendmmsg"),
    (330, "process_vm_readv"),
    (331, "process_vm_writev"),
    (332, "kcmp"),
    (333, "finit_module"),
    (334, "sched_setattr"),
    (335, "sched_getattr"),
    (336, "utimes"),
    (337, "renameat2"),
    (338, "seccomp"),
    (339, "getrandom"),
    (340, "memfd_create"),
    (341, "bpf"),
    (342, "execveat"),
    (343, "membarrier"),
    (344, "userfaultfd"),
    (345, "mlock2"),
    (346, "copy_file_range"),
    (347, "preadv2"),
    (348, "pwritev2"),
    (349, "statx"),
    (350, "io_pgetevents"),
    (351, "pkey_mprotect"),
    (352, "pkey_alloc"),
    (353, "pkey_free"),
    (354, "rseq"),
    (355, "kexec_file_load"),
    (356, "cacheflush"),
    (403, "clock_gettime64"),
    (404, "clock_settime64"),
    (405, "clock_adjtime64"),
    (406, "clock_getres_time64"),
    (407, "clock_nanosleep_time64"),
    (408, "timer_gettime64"),
    (409, "timer_settime64"),
    (410, "timerfd_gettime64"),
    (411, "timerfd_settime64"),
    (412, "utimensat_time64"),
    (413, "pselect6_time64"),
    (414, "ppoll_time64"),
    (416, "io_pgetevents_time64"),
    (417, "recvmmsg_time64"),
    (418, "mq_timedsend_time64"),
    (419, "mq_timedreceive_time64"),
    (420, "semtimedop_time64"),
    (421, "rt_sigtimedwait_time64"),
    (422, "futex_time64"),
    (423, "sched_rr_get_interval_time64"),
    (424, "pidfd_send_signal"),
    (425, "io_uring_setup"),
    (426, "io_uring_enter"),
    (427, "io_uring_register"),
    (428, "open_tree"),
    (429, "move_mount"),
    (430, "fsopen"),
    (431, "fsconfig"),
    (432, "fsmount"),
    (433, "fspick"),
    (434, "pidfd_open"),
    (435, "clone3"),
    (436, "close_range"),
    (437, "openat2"),
    (438, "pidfd_getfd"),
    (439, "faccessat2"),
    (440, "process_madvise"),
    (441, "epoll_pwait2"),
    (442, "mount_setattr"),
    (443, "quotactl_fd"),
    (444, "landlock_create_ruleset"),
    (445, "landlock_add_rule"),
    (446, "landlock_restrict_self"),
    (448, "process_mrelease"),
    (449, "futex_waitv"),
    (450, "set_mempolicy_home_node"),
    (451, "cachestat"),
    (452, "fchmodat2"),
    (453, "map_shadow_stack"),
    (454, "futex_wake"),
    (455, "futex_wait"),
    (456, "futex_requeue"),
    (457, "statmount"),
    (458, "listmount"),
    (459, "lsm_get_self_attr"),
    (460, "lsm_set_self_attr"),
    (461, "lsm_list_modules"),
    (462, "mseal"),
    (463, "setxattrat"),
    (464, "getxattrat"),
    (465, "listxattrat"),
    (466, "removexattrat"),
    (467, "open_tree_attr"),
    (468, "file_getattr"),
    (469, "file_setattr"),
    (470, "listns"),
    (471, "rseq_slice_yield"),
    (472, "fchroot"),
];

/// 番号から `syscall.tbl` の名前を引く（報告・表検査用）。
#[must_use]
pub fn name(nr: u64) -> Option<&'static str> {
    SYSCALLS
        .binary_search_by_key(&nr, |&(n, _)| n)
        .ok()
        .map(|i| SYSCALLS[i].1)
}

/// syscall 処理（`guest-parisc` 機能の内側）。
#[cfg(feature = "guest-parisc")]
pub mod sys;
