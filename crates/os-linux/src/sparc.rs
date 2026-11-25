// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SPARC（sparc32/sparc64）の Linux ゲスト ABI 共通部。
//!
//! 規約：syscall 番号は %g1、引数は %o0–%o5、戻り値は %o0。
//! 失敗はキャリー flag を立てて %o0 に正の errno を入れる
//! （-errno ではない）。sparc32 は `ta 0x10`（tt=0x90）、
//! sparc64 は `ta 0x6d`（tt=0x16d）が発行点。`ta 0x03`
//! （tt=0x83 / V9 では 0x103）は flushw で、すべての
//! 退避済み窓をスタックへ書き出す。ウィンドウのあふれ・不足は
//! sem が tt=0x05/0x80..=0x9f（spill）と tt=0x06/0xc0..=0xdf
//! （fill）で上げ、ここがスタックへの退避・復元を再現する。
//! errno と `O_*`・シグナル番号は asm-generic ではなく
//! SunOS 系の独自表である。
//! 番号表はカーネルの `arch/sparc/kernel/syscalls/syscall.tbl` と
//! `arch/sparc/include/uapi/asm/{errno,fcntl,unistd}.h` 由来の
//! 事実であり、E3 で UAPI ヘッダと突き合わせる。
// Ref: SRC-LINUX (7.3).

/// SPARC Linux の syscall 処理とウィンドウの退避・復元。
/// `guest-sparc` 機能で有効になる。設計の依存規則
/// （`docs/architecture/workspace.md` の「依存規則」）が `os-linux` の
/// `guests/*` 依存を機能フラグ付きで認めている。
#[cfg(feature = "guest-sparc")]
pub mod sys;

/// errno。SunOS 系の独自番号（asm-generic とは値が違う）。
/// 1–34 は errno-base と同じ、36 以降は `uapi/asm/errno.h` の表。
// Ref: SRC-LINUX (7.3) — arch/sparc/include/uapi/asm/errno.h.
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
    pub const EWOULDBLOCK: u32 = EAGAIN;
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
    pub const EINPROGRESS: u32 = 36;
    pub const EALREADY: u32 = 37;
    pub const ENOTSOCK: u32 = 38;
    pub const EDESTADDRREQ: u32 = 39;
    pub const EMSGSIZE: u32 = 40;
    pub const EPROTOTYPE: u32 = 41;
    pub const ENOPROTOOPT: u32 = 42;
    pub const EPROTONOSUPPORT: u32 = 43;
    pub const ESOCKTNOSUPPORT: u32 = 44;
    pub const EOPNOTSUPP: u32 = 45;
    pub const ENOTSUP: u32 = EOPNOTSUPP;
    pub const EPFNOSUPPORT: u32 = 46;
    pub const EAFNOSUPPORT: u32 = 47;
    pub const EADDRINUSE: u32 = 48;
    pub const EADDRNOTAVAIL: u32 = 49;
    pub const ENETDOWN: u32 = 50;
    pub const ENETUNREACH: u32 = 51;
    pub const ENETRESET: u32 = 52;
    pub const ECONNABORTED: u32 = 53;
    pub const ECONNRESET: u32 = 54;
    pub const ENOBUFS: u32 = 55;
    pub const EISCONN: u32 = 56;
    pub const ENOTCONN: u32 = 57;
    pub const ESHUTDOWN: u32 = 58;
    pub const ETOOMANYREFS: u32 = 59;
    pub const ETIMEDOUT: u32 = 60;
    pub const ECONNREFUSED: u32 = 61;
    pub const ELOOP: u32 = 62;
    pub const ENAMETOOLONG: u32 = 63;
    pub const EHOSTDOWN: u32 = 64;
    pub const EHOSTUNREACH: u32 = 65;
    pub const ENOTEMPTY: u32 = 66;
    pub const EPROCLIM: u32 = 67;
    pub const EUSERS: u32 = 68;
    pub const EDQUOT: u32 = 69;
    pub const ESTALE: u32 = 70;
    pub const EREMOTE: u32 = 71;
    pub const ENOSTR: u32 = 72;
    pub const ETIME: u32 = 73;
    pub const ENOSR: u32 = 74;
    pub const ENOMSG: u32 = 75;
    pub const EBADMSG: u32 = 76;
    pub const EFSBADCRC: u32 = EBADMSG;
    pub const EIDRM: u32 = 77;
    pub const EDEADLK: u32 = 78;
    pub const ENOLCK: u32 = 79;
    pub const ENONET: u32 = 80;
    pub const ERREMOTE: u32 = 81;
    pub const ENOLINK: u32 = 82;
    pub const EADV: u32 = 83;
    pub const ESRMNT: u32 = 84;
    pub const ECOMM: u32 = 85;
    pub const EPROTO: u32 = 86;
    pub const EMULTIHOP: u32 = 87;
    pub const EDOTDOT: u32 = 88;
    pub const EREMCHG: u32 = 89;
    pub const ENOSYS: u32 = 90;
    pub const ESTRPIPE: u32 = 91;
    pub const EOVERFLOW: u32 = 92;
    pub const EBADFD: u32 = 93;
    pub const ECHRNG: u32 = 94;
    pub const EL2NSYNC: u32 = 95;
    pub const EL3HLT: u32 = 96;
    pub const EL3RST: u32 = 97;
    pub const ELNRNG: u32 = 98;
    pub const EUNATCH: u32 = 99;
    pub const ENOCSI: u32 = 100;
    pub const EL2HLT: u32 = 101;
    pub const EBADE: u32 = 102;
    pub const EBADR: u32 = 103;
    pub const EXFULL: u32 = 104;
    pub const ENOANO: u32 = 105;
    pub const EBADRQC: u32 = 106;
    pub const EBADSLT: u32 = 107;
    pub const EDEADLOCK: u32 = 108;
    pub const EBFONT: u32 = 109;
    pub const ELIBEXEC: u32 = 110;
    pub const ENODATA: u32 = 111;
    pub const ELIBBAD: u32 = 112;
    pub const ENOPKG: u32 = 113;
    pub const ELIBACC: u32 = 114;
    pub const ENOTUNIQ: u32 = 115;
    pub const ERESTART: u32 = 116;
    pub const EUCLEAN: u32 = 117;
    pub const EFSCORRUPTED: u32 = EUCLEAN;
    pub const ENOTNAM: u32 = 118;
    pub const ENAVAIL: u32 = 119;
    pub const EISNAM: u32 = 120;
    pub const EREMOTEIO: u32 = 121;
    pub const EILSEQ: u32 = 122;
    pub const ELIBMAX: u32 = 123;
    pub const ELIBSCN: u32 = 124;
    pub const ENOMEDIUM: u32 = 125;
    pub const EMEDIUMTYPE: u32 = 126;
    pub const ECANCELED: u32 = 127;
    pub const ENOKEY: u32 = 128;
    pub const EKEYEXPIRED: u32 = 129;
    pub const EKEYREVOKED: u32 = 130;
    pub const EKEYREJECTED: u32 = 131;
    pub const EOWNERDEAD: u32 = 132;
    pub const ENOTRECOVERABLE: u32 = 133;
    pub const ERFKILL: u32 = 134;
    pub const EHWPOISON: u32 = 135;
    pub const EFTYPE: u32 = 136;
}

/// `O_*` 等のフラグ。SPARC 独自の値（`uapi/asm/fcntl.h`）。
/// DIRECTORY/NOFOLLOW は asm-generic のまま。
// Ref: SRC-LINUX (7.3).
pub mod oflag {
    pub const ACCMODE: u32 = 0x3;
    pub const APPEND: u32 = 0x8;
    pub const CREAT: u32 = 0x200;
    pub const TRUNC: u32 = 0x400;
    pub const EXCL: u32 = 0x800;
    pub const DSYNC: u32 = 0x2000;
    pub const NONBLOCK: u32 = 0x4000;
    pub const NOCTTY: u32 = 0x8000;
    pub const DIRECTORY: u32 = 0x1_0000;
    pub const NOFOLLOW: u32 = 0x2_0000;
    pub const LARGEFILE: u32 = 0x4_0000;
    pub const DIRECT: u32 = 0x10_0000;
    pub const NOATIME: u32 = 0x20_0000;
    pub const CLOEXEC: u32 = 0x40_0000;
    pub const SYNC: u32 = 0x80_2000;
}

/// `MAP_*`（asm-generic と同じ値）。
pub mod mmap_flag {
    pub const SHARED: u64 = 0x01;
    pub const PRIVATE: u64 = 0x02;
    pub const FIXED: u64 = 0x10;
    pub const ANONYMOUS: u64 = 0x20;
}

/// `PROT_*`。
pub mod prot {
    pub const NONE: u64 = 0;
    pub const READ: u64 = 1;
    pub const WRITE: u64 = 2;
    pub const EXEC: u64 = 4;
}

/// システムコール番号。`arch/sparc/kernel/syscalls/syscall.tbl` の
/// common/sparc 行（sparc32 と sparc64 で同一番号）。`32` だけの行は
/// コメントを付す。先頭 `_` は大文字化の際に落とす
/// （`_newselect`→`NEWSELECT`、`_llseek`→`LLSEEK`、`_sysctl`→`SYSCTL`）。
// Ref: SRC-LINUX (7.3).
pub mod nr {
    pub const RESTART_SYSCALL: u64 = 0;
    pub const EXIT: u64 = 1;
    pub const FORK: u64 = 2;
    pub const READ: u64 = 3;
    pub const WRITE: u64 = 4;
    pub const OPEN: u64 = 5;
    pub const CLOSE: u64 = 6;
    pub const WAIT4: u64 = 7;
    pub const CREAT: u64 = 8;
    pub const LINK: u64 = 9;
    pub const UNLINK: u64 = 10;
    /// 32 は sunos_execv、64 は sys_nis_syscall。
    pub const EXECV: u64 = 11;
    pub const CHDIR: u64 = 12;
    /// 32 では 16 ビット uid（chown16）。
    pub const CHOWN: u64 = 13;
    pub const MKNOD: u64 = 14;
    pub const CHMOD: u64 = 15;
    /// 32 では 16 ビット uid（lchown16）。
    pub const LCHOWN: u64 = 16;
    pub const BRK: u64 = 17;
    pub const PERFCTR: u64 = 18;
    pub const LSEEK: u64 = 19;
    pub const GETPID: u64 = 20;
    pub const CAPGET: u64 = 21;
    pub const CAPSET: u64 = 22;
    /// 32 では setuid16。
    pub const SETUID: u64 = 23;
    /// 32 では getuid16。
    pub const GETUID: u64 = 24;
    pub const VMSPLICE: u64 = 25;
    pub const PTRACE: u64 = 26;
    pub const ALARM: u64 = 27;
    pub const SIGALTSTACK: u64 = 28;
    /// 64 では sys_nis_syscall。
    pub const PAUSE: u64 = 29;
    /// 32 では utime32（time32 版）。
    pub const UTIME: u64 = 30;
    /// 32 だけ。
    pub const LCHOWN32: u64 = 31;
    /// 32 だけ。
    pub const FCHOWN32: u64 = 32;
    pub const ACCESS: u64 = 33;
    pub const NICE: u64 = 34;
    /// 32 だけ。
    pub const CHOWN32: u64 = 35;
    pub const SYNC: u64 = 36;
    pub const KILL: u64 = 37;
    /// sys_newstat。レイアウトは ABI で違う。
    pub const STAT: u64 = 38;
    /// 32 は sys_sendfile、64 は sys_sendfile64。
    pub const SENDFILE: u64 = 39;
    pub const LSTAT: u64 = 40;
    pub const DUP: u64 = 41;
    pub const PIPE: u64 = 42;
    pub const TIMES: u64 = 43;
    /// 32 だけ。
    pub const GETUID32: u64 = 44;
    pub const UMOUNT2: u64 = 45;
    /// 32 では setgid16。
    pub const SETGID: u64 = 46;
    /// 32 では getgid16。
    pub const GETGID: u64 = 47;
    pub const SIGNAL: u64 = 48;
    /// 32 では geteuid16。
    pub const GETEUID: u64 = 49;
    /// 32 では getegid16。
    pub const GETEGID: u64 = 50;
    pub const ACCT: u64 = 51;
    /// 64 だけ。
    pub const MEMORY_ORDERING: u64 = 52;
    /// 32 だけ。
    pub const GETGID32: u64 = 53;
    pub const IOCTL: u64 = 54;
    pub const REBOOT: u64 = 55;
    /// 32 だけ。オフセットはページ単位。
    pub const MMAP2: u64 = 56;
    pub const SYMLINK: u64 = 57;
    pub const READLINK: u64 = 58;
    /// 32 は sys32_execve、64 は sys64_execve。
    pub const EXECVE: u64 = 59;
    pub const UMASK: u64 = 60;
    pub const CHROOT: u64 = 61;
    /// sys_newfstat。
    pub const FSTAT: u64 = 62;
    pub const FSTAT64: u64 = 63;
    pub const GETPAGESIZE: u64 = 64;
    pub const MSYNC: u64 = 65;
    pub const VFORK: u64 = 66;
    pub const PREAD64: u64 = 67;
    pub const PWRITE64: u64 = 68;
    /// 32 だけ。
    pub const GETEUID32: u64 = 69;
    /// 32 だけ。
    pub const GETEGID32: u64 = 70;
    /// オフセットはバイト単位（mmap2 のページ単位ではない）。
    pub const MMAP: u64 = 71;
    /// 32 だけ。
    pub const SETREUID32: u64 = 72;
    /// 32 は sys_munmap、64 は sys_64_munmap。
    pub const MUNMAP: u64 = 73;
    pub const MPROTECT: u64 = 74;
    pub const MADVISE: u64 = 75;
    pub const VHANGUP: u64 = 76;
    /// 32 だけ。
    pub const TRUNCATE64: u64 = 77;
    pub const MINCORE: u64 = 78;
    /// 32 では getgroups16。
    pub const GETGROUPS: u64 = 79;
    /// 32 では setgroups16。
    pub const SETGROUPS: u64 = 80;
    pub const GETPGRP: u64 = 81;
    /// 32 だけ。
    pub const SETGROUPS32: u64 = 82;
    pub const SETITIMER: u64 = 83;
    /// 32 だけ。
    pub const FTRUNCATE64: u64 = 84;
    pub const SWAPON: u64 = 85;
    pub const GETITIMER: u64 = 86;
    /// 32 だけ。
    pub const SETUID32: u64 = 87;
    pub const SETHOSTNAME: u64 = 88;
    /// 32 だけ。
    pub const SETGID32: u64 = 89;
    pub const DUP2: u64 = 90;
    /// 32 だけ。
    pub const SETFSUID32: u64 = 91;
    pub const FCNTL: u64 = 92;
    pub const SELECT: u64 = 93;
    /// 32 だけ。
    pub const SETFSGID32: u64 = 94;
    pub const FSYNC: u64 = 95;
    pub const SETPRIORITY: u64 = 96;
    pub const SOCKET: u64 = 97;
    pub const CONNECT: u64 = 98;
    pub const ACCEPT: u64 = 99;
    pub const GETPRIORITY: u64 = 100;
    pub const RT_SIGRETURN: u64 = 101;
    pub const RT_SIGACTION: u64 = 102;
    pub const RT_SIGPROCMASK: u64 = 103;
    pub const RT_SIGPENDING: u64 = 104;
    /// 32 では time32 版。
    pub const RT_SIGTIMEDWAIT: u64 = 105;
    pub const RT_SIGQUEUEINFO: u64 = 106;
    pub const RT_SIGSUSPEND: u64 = 107;
    /// 32 では setresuid32。
    pub const SETRESUID: u64 = 108;
    /// 32 では getresuid32。
    pub const GETRESUID: u64 = 109;
    /// 32 では setresgid32。
    pub const SETRESGID: u64 = 110;
    /// 32 では getresgid32。
    pub const GETRESGID: u64 = 111;
    /// 32 だけ。
    pub const SETREGID32: u64 = 112;
    pub const RECVMSG: u64 = 113;
    pub const SENDMSG: u64 = 114;
    /// 32 だけ。
    pub const GETGROUPS32: u64 = 115;
    pub const GETTIMEOFDAY: u64 = 116;
    pub const GETRUSAGE: u64 = 117;
    pub const GETSOCKOPT: u64 = 118;
    pub const GETCWD: u64 = 119;
    pub const READV: u64 = 120;
    pub const WRITEV: u64 = 121;
    pub const SETTIMEOFDAY: u64 = 122;
    /// 32 では fchown16。
    pub const FCHOWN: u64 = 123;
    pub const FCHMOD: u64 = 124;
    pub const RECVFROM: u64 = 125;
    /// 32 では setreuid16。
    pub const SETREUID: u64 = 126;
    /// 32 では setregid16。
    pub const SETREGID: u64 = 127;
    pub const RENAME: u64 = 128;
    pub const TRUNCATE: u64 = 129;
    pub const FTRUNCATE: u64 = 130;
    pub const FLOCK: u64 = 131;
    pub const LSTAT64: u64 = 132;
    pub const SENDTO: u64 = 133;
    pub const SHUTDOWN: u64 = 134;
    pub const SOCKETPAIR: u64 = 135;
    pub const MKDIR: u64 = 136;
    pub const RMDIR: u64 = 137;
    /// 32 では time32 版。
    pub const UTIMES: u64 = 138;
    pub const STAT64: u64 = 139;
    pub const SENDFILE64: u64 = 140;
    pub const GETPEERNAME: u64 = 141;
    /// 32 では time32 版。
    pub const FUTEX: u64 = 142;
    pub const GETTID: u64 = 143;
    pub const GETRLIMIT: u64 = 144;
    pub const SETRLIMIT: u64 = 145;
    pub const PIVOT_ROOT: u64 = 146;
    pub const PRCTL: u64 = 147;
    pub const PCICONFIG_READ: u64 = 148;
    pub const PCICONFIG_WRITE: u64 = 149;
    pub const GETSOCKNAME: u64 = 150;
    pub const INOTIFY_INIT: u64 = 151;
    pub const INOTIFY_ADD_WATCH: u64 = 152;
    pub const POLL: u64 = 153;
    pub const GETDENTS64: u64 = 154;
    /// 32 だけ。
    pub const FCNTL64: u64 = 155;
    pub const INOTIFY_RM_WATCH: u64 = 156;
    pub const STATFS: u64 = 157;
    pub const FSTATFS: u64 = 158;
    pub const UMOUNT: u64 = 159;
    pub const SCHED_SET_AFFINITY: u64 = 160;
    pub const SCHED_GET_AFFINITY: u64 = 161;
    pub const GETDOMAINNAME: u64 = 162;
    pub const SETDOMAINNAME: u64 = 163;
    /// 64 だけ。
    pub const UTRAP_INSTALL: u64 = 164;
    pub const QUOTACTL: u64 = 165;
    pub const SET_TID_ADDRESS: u64 = 166;
    pub const MOUNT: u64 = 167;
    pub const USTAT: u64 = 168;
    pub const SETXATTR: u64 = 169;
    pub const LSETXATTR: u64 = 170;
    pub const FSETXATTR: u64 = 171;
    pub const GETXATTR: u64 = 172;
    pub const LGETXATTR: u64 = 173;
    pub const GETDENTS: u64 = 174;
    pub const SETSID: u64 = 175;
    pub const FCHDIR: u64 = 176;
    pub const FGETXATTR: u64 = 177;
    pub const LISTXATTR: u64 = 178;
    pub const LLISTXATTR: u64 = 179;
    pub const FLISTXATTR: u64 = 180;
    pub const REMOVEXATTR: u64 = 181;
    pub const LREMOVEXATTR: u64 = 182;
    /// 64 では sys_nis_syscall。
    pub const SIGPENDING: u64 = 183;
    pub const QUERY_MODULE: u64 = 184;
    pub const SETPGID: u64 = 185;
    pub const FREMOVEXATTR: u64 = 186;
    pub const TKILL: u64 = 187;
    pub const EXIT_GROUP: u64 = 188;
    pub const UNAME: u64 = 189;
    pub const INIT_MODULE: u64 = 190;
    /// 32 は sys_personality、64 は sys_sparc64_personality。
    pub const PERSONALITY: u64 = 191;
    pub const REMAP_FILE_PAGES: u64 = 192;
    pub const EPOLL_CREATE: u64 = 193;
    pub const EPOLL_CTL: u64 = 194;
    pub const EPOLL_WAIT: u64 = 195;
    pub const IOPRIO_SET: u64 = 196;
    pub const GETPPID: u64 = 197;
    /// 64 では sys_nis_syscall。
    pub const SIGACTION: u64 = 198;
    pub const SGETMASK: u64 = 199;
    pub const SSETMASK: u64 = 200;
    /// 64 では sys_nis_syscall。
    pub const SIGSUSPEND: u64 = 201;
    pub const OLDLSTAT: u64 = 202;
    pub const USELIB: u64 = 203;
    /// 64 では sys_nis_syscall。
    pub const READDIR: u64 = 204;
    pub const READAHEAD: u64 = 205;
    pub const SOCKETCALL: u64 = 206;
    pub const SYSLOG: u64 = 207;
    pub const LOOKUP_DCOOKIE: u64 = 208;
    pub const FADVISE64: u64 = 209;
    pub const FADVISE64_64: u64 = 210;
    pub const TGKILL: u64 = 211;
    pub const WAITPID: u64 = 212;
    pub const SWAPOFF: u64 = 213;
    pub const SYSINFO: u64 = 214;
    /// 32 は sys_ipc、64 は sys_sparc_ipc。
    pub const IPC: u64 = 215;
    /// 64 では sys_nis_syscall。
    pub const SIGRETURN: u64 = 216;
    pub const CLONE: u64 = 217;
    pub const IOPRIO_GET: u64 = 218;
    /// 32 では time32 版。
    pub const ADJTIMEX: u64 = 219;
    /// 64 では sys_nis_syscall。
    pub const SIGPROCMASK: u64 = 220;
    pub const CREATE_MODULE: u64 = 221;
    pub const DELETE_MODULE: u64 = 222;
    pub const GET_KERNEL_SYMS: u64 = 223;
    pub const GETPGID: u64 = 224;
    pub const BDFLUSH: u64 = 225;
    pub const SYSFS: u64 = 226;
    pub const AFS_SYSCALL: u64 = 227;
    pub const SETFSUID: u64 = 228;
    pub const SETFSGID: u64 = 229;
    pub const NEWSELECT: u64 = 230;
    /// 32 だけ（time32 版）。
    pub const TIME: u64 = 231;
    pub const SPLICE: u64 = 232;
    /// 32 では stime32。
    pub const STIME: u64 = 233;
    pub const STATFS64: u64 = 234;
    pub const FSTATFS64: u64 = 235;
    pub const LLSEEK: u64 = 236;
    pub const MLOCK: u64 = 237;
    pub const MUNLOCK: u64 = 238;
    pub const MLOCKALL: u64 = 239;
    pub const MUNLOCKALL: u64 = 240;
    pub const SCHED_SETPARAM: u64 = 241;
    pub const SCHED_GETPARAM: u64 = 242;
    pub const SCHED_SETSCHEDULER: u64 = 243;
    pub const SCHED_GETSCHEDULER: u64 = 244;
    pub const SCHED_YIELD: u64 = 245;
    pub const SCHED_GET_PRIORITY_MAX: u64 = 246;
    pub const SCHED_GET_PRIORITY_MIN: u64 = 247;
    /// 32 では time32 版。
    pub const SCHED_RR_GET_INTERVAL: u64 = 248;
    /// 32 では time32 版。
    pub const NANOSLEEP: u64 = 249;
    /// 32 は sys_mremap、64 は sys_64_mremap。
    pub const MREMAP: u64 = 250;
    pub const SYSCTL: u64 = 251;
    pub const GETSID: u64 = 252;
    pub const FDATASYNC: u64 = 253;
    pub const NFSSERVCTL: u64 = 254;
    pub const SYNC_FILE_RANGE: u64 = 255;
    /// 32 では clock_settime32。
    pub const CLOCK_SETTIME: u64 = 256;
    /// 32 では clock_gettime32。
    pub const CLOCK_GETTIME: u64 = 257;
    /// 32 では time32 版。
    pub const CLOCK_GETRES: u64 = 258;
    /// 32 では time32 版。
    pub const CLOCK_NANOSLEEP: u64 = 259;
    pub const SCHED_GETAFFINITY: u64 = 260;
    pub const SCHED_SETAFFINITY: u64 = 261;
    /// 32 では time32 版。
    pub const TIMER_SETTIME: u64 = 262;
    /// 32 では time32 版。
    pub const TIMER_GETTIME: u64 = 263;
    pub const TIMER_GETOVERRUN: u64 = 264;
    pub const TIMER_DELETE: u64 = 265;
    pub const TIMER_CREATE: u64 = 266;
    /// 旧 vserver。nis。
    pub const VSERVER: u64 = 267;
    pub const IO_SETUP: u64 = 268;
    pub const IO_DESTROY: u64 = 269;
    pub const IO_SUBMIT: u64 = 270;
    pub const IO_CANCEL: u64 = 271;
    /// 32 では time32 版。
    pub const IO_GETEVENTS: u64 = 272;
    pub const MQ_OPEN: u64 = 273;
    pub const MQ_UNLINK: u64 = 274;
    /// 32 では time32 版。
    pub const MQ_TIMEDSEND: u64 = 275;
    /// 32 では time32 版。
    pub const MQ_TIMEDRECEIVE: u64 = 276;
    pub const MQ_NOTIFY: u64 = 277;
    pub const MQ_GETSETATTR: u64 = 278;
    pub const WAITID: u64 = 279;
    pub const TEE: u64 = 280;
    pub const ADD_KEY: u64 = 281;
    pub const REQUEST_KEY: u64 = 282;
    pub const KEYCTL: u64 = 283;
    pub const OPENAT: u64 = 284;
    pub const MKDIRAT: u64 = 285;
    pub const MKNODAT: u64 = 286;
    pub const FCHOWNAT: u64 = 287;
    /// 32 では time32 版。
    pub const FUTIMESAT: u64 = 288;
    pub const FSTATAT64: u64 = 289;
    pub const UNLINKAT: u64 = 290;
    pub const RENAMEAT: u64 = 291;
    pub const LINKAT: u64 = 292;
    pub const SYMLINKAT: u64 = 293;
    pub const READLINKAT: u64 = 294;
    pub const FCHMODAT: u64 = 295;
    pub const FACCESSAT: u64 = 296;
    /// 32 では time32 版。
    pub const PSELECT6: u64 = 297;
    /// 32 では time32 版。
    pub const PPOLL: u64 = 298;
    pub const UNSHARE: u64 = 299;
    pub const SET_ROBUST_LIST: u64 = 300;
    pub const GET_ROBUST_LIST: u64 = 301;
    pub const MIGRATE_PAGES: u64 = 302;
    pub const MBIND: u64 = 303;
    pub const GET_MEMPOLICY: u64 = 304;
    pub const SET_MEMPOLICY: u64 = 305;
    pub const KEXEC_LOAD: u64 = 306;
    pub const MOVE_PAGES: u64 = 307;
    pub const GETCPU: u64 = 308;
    pub const EPOLL_PWAIT: u64 = 309;
    /// 32 では time32 版。
    pub const UTIMENSAT: u64 = 310;
    pub const SIGNALFD: u64 = 311;
    pub const TIMERFD_CREATE: u64 = 312;
    pub const EVENTFD: u64 = 313;
    pub const FALLOCATE: u64 = 314;
    /// 32 では time32 版。
    pub const TIMERFD_SETTIME: u64 = 315;
    /// 32 では time32 版。
    pub const TIMERFD_GETTIME: u64 = 316;
    pub const SIGNALFD4: u64 = 317;
    pub const EVENTFD2: u64 = 318;
    pub const EPOLL_CREATE1: u64 = 319;
    pub const DUP3: u64 = 320;
    pub const PIPE2: u64 = 321;
    pub const INOTIFY_INIT1: u64 = 322;
    pub const ACCEPT4: u64 = 323;
    pub const PREADV: u64 = 324;
    pub const PWRITEV: u64 = 325;
    pub const RT_TGSIGQUEUEINFO: u64 = 326;
    pub const PERF_EVENT_OPEN: u64 = 327;
    /// 32 では time32 版。
    pub const RECVMMSG: u64 = 328;
    pub const FANOTIFY_INIT: u64 = 329;
    pub const FANOTIFY_MARK: u64 = 330;
    pub const PRLIMIT64: u64 = 331;
    pub const NAME_TO_HANDLE_AT: u64 = 332;
    pub const OPEN_BY_HANDLE_AT: u64 = 333;
    /// 32 では clock_adjtime32。
    pub const CLOCK_ADJTIME: u64 = 334;
    pub const SYNCFS: u64 = 335;
    pub const SENDMMSG: u64 = 336;
    pub const SETNS: u64 = 337;
    pub const PROCESS_VM_READV: u64 = 338;
    pub const PROCESS_VM_WRITEV: u64 = 339;
    /// sparc の機能問い合わせ。
    pub const KERN_FEATURES: u64 = 340;
    pub const KCMP: u64 = 341;
    pub const FINIT_MODULE: u64 = 342;
    pub const SCHED_SETATTR: u64 = 343;
    pub const SCHED_GETATTR: u64 = 344;
    pub const RENAMEAT2: u64 = 345;
    pub const SECCOMP: u64 = 346;
    pub const GETRANDOM: u64 = 347;
    pub const MEMFD_CREATE: u64 = 348;
    pub const BPF: u64 = 349;
    /// 32 は sys32_execveat、64 は sys64_execveat。
    pub const EXECVEAT: u64 = 350;
    pub const MEMBARRIER: u64 = 351;
    pub const USERFAULTFD: u64 = 352;
    pub const BIND: u64 = 353;
    pub const LISTEN: u64 = 354;
    pub const SETSOCKOPT: u64 = 355;
    pub const MLOCK2: u64 = 356;
    pub const COPY_FILE_RANGE: u64 = 357;
    pub const PREADV2: u64 = 358;
    pub const PWRITEV2: u64 = 359;
    pub const STATX: u64 = 360;
    /// 32 では time32 版。
    pub const IO_PGETEVENTS: u64 = 361;
    pub const PKEY_MPROTECT: u64 = 362;
    pub const PKEY_ALLOC: u64 = 363;
    pub const PKEY_FREE: u64 = 364;
    pub const RSEQ: u64 = 365;
    /// 64 だけ。
    pub const SEMTIMEDOP: u64 = 392;
    pub const SEMGET: u64 = 393;
    pub const SEMCTL: u64 = 394;
    pub const SHMGET: u64 = 395;
    pub const SHMCTL: u64 = 396;
    pub const SHMAT: u64 = 397;
    pub const SHMDT: u64 = 398;
    pub const MSGGET: u64 = 399;
    pub const MSGSND: u64 = 400;
    pub const MSGRCV: u64 = 401;
    pub const MSGCTL: u64 = 402;
    /// 32 だけ（time64 群はすべて 32 専用）。
    pub const CLOCK_GETTIME64: u64 = 403;
    pub const CLOCK_SETTIME64: u64 = 404;
    pub const CLOCK_ADJTIME64: u64 = 405;
    pub const CLOCK_GETRES_TIME64: u64 = 406;
    pub const CLOCK_NANOSLEEP_TIME64: u64 = 407;
    pub const TIMER_GETTIME64: u64 = 408;
    pub const TIMER_SETTIME64: u64 = 409;
    pub const TIMERFD_GETTIME64: u64 = 410;
    pub const TIMERFD_SETTIME64: u64 = 411;
    pub const UTIMENSAT_TIME64: u64 = 412;
    pub const PSELECT6_TIME64: u64 = 413;
    pub const PPOLL_TIME64: u64 = 414;
    pub const IO_PGETEVENTS_TIME64: u64 = 416;
    pub const RECVMMSG_TIME64: u64 = 417;
    pub const MQ_TIMEDSEND_TIME64: u64 = 418;
    pub const MQ_TIMEDRECEIVE_TIME64: u64 = 419;
    pub const SEMTIMEDOP_TIME64: u64 = 420;
    pub const RT_SIGTIMEDWAIT_TIME64: u64 = 421;
    pub const FUTEX_TIME64: u64 = 422;
    pub const SCHED_RR_GET_INTERVAL_TIME64: u64 = 423;
    pub const PIDFD_SEND_SIGNAL: u64 = 424;
    pub const IO_URING_SETUP: u64 = 425;
    pub const IO_URING_ENTER: u64 = 426;
    pub const IO_URING_REGISTER: u64 = 427;
    pub const OPEN_TREE: u64 = 428;
    pub const MOVE_MOUNT: u64 = 429;
    pub const FSOPEN: u64 = 430;
    pub const FSCONFIG: u64 = 431;
    pub const FSMOUNT: u64 = 432;
    pub const FSPICK: u64 = 433;
    pub const PIDFD_OPEN: u64 = 434;
    pub const CLONE3: u64 = 435;
    pub const CLOSE_RANGE: u64 = 436;
    pub const OPENAT2: u64 = 437;
    pub const PIDFD_GETFD: u64 = 438;
    pub const FACCESSAT2: u64 = 439;
    pub const PROCESS_MADVISE: u64 = 440;
    pub const EPOLL_PWAIT2: u64 = 441;
    pub const MOUNT_SETATTR: u64 = 442;
    pub const QUOTACTL_FD: u64 = 443;
    pub const LANDLOCK_CREATE_RULESET: u64 = 444;
    pub const LANDLOCK_ADD_RULE: u64 = 445;
    pub const LANDLOCK_RESTRICT_SELF: u64 = 446;
    pub const PROCESS_MRELEASE: u64 = 448;
    pub const FUTEX_WAITV: u64 = 449;
    pub const SET_MEMPOLICY_HOME_NODE: u64 = 450;
    pub const CACHESTAT: u64 = 451;
    pub const FCHMODAT2: u64 = 452;
    pub const MAP_SHADOW_STACK: u64 = 453;
    pub const FUTEX_WAKE: u64 = 454;
    pub const FUTEX_WAIT: u64 = 455;
    pub const FUTEX_REQUEUE: u64 = 456;
    pub const STATMOUNT: u64 = 457;
    pub const LISTMOUNT: u64 = 458;
    pub const LSM_GET_SELF_ATTR: u64 = 459;
    pub const LSM_SET_SELF_ATTR: u64 = 460;
    pub const LSM_LIST_MODULES: u64 = 461;
    pub const MSEAL: u64 = 462;
    pub const SETXATTRAT: u64 = 463;
    pub const GETXATTRAT: u64 = 464;
    pub const LISTXATTRAT: u64 = 465;
    pub const REMOVEXATTRAT: u64 = 466;
    pub const OPEN_TREE_ATTR: u64 = 467;
    pub const FILE_GETATTR: u64 = 468;
    pub const FILE_SETATTR: u64 = 469;
    pub const LISTNS: u64 = 470;
    pub const RSEQ_SLICE_YIELD: u64 = 471;
    pub const FCHROOT: u64 = 472;
}

/// 番号から名前を引く。表は番号順なので二分探索する。
#[must_use]
pub fn name(nr: u64) -> Option<&'static str> {
    SYSCALLS
        .binary_search_by_key(&nr, |(n, _)| *n)
        .ok()
        .map(|i| SYSCALLS[i].1)
}

/// `name` の引き表。番号順なので二分探索する。
const SYSCALLS: &[(u64, &str)] = &[
    (0, "restart_syscall"),
    (1, "exit"),
    (2, "fork"),
    (3, "read"),
    (4, "write"),
    (5, "open"),
    (6, "close"),
    (7, "wait4"),
    (8, "creat"),
    (9, "link"),
    (10, "unlink"),
    (11, "execv"),
    (12, "chdir"),
    (13, "chown"),
    (14, "mknod"),
    (15, "chmod"),
    (16, "lchown"),
    (17, "brk"),
    (18, "perfctr"),
    (19, "lseek"),
    (20, "getpid"),
    (21, "capget"),
    (22, "capset"),
    (23, "setuid"),
    (24, "getuid"),
    (25, "vmsplice"),
    (26, "ptrace"),
    (27, "alarm"),
    (28, "sigaltstack"),
    (29, "pause"),
    (30, "utime"),
    (31, "lchown32"),
    (32, "fchown32"),
    (33, "access"),
    (34, "nice"),
    (35, "chown32"),
    (36, "sync"),
    (37, "kill"),
    (38, "stat"),
    (39, "sendfile"),
    (40, "lstat"),
    (41, "dup"),
    (42, "pipe"),
    (43, "times"),
    (44, "getuid32"),
    (45, "umount2"),
    (46, "setgid"),
    (47, "getgid"),
    (48, "signal"),
    (49, "geteuid"),
    (50, "getegid"),
    (51, "acct"),
    (52, "memory_ordering"),
    (53, "getgid32"),
    (54, "ioctl"),
    (55, "reboot"),
    (56, "mmap2"),
    (57, "symlink"),
    (58, "readlink"),
    (59, "execve"),
    (60, "umask"),
    (61, "chroot"),
    (62, "fstat"),
    (63, "fstat64"),
    (64, "getpagesize"),
    (65, "msync"),
    (66, "vfork"),
    (67, "pread64"),
    (68, "pwrite64"),
    (69, "geteuid32"),
    (70, "getegid32"),
    (71, "mmap"),
    (72, "setreuid32"),
    (73, "munmap"),
    (74, "mprotect"),
    (75, "madvise"),
    (76, "vhangup"),
    (77, "truncate64"),
    (78, "mincore"),
    (79, "getgroups"),
    (80, "setgroups"),
    (81, "getpgrp"),
    (82, "setgroups32"),
    (83, "setitimer"),
    (84, "ftruncate64"),
    (85, "swapon"),
    (86, "getitimer"),
    (87, "setuid32"),
    (88, "sethostname"),
    (89, "setgid32"),
    (90, "dup2"),
    (91, "setfsuid32"),
    (92, "fcntl"),
    (93, "select"),
    (94, "setfsgid32"),
    (95, "fsync"),
    (96, "setpriority"),
    (97, "socket"),
    (98, "connect"),
    (99, "accept"),
    (100, "getpriority"),
    (101, "rt_sigreturn"),
    (102, "rt_sigaction"),
    (103, "rt_sigprocmask"),
    (104, "rt_sigpending"),
    (105, "rt_sigtimedwait"),
    (106, "rt_sigqueueinfo"),
    (107, "rt_sigsuspend"),
    (108, "setresuid"),
    (109, "getresuid"),
    (110, "setresgid"),
    (111, "getresgid"),
    (112, "setregid32"),
    (113, "recvmsg"),
    (114, "sendmsg"),
    (115, "getgroups32"),
    (116, "gettimeofday"),
    (117, "getrusage"),
    (118, "getsockopt"),
    (119, "getcwd"),
    (120, "readv"),
    (121, "writev"),
    (122, "settimeofday"),
    (123, "fchown"),
    (124, "fchmod"),
    (125, "recvfrom"),
    (126, "setreuid"),
    (127, "setregid"),
    (128, "rename"),
    (129, "truncate"),
    (130, "ftruncate"),
    (131, "flock"),
    (132, "lstat64"),
    (133, "sendto"),
    (134, "shutdown"),
    (135, "socketpair"),
    (136, "mkdir"),
    (137, "rmdir"),
    (138, "utimes"),
    (139, "stat64"),
    (140, "sendfile64"),
    (141, "getpeername"),
    (142, "futex"),
    (143, "gettid"),
    (144, "getrlimit"),
    (145, "setrlimit"),
    (146, "pivot_root"),
    (147, "prctl"),
    (148, "pciconfig_read"),
    (149, "pciconfig_write"),
    (150, "getsockname"),
    (151, "inotify_init"),
    (152, "inotify_add_watch"),
    (153, "poll"),
    (154, "getdents64"),
    (155, "fcntl64"),
    (156, "inotify_rm_watch"),
    (157, "statfs"),
    (158, "fstatfs"),
    (159, "umount"),
    (160, "sched_set_affinity"),
    (161, "sched_get_affinity"),
    (162, "getdomainname"),
    (163, "setdomainname"),
    (164, "utrap_install"),
    (165, "quotactl"),
    (166, "set_tid_address"),
    (167, "mount"),
    (168, "ustat"),
    (169, "setxattr"),
    (170, "lsetxattr"),
    (171, "fsetxattr"),
    (172, "getxattr"),
    (173, "lgetxattr"),
    (174, "getdents"),
    (175, "setsid"),
    (176, "fchdir"),
    (177, "fgetxattr"),
    (178, "listxattr"),
    (179, "llistxattr"),
    (180, "flistxattr"),
    (181, "removexattr"),
    (182, "lremovexattr"),
    (183, "sigpending"),
    (184, "query_module"),
    (185, "setpgid"),
    (186, "fremovexattr"),
    (187, "tkill"),
    (188, "exit_group"),
    (189, "uname"),
    (190, "init_module"),
    (191, "personality"),
    (192, "remap_file_pages"),
    (193, "epoll_create"),
    (194, "epoll_ctl"),
    (195, "epoll_wait"),
    (196, "ioprio_set"),
    (197, "getppid"),
    (198, "sigaction"),
    (199, "sgetmask"),
    (200, "ssetmask"),
    (201, "sigsuspend"),
    (202, "oldlstat"),
    (203, "uselib"),
    (204, "readdir"),
    (205, "readahead"),
    (206, "socketcall"),
    (207, "syslog"),
    (208, "lookup_dcookie"),
    (209, "fadvise64"),
    (210, "fadvise64_64"),
    (211, "tgkill"),
    (212, "waitpid"),
    (213, "swapoff"),
    (214, "sysinfo"),
    (215, "ipc"),
    (216, "sigreturn"),
    (217, "clone"),
    (218, "ioprio_get"),
    (219, "adjtimex"),
    (220, "sigprocmask"),
    (221, "create_module"),
    (222, "delete_module"),
    (223, "get_kernel_syms"),
    (224, "getpgid"),
    (225, "bdflush"),
    (226, "sysfs"),
    (227, "afs_syscall"),
    (228, "setfsuid"),
    (229, "setfsgid"),
    (230, "_newselect"),
    (231, "time"),
    (232, "splice"),
    (233, "stime"),
    (234, "statfs64"),
    (235, "fstatfs64"),
    (236, "llseek"),
    (237, "mlock"),
    (238, "munlock"),
    (239, "mlockall"),
    (240, "munlockall"),
    (241, "sched_setparam"),
    (242, "sched_getparam"),
    (243, "sched_setscheduler"),
    (244, "sched_getscheduler"),
    (245, "sched_yield"),
    (246, "sched_get_priority_max"),
    (247, "sched_get_priority_min"),
    (248, "sched_rr_get_interval"),
    (249, "nanosleep"),
    (250, "mremap"),
    (251, "sysctl"),
    (252, "getsid"),
    (253, "fdatasync"),
    (254, "nfsservctl"),
    (255, "sync_file_range"),
    (256, "clock_settime"),
    (257, "clock_gettime"),
    (258, "clock_getres"),
    (259, "clock_nanosleep"),
    (260, "sched_getaffinity"),
    (261, "sched_setaffinity"),
    (262, "timer_settime"),
    (263, "timer_gettime"),
    (264, "timer_getoverrun"),
    (265, "timer_delete"),
    (266, "timer_create"),
    (267, "vserver"),
    (268, "io_setup"),
    (269, "io_destroy"),
    (270, "io_submit"),
    (271, "io_cancel"),
    (272, "io_getevents"),
    (273, "mq_open"),
    (274, "mq_unlink"),
    (275, "mq_timedsend"),
    (276, "mq_timedreceive"),
    (277, "mq_notify"),
    (278, "mq_getsetattr"),
    (279, "waitid"),
    (280, "tee"),
    (281, "add_key"),
    (282, "request_key"),
    (283, "keyctl"),
    (284, "openat"),
    (285, "mkdirat"),
    (286, "mknodat"),
    (287, "fchownat"),
    (288, "futimesat"),
    (289, "fstatat64"),
    (290, "unlinkat"),
    (291, "renameat"),
    (292, "linkat"),
    (293, "symlinkat"),
    (294, "readlinkat"),
    (295, "fchmodat"),
    (296, "faccessat"),
    (297, "pselect6"),
    (298, "ppoll"),
    (299, "unshare"),
    (300, "set_robust_list"),
    (301, "get_robust_list"),
    (302, "migrate_pages"),
    (303, "mbind"),
    (304, "get_mempolicy"),
    (305, "set_mempolicy"),
    (306, "kexec_load"),
    (307, "move_pages"),
    (308, "getcpu"),
    (309, "epoll_pwait"),
    (310, "utimensat"),
    (311, "signalfd"),
    (312, "timerfd_create"),
    (313, "eventfd"),
    (314, "fallocate"),
    (315, "timerfd_settime"),
    (316, "timerfd_gettime"),
    (317, "signalfd4"),
    (318, "eventfd2"),
    (319, "epoll_create1"),
    (320, "dup3"),
    (321, "pipe2"),
    (322, "inotify_init1"),
    (323, "accept4"),
    (324, "preadv"),
    (325, "pwritev"),
    (326, "rt_tgsigqueueinfo"),
    (327, "perf_event_open"),
    (328, "recvmmsg"),
    (329, "fanotify_init"),
    (330, "fanotify_mark"),
    (331, "prlimit64"),
    (332, "name_to_handle_at"),
    (333, "open_by_handle_at"),
    (334, "clock_adjtime"),
    (335, "syncfs"),
    (336, "sendmmsg"),
    (337, "setns"),
    (338, "process_vm_readv"),
    (339, "process_vm_writev"),
    (340, "kern_features"),
    (341, "kcmp"),
    (342, "finit_module"),
    (343, "sched_setattr"),
    (344, "sched_getattr"),
    (345, "renameat2"),
    (346, "seccomp"),
    (347, "getrandom"),
    (348, "memfd_create"),
    (349, "bpf"),
    (350, "execveat"),
    (351, "membarrier"),
    (352, "userfaultfd"),
    (353, "bind"),
    (354, "listen"),
    (355, "setsockopt"),
    (356, "mlock2"),
    (357, "copy_file_range"),
    (358, "preadv2"),
    (359, "pwritev2"),
    (360, "statx"),
    (361, "io_pgetevents"),
    (362, "pkey_mprotect"),
    (363, "pkey_alloc"),
    (364, "pkey_free"),
    (365, "rseq"),
    (392, "semtimedop"),
    (393, "semget"),
    (394, "semctl"),
    (395, "shmget"),
    (396, "shmctl"),
    (397, "shmat"),
    (398, "shmdt"),
    (399, "msgget"),
    (400, "msgsnd"),
    (401, "msgrcv"),
    (402, "msgctl"),
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
