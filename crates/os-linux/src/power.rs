// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Power（ppc64）Linux のシステムコール番号と ABI 定数。
//!
//! 番号は `arch/powerpc/include/uapi/asm/unistd.h` の UAPI 表由来の
//! 事実である（`.testdata/uapi-powerpc/syscall.tbl` も参照）。ppc64 は
//! 64 ビット列だけを使い、32 ビット互換の分岐は持たない。
//! システムコールの規約: 番号は r0、引数は r3–r8、戻り値は r3、
//! エラーは CR0.SO（CR の IBM bit3 = 値 0x1000_0000）を立てて r3 に
//! 正の errno を返す。
//! Ref: SRC-LINUX (7.3), SPEC-POWER-ABI (ELFv2 r1.5).

// ---- 番号（ppc64。common/nospu/64 の列から）----
pub const EXIT: u64 = 1;
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
pub const LSEEK: u64 = 19;
pub const GETPID: u64 = 20;
pub const MOUNT: u64 = 21;
pub const SETUID: u64 = 23;
pub const GETUID: u64 = 24;
pub const PTRACE: u64 = 26;
pub const ALARM: u64 = 27;
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
pub const GETEUID: u64 = 49;
pub const GETEGID: u64 = 50;
pub const ACCT: u64 = 51;
pub const UMOUNT2: u64 = 52;
pub const IOCTL: u64 = 54;
pub const FCNTL: u64 = 55;
pub const SETPGID: u64 = 57;
pub const UMASK: u64 = 60;
pub const CHROOT: u64 = 61;
pub const DUP2: u64 = 63;
pub const GETPPID: u64 = 64;
pub const GETPGRP: u64 = 65;
pub const SETSID: u64 = 66;
pub const SETREUID: u64 = 70;
pub const SETREGID: u64 = 71;
pub const SETHOSTNAME: u64 = 74;
pub const SETRLIMIT: u64 = 75;
pub const GETRUSAGE: u64 = 77;
pub const GETTIMEOFDAY: u64 = 78;
pub const SETTIMEOFDAY: u64 = 79;
pub const GETGROUPS: u64 = 80;
pub const SETGROUPS: u64 = 81;
pub const SELECT: u64 = 82;
pub const SYMLINK: u64 = 83;
pub const READLINK: u64 = 85;
pub const SWAPON: u64 = 87;
pub const REBOOT: u64 = 88;
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
pub const SOCKETCALL: u64 = 102;
pub const SYSLOG: u64 = 103;
pub const SETITIMER: u64 = 104;
pub const GETITIMER: u64 = 105;
pub const STAT: u64 = 106;
pub const LSTAT: u64 = 107;
pub const FSTAT: u64 = 108;
pub const VHANGUP: u64 = 111;
pub const WAIT4: u64 = 114;
pub const SWAPOFF: u64 = 115;
pub const SYSINFO: u64 = 116;
pub const IPC: u64 = 117;
pub const FSYNC: u64 = 118;
pub const CLONE: u64 = 120;
pub const SETDOMAINNAME: u64 = 121;
pub const UNAME: u64 = 122;
pub const ADJTIMEX: u64 = 124;
pub const MPROTECT: u64 = 125;
pub const INIT_MODULE: u64 = 128;
pub const DELETE_MODULE: u64 = 129;
pub const QUOTACTL: u64 = 131;
pub const GETPGID: u64 = 132;
pub const FCHDIR: u64 = 133;
pub const SYSFS: u64 = 135;
pub const PERSONALITY: u64 = 136;
pub const SETFSUID: u64 = 138;
pub const SETFSGID: u64 = 139;
pub const LLSEEK: u64 = 140;
pub const GETDENTS: u64 = 141;
pub const NEWSELECT: u64 = 142;
pub const FLOCK: u64 = 143;
pub const MSYNC: u64 = 144;
pub const READV: u64 = 145;
pub const WRITEV: u64 = 146;
pub const GETSID: u64 = 147;
pub const FDATASYNC: u64 = 148;
pub const SYSCTL: u64 = 149;
pub const MLOCK: u64 = 150;
pub const MUNLOCK: u64 = 151;
pub const MLOCKALL: u64 = 152;
pub const MUNLOCKALL: u64 = 153;
pub const SCHED_YIELD: u64 = 158;
pub const NANOSLEEP: u64 = 162;
pub const MREMAP: u64 = 163;
pub const SETRESUID: u64 = 164;
pub const GETRESUID: u64 = 165;
pub const POLL: u64 = 167;
pub const SETRESGID: u64 = 169;
pub const GETRESGID: u64 = 170;
pub const PRCTL: u64 = 171;
pub const RT_SIGRETURN: u64 = 172;
pub const RT_SIGACTION: u64 = 173;
pub const RT_SIGPROCMASK: u64 = 174;
pub const RT_SIGPENDING: u64 = 175;
pub const RT_SIGTIMEDWAIT: u64 = 176;
pub const RT_SIGQUEUEINFO: u64 = 177;
pub const RT_SIGSUSPEND: u64 = 178;
pub const PREAD64: u64 = 179;
pub const PWRITE64: u64 = 180;
pub const CHOWN: u64 = 181;
pub const GETCWD: u64 = 182;
pub const CAPGET: u64 = 183;
pub const CAPSET: u64 = 184;
pub const SIGALTSTACK: u64 = 185;
pub const SENDFILE: u64 = 186;
pub const VFORK: u64 = 189;
pub const GETRLIMIT: u64 = 190;
pub const READAHEAD: u64 = 191;
pub const TRUNCATE64: u64 = 193;
pub const FTRUNCATE64: u64 = 194;
pub const GETDENTS64: u64 = 202;
pub const PIVOT_ROOT: u64 = 203;
pub const FCNTL64: u64 = 204;
pub const MADVISE: u64 = 205;
pub const MINCORE: u64 = 206;
pub const GETTID: u64 = 207;
pub const TKILL: u64 = 208;
pub const FUTEX: u64 = 221;
pub const SCHED_SETAFFINITY: u64 = 222;
pub const SCHED_GETAFFINITY: u64 = 223;
pub const IO_SETUP: u64 = 227;
pub const IO_DESTROY: u64 = 228;
pub const IO_GETEVENTS: u64 = 229;
pub const IO_SUBMIT: u64 = 230;
pub const IO_CANCEL: u64 = 231;
pub const SET_TID_ADDRESS: u64 = 232;
pub const FADVISE64: u64 = 233;
pub const EXIT_GROUP: u64 = 234;
pub const EPOLL_CREATE: u64 = 236;
pub const EPOLL_CTL: u64 = 237;
pub const EPOLL_WAIT: u64 = 238;
pub const CLOCK_SETTIME: u64 = 245;
pub const CLOCK_GETTIME: u64 = 246;
pub const CLOCK_GETRES: u64 = 247;
pub const CLOCK_NANOSLEEP: u64 = 248;
pub const TGKILL: u64 = 250;
pub const STATFS64: u64 = 252;
pub const FSTATFS64: u64 = 253;
pub const WAITID: u64 = 272;
pub const INOTIFY_INIT: u64 = 275;
pub const PSELECT6: u64 = 280;
pub const PPOLL: u64 = 281;
pub const SPLICE: u64 = 283;
pub const TEE: u64 = 284;
pub const VMSPLICE: u64 = 285;
pub const OPENAT: u64 = 286;
pub const MKDIRAT: u64 = 287;
pub const MKNODAT: u64 = 288;
pub const FCHOWNAT: u64 = 289;
pub const NEWFSTATAT: u64 = 291;
pub const UNLINKAT: u64 = 292;
pub const RENAMEAT: u64 = 293;
pub const LINKAT: u64 = 294;
pub const SYMLINKAT: u64 = 295;
pub const READLINKAT: u64 = 296;
pub const FCHMODAT: u64 = 297;
pub const FACCESSAT: u64 = 298;
pub const SET_ROBUST_LIST: u64 = 300;
pub const GETCPU: u64 = 302;
pub const EPOLL_PWAIT: u64 = 303;
pub const UTIMENSAT: u64 = 304;
pub const SIGNALFD: u64 = 305;
pub const TIMERFD_CREATE: u64 = 306;
pub const EVENTFD: u64 = 307;
pub const SYNC_FILE_RANGE: u64 = 308;
pub const FALLOCATE: u64 = 309;
pub const TIMERFD_SETTIME: u64 = 311;
pub const TIMERFD_GETTIME: u64 = 312;
pub const SIGNALFD4: u64 = 313;
pub const EVENTFD2: u64 = 314;
pub const EPOLL_CREATE1: u64 = 315;
pub const DUP3: u64 = 316;
pub const PIPE2: u64 = 317;
pub const INOTIFY_INIT1: u64 = 318;
pub const PERF_EVENT_OPEN: u64 = 319;
pub const PRLIMIT64: u64 = 325;
pub const RENAMEAT2: u64 = 357;
pub const SECCOMP: u64 = 358;
pub const GETRANDOM: u64 = 359;
pub const MEMFD_CREATE: u64 = 360;
pub const MEMBARRIER: u64 = 365;
pub const MLOCK2: u64 = 378;
pub const COPY_FILE_RANGE: u64 = 379;
pub const STATX: u64 = 383;
pub const RSEQ: u64 = 387;

/// 汎用 errno（ppc64 はホストと同じ値）。
// Ref: SRC-LINUX (7.3) `include/uapi/asm-generic/errno*.h`。
pub mod errno {
    pub const EPERM: u32 = 1;
    pub const ENOENT: u32 = 2;
    pub const ESRCH: u32 = 3;
    pub const EINTR: u32 = 4;
    pub const EIO: u32 = 5;
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
    pub const ENFILE: u32 = 23;
    pub const EMFILE: u32 = 24;
    pub const ENOTTY: u32 = 25;
    pub const EFBIG: u32 = 27;
    pub const ENOSPC: u32 = 28;
    pub const ESPIPE: u32 = 29;
    pub const EROFS: u32 = 30;
    pub const EMLINK: u32 = 31;
    pub const EPIPE: u32 = 32;
    pub const ERANGE: u32 = 34;
    pub const ENAMETOOLONG: u32 = 36;
    pub const ENOSYS: u32 = 38;
    pub const ELOOP: u32 = 40;
    pub const EOVERFLOW: u32 = 75;
    pub const EOPNOTSUPP: u32 = 95;
}

/// `open`/`openat` の `O_*`（ppc64 は汎用値と同じ）。
// Ref: SRC-LINUX (7.3) `include/uapi/asm-generic/fcntl.h`。
pub mod oflag {
    pub const CREAT: u64 = 0o100;
    pub const EXCL: u64 = 0o200;
    pub const NOCTTY: u64 = 0o400;
    pub const TRUNC: u64 = 0o1000;
    pub const APPEND: u64 = 0o2000;
    pub const NONBLOCK: u64 = 0o4000;
    pub const DSYNC: u64 = 0o10000;
    pub const DIRECT: u64 = 0o40000;
    pub const LARGEFILE: u64 = 0o100000;
    pub const DIRECTORY: u64 = 0o200000;
    pub const NOFOLLOW: u64 = 0o400000;
    pub const NOATIME: u64 = 0o1000000;
    pub const CLOEXEC: u64 = 0o2000000;
    pub const SYNC: u64 = 0o4010000;
}

/// `mmap` のフラグ（汎用値）。
pub mod mflag {
    pub const SHARED: u64 = 1;
    pub const PRIVATE: u64 = 2;
    pub const FIXED: u64 = 0x10;
    pub const ANONYMOUS: u64 = 0x20;
}

/// `ioctl` の要求番号（powerpc UAPI の値）。
// Ref: SRC-LINUX — `arch/powerpc/include/uapi/asm/ioctls.h`。
pub mod ioc {
    pub const TCGETS: u64 = 0x403C_7413;
    pub const TCSETS: u64 = 0x803C_7414;
    pub const TCSETSW: u64 = 0x803C_7415;
    pub const TCSETSF: u64 = 0x803C_7416;
    pub const TIOCGWINSZ: u64 = 0x4008_7468;
    pub const TIOCSWINSZ: u64 = 0x8008_7467;
    pub const FIONREAD: u64 = 0x4004_667F;
    pub const TIOCNOTTY: u64 = 0x5422;
}

/// ppc64 のシステムコール番号と名前の表（番号順）。
/// `task status` の `syscalls.md` はこの表から生成する。
// Ref: SRC-LINUX (7.3) `arch/powerpc/include/uapi/asm/unistd.h`。
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
    (19, "lseek"),
    (20, "getpid"),
    (21, "mount"),
    (23, "setuid"),
    (24, "getuid"),
    (26, "ptrace"),
    (27, "alarm"),
    (29, "pause"),
    (30, "utime"),
    (33, "access"),
    (34, "nice"),
    (36, "sync"),
    (37, "kill"),
    (38, "rename"),
    (39, "mkdir"),
    (40, "rmdir"),
    (41, "dup"),
    (42, "pipe"),
    (43, "times"),
    (45, "brk"),
    (46, "setgid"),
    (47, "getgid"),
    (49, "geteuid"),
    (50, "getegid"),
    (51, "acct"),
    (52, "umount2"),
    (54, "ioctl"),
    (55, "fcntl"),
    (57, "setpgid"),
    (60, "umask"),
    (61, "chroot"),
    (63, "dup2"),
    (64, "getppid"),
    (65, "getpgrp"),
    (66, "setsid"),
    (70, "setreuid"),
    (71, "setregid"),
    (74, "sethostname"),
    (75, "setrlimit"),
    (77, "getrusage"),
    (78, "gettimeofday"),
    (79, "settimeofday"),
    (80, "getgroups"),
    (81, "setgroups"),
    (82, "select"),
    (83, "symlink"),
    (85, "readlink"),
    (87, "swapon"),
    (88, "reboot"),
    (90, "mmap"),
    (91, "munmap"),
    (92, "truncate"),
    (93, "ftruncate"),
    (94, "fchmod"),
    (95, "fchown"),
    (96, "getpriority"),
    (97, "setpriority"),
    (99, "statfs"),
    (100, "fstatfs"),
    (102, "socketcall"),
    (103, "syslog"),
    (104, "setitimer"),
    (105, "getitimer"),
    (106, "stat"),
    (107, "lstat"),
    (108, "fstat"),
    (111, "vhangup"),
    (114, "wait4"),
    (115, "swapoff"),
    (116, "sysinfo"),
    (117, "ipc"),
    (118, "fsync"),
    (120, "clone"),
    (121, "setdomainname"),
    (122, "uname"),
    (124, "adjtimex"),
    (125, "mprotect"),
    (128, "init_module"),
    (129, "delete_module"),
    (131, "quotactl"),
    (132, "getpgid"),
    (133, "fchdir"),
    (135, "sysfs"),
    (136, "personality"),
    (138, "setfsuid"),
    (139, "setfsgid"),
    (140, "llseek"),
    (141, "getdents"),
    (142, "_newselect"),
    (143, "flock"),
    (144, "msync"),
    (145, "readv"),
    (146, "writev"),
    (147, "getsid"),
    (148, "fdatasync"),
    (149, "sysctl"),
    (150, "mlock"),
    (151, "munlock"),
    (152, "mlockall"),
    (153, "munlockall"),
    (158, "sched_yield"),
    (162, "nanosleep"),
    (163, "mremap"),
    (164, "setresuid"),
    (165, "getresuid"),
    (167, "poll"),
    (169, "setresgid"),
    (170, "getresgid"),
    (171, "prctl"),
    (172, "rt_sigreturn"),
    (173, "rt_sigaction"),
    (174, "rt_sigprocmask"),
    (175, "rt_sigpending"),
    (176, "rt_sigtimedwait"),
    (177, "rt_sigqueueinfo"),
    (178, "rt_sigsuspend"),
    (179, "pread64"),
    (180, "pwrite64"),
    (181, "chown"),
    (182, "getcwd"),
    (183, "capget"),
    (184, "capset"),
    (185, "sigaltstack"),
    (186, "sendfile"),
    (189, "vfork"),
    (190, "getrlimit"),
    (191, "readahead"),
    (193, "truncate64"),
    (194, "ftruncate64"),
    (202, "getdents64"),
    (203, "pivot_root"),
    (204, "fcntl64"),
    (205, "madvise"),
    (206, "mincore"),
    (207, "gettid"),
    (208, "tkill"),
    (221, "futex"),
    (222, "sched_setaffinity"),
    (223, "sched_getaffinity"),
    (227, "io_setup"),
    (228, "io_destroy"),
    (229, "io_getevents"),
    (230, "io_submit"),
    (231, "io_cancel"),
    (232, "set_tid_address"),
    (233, "fadvise64"),
    (234, "exit_group"),
    (236, "epoll_create"),
    (237, "epoll_ctl"),
    (238, "epoll_wait"),
    (245, "clock_settime"),
    (246, "clock_gettime"),
    (247, "clock_getres"),
    (248, "clock_nanosleep"),
    (250, "tgkill"),
    (252, "statfs64"),
    (253, "fstatfs64"),
    (272, "waitid"),
    (275, "inotify_init"),
    (280, "pselect6"),
    (281, "ppoll"),
    (283, "splice"),
    (284, "tee"),
    (285, "vmsplice"),
    (286, "openat"),
    (287, "mkdirat"),
    (288, "mknodat"),
    (289, "fchownat"),
    (291, "newfstatat"),
    (292, "unlinkat"),
    (293, "renameat"),
    (294, "linkat"),
    (295, "symlinkat"),
    (296, "readlinkat"),
    (297, "fchmodat"),
    (298, "faccessat"),
    (300, "set_robust_list"),
    (302, "getcpu"),
    (303, "epoll_pwait"),
    (304, "utimensat"),
    (305, "signalfd"),
    (306, "timerfd_create"),
    (307, "eventfd"),
    (308, "sync_file_range"),
    (309, "fallocate"),
    (311, "timerfd_settime"),
    (312, "timerfd_gettime"),
    (313, "signalfd4"),
    (314, "eventfd2"),
    (315, "epoll_create1"),
    (316, "dup3"),
    (317, "pipe2"),
    (318, "inotify_init1"),
    (319, "perf_event_open"),
    (325, "prlimit64"),
    (326, "socket"),
    (327, "bind"),
    (328, "connect"),
    (329, "listen"),
    (330, "accept"),
    (331, "getsockname"),
    (332, "getpeername"),
    (333, "socketpair"),
    (334, "send"),
    (335, "sendto"),
    (336, "recv"),
    (337, "recvfrom"),
    (338, "shutdown"),
    (339, "setsockopt"),
    (340, "getsockopt"),
    (341, "sendmsg"),
    (342, "recvmsg"),
    (344, "accept4"),
    (357, "renameat2"),
    (358, "seccomp"),
    (359, "getrandom"),
    (360, "memfd_create"),
    (365, "membarrier"),
    (378, "mlock2"),
    (379, "copy_file_range"),
    (383, "statx"),
    (387, "rseq"),
    (441, "epoll_pwait2"),
];

/// 番号から名前を引く。表は番号順なので二分探索する。
#[must_use]
pub fn name(nr: u64) -> Option<&'static str> {
    SYSCALLS
        .binary_search_by_key(&nr, |(n, _)| *n)
        .ok()
        .map(|i| SYSCALLS[i].1)
}

/// Power Linux の syscall 処理。`guest-power` 機能で有効になる。
#[cfg(feature = "guest-power")]
pub mod sys;
