// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SuperH（SH-4・32ビット）の Linux ゲスト ABI 共通部。
//!
//! 規約：syscall 番号は R3、引数は R4–R9、戻り値は R0、失敗は
//! R0 = -errno。発行点は `trapa #16`–`#31`（`#0x10`–`#0x1f`。
//! Linux は引数の個数分だけ入口即値を使い分ける）。
//! errno は asm-generic の値そのまま。番号表は
//! `arch/sh/kernel/syscalls/syscall.tbl` 由来の事実で、S18-2 で
//! UAPI ヘッダと突き合わせる。
//! Ref: SRC-LINUX (7.3) — arch/sh/kernel/syscalls/syscall.tbl,
//! arch/sh/kernel/entry.S.

/// SuperH の Linux syscall 処理。`guest-superh` 機能で有効になる。
#[cfg(feature = "guest-superh")]
pub mod sys;

/// syscall 入口の `trapa` 即値の範囲。
pub const TRAPA_SYS_BASE: u32 = 0x10;
pub const TRAPA_SYS_TOP: u32 = 0x1f;

/// errno。asm-generic の値そのまま（ホストと同じ番号）。
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
    pub const ENFILE: u32 = 23;
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
    pub const EDEADLK: u32 = 35;
    pub const ENAMETOOLONG: u32 = 36;
    pub const ENOLCK: u32 = 37;
    pub const ENOSYS: u32 = 38;
    pub const ENOTEMPTY: u32 = 39;
    pub const ELOOP: u32 = 40;
}

/// syscall 番号。`arch/sh/kernel/syscalls/syscall.tbl` の
/// common 行。
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
    pub const LSEEK: u64 = 19;
    pub const GETPID: u64 = 20;
    pub const MOUNT: u64 = 21;
    pub const UMOUNT: u64 = 22;
    pub const SETUID: u64 = 23;
    pub const GETUID: u64 = 24;
    pub const STIME: u64 = 25;
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
    pub const USTAT: u64 = 62;
    pub const DUP2: u64 = 63;
    pub const GETPPID: u64 = 64;
    pub const GETPGRP: u64 = 65;
    pub const SETSID: u64 = 66;
    pub const SIGACTION: u64 = 67;
    pub const SETRLIMIT: u64 = 75;
    pub const GETRUSAGE: u64 = 77;
    pub const GETTIMEOFDAY: u64 = 78;
    pub const SETTIMEOFDAY: u64 = 79;
    pub const GETGROUPS: u64 = 80;
    pub const SETGROUPS: u64 = 81;
    pub const SYMLINK: u64 = 83;
    pub const READLINK: u64 = 85;
    pub const USELIB: u64 = 86;
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
    pub const FSYNC: u64 = 118;
    pub const SIGRETURN: u64 = 119;
    pub const CLONE: u64 = 120;
    pub const SETDOMAINNAME: u64 = 121;
    pub const UNAME: u64 = 122;
    pub const CACHEFLUSH: u64 = 123;
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
    pub const GETRLIMIT: u64 = 76;
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
    pub const POLL: u64 = 168;
    pub const NFSSERVCTL: u64 = 169;
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
    pub const PREAD64: u64 = 180;
    pub const PWRITE64: u64 = 181;
    pub const CHOWN: u64 = 182;
    pub const GETCWD: u64 = 183;
    pub const CAPGET: u64 = 184;
    pub const CAPSET: u64 = 185;
    pub const SIGALTSTACK: u64 = 186;
    pub const SENDFILE: u64 = 187;
    pub const VFORK: u64 = 190;
    pub const UGETRLIMIT: u64 = 191;
    pub const MMAP2: u64 = 192;
    pub const TRUNCATE64: u64 = 193;
    pub const FTRUNCATE64: u64 = 194;
    pub const STAT64: u64 = 195;
    pub const LSTAT64: u64 = 196;
    pub const FSTAT64: u64 = 197;
    pub const LCHOWN32: u64 = 198;
    pub const GETUID32: u64 = 199;
    pub const GETGID32: u64 = 200;
    pub const GETEUID32: u64 = 201;
    pub const GETEGID32: u64 = 202;
    pub const SETREUID32: u64 = 203;
    pub const SETREGID32: u64 = 204;
    pub const GETGROUPS32: u64 = 205;
    pub const SETGROUPS32: u64 = 206;
    pub const FCHOWN32: u64 = 207;
    pub const SETRESUID32: u64 = 208;
    pub const GETRESUID32: u64 = 209;
    pub const SETRESGID32: u64 = 210;
    pub const GETRESGID32: u64 = 211;
    pub const CHOWN32: u64 = 212;
    pub const SETUID32: u64 = 213;
    pub const SETGID32: u64 = 214;
    pub const SETFSUID32: u64 = 215;
    pub const SETFSGID32: u64 = 216;
    pub const PIVOT_ROOT: u64 = 217;
    pub const MINCORE: u64 = 218;
    pub const MADVISE: u64 = 219;
    pub const GETDENTS64: u64 = 220;
    pub const FCNTL64: u64 = 221;
    pub const GETTID: u64 = 224;
    pub const READAHEAD: u64 = 225;
    pub const SETXATTR: u64 = 226;
    pub const GETXATTR: u64 = 229;
    pub const TKILL: u64 = 238;
    pub const SENDFILE64: u64 = 239;
    pub const FUTEX: u64 = 240;
    pub const SCHED_SETAFFINITY: u64 = 241;
    pub const SCHED_GETAFFINITY: u64 = 242;
    pub const EXIT_GROUP: u64 = 252;
    pub const CLOCK_GETTIME: u64 = 265;
    pub const CLOCK_GETRES: u64 = 266;
    pub const STATFS64: u64 = 268;
    pub const FSTATFS64: u64 = 269;
    pub const TGKILL: u64 = 270;
    pub const UTIMES: u64 = 271;
    pub const FADVISE64_64: u64 = 272;
    pub const IO_SETUP: u64 = 245;
    pub const FADVISE64: u64 = 250;
    pub const EPOLL_CREATE: u64 = 254;
    pub const REMAP_FILE_PAGES: u64 = 257;
    pub const SET_TID_ADDRESS: u64 = 258;
    pub const OPENAT: u64 = 295;
    pub const FSTATAT64: u64 = 300;
    pub const UNLINKAT: u64 = 301;
    pub const READLINKAT: u64 = 305;
    pub const SET_ROBUST_LIST: u64 = 311;
    pub const SPLICE: u64 = 313;
    pub const GETCPU: u64 = 318;
    pub const EVENTFD: u64 = 323;
    pub const GETRANDOM: u64 = 373;
    pub const CLOCK_GETTIME64: u64 = 403;
}

/// `mprotect`/`mmap` の prot ビット（generic ABI）。
pub mod mman {
    /// PROT_READ。
    pub const PROT_READ: u32 = 1;
    /// PROT_WRITE。
    pub const PROT_WRITE: u32 = 2;
    /// PROT_EXEC。
    pub const PROT_EXEC: u32 = 4;
}

/// 番号から名前を引く。`SYSCALLS` は番号順なので二分探索する。
#[must_use]
pub fn name(nr: u64) -> Option<&'static str> {
    SYSCALLS
        .binary_search_by_key(&nr, |(n, _)| *n)
        .ok()
        .map(|i| SYSCALLS[i].1)
}

/// `name` の引き表。`arch/sh/kernel/syscalls/syscall.tbl` の
/// common 行。
const SYSCALLS: &[(u64, &str)] = &[
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
    (18, "oldstat"),
    (19, "lseek"),
    (20, "getpid"),
    (21, "mount"),
    (22, "umount"),
    (23, "setuid"),
    (24, "getuid"),
    (25, "stime"),
    (26, "ptrace"),
    (27, "alarm"),
    (28, "oldfstat"),
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
    (48, "signal"),
    (49, "geteuid"),
    (50, "getegid"),
    (51, "acct"),
    (52, "umount2"),
    (54, "ioctl"),
    (55, "fcntl"),
    (57, "setpgid"),
    (60, "umask"),
    (61, "chroot"),
    (62, "ustat"),
    (63, "dup2"),
    (64, "getppid"),
    (65, "getpgrp"),
    (66, "setsid"),
    (67, "sigaction"),
    (68, "sgetmask"),
    (69, "ssetmask"),
    (70, "setreuid"),
    (71, "setregid"),
    (72, "sigsuspend"),
    (73, "sigpending"),
    (74, "sethostname"),
    (75, "setrlimit"),
    (76, "getrlimit"),
    (77, "getrusage"),
    (78, "gettimeofday"),
    (79, "settimeofday"),
    (80, "getgroups"),
    (81, "setgroups"),
    (83, "symlink"),
    (84, "oldlstat"),
    (85, "readlink"),
    (86, "uselib"),
    (87, "swapon"),
    (88, "reboot"),
    (89, "readdir"),
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
    (109, "olduname"),
    (111, "vhangup"),
    (114, "wait4"),
    (115, "swapoff"),
    (116, "sysinfo"),
    (117, "ipc"),
    (118, "fsync"),
    (119, "sigreturn"),
    (120, "clone"),
    (121, "setdomainname"),
    (122, "uname"),
    (123, "cacheflush"),
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
    (168, "poll"),
    (169, "nfsservctl"),
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
    (180, "pread64"),
    (181, "pwrite64"),
    (182, "chown"),
    (183, "getcwd"),
    (184, "capget"),
    (185, "capset"),
    (186, "sigaltstack"),
    (187, "sendfile"),
    (190, "vfork"),
    (191, "ugetrlimit"),
    (192, "mmap2"),
    (193, "truncate64"),
    (194, "ftruncate64"),
    (195, "stat64"),
    (196, "lstat64"),
    (197, "fstat64"),
    (198, "lchown32"),
    (199, "getuid32"),
    (200, "getgid32"),
    (201, "geteuid32"),
    (202, "getegid32"),
    (203, "setreuid32"),
    (204, "setregid32"),
    (205, "getgroups32"),
    (206, "setgroups32"),
    (207, "fchown32"),
    (208, "setresuid32"),
    (209, "getresuid32"),
    (210, "setresgid32"),
    (211, "getresgid32"),
    (212, "chown32"),
    (213, "setuid32"),
    (214, "setgid32"),
    (215, "setfsuid32"),
    (216, "setfsgid32"),
    (217, "pivot_root"),
    (218, "mincore"),
    (219, "madvise"),
    (220, "getdents64"),
    (221, "fcntl64"),
    (224, "gettid"),
    (225, "readahead"),
    (226, "setxattr"),
    (227, "lsetxattr"),
    (228, "fsetxattr"),
    (229, "getxattr"),
    (230, "lgetxattr"),
    (231, "fgetxattr"),
    (232, "listxattr"),
    (233, "llistxattr"),
    (234, "flistxattr"),
    (235, "removexattr"),
    (236, "lremovexattr"),
    (237, "fremovexattr"),
    (238, "tkill"),
    (239, "sendfile64"),
    (240, "futex"),
    (241, "sched_setaffinity"),
    (242, "sched_getaffinity"),
    (245, "io_setup"),
    (246, "io_destroy"),
    (247, "io_getevents"),
    (248, "io_submit"),
    (249, "io_cancel"),
    (250, "fadvise64"),
    (252, "exit_group"),
    (253, "lookup_dcookie"),
    (254, "epoll_create"),
    (255, "epoll_ctl"),
    (256, "epoll_wait"),
    (257, "remap_file_pages"),
    (258, "set_tid_address"),
    (259, "timer_create"),
    (260, "timer_settime"),
    (261, "timer_gettime"),
    (262, "timer_getoverrun"),
    (263, "timer_delete"),
    (264, "clock_settime"),
    (265, "clock_gettime"),
    (266, "clock_getres"),
    (267, "clock_nanosleep"),
    (268, "statfs64"),
    (269, "fstatfs64"),
    (270, "tgkill"),
    (271, "utimes"),
    (272, "fadvise64_64"),
    (274, "mbind"),
    (275, "get_mempolicy"),
    (276, "set_mempolicy"),
    (277, "mq_open"),
    (278, "mq_unlink"),
    (279, "mq_timedsend"),
    (280, "mq_timedreceive"),
    (281, "mq_notify"),
    (282, "mq_getsetattr"),
    (283, "kexec_load"),
    (284, "waitid"),
    (285, "add_key"),
    (286, "request_key"),
    (287, "keyctl"),
    (288, "ioprio_set"),
    (289, "ioprio_get"),
    (290, "inotify_init"),
    (291, "inotify_add_watch"),
    (292, "inotify_rm_watch"),
    (294, "migrate_pages"),
    (295, "openat"),
    (296, "mkdirat"),
    (297, "mknodat"),
    (298, "fchownat"),
    (299, "futimesat"),
    (300, "fstatat64"),
    (301, "unlinkat"),
    (302, "renameat"),
    (303, "linkat"),
    (304, "symlinkat"),
    (305, "readlinkat"),
    (306, "fchmodat"),
    (307, "faccessat"),
    (308, "pselect6"),
    (309, "ppoll"),
    (310, "unshare"),
    (311, "set_robust_list"),
    (312, "get_robust_list"),
    (313, "splice"),
    (314, "sync_file_range"),
    (315, "tee"),
    (316, "vmsplice"),
    (317, "move_pages"),
    (318, "getcpu"),
    (319, "epoll_pwait"),
    (320, "utimensat"),
    (321, "signalfd"),
    (322, "timerfd_create"),
    (323, "eventfd"),
    (324, "fallocate"),
    (325, "timerfd_settime"),
    (326, "timerfd_gettime"),
    (327, "signalfd4"),
    (328, "eventfd2"),
    (329, "epoll_create1"),
    (330, "dup3"),
    (331, "pipe2"),
    (332, "inotify_init1"),
    (333, "preadv"),
    (334, "pwritev"),
    (335, "rt_tgsigqueueinfo"),
    (336, "perf_event_open"),
    (337, "fanotify_init"),
    (338, "fanotify_mark"),
    (339, "prlimit64"),
    (340, "socket"),
    (341, "bind"),
    (342, "connect"),
    (343, "listen"),
    (344, "accept"),
    (345, "getsockname"),
    (346, "getpeername"),
    (347, "socketpair"),
    (348, "send"),
    (349, "sendto"),
    (350, "recv"),
    (351, "recvfrom"),
    (352, "shutdown"),
    (353, "setsockopt"),
    (354, "getsockopt"),
    (355, "sendmsg"),
    (356, "recvmsg"),
    (357, "recvmmsg"),
    (358, "accept4"),
    (359, "name_to_handle_at"),
    (360, "open_by_handle_at"),
    (361, "clock_adjtime"),
    (362, "syncfs"),
    (363, "sendmmsg"),
    (364, "setns"),
    (365, "process_vm_readv"),
    (366, "process_vm_writev"),
    (367, "kcmp"),
    (368, "finit_module"),
    (369, "sched_getattr"),
    (370, "sched_setattr"),
    (371, "renameat2"),
    (372, "seccomp"),
    (373, "getrandom"),
    (374, "memfd_create"),
    (375, "bpf"),
    (376, "execveat"),
    (377, "userfaultfd"),
    (378, "membarrier"),
    (379, "mlock2"),
    (380, "copy_file_range"),
    (381, "preadv2"),
    (382, "pwritev2"),
    (383, "statx"),
    (384, "pkey_mprotect"),
    (385, "pkey_alloc"),
    (386, "pkey_free"),
    (387, "rseq"),
    (388, "sync_file_range2"),
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
