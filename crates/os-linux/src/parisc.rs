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
/// `uapi/asm/errno.h` の独自表（HP-UX 系の値。ENOSYS=251 など）。
/// 負で `r28` に返す。
// Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/errno.h.
pub mod errno {
    pub const EPERM: u32 = 1;
    pub const ENOENT: u32 = 2;
    pub const EINTR: u32 = 4;
    pub const EIO: u32 = 5;
    pub const ENOEXEC: u32 = 8;
    pub const EBADF: u32 = 9;
    pub const EAGAIN: u32 = 11;
    pub const ENOMEM: u32 = 12;
    pub const EACCES: u32 = 13;
    pub const EFAULT: u32 = 14;
    pub const EBUSY: u32 = 16;
    pub const EEXIST: u32 = 17;
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
    pub const EPIPE: u32 = 32;
    pub const ERANGE: u32 = 34;
    pub const EOVERFLOW: u32 = 72;
    pub const EOPNOTSUPP: u32 = 223;
    pub const ENAMETOOLONG: u32 = 248;
    pub const ELOOP: u32 = 249;
    pub const ENOSYS: u32 = 251;
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

/// `open`/`openat` の O_*。hppa は独自のビット位置に置く（TRUNC
/// だけ arch 側の定義がなく asm-generic/fcntl.h の値）。
// Ref: SRC-LINUX (7.3) — arch/parisc/include/uapi/asm/fcntl.h.
pub mod oflag {
    pub const CREAT: u64 = 0o400; // 1 << 8
    pub const EXCL: u64 = 0o2000; // 1 << 10
    pub const TRUNC: u64 = 0o1000; // 1 << 9（asm-generic）
    pub const APPEND: u64 = 0o10; // 1 << 3
    pub const NONBLOCK: u64 = 0o200000; // 1 << 16
    pub const DIRECTORY: u64 = 0o10000; // 1 << 12
    pub const NOFOLLOW: u64 = 0o200; // 1 << 7
    pub const CLOEXEC: u64 = 0o1000_0000; // 1 << 21
}

// ---- 番号（syscall.tbl。実装で使う分を名前付き定数に）----
pub mod nr {
    pub const EXIT: u64 = 1;
    pub const READ: u64 = 3;
    pub const WRITE: u64 = 4;
    pub const OPEN: u64 = 5;
    pub const CLOSE: u64 = 6;
    pub const LSEEK: u64 = 19;
    pub const GETPID: u64 = 20;
    pub const GETUID: u64 = 24;
    pub const FSTAT: u64 = 28;
    pub const ACCESS: u64 = 33;
    pub const BRK: u64 = 45;
    pub const GETGID: u64 = 47;
    pub const GETEUID: u64 = 49;
    pub const GETEGID: u64 = 50;
    pub const IOCTL: u64 = 54;
    pub const UNAME: u64 = 59;
    pub const UMASK: u64 = 60;
    pub const DUP2: u64 = 63;
    pub const GETPPID: u64 = 64;
    pub const SIGPENDING: u64 = 73;
    pub const GETTIMEOFDAY: u64 = 78;
    pub const GETGROUPS: u64 = 80;
    pub const READLINK: u64 = 85;
    pub const MMAP2: u64 = 89;
    pub const MMAP: u64 = 90;
    pub const MUNMAP: u64 = 91;
    pub const MPROTECT: u64 = 125;
    pub const SIGPROCMASK: u64 = 126;
    pub const GETCWD: u64 = 110;
    pub const FSTAT64: u64 = 112;
    pub const SYSINFO: u64 = 116;
    pub const _LLSEEK: u64 = 140;
    pub const _NEWSELECT: u64 = 142;
    pub const READV: u64 = 145;
    pub const WRITEV: u64 = 146;
    pub const NANOSLEEP: u64 = 162;
    pub const SIGALTSTACK: u64 = 166;
    pub const RT_SIGACTION: u64 = 174;
    pub const RT_SIGPROCMASK: u64 = 175;
    pub const RT_SIGPENDING: u64 = 176;
    pub const RT_SIGSUSPEND: u64 = 179;
    pub const GETDENTS64: u64 = 201;
    pub const FCNTL64: u64 = 202;
    pub const GETTID: u64 = 206;
    pub const EXIT_GROUP: u64 = 222;
    pub const SET_TID_ADDRESS: u64 = 237;
    pub const CLOCK_GETTIME: u64 = 256;
    pub const CLOCK_GETRES: u64 = 257;
    pub const OPENAT: u64 = 275;
    pub const FSTATAT64: u64 = 280;
    pub const READLINKAT: u64 = 285;
    pub const FACCESSAT: u64 = 287;
    pub const SET_ROBUST_LIST: u64 = 289;
    pub const GETRANDOM: u64 = 339;
    pub const STATX: u64 = 349;
    pub const RSEQ: u64 = 354;
    pub const CLOCK_GETTIME64: u64 = 403;
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
