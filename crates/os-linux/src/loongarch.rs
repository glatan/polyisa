// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! LoongArch（LA64/LA32）の Linux ゲスト ABI 共通部。
//!
//! 規約：syscall 番号は $a7（$r11）、引数は $a0–$a5（$r4–$r9）、
//! 戻り値は $a0（$r4）、失敗は $a0 = -errno。発行点は
//! `syscall`（慣例の即値 0）。番号表は asm-generic
//! （include/uapi/asm-generic/unistd.h）そのまま。la64 は
//! `scripts/syscall.tbl` の abi ∈ {common, 64, memfd_secret} の
//! 行を使い、stat64・rlimit・32・time32・renameat の opt-in 行は
//! 持たない（nr 38 は未配線。実装は renameat も受理する近似）
//! （`arch/loongarch/kernel/Makefile.syscalls` が opt-in するのは
//! memfd_secret のみ）。
//! Ref: SRC-LINUX — arch/loongarch/kernel/entry.S,
//! include/uapi/asm-generic/unistd.h;
//! SRC-LINUX-LOONGARCH-UAPI — scripts/syscall.tbl,
//! arch/loongarch/kernel/Makefile.syscalls.

/// LoongArch の Linux syscall 処理。`guest-loongarch` 機能で有効になる。
#[cfg(feature = "guest-loongarch")]
pub mod sys;

/// syscall 番号定数（asm-generic）。処理系が引くものだけ置く。
/// Ref: SRC-LINUX — include/uapi/asm-generic/unistd.h.
pub mod nr {
    pub const GETCWD: u64 = 17;
    pub const DUP: u64 = 23;
    pub const DUP3: u64 = 24;
    pub const FCNTL: u64 = 25;
    pub const IOCTL: u64 = 29;
    pub const FLOCK: u64 = 32;
    pub const MKNODAT: u64 = 33;
    pub const MKDIRAT: u64 = 34;
    pub const UNLINKAT: u64 = 35;
    pub const SYMLINKAT: u64 = 36;
    pub const LINKAT: u64 = 37;
    pub const RENAMEAT: u64 = 38;
    pub const STATFS: u64 = 43;
    pub const FSTATFS: u64 = 44;
    pub const TRUNCATE: u64 = 45;
    pub const FTRUNCATE: u64 = 46;
    pub const FACCESSAT: u64 = 48;
    pub const CHDIR: u64 = 49;
    pub const FCHDIR: u64 = 50;
    pub const FCHMOD: u64 = 52;
    pub const FCHMODAT: u64 = 53;
    pub const FCHOWNAT: u64 = 54;
    pub const FCHOWN: u64 = 55;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const PIPE2: u64 = 59;
    pub const GETDENTS64: u64 = 61;
    pub const LSEEK: u64 = 62;
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const READV: u64 = 65;
    pub const WRITEV: u64 = 66;
    pub const PREAD64: u64 = 67;
    pub const PWRITE64: u64 = 68;
    pub const SENDFILE: u64 = 71;
    pub const PSELECT6: u64 = 72;
    pub const PPOLL: u64 = 73;
    pub const READLINKAT: u64 = 78;
    pub const NEWFSTATAT: u64 = 79;
    pub const FSTAT: u64 = 80;
    pub const SYNC: u64 = 81;
    pub const FSYNC: u64 = 82;
    pub const FDATASYNC: u64 = 83;
    pub const UTIMENSAT: u64 = 88;
    pub const EXIT: u64 = 93;
    pub const EXIT_GROUP: u64 = 94;
    pub const WAITID: u64 = 95;
    pub const SET_TID_ADDRESS: u64 = 96;
    pub const FUTEX: u64 = 98;
    pub const SET_ROBUST_LIST: u64 = 99;
    pub const NANOSLEEP: u64 = 101;
    pub const CLOCK_GETTIME: u64 = 113;
    pub const CLOCK_GETRES: u64 = 114;
    pub const CLOCK_NANOSLEEP: u64 = 115;
    pub const SCHED_GETAFFINITY: u64 = 123;
    pub const SCHED_YIELD: u64 = 124;
    pub const KILL: u64 = 129;
    pub const SIGALTSTACK: u64 = 132;
    pub const RT_SIGACTION: u64 = 134;
    pub const RT_SIGPROCMASK: u64 = 135;
    pub const RT_SIGRETURN: u64 = 139;
    pub const SETPRIORITY: u64 = 140;
    pub const GETPRIORITY: u64 = 141;
    pub const TIMES: u64 = 153;
    pub const UTSNAME: u64 = 160;
    pub const GETRUSAGE: u64 = 165;
    pub const UMASK: u64 = 166;
    pub const PRCTL: u64 = 167;
    pub const GETCPU: u64 = 168;
    pub const GETTIMEOFDAY: u64 = 169;
    pub const GETPID: u64 = 172;
    pub const GETPPID: u64 = 173;
    pub const GETUID: u64 = 174;
    pub const GETEUID: u64 = 175;
    pub const GETGID: u64 = 176;
    pub const GETEGID: u64 = 177;
    pub const GETTID: u64 = 178;
    pub const SYSINFO: u64 = 179;
    pub const MSYNC: u64 = 227;
    pub const MINCORE: u64 = 232;
    pub const MADVISE: u64 = 233;
    pub const BRK: u64 = 214;
    pub const MUNMAP: u64 = 215;
    pub const MREMAP: u64 = 216;
    pub const CLONE: u64 = 220;
    pub const EXECVE: u64 = 221;
    pub const MMAP: u64 = 222;
    pub const MPROTECT: u64 = 226;
    pub const WAIT4: u64 = 260;
    pub const PRLIMIT64: u64 = 261;
    pub const RENAMEAT2: u64 = 276;
    pub const GETRANDOM: u64 = 278;
    pub const EXECVEAT: u64 = 281;
    pub const STATX: u64 = 291;
    pub const RSEQ: u64 = 293;
}

/// syscall 番号から名前を引く（診断用）。
#[must_use]
pub fn name(nr: u64) -> Option<&'static str> {
    SYSCALLS
        .binary_search_by_key(&nr, |(n, _)| *n)
        .ok()
        .map(|i| SYSCALLS[i].1)
}

/// `name` の引き表。la64 の UAPI 全集（`scripts/syscall.tbl` の
/// abi ∈ {common, 64, memfd_secret} の 325 行。
/// SRC-LINUX-LOONGARCH-UAPI）。
/// Ref: SRC-LINUX-LOONGARCH-UAPI — scripts/syscall.tbl.
pub const SYSCALLS: &[(u64, &str)] = &[
    (0, "io_setup"),
    (1, "io_destroy"),
    (2, "io_submit"),
    (3, "io_cancel"),
    (4, "io_getevents"),
    (5, "setxattr"),
    (6, "lsetxattr"),
    (7, "fsetxattr"),
    (8, "getxattr"),
    (9, "lgetxattr"),
    (10, "fgetxattr"),
    (11, "listxattr"),
    (12, "llistxattr"),
    (13, "flistxattr"),
    (14, "removexattr"),
    (15, "lremovexattr"),
    (16, "fremovexattr"),
    (17, "getcwd"),
    (18, "lookup_dcookie"),
    (19, "eventfd2"),
    (20, "epoll_create1"),
    (21, "epoll_ctl"),
    (22, "epoll_pwait"),
    (23, "dup"),
    (24, "dup3"),
    (25, "fcntl"),
    (26, "inotify_init1"),
    (27, "inotify_add_watch"),
    (28, "inotify_rm_watch"),
    (29, "ioctl"),
    (30, "ioprio_set"),
    (31, "ioprio_get"),
    (32, "flock"),
    (33, "mknodat"),
    (34, "mkdirat"),
    (35, "unlinkat"),
    (36, "symlinkat"),
    (37, "linkat"),
    (39, "umount2"),
    (40, "mount"),
    (41, "pivot_root"),
    (42, "nfsservctl"),
    (43, "statfs"),
    (44, "fstatfs"),
    (45, "truncate"),
    (46, "ftruncate"),
    (47, "fallocate"),
    (48, "faccessat"),
    (49, "chdir"),
    (50, "fchdir"),
    (51, "chroot"),
    (52, "fchmod"),
    (53, "fchmodat"),
    (54, "fchownat"),
    (55, "fchown"),
    (56, "openat"),
    (57, "close"),
    (58, "vhangup"),
    (59, "pipe2"),
    (60, "quotactl"),
    (61, "getdents64"),
    (62, "lseek"),
    (63, "read"),
    (64, "write"),
    (65, "readv"),
    (66, "writev"),
    (67, "pread64"),
    (68, "pwrite64"),
    (69, "preadv"),
    (70, "pwritev"),
    (71, "sendfile"),
    (72, "pselect6"),
    (73, "ppoll"),
    (74, "signalfd4"),
    (75, "vmsplice"),
    (76, "splice"),
    (77, "tee"),
    (78, "readlinkat"),
    (79, "newfstatat"),
    (80, "fstat"),
    (81, "sync"),
    (82, "fsync"),
    (83, "fdatasync"),
    (84, "sync_file_range"),
    (85, "timerfd_create"),
    (86, "timerfd_settime"),
    (87, "timerfd_gettime"),
    (88, "utimensat"),
    (89, "acct"),
    (90, "capget"),
    (91, "capset"),
    (92, "personality"),
    (93, "exit"),
    (94, "exit_group"),
    (95, "waitid"),
    (96, "set_tid_address"),
    (97, "unshare"),
    (98, "futex"),
    (99, "set_robust_list"),
    (100, "get_robust_list"),
    (101, "nanosleep"),
    (102, "getitimer"),
    (103, "setitimer"),
    (104, "kexec_load"),
    (105, "init_module"),
    (106, "delete_module"),
    (107, "timer_create"),
    (108, "timer_gettime"),
    (109, "timer_getoverrun"),
    (110, "timer_settime"),
    (111, "timer_delete"),
    (112, "clock_settime"),
    (113, "clock_gettime"),
    (114, "clock_getres"),
    (115, "clock_nanosleep"),
    (116, "syslog"),
    (117, "ptrace"),
    (118, "sched_setparam"),
    (119, "sched_setscheduler"),
    (120, "sched_getscheduler"),
    (121, "sched_getparam"),
    (122, "sched_setaffinity"),
    (123, "sched_getaffinity"),
    (124, "sched_yield"),
    (125, "sched_get_priority_max"),
    (126, "sched_get_priority_min"),
    (127, "sched_rr_get_interval"),
    (128, "restart_syscall"),
    (129, "kill"),
    (130, "tkill"),
    (131, "tgkill"),
    (132, "sigaltstack"),
    (133, "rt_sigsuspend"),
    (134, "rt_sigaction"),
    (135, "rt_sigprocmask"),
    (136, "rt_sigpending"),
    (137, "rt_sigtimedwait"),
    (138, "rt_sigqueueinfo"),
    (139, "rt_sigreturn"),
    (140, "setpriority"),
    (141, "getpriority"),
    (142, "reboot"),
    (143, "setregid"),
    (144, "setgid"),
    (145, "setreuid"),
    (146, "setuid"),
    (147, "setresuid"),
    (148, "getresuid"),
    (149, "setresgid"),
    (150, "getresgid"),
    (151, "setfsuid"),
    (152, "setfsgid"),
    (153, "times"),
    (154, "setpgid"),
    (155, "getpgid"),
    (156, "getsid"),
    (157, "setsid"),
    (158, "getgroups"),
    (159, "setgroups"),
    (160, "uname"),
    (161, "sethostname"),
    (162, "setdomainname"),
    (165, "getrusage"),
    (166, "umask"),
    (167, "prctl"),
    (168, "getcpu"),
    (169, "gettimeofday"),
    (170, "settimeofday"),
    (171, "adjtimex"),
    (172, "getpid"),
    (173, "getppid"),
    (174, "getuid"),
    (175, "geteuid"),
    (176, "getgid"),
    (177, "getegid"),
    (178, "gettid"),
    (179, "sysinfo"),
    (180, "mq_open"),
    (181, "mq_unlink"),
    (182, "mq_timedsend"),
    (183, "mq_timedreceive"),
    (184, "mq_notify"),
    (185, "mq_getsetattr"),
    (186, "msgget"),
    (187, "msgctl"),
    (188, "msgrcv"),
    (189, "msgsnd"),
    (190, "semget"),
    (191, "semctl"),
    (192, "semtimedop"),
    (193, "semop"),
    (194, "shmget"),
    (195, "shmctl"),
    (196, "shmat"),
    (197, "shmdt"),
    (198, "socket"),
    (199, "socketpair"),
    (200, "bind"),
    (201, "listen"),
    (202, "accept"),
    (203, "connect"),
    (204, "getsockname"),
    (205, "getpeername"),
    (206, "sendto"),
    (207, "recvfrom"),
    (208, "setsockopt"),
    (209, "getsockopt"),
    (210, "shutdown"),
    (211, "sendmsg"),
    (212, "recvmsg"),
    (213, "readahead"),
    (214, "brk"),
    (215, "munmap"),
    (216, "mremap"),
    (217, "add_key"),
    (218, "request_key"),
    (219, "keyctl"),
    (220, "clone"),
    (221, "execve"),
    (222, "mmap"),
    (223, "fadvise64"),
    (224, "swapon"),
    (225, "swapoff"),
    (226, "mprotect"),
    (227, "msync"),
    (228, "mlock"),
    (229, "munlock"),
    (230, "mlockall"),
    (231, "munlockall"),
    (232, "mincore"),
    (233, "madvise"),
    (234, "remap_file_pages"),
    (235, "mbind"),
    (236, "get_mempolicy"),
    (237, "set_mempolicy"),
    (238, "migrate_pages"),
    (239, "move_pages"),
    (240, "rt_tgsigqueueinfo"),
    (241, "perf_event_open"),
    (242, "accept4"),
    (243, "recvmmsg"),
    (260, "wait4"),
    (261, "prlimit64"),
    (262, "fanotify_init"),
    (263, "fanotify_mark"),
    (264, "name_to_handle_at"),
    (265, "open_by_handle_at"),
    (266, "clock_adjtime"),
    (267, "syncfs"),
    (268, "setns"),
    (269, "sendmmsg"),
    (270, "process_vm_readv"),
    (271, "process_vm_writev"),
    (272, "kcmp"),
    (273, "finit_module"),
    (274, "sched_setattr"),
    (275, "sched_getattr"),
    (276, "renameat2"),
    (277, "seccomp"),
    (278, "getrandom"),
    (279, "memfd_create"),
    (280, "bpf"),
    (281, "execveat"),
    (282, "userfaultfd"),
    (283, "membarrier"),
    (284, "mlock2"),
    (285, "copy_file_range"),
    (286, "preadv2"),
    (287, "pwritev2"),
    (288, "pkey_mprotect"),
    (289, "pkey_alloc"),
    (290, "pkey_free"),
    (291, "statx"),
    (292, "io_pgetevents"),
    (293, "rseq"),
    (294, "kexec_file_load"),
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
    (447, "memfd_secret"),
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
