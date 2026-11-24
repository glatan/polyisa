// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ARM（AArch32・EABI）の Linux ゲスト ABI 共通部。
//!
//! EABI の規約：syscall 番号は r7、引数は r0–r5（7 個目以降はスタック）、
//! 戻り値は r0、失敗は r0 = -errno。errno・`O_*`/`MAP_*` の値は
//! asm-generic と同じなので、ホストの errno をそのまま使う。
//! 番号表はカーネルの `arch/arm/tools/syscall.tbl` 由来の事実であり、
//! `heavy_abi_arm` で UAPI ヘッダと突き合わせる。
// Ref: SRC-LINUX (7.3).

/// ARM の Linux syscall 処理。`guest-arm` 機能で有効になる。
/// 設計の依存規則（`docs/design/workspace.md` の「依存規則」）が
/// `os-linux` の `guests/*` 依存を機能フラグ付きで認めている。
#[cfg(feature = "guest-arm")]
pub mod sys;

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
    pub const ENOMSG: u32 = 42;
    pub const EIDRM: u32 = 43;
    pub const EDEADLK: u32 = 35;
    pub const ENOLCK: u32 = 37;
    pub const ENOSYS: u32 = 38;
    pub const ENOTEMPTY: u32 = 39;
    pub const ELOOP: u32 = 40;
    pub const ENOSTR: u32 = 60;
    pub const ENODATA: u32 = 61;
    pub const ETIME: u32 = 62;
    pub const ENOSR: u32 = 63;
    pub const ENOLINK: u32 = 67;
    pub const EPROTO: u32 = 71;
    pub const EMULTIHOP: u32 = 72;
    pub const EBADMSG: u32 = 74;
    pub const EOVERFLOW: u32 = 75;
    pub const ENOTSOCK: u32 = 88;
    pub const EDESTADDRREQ: u32 = 89;
    pub const EMSGSIZE: u32 = 90;
    pub const EPROTOTYPE: u32 = 91;
    pub const ENOPROTOOPT: u32 = 92;
    pub const EPROTONOSUPPORT: u32 = 93;
    pub const EOPNOTSUPP: u32 = 95;
    pub const EAFNOSUPPORT: u32 = 97;
    pub const EADDRINUSE: u32 = 98;
    pub const EADDRNOTAVAIL: u32 = 99;
    pub const ENETDOWN: u32 = 100;
    pub const ECONNABORTED: u32 = 103;
    pub const ECONNRESET: u32 = 104;
    pub const ENOBUFS: u32 = 105;
    pub const EISCONN: u32 = 106;
    pub const ENOTCONN: u32 = 107;
    pub const ETIMEDOUT: u32 = 110;
    pub const ECONNREFUSED: u32 = 111;
    pub const EINPROGRESS: u32 = 115;
    pub const EILSEQ: u32 = 84;
    pub const EUSERS: u32 = 87;
    pub const ESTALE: u32 = 116;
    pub const ENOTSUP: u32 = 95;
    pub const ENAMETOOLONG: u32 = 36;
    pub const ERESTART: u32 = 85;
    pub const ENOTBLK: u32 = 15;
    pub const EPFNOSUPPORT: u32 = 96;
    pub const EDQUOT: u32 = 122;
}

/// `O_*` 等のフラグ。asm-generic の値（ARM は独自値を持たない）。
pub mod oflag {
    pub const ACCMODE: u32 = 0x3;
    pub const CREAT: u32 = 0x40;
    pub const EXCL: u32 = 0x80;
    pub const NOCTTY: u32 = 0x100;
    pub const TRUNC: u32 = 0x200;
    pub const APPEND: u32 = 0x400;
    pub const NONBLOCK: u32 = 0x800;
    pub const DSYNC: u32 = 0x1000;
    pub const DIRECT: u32 = 0x4000;
    pub const LARGEFILE: u32 = 0x8000;
    pub const DIRECTORY: u32 = 0x1_0000;
    pub const NOFOLLOW: u32 = 0x2_0000;
    pub const NOATIME: u32 = 0x4_0000;
    pub const CLOEXEC: u32 = 0x8_0000;
    pub const SYNC: u32 = 0x10_1000;
}

/// `MAP_*`（asm-generic）。
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

/// システムコール番号。`arch/arm/tools/syscall.tbl` の common/arm 行。
// Ref: SRC-LINUX (7.3).
pub const RESTART_SYSCALL: u64 = 0;
pub const EXIT: u64 = 1;
pub const FORK: u64 = 2;
pub const READ: u64 = 3;
pub const WRITE: u64 = 4;
pub const OPEN: u64 = 5;
pub const CLOSE: u64 = 6;
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
pub const PTRACE: u64 = 26;
pub const PAUSE: u64 = 29;
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
pub const SETREUID: u64 = 70;
pub const SETREGID: u64 = 71;
pub const SIGSUSPEND: u64 = 72;
pub const SIGPENDING: u64 = 73;
pub const SETHOSTNAME: u64 = 74;
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
pub const MUNMAP: u64 = 91;
pub const TRUNCATE: u64 = 92;
pub const FTRUNCATE: u64 = 93;
pub const FCHMOD: u64 = 94;
pub const FCHOWN: u64 = 95;
pub const GETPRIORITY: u64 = 96;
pub const SETPRIORITY: u64 = 97;
pub const STATFS: u64 = 99;
pub const FSTATFS: u64 = 100;
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
pub const CLONE: u64 = 120;
pub const SETDOMAINNAME: u64 = 121;
pub const UNAME: u64 = 122;
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
pub const LLSEEK: u64 = 140;
pub const GETDENTS: u64 = 141;
pub const SELECT: u64 = 82;
pub const NEWSELECT: u64 = 142;
pub const FLOCK: u64 = 143;
pub const MSYNC: u64 = 144;
pub const READV: u64 = 145;
pub const WRITEV: u64 = 146;
pub const GETSID: u64 = 147;
pub const FDATASYNC: u64 = 148;
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
pub const GETDENTS64: u64 = 217;
pub const PIVOT_ROOT: u64 = 218;
pub const MINCORE: u64 = 219;
pub const MADVISE: u64 = 220;
pub const FCNTL64: u64 = 221;
pub const GETTID: u64 = 224;
pub const READAHEAD: u64 = 225;
pub const SETXATTR: u64 = 226;
pub const LSETXATTR: u64 = 227;
pub const FSETXATTR: u64 = 228;
pub const GETXATTR: u64 = 229;
pub const LGETXATTR: u64 = 230;
pub const FGETXATTR: u64 = 231;
pub const LISTXATTR: u64 = 232;
pub const LLISTXATTR: u64 = 233;
pub const FLISTXATTR: u64 = 234;
pub const REMOVEXATTR: u64 = 235;
pub const LREMOVEXATTR: u64 = 236;
pub const FREMOVEXATTR: u64 = 237;
pub const TKILL: u64 = 238;
pub const SENDFILE64: u64 = 239;
pub const FUTEX: u64 = 240;
pub const SCHED_SETAFFINITY: u64 = 241;
pub const SCHED_GETAFFINITY: u64 = 242;
pub const IO_SETUP: u64 = 243;
pub const IO_DESTROY: u64 = 244;
pub const IO_GETEVENTS: u64 = 245;
pub const IO_SUBMIT: u64 = 246;
pub const IO_CANCEL: u64 = 247;
pub const EXIT_GROUP: u64 = 248;
pub const LOOKUP_DCOOKIE: u64 = 249;
pub const EPOLL_CREATE: u64 = 250;
pub const EPOLL_CTL: u64 = 251;
pub const EPOLL_WAIT: u64 = 252;
pub const REMAP_FILE_PAGES: u64 = 253;
pub const SET_TID_ADDRESS: u64 = 256;
pub const TIMER_CREATE: u64 = 257;
pub const TIMER_SETTIME: u64 = 258;
pub const TIMER_GETTIME: u64 = 259;
pub const TIMER_GETOVERRUN: u64 = 260;
pub const TIMER_DELETE: u64 = 261;
pub const CLOCK_SETTIME: u64 = 262;
pub const CLOCK_GETTIME: u64 = 263;
pub const CLOCK_GETRES: u64 = 264;
pub const CLOCK_NANOSLEEP: u64 = 265;
pub const STATFS64: u64 = 266;
pub const FSTATFS64: u64 = 267;
pub const TGKILL: u64 = 268;
pub const UTIMES: u64 = 269;
pub const FADVISE64: u64 = 270;
pub const PCICONFIG_IOBASE: u64 = 271;
pub const PCICONFIG_READ: u64 = 272;
pub const PCICONFIG_WRITE: u64 = 273;
pub const MQ_OPEN: u64 = 274;
pub const MQ_UNLINK: u64 = 275;
pub const MQ_TIMEDSEND: u64 = 276;
pub const MQ_TIMEDRECEIVE: u64 = 277;
pub const MQ_NOTIFY: u64 = 278;
pub const MQ_GETSETATTR: u64 = 279;
pub const WAITID: u64 = 280;
pub const SOCKET: u64 = 281;
pub const BIND: u64 = 282;
pub const CONNECT: u64 = 283;
pub const LISTEN: u64 = 284;
pub const ACCEPT: u64 = 285;
pub const GETSOCKNAME: u64 = 286;
pub const GETPEERNAME: u64 = 287;
pub const SOCKETPAIR: u64 = 288;
pub const SEND: u64 = 289;
pub const SENDTO: u64 = 290;
pub const RECV: u64 = 291;
pub const RECVFROM: u64 = 292;
pub const SHUTDOWN: u64 = 293;
pub const SETSOCKOPT: u64 = 294;
pub const GETSOCKOPT: u64 = 295;
pub const SENDMSG: u64 = 296;
pub const RECVMSG: u64 = 297;
pub const SEMOP: u64 = 298;
pub const SEMGET: u64 = 299;
pub const SEMCTL: u64 = 300;
pub const MSGSND: u64 = 301;
pub const MSGRCV: u64 = 302;
pub const MSGGET: u64 = 303;
pub const MSGCTL: u64 = 304;
pub const SHMAT: u64 = 305;
pub const SHMDT: u64 = 306;
pub const SHMGET: u64 = 307;
pub const SHMCTL: u64 = 308;
pub const ADD_KEY: u64 = 309;
pub const REQUEST_KEY: u64 = 310;
pub const KEYCTL: u64 = 311;
pub const SEMTIMEDOP: u64 = 312;
pub const IOPRIO_SET: u64 = 314;
pub const IOPRIO_GET: u64 = 315;
pub const INOTIFY_INIT: u64 = 316;
pub const INOTIFY_ADD_WATCH: u64 = 317;
pub const INOTIFY_RM_WATCH: u64 = 318;
pub const MBIND: u64 = 319;
pub const GET_MEMPOLICY: u64 = 320;
pub const SET_MEMPOLICY: u64 = 321;
pub const OPENAT: u64 = 322;
pub const MKDIRAT: u64 = 323;
pub const MKNODAT: u64 = 324;
pub const FCHOWNAT: u64 = 325;
pub const FUTIMESAT: u64 = 326;
pub const FSTATAT64: u64 = 327;
pub const UNLINKAT: u64 = 328;
pub const RENAMEAT: u64 = 329;
pub const LINKAT: u64 = 330;
pub const SYMLINKAT: u64 = 331;
pub const READLINKAT: u64 = 332;
pub const FCHMODAT: u64 = 333;
pub const FACCESSAT: u64 = 334;
pub const PSELECT6: u64 = 335;
pub const PPOLL: u64 = 336;
pub const UNSHARE: u64 = 337;
pub const SET_ROBUST_LIST: u64 = 338;
pub const GET_ROBUST_LIST: u64 = 339;
pub const SPLICE: u64 = 340;
pub const SYNC_FILE_RANGE2: u64 = 341;
pub const TEE: u64 = 342;
pub const VMSPLICE: u64 = 343;
pub const MOVE_PAGES: u64 = 344;
pub const GETCPU: u64 = 345;
pub const EPOLL_PWAIT: u64 = 346;
pub const KEXEC_LOAD: u64 = 347;
pub const UTIMENSAT: u64 = 348;
pub const SIGNALFD: u64 = 349;
pub const TIMERFD_CREATE: u64 = 350;
pub const EVENTFD: u64 = 351;
pub const FALLOCATE: u64 = 352;
pub const TIMERFD_SETTIME: u64 = 353;
pub const TIMERFD_GETTIME: u64 = 354;
pub const SIGNALFD4: u64 = 355;
pub const EVENTFD2: u64 = 356;
pub const EPOLL_CREATE1: u64 = 357;
pub const DUP3: u64 = 358;
pub const PIPE2: u64 = 359;
pub const INOTIFY_INIT1: u64 = 360;
pub const PREADV: u64 = 361;
pub const PWRITEV: u64 = 362;
pub const RT_TGSIGQUEUEINFO: u64 = 363;
pub const PERF_EVENT_OPEN: u64 = 364;
pub const RECVMMSG: u64 = 365;
pub const ACCEPT4: u64 = 366;
pub const FANOTIFY_INIT: u64 = 367;
pub const FANOTIFY_MARK: u64 = 368;
pub const PRLIMIT64: u64 = 369;
pub const NAME_TO_HANDLE_AT: u64 = 370;
pub const OPEN_BY_HANDLE_AT: u64 = 371;
pub const CLOCK_ADJTIME: u64 = 372;
pub const SYNCFS: u64 = 373;
pub const SENDMMSG: u64 = 374;
pub const SETNS: u64 = 375;
pub const PROCESS_VM_READV: u64 = 376;
pub const PROCESS_VM_WRITEV: u64 = 377;
pub const KCMP: u64 = 378;
pub const FINIT_MODULE: u64 = 379;
pub const SCHED_SETATTR: u64 = 380;
pub const SCHED_GETATTR: u64 = 381;
pub const RENAMEAT2: u64 = 382;
pub const SECCOMP: u64 = 383;
pub const GETRANDOM: u64 = 384;
pub const MEMFD_CREATE: u64 = 385;
pub const BPF: u64 = 386;
pub const EXECVEAT: u64 = 387;
pub const USERFAULTFD: u64 = 388;
pub const MEMBARRIER: u64 = 389;
pub const MLOCK2: u64 = 390;
pub const COPY_FILE_RANGE: u64 = 391;
pub const PREADV2: u64 = 392;
pub const PWRITEV2: u64 = 393;
pub const PKEY_MPROTECT: u64 = 394;
pub const PKEY_ALLOC: u64 = 395;
pub const PKEY_FREE: u64 = 396;
pub const STATX: u64 = 397;
pub const RSEQ: u64 = 398;
pub const IO_PGETEVENTS: u64 = 399;
pub const MIGRATE_PAGES: u64 = 400;
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
pub const OPEN_TREE: u64 = 428;
pub const MOVE_MOUNT: u64 = 429;
pub const FSOPEN: u64 = 430;
pub const PIDFD_OPEN: u64 = 434;
pub const CLONE3: u64 = 435;
pub const CLOSE_RANGE: u64 = 436;
pub const OPENAT2: u64 = 437;
pub const PIDFD_GETFD: u64 = 438;
pub const FACCESSAT2: u64 = 439;
pub const PROCESS_MADVISE: u64 = 440;
pub const EPOLL_PWAIT2: u64 = 441;
pub const MOUNT_SETATTR: u64 = 442;
pub const FUTEX_WAITV: u64 = 449;

/// ARM 固有（__ARM_NR_*）。0xf0000 帯のプライベート番号。
pub const ARM_NR_BASE: u64 = 0xf0000;
pub const ARM_NR_BREAKPOINT: u64 = 0xf0001;
pub const ARM_NR_CACHEFLUSH: u64 = 0xf0002;
pub const ARM_NR_USR26: u64 = 0xf0003;
pub const ARM_NR_USR32: u64 = 0xf0004;
pub const ARM_NR_SET_TLS: u64 = 0xf0005;
pub const ARM_NR_GET_TLS: u64 = 0xf0006;
/// `__ARM_NR_BASE + 0xfff0`。UAPI ヘッダには現れず、
/// カーネルの `arch/arm/include/asm/unistd.h` が定める。
pub const ARM_NR_CMPXCHG: u64 = 0xffff0;

/// 番号から名前を引く。表は番号順なので二分探索する。
#[must_use]
pub fn name(nr: u64) -> Option<&'static str> {
    SYSCALLS
        .binary_search_by_key(&nr, |(n, _)| *n)
        .ok()
        .map(|i| SYSCALLS[i].1)
}

/// `task status` の `syscalls.md` はこの表から生成する。
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
    (19, "lseek"),
    (20, "getpid"),
    (21, "mount"),
    (22, "umount"),
    (23, "setuid"),
    (24, "getuid"),
    (26, "ptrace"),
    (29, "pause"),
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
    (62, "ustat"),
    (63, "dup2"),
    (64, "getppid"),
    (65, "getpgrp"),
    (66, "setsid"),
    (67, "sigaction"),
    (70, "setreuid"),
    (71, "setregid"),
    (72, "sigsuspend"),
    (73, "sigpending"),
    (74, "sethostname"),
    (75, "setrlimit"),
    (77, "getrusage"),
    (78, "gettimeofday"),
    (79, "settimeofday"),
    (80, "getgroups"),
    (81, "setgroups"),
    (83, "symlink"),
    (85, "readlink"),
    (86, "uselib"),
    (87, "swapon"),
    (88, "reboot"),
    (91, "munmap"),
    (92, "truncate"),
    (93, "ftruncate"),
    (94, "fchmod"),
    (95, "fchown"),
    (96, "getpriority"),
    (97, "setpriority"),
    (99, "statfs"),
    (100, "fstatfs"),
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
    (120, "clone"),
    (121, "setdomainname"),
    (122, "uname"),
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
    (82, "select"),
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
    (191, "getrlimit"),
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
    (217, "getdents64"),
    (218, "pivot_root"),
    (219, "mincore"),
    (220, "madvise"),
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
    (243, "io_setup"),
    (244, "io_destroy"),
    (245, "io_getevents"),
    (246, "io_submit"),
    (247, "io_cancel"),
    (248, "exit_group"),
    (249, "lookup_dcookie"),
    (250, "epoll_create"),
    (251, "epoll_ctl"),
    (252, "epoll_wait"),
    (253, "remap_file_pages"),
    (256, "set_tid_address"),
    (257, "timer_create"),
    (258, "timer_settime"),
    (259, "timer_gettime"),
    (260, "timer_getoverrun"),
    (261, "timer_delete"),
    (262, "clock_settime"),
    (263, "clock_gettime"),
    (264, "clock_getres"),
    (265, "clock_nanosleep"),
    (266, "statfs64"),
    (267, "fstatfs64"),
    (268, "tgkill"),
    (269, "utimes"),
    (270, "fadvise64"),
    (271, "pciconfig_iobase"),
    (272, "pciconfig_read"),
    (273, "pciconfig_write"),
    (274, "mq_open"),
    (275, "mq_unlink"),
    (276, "mq_timedsend"),
    (277, "mq_timedreceive"),
    (278, "mq_notify"),
    (279, "mq_getsetattr"),
    (280, "waitid"),
    (281, "socket"),
    (282, "bind"),
    (283, "connect"),
    (284, "listen"),
    (285, "accept"),
    (286, "getsockname"),
    (287, "getpeername"),
    (288, "socketpair"),
    (289, "send"),
    (290, "sendto"),
    (291, "recv"),
    (292, "recvfrom"),
    (293, "shutdown"),
    (294, "setsockopt"),
    (295, "getsockopt"),
    (296, "sendmsg"),
    (297, "recvmsg"),
    (298, "semop"),
    (299, "semget"),
    (300, "semctl"),
    (301, "msgsnd"),
    (302, "msgrcv"),
    (303, "msgget"),
    (304, "msgctl"),
    (305, "shmat"),
    (306, "shmdt"),
    (307, "shmget"),
    (308, "shmctl"),
    (309, "add_key"),
    (310, "request_key"),
    (311, "keyctl"),
    (312, "semtimedop"),
    (314, "ioprio_set"),
    (315, "ioprio_get"),
    (316, "inotify_init"),
    (317, "inotify_add_watch"),
    (318, "inotify_rm_watch"),
    (319, "mbind"),
    (320, "get_mempolicy"),
    (321, "set_mempolicy"),
    (322, "openat"),
    (323, "mkdirat"),
    (324, "mknodat"),
    (325, "fchownat"),
    (326, "futimesat"),
    (327, "fstatat64"),
    (328, "unlinkat"),
    (329, "renameat"),
    (330, "linkat"),
    (331, "symlinkat"),
    (332, "readlinkat"),
    (333, "fchmodat"),
    (334, "faccessat"),
    (335, "pselect6"),
    (336, "ppoll"),
    (337, "unshare"),
    (338, "set_robust_list"),
    (339, "get_robust_list"),
    (340, "splice"),
    (341, "sync_file_range2"),
    (342, "tee"),
    (343, "vmsplice"),
    (344, "move_pages"),
    (345, "getcpu"),
    (346, "epoll_pwait"),
    (347, "kexec_load"),
    (348, "utimensat"),
    (349, "signalfd"),
    (350, "timerfd_create"),
    (351, "eventfd"),
    (352, "fallocate"),
    (353, "timerfd_settime"),
    (354, "timerfd_gettime"),
    (355, "signalfd4"),
    (356, "eventfd2"),
    (357, "epoll_create1"),
    (358, "dup3"),
    (359, "pipe2"),
    (360, "inotify_init1"),
    (361, "preadv"),
    (362, "pwritev"),
    (363, "rt_tgsigqueueinfo"),
    (364, "perf_event_open"),
    (365, "recvmmsg"),
    (366, "accept4"),
    (367, "fanotify_init"),
    (368, "fanotify_mark"),
    (369, "prlimit64"),
    (370, "name_to_handle_at"),
    (371, "open_by_handle_at"),
    (372, "clock_adjtime"),
    (373, "syncfs"),
    (374, "sendmmsg"),
    (375, "setns"),
    (376, "process_vm_readv"),
    (377, "process_vm_writev"),
    (378, "kcmp"),
    (379, "finit_module"),
    (380, "sched_setattr"),
    (381, "sched_getattr"),
    (382, "renameat2"),
    (383, "seccomp"),
    (384, "getrandom"),
    (385, "memfd_create"),
    (386, "bpf"),
    (387, "execveat"),
    (388, "userfaultfd"),
    (389, "membarrier"),
    (390, "mlock2"),
    (391, "copy_file_range"),
    (392, "preadv2"),
    (393, "pwritev2"),
    (394, "pkey_mprotect"),
    (395, "pkey_alloc"),
    (396, "pkey_free"),
    (397, "statx"),
    (398, "rseq"),
    (399, "io_pgetevents"),
    (400, "migrate_pages"),
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
    (428, "open_tree"),
    (429, "move_mount"),
    (430, "fsopen"),
    (434, "pidfd_open"),
    (435, "clone3"),
    (436, "close_range"),
    (437, "openat2"),
    (438, "pidfd_getfd"),
    (439, "faccessat2"),
    (440, "process_madvise"),
    (441, "epoll_pwait2"),
    (442, "mount_setattr"),
    (449, "futex_waitv"),
    (0xf0001, "breakpoint"),
    (0xf0002, "cacheflush"),
    (0xf0003, "usr26"),
    (0xf0004, "usr32"),
    (0xf0005, "set_tls"),
    (0xf0006, "get_tls"),
    (0xffff0, "cmpxchg"),
];
