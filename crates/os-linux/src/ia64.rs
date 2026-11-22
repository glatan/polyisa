// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64（Itanium）Linux のシステムコール ABI 定数。
//!
//! 規約（正本 entry.S・gate.S）: 発行点は `break 0x100000`
//! （__IA64_BREAK_SYSCALL）かゲートページの入口呼出。r15 = 番号
//! （実番号 = syscall.tbl の番号 + 1024）、引数は呼出側フレームの
//! 出力 out0–out5（現在 CFM の out 域で r32+sol 起点に対応する
//! 物理位置）、戻り値は r8 とエラー旗 r10（成功 0、失敗 −1 で
//! r8=errno）。戻り先は break の次の命令位置。
//! ゲートページは RGN 5 の先頭（GATE_ADDR）から始まり、コード
//! ページは GATE_ADDR+PERCPU_PAGE_SIZE。auxv は AT_SYSINFO(32) が
//! __kernel_syscall_via_epc 入口、AT_SYSINFO_EHDR(33) が
//! GATE_ADDR を指す。
//! Ref: SRC-LINUX-66 — uapi-asm/{break,auxvec}.h,
//! kernel-asm/{page,elf}.h, kernel/{entry,gate}.S, mm-init.c.

/// syscall 番号の基底。実番号 = tbl 番号 + BASE（`__NR_Linux`）。
// Ref: SRC-LINUX-66 — uapi-asm/unistd.h.
pub const NR_BASE: u64 = 1024;

/// v6.6 の syscall.tbl の表番号の上限 + 1（0–452、435・447 は
/// ia64 では予約）。範囲検査に使う。
// Ref: SRC-LINUX-66 — syscall.tbl.
pub const NR_SYSCALLS: u64 = 453;

/// auxv の種別（`uapi/asm/auxvec.h`）。
// Ref: SRC-LINUX-66 — uapi-asm/auxvec.h, kernel-asm/elf.h.
pub mod at {
    /// `AT_SYSINFO`（32）。値は __kernel_syscall_via_epc の入口
    /// 番地（`gate::SYSCALL_VIA_EPC`）。
    pub const SYSINFO: u64 = 32;
    /// `AT_SYSINFO_EHDR`（33）。値はゲート領域の ELF ヘッダ番地
    /// （`gate::ADDR`）。
    pub const SYSINFO_EHDR: u64 = 33;
}

/// `break` の即値（`uapi/asm/break.h` の __IA64_BREAK_*）。
/// __IA64_BREAK_KDB（0x80100）・__IA64_BREAK_KPROBE
/// （0x81000–0x81fff）はカーネル内のデバッグ経路で、ユーザ
/// モードからは到達しない（パーソナリティは未実装に畳む）。
// Ref: SRC-LINUX-66 — uapi-asm/break.h.
pub mod brk {
    /// __IA64_BREAK_SYSCALL。Linux syscall の発行点。
    pub const SYSCALL: u32 = 0x10_0000;
}

/// ゲート領域の配置。領域先頭とコードページの位置は正本の
/// 事実（page.h/mm-init.c）、コードページ内の入口配置は
/// パーソナリティの供給物に付随する選択で、
/// `sys::install_gate_page` が同じ値で命令列を書く。
// Ref: SRC-LINUX-66 — kernel-asm/page.h, kernel/mm-init.c.
pub mod gate {
    /// ゲート領域の先頭（`RGN_BASE(RGN_GATE)` = 5<<61）。
    /// AT_SYSINFO_EHDR が指す ELF ヘッダページの位置でもある。
    pub const ADDR: u64 = 0xa000_0000_0000_0000;
    /// per-CPU 領域のサイズ（`PERCPU_PAGE_SIZE`）。コード
    /// ページは ADDR+SIZE（非 BUGGY_SEGREL の配置）。
    pub const PERCPU_PAGE_SIZE: u64 = 1 << 18;
    /// ゲートコードページの先頭。
    pub const CODE: u64 = ADDR + PERCPU_PAGE_SIZE;
    /// `__kernel_syscall_via_break` の入口（CODE 先頭）。
    pub const SYSCALL_VIA_BREAK: u64 = CODE;
    /// `__kernel_sigtramp` の入口（位置の予約のみ。シグナル
    /// 配送は未実装 — Gap: GAP-0068）。
    pub const SIGTRAMP: u64 = CODE + 0x100;
    /// `__kernel_syscall_via_epc` の入口。AT_SYSINFO が指す値。
    pub const SYSCALL_VIA_EPC: u64 = CODE + 0x200;
}

/// errno。ia64 は asm-generic/errno*.h の値そのまま
/// （arch/ia64/include/uapi/asm/errno.h は include のみ）。
// Ref: SRC-LINUX-66 — uapi-asm-generic/errno*.h.
pub mod errno {
    pub const EPERM: u64 = 1;
    pub const ENOENT: u64 = 2;
    pub const ESRCH: u64 = 3;
    pub const EINTR: u64 = 4;
    pub const EIO: u64 = 5;
    pub const ENXIO: u64 = 6;
    pub const E2BIG: u64 = 7;
    pub const ENOEXEC: u64 = 8;
    pub const EBADF: u64 = 9;
    pub const ECHILD: u64 = 10;
    pub const EAGAIN: u64 = 11;
    pub const ENOMEM: u64 = 12;
    pub const EACCES: u64 = 13;
    pub const EFAULT: u64 = 14;
    pub const ENOTBLK: u64 = 15;
    pub const EBUSY: u64 = 16;
    pub const EEXIST: u64 = 17;
    pub const EXDEV: u64 = 18;
    pub const ENODEV: u64 = 19;
    pub const ENOTDIR: u64 = 20;
    pub const EISDIR: u64 = 21;
    pub const EINVAL: u64 = 22;
    pub const ENFILE: u64 = 23;
    pub const EMFILE: u64 = 24;
    pub const ENOTTY: u64 = 25;
    pub const ETXTBSY: u64 = 26;
    pub const EFBIG: u64 = 27;
    pub const ENOSPC: u64 = 28;
    pub const ESPIPE: u64 = 29;
    pub const EROFS: u64 = 30;
    pub const EMLINK: u64 = 31;
    pub const EPIPE: u64 = 32;
    pub const EDOM: u64 = 33;
    pub const ERANGE: u64 = 34;
    pub const ENAMETOOLONG: u64 = 36;
    pub const ENOLCK: u64 = 37;
    pub const ENOSYS: u64 = 38;
    pub const ENOTEMPTY: u64 = 39;
    pub const ELOOP: u64 = 40;
    pub const ENOMSG: u64 = 42;
    pub const EIDRM: u64 = 43;
    pub const ENODATA: u64 = 61;
    pub const EOVERFLOW: u64 = 75;
    pub const EILSEQ: u64 = 84;
    pub const ENOTSOCK: u64 = 88;
    pub const EDESTADDRREQ: u64 = 89;
    pub const EMSGSIZE: u64 = 90;
    pub const EOPNOTSUPP: u64 = 95;
    pub const EAFNOSUPPORT: u64 = 97;
    pub const EADDRINUSE: u64 = 98;
    pub const EADDRNOTAVAIL: u64 = 99;
    pub const ENETDOWN: u64 = 100;
    pub const ECONNABORTED: u64 = 103;
    pub const ECONNRESET: u64 = 104;
    pub const ENOBUFS: u64 = 105;
    pub const EISCONN: u64 = 106;
    pub const ENOTCONN: u64 = 107;
    pub const ETIMEDOUT: u64 = 110;
    pub const ECONNREFUSED: u64 = 111;
    pub const EINPROGRESS: u64 = 115;
    pub const EALREADY: u64 = 114;
    pub const EDQUOT: u64 = 122;
}

/// O_*。ia64 は asm-generic/fcntl.h の値そのまま
/// （arch/ia64/include/uapi/asm/fcntl.h は include のみ）。
// Ref: SRC-LINUX-66 — uapi-asm-generic/fcntl.h.
pub mod oflag {
    pub const ACCMODE: u64 = 3;
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
    pub const PATH: u64 = 0o10000000;
    pub const TMPFILE: u64 = 0o20000000 | DIRECTORY;
}

/// PROT_*/MAP_*。ia64 の uapi-asm/mman.h は asm-generic に
/// `MAP_GROWSUP` を足すだけ。
// Ref: SRC-LINUX-66 — uapi-asm/mman.h, uapi-asm-generic/mman*.h.
pub mod mman {
    pub const PROT_NONE: u64 = 0;
    pub const PROT_READ: u64 = 1;
    pub const PROT_WRITE: u64 = 2;
    pub const PROT_EXEC: u64 = 4;
    pub const MAP_SHARED: u64 = 1;
    pub const MAP_PRIVATE: u64 = 2;
    pub const MAP_TYPE: u64 = 0xf;
    pub const MAP_FIXED: u64 = 0x10;
    pub const MAP_ANONYMOUS: u64 = 0x20;
    pub const MAP_GROWSDOWN: u64 = 0x0100;
    /// レジスタスタック風（上方向）に伸びる領域。
    /// エミュレート側では MAP_GROWSDOWN 同様に領域全体を
    /// 確保して畳む。
    pub const MAP_GROWSUP: u64 = 0x0200;
    pub const MAP_DENYWRITE: u64 = 0x0800;
    pub const MAP_EXECUTABLE: u64 = 0x1000;
    pub const MAP_LOCKED: u64 = 0x2000;
    pub const MAP_NORESERVE: u64 = 0x4000;
    pub const MAP_POPULATE: u64 = 0x8000;
    pub const MAP_NONBLOCK: u64 = 0x10000;
    pub const MAP_STACK: u64 = 0x20000;
    pub const MAP_HUGETLB: u64 = 0x40000;
    pub const MAP_FIXED_NOREPLACE: u64 = 0x100000;
    pub const MREMAP_MAYMOVE: u64 = 1;
    pub const MREMAP_FIXED: u64 = 2;
    pub const MADV_NORMAL: u64 = 0;
    pub const MADV_RANDOM: u64 = 1;
    pub const MADV_SEQUENTIAL: u64 = 2;
    pub const MADV_WILLNEED: u64 = 3;
    pub const MADV_DONTNEED: u64 = 4;
    pub const MADV_FREE: u64 = 8;
}

/// syscall 番号（`syscall.tbl` の表番号。実番号は +`NR_BASE`）。
/// 表の穴（96–98・108・111・112・334–423・435・447）には定数を
/// 置かない。診断名は `name` / `SYSCALLS` が表全体を持つ。
// Ref: SRC-LINUX-66 — syscall.tbl.
pub mod nr {
    pub const EXIT: u64 = 1;
    pub const READ: u64 = 2;
    pub const WRITE: u64 = 3;
    pub const OPEN: u64 = 4;
    pub const CLOSE: u64 = 5;
    pub const CREAT: u64 = 6;
    pub const LINK: u64 = 7;
    pub const UNLINK: u64 = 8;
    pub const EXECVE: u64 = 9;
    pub const CHDIR: u64 = 10;
    pub const FCHDIR: u64 = 11;
    pub const UTIMES: u64 = 12;
    pub const MKNOD: u64 = 13;
    pub const CHMOD: u64 = 14;
    pub const CHOWN: u64 = 15;
    pub const LSEEK: u64 = 16;
    pub const GETPID: u64 = 17;
    pub const GETPPID: u64 = 18;
    pub const SETUID: u64 = 21;
    pub const GETUID: u64 = 22;
    pub const GETEUID: u64 = 23;
    pub const PTRACE: u64 = 24;
    pub const ACCESS: u64 = 25;
    pub const SYNC: u64 = 26;
    pub const FSYNC: u64 = 27;
    pub const FDATASYNC: u64 = 28;
    pub const KILL: u64 = 29;
    pub const RENAME: u64 = 30;
    pub const MKDIR: u64 = 31;
    pub const RMDIR: u64 = 32;
    pub const DUP: u64 = 33;
    pub const PIPE: u64 = 34;
    pub const TIMES: u64 = 35;
    pub const BRK: u64 = 36;
    pub const SETGID: u64 = 37;
    pub const GETGID: u64 = 38;
    pub const GETEGID: u64 = 39;
    pub const IOCTL: u64 = 41;
    pub const FCNTL: u64 = 42;
    pub const UMASK: u64 = 43;
    pub const DUP2: u64 = 46;
    pub const SETREUID: u64 = 47;
    pub const SETREGID: u64 = 48;
    pub const GETRESUID: u64 = 49;
    pub const GETRESGID: u64 = 51;
    pub const GETGROUPS: u64 = 53;
    pub const SETGROUPS: u64 = 54;
    pub const GETPGID: u64 = 55;
    pub const SETPGID: u64 = 56;
    pub const SETSID: u64 = 57;
    pub const GETSID: u64 = 58;
    pub const SETHOSTNAME: u64 = 59;
    pub const SETRLIMIT: u64 = 60;
    pub const GETRLIMIT: u64 = 61;
    pub const GETRUSAGE: u64 = 62;
    pub const GETTIMEOFDAY: u64 = 63;
    pub const SELECT: u64 = 65;
    pub const POLL: u64 = 66;
    pub const SYMLINK: u64 = 67;
    pub const READLINK: u64 = 68;
    pub const TRUNCATE: u64 = 73;
    pub const FTRUNCATE: u64 = 74;
    pub const FCHMOD: u64 = 75;
    pub const FCHOWN: u64 = 76;
    pub const GETPRIORITY: u64 = 77;
    pub const SETPRIORITY: u64 = 78;
    pub const STATFS: u64 = 79;
    pub const FSTATFS: u64 = 80;
    pub const GETTID: u64 = 81;
    pub const SYSLOG: u64 = 93;
    pub const SETITIMER: u64 = 94;
    pub const GETITIMER: u64 = 95;
    pub const VHANGUP: u64 = 99;
    pub const LCHOWN: u64 = 100;
    pub const WAIT4: u64 = 102;
    pub const SYSINFO: u64 = 103;
    pub const CLONE: u64 = 104;
    pub const UNAME: u64 = 106;
    pub const SETDOMAINNAME: u64 = 105;
    pub const ADJTIMEX: u64 = 107;
    pub const PERSONALITY: u64 = 116;
    pub const GETDENTS: u64 = 120;
    pub const FLOCK: u64 = 121;
    pub const READV: u64 = 122;
    pub const WRITEV: u64 = 123;
    pub const PREAD64: u64 = 124;
    pub const PWRITE64: u64 = 125;
    /// ia64 の mmap は 6 引数そのまま（pgoff はバイト単位）。
    pub const MMAP: u64 = 127;
    pub const MUNMAP: u64 = 128;
    pub const MLOCK: u64 = 129;
    pub const MLOCKALL: u64 = 130;
    pub const MPROTECT: u64 = 131;
    pub const MREMAP: u64 = 132;
    pub const MSYNC: u64 = 133;
    pub const MUNLOCK: u64 = 134;
    pub const MUNLOCKALL: u64 = 135;
    pub const SCHED_GETPARAM: u64 = 136;
    pub const SCHED_SETPARAM: u64 = 137;
    pub const SCHED_GETSCHEDULER: u64 = 138;
    pub const SCHED_SETSCHEDULER: u64 = 139;
    pub const SCHED_YIELD: u64 = 140;
    pub const SCHED_GET_PRIORITY_MAX: u64 = 141;
    pub const SCHED_GET_PRIORITY_MIN: u64 = 142;
    pub const SCHED_RR_GET_INTERVAL: u64 = 143;
    pub const NANOSLEEP: u64 = 144;
    pub const PRCTL: u64 = 146;
    pub const OLD_GETPAGESIZE: u64 = 147;
    /// pgoff をページ単位で取る mmap。ia64 にも別入口がある。
    pub const MMAP2: u64 = 148;
    /// ia64 専用（perfmon 制御）。未実装。
    pub const PERFMONCTL: u64 = 151;
    pub const SIGALTSTACK: u64 = 152;
    pub const RT_SIGACTION: u64 = 153;
    pub const RT_SIGPENDING: u64 = 154;
    pub const RT_SIGPROCMASK: u64 = 155;
    pub const RT_SIGQUEUEINFO: u64 = 156;
    pub const RT_SIGRETURN: u64 = 157;
    pub const RT_SIGSUSPEND: u64 = 158;
    pub const RT_SIGTIMEDWAIT: u64 = 159;
    pub const GETCWD: u64 = 160;
    pub const CAPGET: u64 = 161;
    pub const CAPSET: u64 = 162;
    pub const SENDFILE: u64 = 163;
    pub const MINCORE: u64 = 184;
    pub const MADVISE: u64 = 185;
    /// ia64 には stat64 系の別名がなく、stat/lstat/fstat が
    /// 本表の入口（144B struct stat）。
    pub const STAT: u64 = 186;
    pub const LSTAT: u64 = 187;
    pub const FSTAT: u64 = 188;
    /// ia64 専用。clone の引数順が異なる（ptid・tls・ctid）。
    pub const CLONE2: u64 = 189;
    pub const GETDENTS64: u64 = 190;
    /// ia64 専用（アンワインド情報）。未実装。
    pub const GETUNWIND: u64 = 191;
    pub const READAHEAD: u64 = 192;
    pub const SETXATTR: u64 = 193;
    pub const GETXATTR: u64 = 196;
    pub const LISTXATTR: u64 = 199;
    pub const REMOVEXATTR: u64 = 202;
    pub const TKILL: u64 = 205;
    pub const FUTEX: u64 = 206;
    pub const SCHED_SETAFFINITY: u64 = 207;
    pub const SCHED_GETAFFINITY: u64 = 208;
    pub const SET_TID_ADDRESS: u64 = 209;
    pub const FADVISE64: u64 = 210;
    pub const TGKILL: u64 = 211;
    pub const EXIT_GROUP: u64 = 212;
    pub const IO_SETUP: u64 = 214;
    pub const EPOLL_CREATE: u64 = 219;
    pub const EPOLL_CTL: u64 = 220;
    pub const EPOLL_WAIT: u64 = 221;
    pub const RESTART_SYSCALL: u64 = 222;
    pub const CLOCK_SETTIME: u64 = 229;
    pub const CLOCK_GETTIME: u64 = 230;
    pub const CLOCK_GETRES: u64 = 231;
    pub const CLOCK_NANOSLEEP: u64 = 232;
    pub const FSTATFS64: u64 = 233;
    pub const STATFS64: u64 = 234;
    pub const WAITID: u64 = 246;
    pub const IOPRIO_SET: u64 = 250;
    pub const IOPRIO_GET: u64 = 251;
    pub const INOTIFY_INIT: u64 = 253;
    pub const OPENAT: u64 = 257;
    pub const MKDIRAT: u64 = 258;
    pub const MKNODAT: u64 = 259;
    pub const FCHOWNAT: u64 = 260;
    pub const FUTIMESAT: u64 = 261;
    /// newfstatat（glibc の stat 系はこの入口を使う）。
    pub const NEWFSTATAT: u64 = 262;
    pub const UNLINKAT: u64 = 263;
    pub const RENAMEAT: u64 = 264;
    pub const LINKAT: u64 = 265;
    pub const SYMLINKAT: u64 = 266;
    pub const READLINKAT: u64 = 267;
    pub const FCHMODAT: u64 = 268;
    pub const FACCESSAT: u64 = 269;
    pub const PSELECT6: u64 = 270;
    pub const PPOLL: u64 = 271;
    pub const UNSHARE: u64 = 272;
    pub const SPLICE: u64 = 273;
    pub const SET_ROBUST_LIST: u64 = 274;
    pub const SYNC_FILE_RANGE: u64 = 276;
    pub const FALLOCATE: u64 = 279;
    pub const GETCPU: u64 = 280;
    pub const EPOLL_PWAIT: u64 = 281;
    pub const UTIMENSAT: u64 = 282;
    pub const TIMERFD_CREATE: u64 = 286;
    pub const EPOLL_CREATE1: u64 = 291;
    pub const DUP3: u64 = 292;
    pub const PIPE2: u64 = 293;
    pub const INOTIFY_INIT1: u64 = 294;
    pub const PREADV: u64 = 295;
    pub const PWRITEV: u64 = 296;
    pub const PRLIMIT64: u64 = 301;
    pub const PROCESS_VM_READV: u64 = 308;
    pub const PROCESS_VM_WRITEV: u64 = 309;
    pub const ACCEPT4: u64 = 310;
    pub const RENAMEAT2: u64 = 314;
    pub const GETRANDOM: u64 = 315;
    pub const MEMFD_CREATE: u64 = 316;
    pub const EXECVEAT: u64 = 318;
    pub const MLOCK2: u64 = 322;
    pub const COPY_FILE_RANGE: u64 = 323;
    pub const STATX: u64 = 326;
    pub const SECCOMP: u64 = 329;
    pub const RSEQ: u64 = 333;
    pub const CLOSE_RANGE: u64 = 436;
    pub const OPENAT2: u64 = 437;
    pub const FACCESSAT2: u64 = 439;
}

/// syscall.tbl（0 起点、SRC-LINUX-66）をそのまま写した番号
/// 表。全エントリは common ABI。実番号は +`NR_BASE`。
/// 診断と ABI 照合に使う。
pub static SYSCALLS: &[(u64, &str)] = &[
    (0, "ni_syscall"),
    (1, "exit"),
    (2, "read"),
    (3, "write"),
    (4, "open"),
    (5, "close"),
    (6, "creat"),
    (7, "link"),
    (8, "unlink"),
    (9, "execve"),
    (10, "chdir"),
    (11, "fchdir"),
    (12, "utimes"),
    (13, "mknod"),
    (14, "chmod"),
    (15, "chown"),
    (16, "lseek"),
    (17, "getpid"),
    (18, "getppid"),
    (19, "mount"),
    (20, "umount2"),
    (21, "setuid"),
    (22, "getuid"),
    (23, "geteuid"),
    (24, "ptrace"),
    (25, "access"),
    (26, "sync"),
    (27, "fsync"),
    (28, "fdatasync"),
    (29, "kill"),
    (30, "rename"),
    (31, "mkdir"),
    (32, "rmdir"),
    (33, "dup"),
    (34, "pipe"),
    (35, "times"),
    (36, "brk"),
    (37, "setgid"),
    (38, "getgid"),
    (39, "getegid"),
    (40, "acct"),
    (41, "ioctl"),
    (42, "fcntl"),
    (43, "umask"),
    (44, "chroot"),
    (45, "ustat"),
    (46, "dup2"),
    (47, "setreuid"),
    (48, "setregid"),
    (49, "getresuid"),
    (50, "setresuid"),
    (51, "getresgid"),
    (52, "setresgid"),
    (53, "getgroups"),
    (54, "setgroups"),
    (55, "getpgid"),
    (56, "setpgid"),
    (57, "setsid"),
    (58, "getsid"),
    (59, "sethostname"),
    (60, "setrlimit"),
    (61, "getrlimit"),
    (62, "getrusage"),
    (63, "gettimeofday"),
    (64, "settimeofday"),
    (65, "select"),
    (66, "poll"),
    (67, "symlink"),
    (68, "readlink"),
    (69, "uselib"),
    (70, "swapon"),
    (71, "swapoff"),
    (72, "reboot"),
    (73, "truncate"),
    (74, "ftruncate"),
    (75, "fchmod"),
    (76, "fchown"),
    (77, "getpriority"),
    (78, "setpriority"),
    (79, "statfs"),
    (80, "fstatfs"),
    (81, "gettid"),
    (82, "semget"),
    (83, "semop"),
    (84, "semctl"),
    (85, "msgget"),
    (86, "msgsnd"),
    (87, "msgrcv"),
    (88, "msgctl"),
    (89, "shmget"),
    (90, "shmat"),
    (91, "shmdt"),
    (92, "shmctl"),
    (93, "syslog"),
    (94, "setitimer"),
    (95, "getitimer"),
    (99, "vhangup"),
    (100, "lchown"),
    (101, "remap_file_pages"),
    (102, "wait4"),
    (103, "sysinfo"),
    (104, "clone"),
    (105, "setdomainname"),
    (106, "uname"),
    (107, "adjtimex"),
    (109, "init_module"),
    (110, "delete_module"),
    (113, "quotactl"),
    (114, "bdflush"),
    (115, "sysfs"),
    (116, "personality"),
    (117, "afs_syscall"),
    (118, "setfsuid"),
    (119, "setfsgid"),
    (120, "getdents"),
    (121, "flock"),
    (122, "readv"),
    (123, "writev"),
    (124, "pread64"),
    (125, "pwrite64"),
    (126, "_sysctl"),
    (127, "mmap"),
    (128, "munmap"),
    (129, "mlock"),
    (130, "mlockall"),
    (131, "mprotect"),
    (132, "mremap"),
    (133, "msync"),
    (134, "munlock"),
    (135, "munlockall"),
    (136, "sched_getparam"),
    (137, "sched_setparam"),
    (138, "sched_getscheduler"),
    (139, "sched_setscheduler"),
    (140, "sched_yield"),
    (141, "sched_get_priority_max"),
    (142, "sched_get_priority_min"),
    (143, "sched_rr_get_interval"),
    (144, "nanosleep"),
    (145, "nfsservctl"),
    (146, "prctl"),
    (147, "old_getpagesize"),
    (148, "mmap2"),
    (149, "pciconfig_read"),
    (150, "pciconfig_write"),
    (151, "perfmonctl"),
    (152, "sigaltstack"),
    (153, "rt_sigaction"),
    (154, "rt_sigpending"),
    (155, "rt_sigprocmask"),
    (156, "rt_sigqueueinfo"),
    (157, "rt_sigreturn"),
    (158, "rt_sigsuspend"),
    (159, "rt_sigtimedwait"),
    (160, "getcwd"),
    (161, "capget"),
    (162, "capset"),
    (163, "sendfile"),
    (164, "getpmsg"),
    (165, "putpmsg"),
    (166, "socket"),
    (167, "bind"),
    (168, "connect"),
    (169, "listen"),
    (170, "accept"),
    (171, "getsockname"),
    (172, "getpeername"),
    (173, "socketpair"),
    (174, "send"),
    (175, "sendto"),
    (176, "recv"),
    (177, "recvfrom"),
    (178, "shutdown"),
    (179, "setsockopt"),
    (180, "getsockopt"),
    (181, "sendmsg"),
    (182, "recvmsg"),
    (183, "pivot_root"),
    (184, "mincore"),
    (185, "madvise"),
    (186, "stat"),
    (187, "lstat"),
    (188, "fstat"),
    (189, "clone2"),
    (190, "getdents64"),
    (191, "getunwind"),
    (192, "readahead"),
    (193, "setxattr"),
    (194, "lsetxattr"),
    (195, "fsetxattr"),
    (196, "getxattr"),
    (197, "lgetxattr"),
    (198, "fgetxattr"),
    (199, "listxattr"),
    (200, "llistxattr"),
    (201, "flistxattr"),
    (202, "removexattr"),
    (203, "lremovexattr"),
    (204, "fremovexattr"),
    (205, "tkill"),
    (206, "futex"),
    (207, "sched_setaffinity"),
    (208, "sched_getaffinity"),
    (209, "set_tid_address"),
    (210, "fadvise64"),
    (211, "tgkill"),
    (212, "exit_group"),
    (213, "lookup_dcookie"),
    (214, "io_setup"),
    (215, "io_destroy"),
    (216, "io_getevents"),
    (217, "io_submit"),
    (218, "io_cancel"),
    (219, "epoll_create"),
    (220, "epoll_ctl"),
    (221, "epoll_wait"),
    (222, "restart_syscall"),
    (223, "semtimedop"),
    (224, "timer_create"),
    (225, "timer_settime"),
    (226, "timer_gettime"),
    (227, "timer_getoverrun"),
    (228, "timer_delete"),
    (229, "clock_settime"),
    (230, "clock_gettime"),
    (231, "clock_getres"),
    (232, "clock_nanosleep"),
    (233, "fstatfs64"),
    (234, "statfs64"),
    (235, "mbind"),
    (236, "get_mempolicy"),
    (237, "set_mempolicy"),
    (238, "mq_open"),
    (239, "mq_unlink"),
    (240, "mq_timedsend"),
    (241, "mq_timedreceive"),
    (242, "mq_notify"),
    (243, "mq_getsetattr"),
    (244, "kexec_load"),
    (245, "vserver"),
    (246, "waitid"),
    (247, "add_key"),
    (248, "request_key"),
    (249, "keyctl"),
    (250, "ioprio_set"),
    (251, "ioprio_get"),
    (252, "move_pages"),
    (253, "inotify_init"),
    (254, "inotify_add_watch"),
    (255, "inotify_rm_watch"),
    (256, "migrate_pages"),
    (257, "openat"),
    (258, "mkdirat"),
    (259, "mknodat"),
    (260, "fchownat"),
    (261, "futimesat"),
    (262, "newfstatat"),
    (263, "unlinkat"),
    (264, "renameat"),
    (265, "linkat"),
    (266, "symlinkat"),
    (267, "readlinkat"),
    (268, "fchmodat"),
    (269, "faccessat"),
    (270, "pselect6"),
    (271, "ppoll"),
    (272, "unshare"),
    (273, "splice"),
    (274, "set_robust_list"),
    (275, "get_robust_list"),
    (276, "sync_file_range"),
    (277, "tee"),
    (278, "vmsplice"),
    (279, "fallocate"),
    (280, "getcpu"),
    (281, "epoll_pwait"),
    (282, "utimensat"),
    (283, "signalfd"),
    (284, "timerfd"),
    (285, "eventfd"),
    (286, "timerfd_create"),
    (287, "timerfd_settime"),
    (288, "timerfd_gettime"),
    (289, "signalfd4"),
    (290, "eventfd2"),
    (291, "epoll_create1"),
    (292, "dup3"),
    (293, "pipe2"),
    (294, "inotify_init1"),
    (295, "preadv"),
    (296, "pwritev"),
    (297, "rt_tgsigqueueinfo"),
    (298, "recvmmsg"),
    (299, "fanotify_init"),
    (300, "fanotify_mark"),
    (301, "prlimit64"),
    (302, "name_to_handle_at"),
    (303, "open_by_handle_at"),
    (304, "clock_adjtime"),
    (305, "syncfs"),
    (306, "setns"),
    (307, "sendmmsg"),
    (308, "process_vm_readv"),
    (309, "process_vm_writev"),
    (310, "accept4"),
    (311, "finit_module"),
    (312, "sched_setattr"),
    (313, "sched_getattr"),
    (314, "renameat2"),
    (315, "getrandom"),
    (316, "memfd_create"),
    (317, "bpf"),
    (318, "execveat"),
    (319, "userfaultfd"),
    (320, "membarrier"),
    (321, "kcmp"),
    (322, "mlock2"),
    (323, "copy_file_range"),
    (324, "preadv2"),
    (325, "pwritev2"),
    (326, "statx"),
    (327, "io_pgetevents"),
    (328, "perf_event_open"),
    (329, "seccomp"),
    (330, "pkey_mprotect"),
    (331, "pkey_alloc"),
    (332, "pkey_free"),
    (333, "rseq"),
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
];

/// 表番号 `n`（r15 − NR_BASE）の名前。表に無い番号は None。
#[must_use]
pub fn name(n: u64) -> Option<&'static str> {
    SYSCALLS
        .binary_search_by_key(&n, |e| e.0)
        .ok()
        .map(|i| SYSCALLS[i].1)
}

/// IA-64 の Linux syscall 処理。`guest-ia64` 機能で有効になる。
#[cfg(feature = "guest-ia64")]
pub mod sys;
