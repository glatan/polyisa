// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Linux パーソナリティ。仮想カーネルの上で Linux の規約を実装する.
//!
//! 番号表は Linux カーネルの UAPI 由来の事実を自前表現で書く。
//! 条文・コードの複製はしない.

// Ref: SRC-LINUX (7.3).

#![forbid(unsafe_code)]

/// x86 のシステムコール実装。`guest-x86` 機能で有効になる。
/// 設計の依存規則（`docs/design/workspace.md` の「依存規則」）が
/// `os-linux` の `guests/*` 依存を機能フラグ付きで認めている。
/// 番号表は ABI 名のモジュール（`x86_64`・`x86_32`）に、実装はこのモジュールに置く
/// （x86-32 と x86-64 の両 ABI を一つの実装で扱う）。
#[cfg(feature = "guest-x86")]
pub mod x86;

/// MIPS の Linux パーソナリティ（o32/n32/n64 の syscall 処理と ABI 定数）。
// Ref: SRC-LINUX (7.3).
#[cfg(feature = "guest-mips")]
pub mod mips;

/// MIPS o32 のシステムコール番号。
// Ref: SRC-LINUX (7.3).
pub mod mips_o32;

/// MIPS n32 のシステムコール番号。
// Ref: SRC-LINUX (7.3).
pub mod mips_n32;

/// MIPS n64 のシステムコール番号。
// Ref: SRC-LINUX (7.3).
pub mod mips_n64;

/// AArch64（asm-generic・LP64）のシステムコール番号と syscall 処理。
// Ref: SRC-LINUX (7.3).
pub mod aarch64;

/// ARM（AArch32・EABI）のシステムコール番号と syscall 処理。
// Ref: SRC-LINUX (7.3).
pub mod arm;

/// Power（ppc64・ELFv2）のシステムコール番号と syscall 処理。
// Ref: SRC-LINUX (7.3), SPEC-POWER-ABI (ELFv2 r1.5).
pub mod power;

/// RISC-V（asm-generic）のシステムコール番号と syscall 処理。
pub mod rv64;

/// s390x（Linux・64ビット・ビッグエンディアン）のシステムコール番号と
/// syscall 処理（`sys` の実装だけ `guest-s390` 機能の内側）。
// Ref: SRC-LINUX (7.3), SPEC-S390-ABI.
pub mod s390;

/// x86 の 32ビット（Linux の i386 ABI、EM_386）のシステムコール番号。
// Ref: SRC-LINUX (7.3).
pub mod x86_32;

/// x86_64（Linux・64ビット）のシステムコール番号。
// Ref: SRC-LINUX (7.3).
pub mod x86_64;

/// x32（Linux・ILP32、EM_X86_64 + ELFCLASS32）のシステムコール番号。
// Ref: SRC-LINUX (7.3).
pub mod x86_x32;

/// ゲストパスをホストパスへ写す補助（cwd 連結とルート閉じ込め）。
pub mod guest_path;

/// 未実装のシステムコールに返す errno（asm-generic の ENOSYS）。
/// 設計: `docs/design/user-mode.md` の「未実装のシステムコール」。
pub const ENOSYS: u32 = 38;

/// ゲストの ABI。システムコール番号の表を選ぶときに使う。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GuestAbi {
    Unknown,
    Rv64Linux,
    X86_64Linux,
    X86_32Linux,
    X32Linux,
    MipsO32,
    Aarch64Linux,
    ArmLinux,
}

/// 実行ループとの境界。定義は実行エンジンにある。
pub use polyisa_engine::run::{TrapHandler, TrapOutcome};

use polyisa_mem::Endian;

/// Linux の `clone` フラグ。アドレス空間の共有はプロセス生成では使わない。
// Ref: SRC-LINUX (7.3).
pub mod clone_flag {
    pub const VM: u64 = 0x100;
    pub const THREAD: u64 = 0x0001_0000;
}

/// 正常終了の wait ステータス。終了コードは 8–15 ビットに置く。
#[must_use]
pub fn exited_wait_status(code: u32) -> u32 {
    (code & 0xff) << 8
}

/// ABI と番号から名前を引く。
#[must_use]
pub fn syscall_name(abi: GuestAbi, nr: u64) -> Option<&'static str> {
    match abi {
        GuestAbi::Rv64Linux => match nr {
            rv64::READ => Some("read"),
            rv64::WRITE => Some("write"),
            rv64::CLOSE => Some("close"),
            rv64::MMAP => Some("mmap"),
            rv64::MPROTECT => Some("mprotect"),
            rv64::MUNMAP => Some("munmap"),
            rv64::BRK => Some("brk"),
            rv64::EXIT => Some("exit"),
            rv64::EXIT_GROUP => Some("exit_group"),
            rv64::UNAME => Some("uname"),
            rv64::SET_TID_ADDRESS => Some("set_tid_address"),
            rv64::GETTID => Some("gettid"),
            rv64::GETPID => Some("getpid"),
            rv64::TGKILL => Some("tgkill"),
            rv64::GETUID => Some("getuid"),
            rv64::GETEUID => Some("geteuid"),
            rv64::GETGID => Some("getgid"),
            rv64::GETEGID => Some("getegid"),
            rv64::RT_SIGACTION => Some("rt_sigaction"),
            rv64::RT_SIGPROCMASK => Some("rt_sigprocmask"),
            rv64::CLOCK_GETTIME => Some("clock_gettime"),
            rv64::GETRANDOM => Some("getrandom"),
            rv64::OPENAT => Some("openat"),
            rv64::LSEEK => Some("lseek"),
            rv64::GETDENTS64 => Some("getdents64"),
            rv64::GETCWD => Some("getcwd"),
            rv64::DUP3 => Some("dup3"),
            rv64::FCNTL => Some("fcntl"),
            rv64::IOCTL => Some("ioctl"),
            rv64::PREAD64 => Some("pread64"),
            rv64::READLINKAT => Some("readlinkat"),
            rv64::NEWFSTATAT => Some("newfstatat"),
            rv64::FSTAT => Some("fstat"),
            rv64::STATX => Some("statx"),
            rv64::READV => Some("readv"),
            rv64::WRITEV => Some("writev"),
            rv64::SENDFILE => Some("sendfile"),
            rv64::CLOCK_NANOSLEEP => Some("clock_nanosleep"),
            _ => None,
        },
        GuestAbi::X86_32Linux => match nr {
            x86_32::READ => Some("read"),
            x86_32::WRITE => Some("write"),
            x86_32::CLOSE => Some("close"),
            x86_32::MMAP => Some("mmap"),
            x86_32::MMAP_PG => Some("mmap"),
            x86_32::MPROTECT => Some("mprotect"),
            x86_32::MUNMAP => Some("munmap"),
            x86_32::BRK => Some("brk"),
            x86_32::EXIT => Some("exit"),
            x86_32::EXIT_GROUP => Some("exit_group"),
            x86_32::UNAME => Some("uname"),
            x86_32::SET_THREAD_AREA => Some("set_thread_area"),
            x86_32::SET_TID_ADDRESS => Some("set_tid_address"),
            x86_32::GETTID => Some("gettid"),
            x86_32::GETPID => Some("getpid"),
            x86_32::TGKILL => Some("tgkill"),
            x86_32::GETUID => Some("getuid"),
            x86_32::GETEUID => Some("geteuid"),
            x86_32::GETGID => Some("getgid"),
            x86_32::GETEGID => Some("getegid"),
            x86_32::RT_SIGACTION => Some("rt_sigaction"),
            x86_32::RT_SIGPROCMASK => Some("rt_sigprocmask"),
            x86_32::RT_SIGRETURN => Some("rt_sigreturn"),
            x86_32::PAUSE => Some("pause"),
            x86_32::RT_SIGPENDING => Some("rt_sigpending"),
            x86_32::RT_SIGTIMEDWAIT => Some("rt_sigtimedwait"),
            x86_32::RT_SIGSUSPEND => Some("rt_sigsuspend"),
            x86_32::CLOCK_GETTIME => Some("clock_gettime"),
            x86_32::GETRANDOM => Some("getrandom"),
            x86_32::OPENAT => Some("openat"),
            x86_32::LSEEK => Some("lseek"),
            x86_32::GETDENTS64 => Some("getdents64"),
            x86_32::GETCWD => Some("getcwd"),
            x86_32::DUP3 => Some("dup3"),
            x86_32::FCNTL => Some("fcntl"),
            x86_32::IOCTL => Some("ioctl"),
            x86_32::PREAD64 => Some("pread64"),
            x86_32::READLINKAT => Some("readlinkat"),
            x86_32::READLINK => Some("readlink"),
            x86_32::FSTATAT64 => Some("fstatat64"),
            x86_32::FSTAT => Some("fstat"),
            x86_32::STATX => Some("statx"),
            x86_32::READV => Some("readv"),
            x86_32::WRITEV => Some("writev"),
            x86_32::SENDFILE => Some("sendfile"),
            x86_32::TIME => Some("time"),
            x86_32::NANOSLEEP => Some("nanosleep"),
            x86_32::GETGROUPS => Some("getgroups"),
            x86_32::GETGROUPS32 => Some("getgroups32"),
            x86_32::SETGROUPS32 => Some("setgroups"),
            x86_32::FCHDIR => Some("fchdir"),
            x86_32::SYSINFO => Some("sysinfo"),
            x86_32::PERSONALITY => Some("personality"),
            x86_32::SETSID => Some("setsid"),
            x86_32::MKDIR => Some("mkdir"),
            x86_32::RMDIR => Some("rmdir"),
            x86_32::UNLINK => Some("unlink"),
            x86_32::ACCESS => Some("access"),
            x86_32::UTIMENSAT => Some("utimensat"),
            x86_32::DUP => Some("dup"),
            x86_32::DUP2 => Some("dup2"),
            x86_32::MKDIRAT => Some("mkdirat"),
            x86_32::UNLINKAT => Some("unlinkat"),
            x86_32::FACCESSAT => Some("faccessat"),
            x86_32::CHMOD => Some("chmod"),
            x86_32::FCHMOD => Some("fchmod"),
            x86_32::FCHMODAT => Some("fchmodat"),
            x86_32::UMASK => Some("umask"),
            x86_32::FTRUNCATE => Some("ftruncate"),
            x86_32::RENAME => Some("rename"),
            x86_32::SYMLINK => Some("symlink"),
            x86_32::STATFS => Some("statfs"),
            x86_32::FSTATFS => Some("fstatfs"),
            x86_32::STATFS64 => Some("statfs64"),
            x86_32::FSTATFS64 => Some("fstatfs64"),
            x86_32::CLONE => Some("clone"),
            x86_32::EXECVE => Some("execve"),
            x86_32::WAIT4 => Some("wait4"),
            x86_32::PIPE2 => Some("pipe2"),
            x86_32::SETPGID => Some("setpgid"),
            x86_32::GETPGID => Some("getpgid"),
            x86_32::CHDIR => Some("chdir"),
            x86_32::KILL => Some("kill"),
            x86_32::OPEN => Some("open"),
            x86_32::FORK => Some("fork"),
            x86_32::VFORK => Some("vfork"),
            x86_32::PIPE => Some("pipe"),
            x86_32::GETPPID => Some("getppid"),
            x86_32::GETTIMEOFDAY => Some("gettimeofday"),
            x86_32::GETCPU => Some("getcpu"),
            x86_32::LLSEEK => Some("llseek"),
            x86_32::STAT64 => Some("stat"),
            x86_32::LSTAT64 => Some("lstat"),
            x86_32::FSTAT64 => Some("fstat"),
            x86_32::GETUID32 => Some("getuid"),
            x86_32::GETGID32 => Some("getgid"),
            x86_32::GETEUID32 => Some("geteuid"),
            x86_32::GETEGID32 => Some("getegid"),
            x86_32::SETUID32 => Some("setuid"),
            x86_32::SETGID32 => Some("setgid"),
            x86_32::FCNTL64 => Some("fcntl"),
            x86_32::CLOCK_GETTIME64 => Some("clock_gettime"),
            _ => None,
        },
        GuestAbi::X32Linux => {
            if nr & x86_x32::SYSCALL_BIT == 0 {
                // ビットのない番号は x86-64 と同じ表を使う。
                return syscall_name(GuestAbi::X86_64Linux, nr);
            }
            let base = nr & !x86_x32::SYSCALL_BIT;
            // x32 の呼び出しはすべてビットを立てる。ベース 0-511 は
            // x86-64 の表をそのまま使い、512-547 が x32 専用になる。
            if !(512..=547).contains(&base) {
                return syscall_name(GuestAbi::X86_64Linux, base);
            }
            match base {
                512 => Some("rt_sigaction"),
                513 => Some("rt_sigreturn"),
                514 => Some("ioctl"),
                515 => Some("readv"),
                516 => Some("writev"),
                517 => Some("recvfrom"),
                518 => Some("sendmsg"),
                519 => Some("recvmsg"),
                520 => Some("execve"),
                521 => Some("ptrace"),
                522 => Some("rt_sigpending"),
                523 => Some("rt_sigtimedwait"),
                524 => Some("rt_sigqueueinfo"),
                525 => Some("sigaltstack"),
                526 => Some("timer_create"),
                527 => Some("mq_notify"),
                528 => Some("kexec_load"),
                529 => Some("waitid"),
                530 => Some("set_robust_list"),
                531 => Some("get_robust_list"),
                532 => Some("vmsplice"),
                533 => Some("move_pages"),
                534 => Some("preadv"),
                535 => Some("pwritev"),
                536 => Some("rt_tgsigqueueinfo"),
                537 => Some("recvmmsg"),
                538 => Some("sendmmsg"),
                539 => Some("process_vm_readv"),
                540 => Some("process_vm_writev"),
                541 => Some("setsockopt"),
                542 => Some("getsockopt"),
                543 => Some("io_setup"),
                544 => Some("io_submit"),
                545 => Some("execveat"),
                546 => Some("preadv2"),
                547 => Some("pwritev2"),
                _ => None,
            }
        }
        GuestAbi::X86_64Linux => match nr {
            x86_64::READ => Some("read"),
            x86_64::WRITE => Some("write"),
            x86_64::CLOSE => Some("close"),
            x86_64::MMAP => Some("mmap"),
            x86_64::MPROTECT => Some("mprotect"),
            x86_64::MUNMAP => Some("munmap"),
            x86_64::BRK => Some("brk"),
            x86_64::EXIT => Some("exit"),
            x86_64::EXIT_GROUP => Some("exit_group"),
            x86_64::UNAME => Some("uname"),
            x86_64::SET_TID_ADDRESS => Some("set_tid_address"),
            x86_64::GETTID => Some("gettid"),
            x86_64::GETPID => Some("getpid"),
            x86_64::TGKILL => Some("tgkill"),
            x86_64::GETUID => Some("getuid"),
            x86_64::GETEUID => Some("geteuid"),
            x86_64::GETGID => Some("getgid"),
            x86_64::GETEGID => Some("getegid"),
            x86_64::RT_SIGACTION => Some("rt_sigaction"),
            x86_64::RT_SIGPROCMASK => Some("rt_sigprocmask"),
            x86_64::RT_SIGRETURN => Some("rt_sigreturn"),
            x86_64::PAUSE => Some("pause"),
            x86_64::RT_SIGPENDING => Some("rt_sigpending"),
            x86_64::RT_SIGTIMEDWAIT => Some("rt_sigtimedwait"),
            x86_64::RT_SIGSUSPEND => Some("rt_sigsuspend"),
            x86_64::CLOCK_GETTIME => Some("clock_gettime"),
            x86_64::GETRANDOM => Some("getrandom"),
            x86_64::OPENAT => Some("openat"),
            x86_64::OPEN => Some("open"),
            x86_64::LSEEK => Some("lseek"),
            x86_64::GETDENTS64 => Some("getdents64"),
            x86_64::GETCWD => Some("getcwd"),
            x86_64::DUP3 => Some("dup3"),
            x86_64::FCNTL => Some("fcntl"),
            x86_64::IOCTL => Some("ioctl"),
            x86_64::PREAD64 => Some("pread64"),
            x86_64::READLINKAT => Some("readlinkat"),
            x86_64::READLINK => Some("readlink"),
            x86_64::NEWFSTATAT => Some("newfstatat"),
            x86_64::FSTAT => Some("fstat"),
            x86_64::STAT => Some("stat"),
            x86_64::LSTAT => Some("lstat"),
            x86_64::STATX => Some("statx"),
            x86_64::READV => Some("readv"),
            x86_64::WRITEV => Some("writev"),
            x86_64::SENDFILE => Some("sendfile"),
            x86_64::TIME => Some("time"),
            x86_64::GETTIMEOFDAY => Some("gettimeofday"),
            x86_64::GETCPU => Some("getcpu"),
            x86_64::NANOSLEEP => Some("nanosleep"),
            x86_64::CLOCK_NANOSLEEP => Some("clock_nanosleep"),
            x86_64::SCHED_GETAFFINITY => Some("sched_getaffinity"),
            x86_64::GETGROUPS => Some("getgroups"),
            x86_64::MKDIR => Some("mkdir"),
            x86_64::RMDIR => Some("rmdir"),
            x86_64::MKNOD => Some("mknod"),
            x86_64::UNLINK => Some("unlink"),
            x86_64::ACCESS => Some("access"),
            x86_64::UTIMENSAT => Some("utimensat"),
            x86_64::DUP => Some("dup"),
            x86_64::DUP2 => Some("dup2"),
            x86_64::MKDIRAT => Some("mkdirat"),
            x86_64::UNLINKAT => Some("unlinkat"),
            x86_64::FACCESSAT => Some("faccessat"),
            x86_64::CHMOD => Some("chmod"),
            x86_64::FCHMOD => Some("fchmod"),
            x86_64::CHOWN => Some("chown"),
            x86_64::FCHOWN => Some("fchown"),
            x86_64::LCHOWN => Some("lchown"),
            x86_64::FCHMODAT => Some("fchmodat"),
            x86_64::UMASK => Some("umask"),
            x86_64::FTRUNCATE => Some("ftruncate"),
            x86_64::FALLOCATE => Some("fallocate"),
            x86_64::RENAME => Some("rename"),
            x86_64::SYMLINK => Some("symlink"),
            x86_64::LINK => Some("link"),
            x86_64::SYNC => Some("sync"),
            x86_64::ARCH_PRCTL => Some("arch_prctl"),
            x86_64::SET_ROBUST_LIST => Some("set_robust_list"),
            x86_64::RSEQ => Some("rseq"),
            x86_64::PRLIMIT64 => Some("prlimit64"),
            x86_64::STATFS => Some("statfs"),
            x86_64::FSTATFS => Some("fstatfs"),
            x86_64::CLONE => Some("clone"),
            x86_64::FORK => Some("fork"),
            x86_64::VFORK => Some("vfork"),
            x86_64::EXECVE => Some("execve"),
            x86_64::WAIT4 => Some("wait4"),
            x86_64::PIPE2 => Some("pipe2"),
            x86_64::PIPE => Some("pipe"),
            x86_64::SETPGID => Some("setpgid"),
            x86_64::SETSID => Some("setsid"),
            x86_64::GETPGID => Some("getpgid"),
            x86_64::GETPRIORITY => Some("getpriority"),
            x86_64::SETPRIORITY => Some("setpriority"),
            x86_64::PERSONALITY => Some("personality"),
            x86_64::SCHED_SETAFFINITY => Some("sched_setaffinity"),
            x86_64::IOPRIO_SET => Some("ioprio_set"),
            x86_64::IOPRIO_GET => Some("ioprio_get"),
            x86_64::FSYNC => Some("fsync"),
            x86_64::FDATASYNC => Some("fdatasync"),
            x86_64::UNSHARE => Some("unshare"),
            x86_64::FCHDIR => Some("fchdir"),
            x86_64::SETGROUPS => Some("setgroups"),
            x86_64::CHROOT => Some("chroot"),
            x86_64::GETPPID => Some("getppid"),
            x86_64::SYSINFO => Some("sysinfo"),
            x86_64::REBOOT => Some("reboot"),
            x86_64::SYSLOG => Some("syslog"),
            x86_64::INIT_MODULE => Some("init_module"),
            x86_64::DELETE_MODULE => Some("delete_module"),
            x86_64::FINIT_MODULE => Some("finit_module"),
            x86_64::SWAPON => Some("swapon"),
            x86_64::SWAPOFF => Some("swapoff"),
            x86_64::PIVOT_ROOT => Some("pivot_root"),
            x86_64::UMOUNT2 => Some("umount2"),
            x86_64::FLOCK => Some("flock"),
            x86_64::SHMGET => Some("shmget"),
            x86_64::SHMCTL => Some("shmctl"),
            x86_64::SEMGET => Some("semget"),
            x86_64::SEMCTL => Some("semctl"),
            x86_64::MSGGET => Some("msgget"),
            x86_64::MSGCTL => Some("msgctl"),
            x86_64::GETITIMER => Some("getitimer"),
            x86_64::SETITIMER => Some("setitimer"),
            x86_64::SOCKET => Some("socket"),
            x86_64::SOCKETPAIR => Some("socketpair"),
            x86_64::BIND => Some("bind"),
            x86_64::CONNECT => Some("connect"),
            x86_64::SENDTO => Some("sendto"),
            x86_64::RECVFROM => Some("recvfrom"),
            x86_64::GETSOCKNAME => Some("getsockname"),
            x86_64::SETXATTR => Some("setxattr"),
            x86_64::LSETXATTR => Some("lsetxattr"),
            x86_64::FSETXATTR => Some("fsetxattr"),
            x86_64::MOUNT => Some("mount"),
            x86_64::POLL => Some("poll"),
            x86_64::SELECT => Some("select"),
            x86_64::PSELECT6 => Some("pselect6"),
            x86_64::SYSFS => Some("sysfs"),
            x86_64::TKILL => Some("tkill"),
            x86_64::INOTIFY_INIT1 => Some("inotify_init1"),
            x86_64::INOTIFY_INIT => Some("inotify_init"),
            x86_64::INOTIFY_ADD_WATCH => Some("inotify_add_watch"),
            x86_64::ADJTIMEX => Some("adjtimex"),
            x86_64::SETUID => Some("setuid"),
            x86_64::SETGID => Some("setgid"),
            x86_64::SETREUID => Some("setreuid"),
            x86_64::SETREGID => Some("setregid"),
            x86_64::SETRESUID => Some("setresuid"),
            x86_64::SETRESGID => Some("setresgid"),
            x86_64::SCHED_SETPARAM => Some("sched_setparam"),
            x86_64::SCHED_GETPARAM => Some("sched_getparam"),
            x86_64::SCHED_SETSCHEDULER => Some("sched_setscheduler"),
            x86_64::SCHED_GETSCHEDULER => Some("sched_getscheduler"),
            x86_64::SCHED_GET_PRIORITY_MAX => Some("sched_get_priority_max"),
            x86_64::SCHED_GET_PRIORITY_MIN => Some("sched_get_priority_min"),
            x86_64::CHDIR => Some("chdir"),
            x86_64::KILL => Some("kill"),
            _ => None,
        },
        GuestAbi::MipsO32 => mips_o32::name(nr),
        GuestAbi::Aarch64Linux => aarch64::name(nr),
        GuestAbi::ArmLinux => arm::name(nr),
        GuestAbi::Unknown => None,
    }
}

/// 初期スタックの写像を作る。`top` はスタック上端（16B整列）で、戻り値は
/// （配置するバイト列，初期SP）である。引数・環境はNUL終端文字列として置く。
/// 配置の規約は psABI と Linux の慣行に従う.
// Ref: SPEC-RISCV-PSABI (v1.0).
#[must_use]
pub fn build_initial_stack(
    top: u64,
    args: &[Vec<u8>],
    env: &[Vec<u8>],
    auxv: &[(u64, u64)],
) -> (Vec<u8>, u64) {
    build_initial_stack_ws(top, args, env, auxv, 8, Endian::Le)
}

/// `build_initial_stack` にゲストのデータエンディアンを添える形。
/// auxv や argv ポインタの各ワードはゲストのエンディアンで書く。
#[must_use]
pub fn build_initial_stack_endian(
    top: u64,
    args: &[Vec<u8>],
    env: &[Vec<u8>],
    auxv: &[(u64, u64)],
    endian: Endian,
) -> (Vec<u8>, u64) {
    build_initial_stack_ws(top, args, env, auxv, 8, endian)
}

/// i386 の初期スタック。エントリ幅が 4 バイト（argc/argv/envp/auxv すべて u32）。
pub fn build_initial_stack32(
    top: u64,
    args: &[Vec<u8>],
    env: &[Vec<u8>],
    auxv: &[(u64, u64)],
) -> (Vec<u8>, u64) {
    build_initial_stack_ws(top, args, env, auxv, 4, Endian::Le)
}

/// `build_initial_stack32` にゲストのデータエンディアンを添える形。
/// o32/n32 の MIPS はエントリ幅が 4 バイト。
#[must_use]
pub fn build_initial_stack32_endian(
    top: u64,
    args: &[Vec<u8>],
    env: &[Vec<u8>],
    auxv: &[(u64, u64)],
    endian: Endian,
) -> (Vec<u8>, u64) {
    build_initial_stack_ws(top, args, env, auxv, 4, endian)
}

fn build_initial_stack_ws(
    top: u64,
    args: &[Vec<u8>],
    env: &[Vec<u8>],
    auxv: &[(u64, u64)],
    ws: usize,
    endian: Endian,
) -> (Vec<u8>, u64) {
    let w = |out: &mut [u8], off: usize, v: u64| {
        let b = match endian {
            // 8 バイト値の下位 ws バイトを取り出す。BE は末尾側。
            Endian::Be => v.to_be_bytes()[8 - ws..].to_vec(),
            Endian::Le => v.to_le_bytes()[..ws].to_vec(),
        };
        out[off..off + ws].copy_from_slice(&b);
    };
    // AT_RANDOM (25) が指す 16 バイト。スタックガード等の種。
    // 実機は execve のたびに乱数を置くが、再現性のため固定種にする
    // （execve 後も同じ値になる）。
    const AT_RANDOM_SEED: [u8; 16] = [
        0x35, 0xA7, 0xC1, 0x5E, 0x9B, 0x02, 0xF8, 0x6D, 0x4E, 0x11, 0x88, 0xD9, 0x27, 0xBC, 0x73,
        0xE0,
    ];
    let strings_len: usize = args.iter().map(|a| a.len() + 1).sum::<usize>()
        + env.iter().map(|e| e.len() + 1).sum::<usize>()
        + AT_RANDOM_SEED.len();
    // AT_EXECFN を args[0] 向けに1件足す（args 空では付けない）。
    // AT_RANDOM は常に1件足す。終端の AT_NULL は +1 側に含む。
    let execfn_extra: usize = if args.is_empty() { 0 } else { 2 * ws };
    let arrays_len: usize =
        ws * (1 + (args.len() + 1) + (env.len() + 1)) + 2 * ws * (auxv.len() + 2) + execfn_extra;
    let total = arrays_len + strings_len;
    let aligned = total.next_multiple_of(16);
    let sp = top - aligned as u64;
    let mut img = vec![0u8; aligned];
    let str_base = sp + (aligned - strings_len) as u64;
    // 文字列を詰める。
    let mut pos = 0usize;
    let mut addrs = Vec::new();
    for s in args.iter().chain(env.iter()) {
        let addr = str_base + pos as u64;
        img[aligned - strings_len + pos..aligned - strings_len + pos + s.len()].copy_from_slice(s);
        pos += s.len() + 1; // NUL は vec 初期値の 0 のまま.
        addrs.push(addr);
    }
    let rand_addr = str_base + pos as u64;
    img[aligned - strings_len + pos..aligned - strings_len + pos + AT_RANDOM_SEED.len()]
        .copy_from_slice(&AT_RANDOM_SEED);
    pos += AT_RANDOM_SEED.len();
    // 配列部。
    let mut off = 0usize;
    w(&mut img, off, args.len() as u64);
    off += ws;
    for addr in addrs.iter().take(args.len()) {
        w(&mut img, off, *addr);
        off += ws;
    }
    off += ws; // argv NULL.
    for i in 0..env.len() {
        w(&mut img, off, addrs[args.len() + i]);
        off += ws;
    }
    off += ws; // envp NULL.
    for (k, v) in auxv {
        w(&mut img, off, *k);
        w(&mut img, off + ws, *v);
        off += 2 * ws;
    }
    // AT_RANDOM (25) は上で詰めた 16 バイトの番地を指す。
    // glibc の _dl_random がここからスタックガードを取る.
    const AT_RANDOM: u64 = 25;
    w(&mut img, off, AT_RANDOM);
    w(&mut img, off + ws, rand_addr);
    off += 2 * ws;
    // AT_EXECFN (31) は args[0] の番地を指す。静的 glibc の _dl_get_origin が参照する.
    // args が空の単体テストでは付けない.
    if !args.is_empty() {
        const AT_EXECFN: u64 = 31;
        w(&mut img, off, AT_EXECFN);
        w(&mut img, off + ws, addrs[0]);
        off += 2 * ws;
    }
    // AT_NULL 終端は img のゼロ初期化で表す.
    let _ = (off, pos);
    (img, sp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack32_be_writes_low_bytes() {
        // BE 32 ビット環境の初期スタックでは、argc/argv/auxv の各ワードは
        // 8 バイト値の下位 4 バイトでなければならない。上位を取ると
        // すべて 0 になり、auxv が読めず musl の libc.page_size が 0 になる
        // （n32 の mallocng が pagesize-1=0xffffffff でマスクして崩壊する）。
        let (img, sp) =
            build_initial_stack32_endian(0x8000, &[b"p".to_vec()], &[], &[(6, 0x1000)], Endian::Be);
        // sp からの配列: argc=1, argv[0]=文字列番地, argv NULL, auxv(6,0x1000),
        // AT_RANDOM(25), AT_EXECFN(31), AT_NULL.
        let u32be = |off: usize| u32::from_be_bytes(img[off..off + 4].try_into().unwrap());
        assert_eq!(u32be(0), 1, "argc");
        let argv0 = u32be(4);
        assert!(
            argv0 > sp as u32 && argv0 < 0x8000,
            "argv[0] ptr {argv0:#x}"
        );
        assert_eq!(u32be(8), 0, "argv NULL");
        assert_eq!(u32be(12), 0, "envp NULL");
        assert_eq!(u32be(16), 6, "AT_PAGESZ key");
        assert_eq!(u32be(20), 0x1000, "AT_PAGESZ value");
        assert_eq!(u32be(24), 25, "AT_RANDOM key");
        let rnd = u32be(28);
        assert!(rnd > sp as u32 && rnd < 0x8000, "AT_RANDOM ptr {rnd:#x}");
        assert_eq!(u32be(32), 31, "AT_EXECFN key");
    }

    #[test]
    fn rv64_stage1_numbers() {
        // 代表的な番号が asm-generic と一致する。
        assert_eq!(rv64::WRITE, 64);
        assert_eq!(rv64::EXIT_GROUP, 94);
        assert_eq!(rv64::MMAP, 222);
        assert_eq!(rv64::BRK, 214);
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 64), Some("write"));
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 291), Some("statx"));
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 61), Some("getdents64"));
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 9999), None);
        assert_eq!(rv64::SENDFILE, 71);
        assert_eq!(syscall_name(GuestAbi::Rv64Linux, 71), Some("sendfile"));
        assert_eq!(rv64::CLOCK_NANOSLEEP, 115);
        assert_eq!(
            syscall_name(GuestAbi::Rv64Linux, 115),
            Some("clock_nanosleep")
        );
    }

    #[test]
    fn x86_64_stage1_numbers() {
        // 代表的な番号が x86_64 の UAPI と一致する（全体は層6で突合せ）。
        assert_eq!(x86_64::WRITE, 1);
        assert_eq!(x86_64::EXIT_GROUP, 231);
        assert_eq!(x86_64::MMAP, 9);
        assert_eq!(x86_64::BRK, 12);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 1), Some("write"));
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 332), Some("statx"));
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 217), Some("getdents64"));
        assert_eq!(x86_64::SEMGET, 64);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 64), Some("semget"));
        assert_eq!(x86_64::SENDFILE, 40);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 40), Some("sendfile"));
        assert_eq!(x86_64::TIME, 201);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 201), Some("time"));
        assert_eq!(x86_64::NANOSLEEP, 35);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 35), Some("nanosleep"));
        assert_eq!(x86_64::SCHED_GETAFFINITY, 204);
        assert_eq!(
            syscall_name(GuestAbi::X86_64Linux, 204),
            Some("sched_getaffinity")
        );
        assert_eq!(x86_64::CLOCK_NANOSLEEP, 230);
        assert_eq!(
            syscall_name(GuestAbi::X86_64Linux, 230),
            Some("clock_nanosleep")
        );
        assert_eq!(x86_64::GETGROUPS, 115);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 115), Some("getgroups"));
        assert_eq!(x86_64::STATFS, 137);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 137), Some("statfs"));
        assert_eq!(x86_64::FSTATFS, 138);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 138), Some("fstatfs"));
        assert_eq!(x86_64::STAT, 4);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 4), Some("stat"));
        assert_eq!(x86_64::LSTAT, 6);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 6), Some("lstat"));
        assert_eq!(x86_64::ARCH_PRCTL, 158);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 158), Some("arch_prctl"));
        assert_eq!(x86_64::SET_ROBUST_LIST, 273);
        assert_eq!(
            syscall_name(GuestAbi::X86_64Linux, 273),
            Some("set_robust_list")
        );
        assert_eq!(x86_64::RSEQ, 334);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 334), Some("rseq"));
        assert_eq!(x86_64::PRLIMIT64, 302);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 302), Some("prlimit64"));
        assert_eq!(x86_64::LINK, 86);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 86), Some("link"));
        assert_eq!(x86_64::SYNC, 162);
        assert_eq!(syscall_name(GuestAbi::X86_64Linux, 162), Some("sync"));
    }

    #[test]
    fn x86_32_stage1_numbers() {
        // 代表的な番号が 32ビットの UAPI と一致する（全体は層6で突合せ）。
        // newfstatat は 32ビットに存在しないため fstatat64 を持つ。
        assert_eq!(x86_32::WRITE, 4);
        assert_eq!(x86_32::EXIT_GROUP, 252);
        assert_eq!(x86_32::MMAP, 90);
        assert_eq!(x86_32::BRK, 45);
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 4), Some("write"));
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 383), Some("statx"));
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 300), Some("fstatat64"));
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 220), Some("getdents64"));
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 64), Some("getppid"));
        assert_eq!(x86_32::SENDFILE, 187);
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 187), Some("sendfile"));
        assert_eq!(x86_32::TIME, 13);
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 13), Some("time"));
        assert_eq!(x86_32::NANOSLEEP, 162);
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 162), Some("nanosleep"));
        assert_eq!(x86_32::GETGROUPS, 80);
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 80), Some("getgroups"));
        assert_eq!(x86_32::GETGROUPS32, 205);
        assert_eq!(
            syscall_name(GuestAbi::X86_32Linux, 205),
            Some("getgroups32")
        );
        assert_eq!(x86_32::STATFS, 99);
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 99), Some("statfs"));
        assert_eq!(x86_32::FSTATFS, 100);
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 100), Some("fstatfs"));
        assert_eq!(x86_32::STATFS64, 268);
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 268), Some("statfs64"));
        assert_eq!(x86_32::FSTATFS64, 269);
        assert_eq!(syscall_name(GuestAbi::X86_32Linux, 269), Some("fstatfs64"));
    }

    #[test]
    fn initial_stack_layout() {
        let top = 0x7fff_0000u64;
        let args = [b"prog".to_vec(), b"hi".to_vec()];
        let env: [Vec<u8>; 0] = [];
        let (img, sp) = build_initial_stack(top, &args, &env, &[(6, 0x1000)]);
        assert_eq!(sp % 16, 0);
        let r64 = |off: usize| u64::from_le_bytes(img[off..off + 8].try_into().unwrap());
        assert_eq!(r64(0), 2);
        let a0 = r64(8);
        let a1 = r64(16);
        assert_eq!(r64(24), 0);
        assert_eq!(r64(32), 0);
        // auxv: (6,0x1000) + AT_RANDOM(25,seed) + AT_EXECFN(31,args[0]) + AT_NULL.
        assert_eq!(r64(40), 6);
        assert_eq!(r64(48), 0x1000);
        assert_eq!(r64(56), 25);
        let rnd = r64(64);
        assert_eq!(r64(72), 31);
        assert_eq!(r64(80), a0);
        assert_eq!(r64(88), 0);
        assert_eq!(r64(96), 0);
        // 文字列の解決。
        let at = |addr: u64| (addr - sp) as usize;
        assert_eq!(&img[at(a0)..at(a0) + 4], b"prog");
        assert_eq!(&img[at(a1)..at(a1) + 2], b"hi");
        // AT_RANDOM は 16 バイトの種を指す（argv/envp 文字列の後ろ）。
        assert!(rnd > a1, "AT_RANDOM は文字列の後ろ");
        assert_eq!(img[at(rnd)..at(rnd) + 16].len(), 16);
        assert_eq!(syscall_name(GuestAbi::Unknown, 64), None);
    }

    #[test]
    fn mips_o32_numbers() {
        assert_eq!(mips_o32::name(4001), Some("exit"));
        assert_eq!(mips_o32::name(4004), Some("write"));
        assert_eq!(syscall_name(GuestAbi::MipsO32, 4004), Some("write"));
        assert_eq!(syscall_name(GuestAbi::MipsO32, 4001), Some("exit"));
        assert_eq!(syscall_name(GuestAbi::MipsO32, 9999), None);
    }
}
