// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x32（Linux・ILP32、EM_X86_64 + ELFCLASS32）のシステムコール番号。
//! 値はカーネルの UAPI 由来の事実である。x32 専用の呼び出しは
//! `SYSCALL_BIT`（__X32_SYSCALL_BIT = 0x40000000）を立てた 512–547 に
//! あり、ビットのない番号は x86-64 と同じ表（`x86_64` モジュール）を使う。
// Ref: SRC-LINUX (7.3).

/// __X32_SYSCALL_BIT。x32 専用番号の目印。
pub const SYSCALL_BIT: u64 = 0x4000_0000;

pub const RT_SIGACTION: u64 = SYSCALL_BIT | 512;
pub const RT_SIGRETURN: u64 = SYSCALL_BIT | 513;
pub const IOCTL: u64 = SYSCALL_BIT | 514;
pub const READV: u64 = SYSCALL_BIT | 515;
pub const WRITEV: u64 = SYSCALL_BIT | 516;
pub const RECVFROM: u64 = SYSCALL_BIT | 517;
pub const SENDMSG: u64 = SYSCALL_BIT | 518;
pub const RECVMSG: u64 = SYSCALL_BIT | 519;
pub const EXECVE: u64 = SYSCALL_BIT | 520;
pub const PTRACE: u64 = SYSCALL_BIT | 521;
pub const RT_SIGPENDING: u64 = SYSCALL_BIT | 522;
pub const RT_SIGTIMEDWAIT: u64 = SYSCALL_BIT | 523;
pub const RT_SIGQUEUEINFO: u64 = SYSCALL_BIT | 524;
pub const SIGALTSTACK: u64 = SYSCALL_BIT | 525;
pub const TIMER_CREATE: u64 = SYSCALL_BIT | 526;
pub const MQ_NOTIFY: u64 = SYSCALL_BIT | 527;
pub const KEXEC_LOAD: u64 = SYSCALL_BIT | 528;
pub const WAITID: u64 = SYSCALL_BIT | 529;
pub const SET_ROBUST_LIST: u64 = SYSCALL_BIT | 530;
pub const GET_ROBUST_LIST: u64 = SYSCALL_BIT | 531;
pub const VMSPLICE: u64 = SYSCALL_BIT | 532;
pub const MOVE_PAGES: u64 = SYSCALL_BIT | 533;
pub const PREADV: u64 = SYSCALL_BIT | 534;
pub const PWRITEV: u64 = SYSCALL_BIT | 535;
pub const RT_TGSIGQUEUEINFO: u64 = SYSCALL_BIT | 536;
pub const RECVMMSG: u64 = SYSCALL_BIT | 537;
pub const SENDMMSG: u64 = SYSCALL_BIT | 538;
pub const PROCESS_VM_READV: u64 = SYSCALL_BIT | 539;
pub const PROCESS_VM_WRITEV: u64 = SYSCALL_BIT | 540;
pub const SETSOCKOPT: u64 = SYSCALL_BIT | 541;
pub const GETSOCKOPT: u64 = SYSCALL_BIT | 542;
pub const IO_SETUP: u64 = SYSCALL_BIT | 543;
pub const IO_SUBMIT: u64 = SYSCALL_BIT | 544;
pub const EXECVEAT: u64 = SYSCALL_BIT | 545;
pub const PREADV2: u64 = SYSCALL_BIT | 546;
pub const PWRITEV2: u64 = SYSCALL_BIT | 547;
