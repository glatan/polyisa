// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 用のシステムコール文脈。`cli` の実行側と共有する。
//!
//! GAP-0001（ADR-0015）の移管の最初の一片として、`run_x86.rs` にあった
//! 定義を移す。番号表は従来どおり `super`（`GuestAbi`）に置く。

// Ref: SRC-LINUX (7.3).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_x86::sem::Gpr;

use super::TrapOutcome;

/// Linux 汎用の errno 番号の一部。負数で返す。
// Ref: SRC-LINUX (7.3).
pub const EPERM: u32 = 1;
pub const ENOENT: u32 = 2;
pub const ESRCH: u32 = 3;
pub const ENOEXEC: u32 = 8;
pub const EBADF: u32 = 9;
pub const ECHILD: u32 = 10;
pub const EAGAIN: u32 = 11;
pub const EINTR: u32 = 4;
pub const EFAULT: u32 = 14;
pub const EACCES: u32 = 13;
pub const ENOMEM: u32 = 12;
pub const ENOTDIR: u32 = 20;
pub const EINVAL: u32 = 22;
pub const EPIPE: u32 = 32;
pub const ERANGE: u32 = 34;
pub const ENOTTY: u32 = 25;

pub fn get64(env: &mut BareEnv, r: Gpr) -> u64 {
    polyisa_guest_x86::sem::read64(&mut env.backend, r)
}

pub fn set64(env: &mut BareEnv, r: Gpr, v: u64) {
    polyisa_guest_x86::sem::write64(&mut env.backend, r, v)
}

/// dirfd の AT_FDCWD を 32 ビットで比べるときの値。
pub const AT_FDCWD_U32: u32 = 0xffff_ff9c;

/// 32ビットの負 errno。
pub fn neg_errno(n: u32) -> u32 {
    (n as i32).wrapping_neg() as u32
}

/// 64ビットの負 errno（符号拡張する）。
pub fn neg_errno64(n: u32) -> u64 {
    (n as i32).wrapping_neg() as i64 as u64
}

/// 1 回のシステムコールで共通に使う値。
pub struct SysCtx {
    pub r_a: Gpr,
    pub r_b: Gpr,
    pub r_c: Gpr,
    pub is64: bool,
    pub at_fdcwd: u64,
}

impl SysCtx {
    /// dirfd が AT_FDCWD か。x86-64 は下位 32 ビット、i386 は値そのものを比べる.
    pub fn is_at_fdcwd(&self, dirfd: u64) -> bool {
        if self.is64 {
            (dirfd as u32) == AT_FDCWD_U32
        } else {
            dirfd == self.at_fdcwd
        }
    }

    /// 戻り値の負 errno。x86-64 は 64 ビット符号拡張、i386 は 32 ビット。
    pub fn neg(&self, n: u32) -> u64 {
        if self.is64 {
            neg_errno64(n)
        } else {
            u64::from(neg_errno(n))
        }
    }
}

/// socket 系。段階 C までの暫定で常に EPERM。失敗形のアプレット合わせに使う。
pub fn sys_socket(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), cx.neg(EPERM));
    Some(TrapOutcome::Handled)
}

/// socketpair。`sys_socket` に委ねる。
pub fn sys_socketpair(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_socket(env, cx)
}

/// bind。`sys_socket` に委ねる。
pub fn sys_bind(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_socket(env, cx)
}

/// connect。`sys_socket` に委ねる。
pub fn sys_connect(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_socket(env, cx)
}

/// sendto。`sys_socket` に委ねる。
pub fn sys_sendto(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_socket(env, cx)
}

/// recvfrom。`sys_socket` に委ねる。
pub fn sys_recvfrom(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_socket(env, cx)
}

/// getsockname。`sys_socket` に委ねる。
pub fn sys_getsockname(env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_socket(env, cx)
}
