// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 用のシステムコール文脈。`cli` の実行側と共有する。
//!
//! GAP-0001（ADR-0015）の移管の最初の一片として、`run_x86.rs` にあった
//! 定義を移す。番号表は従来どおり `super`（`GuestAbi`）に置く。

// Ref: SRC-LINUX (7.3).

use polyisa_guest_x86::sem::Gpr;

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
