// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PA-RISC の命令意味論。
//!
//! 段階17-2 は骨格のみ。レジスタ参照と、後続段階が足す
//! 意味論の入口 `exec`（現状は全て `Ok(false)` = 未実装）
//! を提供する。
//!
//! 出典は SPEC-PARISC-11・SPEC-PARISC-20 である。
//! Ref: SPEC-PARISC-11, SPEC-PARISC-20.

use polyisa_sem::{Backend, StateRef, W64};

use super::{CpuState, Insn};

/// 汎用レジスタ参照。r0 は読み出しで常に 0、書き込みは破棄される。
// Ref: SPEC-PARISC-11 §2.2（r0 はソースで 0 を供給する。
// 実機でも書き込みは格納されるが、参照は常に 0 を返す契約に揃える）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gr(pub u8);

impl Gr {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, gr) + (self.0 as usize) * 8)
    }

    /// 読み出し。r0 はハード的に 0 を返す。
    pub fn get<B: Backend>(self, b: &mut B) -> B::V<W64> {
        if self.0 == 0 {
            b.konst::<W64>(0)
        } else {
            b.get(self.state())
        }
    }

    /// 書き込み。r0 への書き込みは捨てる。
    pub fn set<B: Backend>(self, b: &mut B, v: B::V<W64>) {
        if self.0 != 0 {
            b.set(self.state(), v);
        }
    }
}

/// FP レジスタ参照。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fpr(pub u8);

impl Fpr {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, f) + (self.0 as usize) * 8)
    }
}

/// 制御レジスタ参照。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cr(pub u8);

impl Cr {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, cr) + (self.0 as usize) * 8)
    }
}

/// 空間レジスタ参照。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Sr(pub u8);

impl Sr {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, sr) + (self.0 as usize) * 8)
    }
}

/// 命令 1 個の実行。`Ok(true)` = 実行した、`Ok(false)` = 未実装。
pub fn exec<B: Backend>(_b: &mut B, _insn: Insn, _word: u32, _pc: u64) -> Result<bool, B::Exit> {
    Ok(false)
}
