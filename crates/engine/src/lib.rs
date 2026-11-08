// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 実行エンジン。インタプリタのバックエンド、ブロック管理、実行ループ。
//!
//! 詳しくは [実行エンジン](../../docs/design/execution-engine.md) を見る。

#![forbid(unsafe_code)]

pub mod bare;
pub mod cache;
pub mod interp;

use polyisa_mem::Tlb;

/// 実行の単位の数か、仮想時間のサイクル数で与える。実時間では与えない。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Budget {
    Steps(u64),
    Cycles(u64),
}

/// 未実装の到達点の情報。
#[derive(Clone, Debug)]
pub struct Unimpl {
    pub pc: u64,
    pub name: String,
}

/// エンジンが呼び出し側に返す退出の理由。
#[derive(Clone, Debug)]
pub enum Stop {
    /// システムコール命令を実行した。
    Syscall,
    /// CPU 例外が起きた。
    Exception(polyisa_sem::GuestException),
    /// 実行予算を使い切った。
    BudgetExhausted,
    /// デバッガのブレークポイントに達した。
    Breakpoint(u64),
    /// 未実装の命令や機能に達した。
    Unimplemented(Unimpl),
}

/// ブロックキー。ページフレームの識別子、ページ内オフセット、実行モード、
/// CPU モデルの世代（機能集合と挙動パラメータの値の版）の組。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlockKey {
    /// ページフレームの識別子。暫定ではページ番号で代用する。
    pub frame: u64,
    /// ページ内オフセット。
    pub offset: u32,
    /// 実行モード（x86 の既定オペランドサイズなど）。
    pub mode: u32,
    /// CPU モデルの世代。`--cpu` の変更で変わる。
    pub model_gen: u64,
}

/// vCPU が持つ実行の状態。ゲスト ISA の CPU 状態は外から渡す。
#[derive(Debug)]
pub struct Vcpu {
    /// 現在の実行モード。
    pub mode: u32,
    /// CPU モデルの世代。ブロックキーに含める。
    pub model_gen: u64,
    /// ソフトウェア TLB。
    pub tlb: Tlb,
    /// 予約付きロードの予約。
    pub reservation: polyisa_mem::Reservation,
    /// 実行したステップ数。
    pub steps: u64,
}

impl Vcpu {
    #[must_use]
    pub fn new() -> Self {
        Self {
            mode: 0,
            model_gen: 0,
            tlb: Tlb::new(64),
            reservation: polyisa_mem::Reservation::empty(),
            steps: 0,
        }
    }

    /// 現在位置のブロックキーを作る。
    #[must_use]
    pub const fn block_key(&self, frame: u64, offset: u32) -> BlockKey {
        BlockKey {
            frame,
            offset,
            mode: self.mode,
            model_gen: self.model_gen,
        }
    }
}

impl Default for Vcpu {
    fn default() -> Self {
        Self::new()
    }
}

/// エンジンの実行時の引き数。予算の残量などを持つ。
#[derive(Debug, Default)]
pub struct EngineCtx {
    /// 残りの予算（ステップ数）。ブロックの終わりで確認する。
    pub budget_left: u64,
}

/// vCPU の実行器。仮想カーネルは型を知らずに `run` を呼ぶ。
pub trait VcpuRunner {
    fn run(&mut self, ctx: &mut EngineCtx, budget: Budget) -> Stop;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_key_includes_model() {
        let mut v = Vcpu::new();
        let a = v.block_key(1, 0);
        v.model_gen = 2;
        let b = v.block_key(1, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn budget_variants() {
        assert_ne!(Budget::Steps(1), Budget::Cycles(1));
    }
}
