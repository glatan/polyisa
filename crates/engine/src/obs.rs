// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 実行の観測点。
//!
//! トレース、デバッガ、統計のための呼出し点を `Observer` として持つ。
//! 観測しない `NoObserver` では呼出しがすべてインライン展開されて消える。

use crate::bare::BareEnv;
use crate::run::Outcome;

/// 実行の観測点。呼び出しはインラインで消える形（`NoObserver`）。
/// 各呼出しには実行環境 `env` を渡すので、観測側はゲストメモリや
/// レジスタを読んで命令の逆アセンブルなどができる。
pub trait Observer {
    /// 1 ステップの実行前。`pc` はこれから実行を試みる命令の位置。
    /// ブレークポイントの停止や実行の失敗で命令が実行されないときも
    /// 呼ばれるので、「実行した命令」の確定は `post_step` で行う。
    fn pre_step(&mut self, env: &mut BareEnv, pc: u64) {
        let _ = (env, pc);
    }

    /// 1 ステップの実行後。`pc` は実行後の位置。退出したステップでは
    /// 呼ばない。実行した命令の記録はこの呼出しで確定する。
    fn post_step(&mut self, env: &mut BareEnv, pc: u64) {
        let _ = (env, pc);
    }

    /// 実行ループの退出時に一度だけ呼ぶ。
    fn exit(&mut self, env: &mut BareEnv, outcome: &Outcome) {
        let _ = (env, outcome);
    }
}

/// 観測しない観測点。
pub struct NoObserver;

impl Observer for NoObserver {}
