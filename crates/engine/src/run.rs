// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 実行ループの駆動。
//!
//! 繰り返しと実行予算・退出の判定をここで行い、1 命令ぶんのフェッチ・
//! 解読・意味論とトラップ境界の解決は ISA ごとの `step` 実装に委ねる。
//! `engine` はゲスト ISA に依存しないので、命令の振り分けは
//! `guests/*` を見える側（`cli` や OS パーソナリティ）が渡す。

use crate::bare::BareEnv;
use crate::{Budget, EngineCtx, Stop, Unimpl, VcpuRunner};

/// 実行の結果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// 終了コード付きの正常終了。
    Exit(u64),
    /// 未実装の到達点。
    Unimplemented { pc: u64, word: u128 },
    /// 実行予算（ステップ数）を使い切った。
    StepLimit { pc: u64 },
    /// 実行できるスレッドがない。待ちの対象は報告済み。
    Deadlock,
}

/// トラップの処理結果。OS パーソナリティが `handle_trap` の戻り値として返す。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrapOutcome {
    /// 処理して次の命令から続ける。
    Handled,
    /// 終了コード付きで抜ける。
    Exit(u32),
    /// このスレッドは待っている。実行ループが他のスレッドへ切り替える。
    Blocked,
    /// 未実装として止める。
    Unimplemented,
}

/// 実行ループと OS パーソナリティの境界。SYSCALL や INT 命令などの
/// トラップは `handle_trap` に渡し、ゲスト状態の読み書きは実装側で行う。
pub trait TrapHandler {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome;

    /// プログラムブレークの初期値を伝える。ヒープを持つ
    /// ハンドラだけが実装する。既定では何もしない。
    fn init_brk(&mut self, _image_end: u64) {}

    /// 1 命令を実行したあと。既定では何もしない。
    fn after_step(&mut self, _env: &mut BareEnv) {}

    /// 待っているスレッドから切り替える。切り替えたら真。
    fn on_block(&mut self, _env: &mut BareEnv) -> bool {
        false
    }

    /// 終了を別のスレッドの実行へ引き継ぐなら真。既定では終了で抜ける。
    fn take_exit(&mut self, _env: &mut BareEnv, _code: u32) -> bool {
        false
    }
}

/// 実行ループ。`step` が 1 命令ぶんのフェッチ・解読・意味論とトラップ
/// 境界の解決を担い、継続なら `Ok(())`、退出なら退出理由を返す。
/// `pc` は実行中のプログラムカウンタを読む。
pub fn run<H: ?Sized, S, P>(
    env: &mut BareEnv,
    sys: &mut H,
    limit: u64,
    pc: P,
    mut step: S,
) -> Outcome
where
    S: FnMut(&mut BareEnv, &mut H) -> Result<(), Outcome>,
    P: Fn(&mut BareEnv) -> u64,
{
    for _ in 0..limit {
        if let Err(o) = step(env, sys) {
            return o;
        }
    }
    Outcome::StepLimit { pc: pc(env) }
}

/// `step` 方式の実行器を `VcpuRunner` に適合する。
///
/// 実行予算はステップ数のみ受け付ける。サイクル予算はタイミングモデルとの
/// 接続が必要で、この駆動の範囲外である。
pub struct StepRunner<'a, H: ?Sized, S, P> {
    pub env: &'a mut BareEnv,
    pub sys: &'a mut H,
    pub pc: P,
    pub step: S,
}

impl<H: ?Sized, S, P> VcpuRunner for StepRunner<'_, H, S, P>
where
    S: FnMut(&mut BareEnv, &mut H) -> Result<(), Outcome>,
    P: Fn(&mut BareEnv) -> u64,
{
    fn run(&mut self, ctx: &mut EngineCtx, budget: Budget) -> Stop {
        let limit = match budget {
            Budget::Steps(n) => n,
            Budget::Cycles(_) => {
                return Stop::Unimplemented(Unimpl {
                    pc: (self.pc)(self.env),
                    name: "cycle budget".to_string(),
                });
            }
        };
        ctx.budget_left = 0;
        match run(self.env, self.sys, limit, &self.pc, &mut self.step) {
            Outcome::Exit(code) => Stop::Exit(code),
            Outcome::Unimplemented { pc, word } => Stop::Unimplemented(Unimpl {
                pc,
                name: format!("word {word:#x}"),
            }),
            Outcome::StepLimit { .. } => Stop::BudgetExhausted,
            Outcome::Deadlock => Stop::Deadlock,
        }
    }
}
