// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 実行ループの駆動。
//!
//! 繰り返しと実行予算・退出の判定をここで行い、1 命令ぶんのフェッチ・
//! 解読・意味論とトラップ境界の解決は ISA ごとの `step` 実装に委ねる。
//! `engine` はゲスト ISA に依存しないので、命令の振り分けは
//! `guests/*` を見える側（`cli` や OS パーソナリティ）が渡す。

use std::collections::BTreeSet;

use crate::bare::BareEnv;
use crate::obs::{NoObserver, Observer};
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
    /// ブレークポイントの表にある pc に達した。命令は実行していない。
    Breakpoint { pc: u64 },
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

    /// 解読不能または未実装の命令語 `word`（実行中の pc 位置）。
    /// コプロセッサ命令のカーネルエミュレーションや、削除命令の
    /// 補完（68040/68060 の unimplemented integer instruction 相当）
    /// に使う。Handled ならハンドラが復帰 PC を設定済みの契約
    /// （`pc` 自動進めはしない）。既定では未実装を返し、呼び出し側が
    /// 実機の例外（illegal/Line-A/Line-F）に写す。
    fn handle_unimpl(&mut self, _env: &mut BareEnv, _pc: u64, _word: u64) -> TrapOutcome {
        TrapOutcome::Unimplemented
    }
}

/// ブレークポイントの表。実行中の pc がこの表にあれば実行を止める。
/// ゲストのメモリは書き換えない。
#[derive(Clone, Default, Debug)]
pub struct Breakpoints(BTreeSet<u64>);

impl Breakpoints {
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// 登録する。すでにあれば偽。
    pub fn insert(&mut self, pc: u64) -> bool {
        self.0.insert(pc)
    }

    /// 外す。無ければ偽。
    pub fn remove(&mut self, pc: u64) -> bool {
        self.0.remove(&pc)
    }

    #[must_use]
    pub fn contains(&self, pc: u64) -> bool {
        self.0.contains(&pc)
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// `run_observed` に渡す集合の参照。
    #[must_use]
    pub fn as_set(&self) -> &BTreeSet<u64> {
        &self.0
    }

    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.iter().copied()
    }
}

/// 実行ループ。`step` が 1 命令ぶんのフェッチ・解読・意味論とトラップ
/// 境界の解決を担い、継続なら `Ok(())`、退出なら退出理由を返す。
/// `pc` は実行中のプログラムカウンタを読む。
pub fn run<H: ?Sized, S, P>(env: &mut BareEnv, sys: &mut H, limit: u64, pc: P, step: S) -> Outcome
where
    S: FnMut(&mut BareEnv, &mut H) -> Result<(), Outcome>,
    P: Fn(&mut BareEnv) -> u64,
{
    run_observed(env, sys, limit, pc, step, &BTreeSet::new(), &mut NoObserver)
}

/// 観測点とブレークポイントの表を持つ実行ループ。
///
/// 各ステップの前に `obs.pre_step`、pc が `bps` にあれば実行せず
/// `Outcome::Breakpoint` で止め、継続したステップの後に `obs.post_step` を
/// 呼ぶ。どの経路で抜けるときも `obs.exit` を一度だけ呼ぶ。
pub fn run_observed<H: ?Sized, S, P, O>(
    env: &mut BareEnv,
    sys: &mut H,
    limit: u64,
    pc: P,
    mut step: S,
    bps: &BTreeSet<u64>,
    obs: &mut O,
) -> Outcome
where
    S: FnMut(&mut BareEnv, &mut H) -> Result<(), Outcome>,
    P: Fn(&mut BareEnv) -> u64,
    O: Observer,
{
    let has_bps = !bps.is_empty();
    for _ in 0..limit {
        let at = pc(env);
        obs.pre_step(env, at);
        if has_bps && bps.contains(&at) {
            let o = Outcome::Breakpoint { pc: at };
            obs.exit(env, &o);
            return o;
        }
        if let Err(o) = step(env, sys) {
            obs.exit(env, &o);
            return o;
        }
        let at = pc(env);
        obs.post_step(env, at);
    }
    let o = Outcome::StepLimit { pc: pc(env) };
    obs.exit(env, &o);
    o
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
            Outcome::Breakpoint { pc } => Stop::Breakpoint(pc),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obs::Observer;

    struct Rec {
        log: Vec<String>,
    }

    impl Observer for Rec {
        fn pre_step(&mut self, _env: &mut BareEnv, pc: u64) {
            self.log.push(format!("pre {pc:#x}"));
        }
        fn post_step(&mut self, _env: &mut BareEnv, pc: u64) {
            self.log.push(format!("post {pc:#x}"));
        }
        fn exit(&mut self, _env: &mut BareEnv, outcome: &Outcome) {
            self.log.push(format!("exit {outcome:?}"));
        }
    }

    fn env() -> BareEnv {
        BareEnv::new(8)
    }

    #[test]
    fn breakpoint_stops_before_step() {
        let mut env = env();
        let mut sys = ();
        let mut bps = BTreeSet::new();
        bps.insert(0x10);
        let pc = std::cell::Cell::new(0u64);
        let mut obs = Rec { log: Vec::new() };
        let o = run_observed(
            &mut env,
            &mut sys,
            8,
            |_| pc.get(),
            |_, _: &mut ()| {
                pc.set(pc.get() + 4);
                Ok(())
            },
            &bps,
            &mut obs,
        );
        // pc=0,4 は実行、pc=0x10 で実行せず止まる。
        assert_eq!(o, Outcome::Breakpoint { pc: 0x10 });
        assert_eq!(pc.get(), 0x10);
        assert_eq!(
            obs.log,
            [
                "pre 0x0",
                "post 0x4",
                "pre 0x4",
                "post 0x8",
                "pre 0x8",
                "post 0xc",
                "pre 0xc",
                "post 0x10",
                "pre 0x10",
                "exit Breakpoint { pc: 16 }",
            ]
        );
    }

    #[test]
    fn exit_called_once_on_step_exit() {
        let mut env = env();
        let mut sys = ();
        let bps = BTreeSet::new();
        let mut obs = Rec { log: Vec::new() };
        let o = run_observed(
            &mut env,
            &mut sys,
            8,
            |_| 0,
            |_, _: &mut ()| Err(Outcome::Exit(3)),
            &bps,
            &mut obs,
        );
        assert_eq!(o, Outcome::Exit(3));
        assert_eq!(obs.log, ["pre 0x0", "exit Exit(3)"]);
    }

    #[test]
    fn breakpoints_table() {
        let mut bps = Breakpoints::new();
        assert!(bps.insert(0x20));
        assert!(!bps.insert(0x20));
        assert!(bps.contains(0x20));
        assert!(bps.remove(0x20));
        assert!(!bps.remove(0x20));
        bps.insert(0x30);
        bps.insert(0x10);
        assert_eq!(bps.iter().collect::<Vec<_>>(), [0x10, 0x30]);
        bps.clear();
        assert!(!bps.contains(0x30));
    }
}
