// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! JIT。意味論を IR に記録し、x86-64 の機械語にして実行する。
//!
//! 設計は docs/design/jit.md。インタプリタはオラクルとして残り、
//! JIT の実行はブロックの境界ごとに同じ CPU 状態・メモリを与える
//! ことを差分試験 `heavy_jit_diff` が確かめる。
//!
//! ```text
//! entry pc ──> Translate::key ──> blocks hit ──> 機械語
//!                  │ miss
//!                  └─> hot[pc] += 1 ──> 閾値未満 ──> IR 解釈
//!                                      閾値到達 ──> Translate::record
//!                                                  ──> optimize ──> compile
//! ```

// unsafe 許可クレート（docs/design/workspace.md「`unsafe` の扱い」）。
// 生成した機械語を実行するため。
#![allow(unsafe_code)]

pub mod ctx;
// ホストのバックエンドはホストの ISA ごとのモジュールに閉じる
// （docs/design/host.md）。生成コードは sysv64 呼出し規約で `rt`
// の関数を呼ぶので、x86-64 の Unix 系ホストだけが機械語を持てる。
#[cfg(all(unix, target_arch = "x86_64"))]
mod rt;
#[cfg(all(unix, target_arch = "x86_64"))]
mod x64;

/// ホストのバックエンド。対応ホストでは `x64`、それ以外では
/// コンパイルが常に失敗するスタブになり、ブロックは IR 解釈で走る。
#[cfg(all(unix, target_arch = "x86_64"))]
use x64 as backend;

/// バックエンドのないホスト向けのスタブ。`Compiled` は決して
/// 作られないので `Jit` の機械語の経路には入らない。
#[cfg(not(all(unix, target_arch = "x86_64")))]
mod backend {
    use polyisa_ir::Recorded;

    use crate::ctx::RtCtx;

    /// 対応ホストのバックエンドがないため作られないブロック。
    pub struct Compiled;

    impl Compiled {
        /// 実体がないため呼ばれない。
        ///
        /// # 安全性
        /// `Compiled` を得る経路がない。
        pub unsafe fn call(&self, _ctx: *mut RtCtx) {}
    }

    /// 対応ホストのバックエンドがないため常に `None`。
    pub fn compile(_rec: &Recorded) -> Option<Compiled> {
        None
    }
}

use std::collections::{HashMap, HashSet};

use polyisa_engine::interp::InterpBackend;
use polyisa_ir::{IrOutcome, Recorded};
use polyisa_sem::GuestException;

pub use ctx::{RtCtx, read_exc, write_exc};

/// ブロック実行の終わり方。`IrOutcome` と形を揃える。
#[derive(Clone, Debug)]
pub enum BlockExit {
    /// 次の fetch 先。
    Next(u64),
    /// 例外で抜けた。`pc` は例外を起こした命令、`next` はその直後。
    Raise {
        e: GuestException,
        pc: u64,
        next: u64,
    },
    /// 未実装の操作に当たった。
    Unimpl { pc: u64 },
}

impl From<IrOutcome> for BlockExit {
    fn from(o: IrOutcome) -> Self {
        match o {
            IrOutcome::Next(pc) => Self::Next(pc),
            IrOutcome::Raise { e, pc, next } => Self::Raise { e, pc, next },
            IrOutcome::Unimpl { pc } => Self::Unimpl { pc },
        }
    }
}

/// ISA ごとの翻訳器。`key` はブロックの同一性（モードや FS ベースなど
/// 意味が変わる状況も含める）、`record` は `entry` からの直線ブロックを
/// `IrBackend` に記録して `Recorded` にする。
pub trait Translate {
    /// `pc` のブロックの同一性。
    fn key(&self, b: &InterpBackend, pc: u64) -> u64;
    /// `entry` から 1 ブロックを記録する。記録できない（境界から始まる
    /// 命令）なら `None`。返す前に `optimize` を掛けること。
    fn record(&self, b: &mut InterpBackend, entry: u64) -> Option<Recorded>;
}

/// JIT 実行器。ブロックのキャッシュと呼び出し回数を持つ。
pub struct Jit {
    blocks: HashMap<u64, backend::Compiled>,
    /// まだコンパイルしていない入口の呼び出し数。
    hot: HashMap<u64, u32>,
    /// 記録できない入口（機械語にしないまま IR 解釈で走る）。
    cold: HashSet<u64>,
    /// コンパイルする閾値。
    threshold: u32,
    /// 機械語で走ったブロック数。
    ran: u64,
    /// IR 解釈で走ったブロック数。
    interp: u64,
}

impl Default for Jit {
    fn default() -> Self {
        Self::new()
    }
}

impl Jit {
    #[must_use]
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            hot: HashMap::new(),
            cold: HashSet::new(),
            threshold: 64,
            ran: 0,
            interp: 0,
        }
    }

    /// コンパイル閾値を変える（試験が 1 にして即コンパイルさせるため）。
    pub fn set_threshold(&mut self, n: u32) {
        self.threshold = n;
    }

    /// コンパイル済みブロック数。
    #[must_use]
    pub fn compiled(&self) -> usize {
        self.blocks.len()
    }

    /// 機械語 / IR 解釈で走ったブロック数。
    #[must_use]
    pub fn stats(&self) -> (u64, u64) {
        (self.ran, self.interp)
    }

    /// ブロックを全部捨てる（コードの書き込み・フォーク）。
    pub fn invalidate(&mut self) {
        self.blocks.clear();
        self.hot.clear();
        self.cold.clear();
    }

    /// `env.backend` の上で `pc` のブロックを 1 つ実行する。
    /// 入口の命令が記録できないときは `None`（呼び出し側はインタプリタ
    /// で 1 命令進める）。
    pub fn exec_block<T: Translate>(
        &mut self,
        b: &mut InterpBackend,
        t: &T,
        pc: u64,
    ) -> Option<BlockExit> {
        let key = t.key(b, pc);
        if self.cold.contains(&key) {
            return None;
        }
        if let Some(c) = self.blocks.get(&key) {
            let (x, inv) = call_block(b, c);
            self.ran += 1;
            if inv {
                self.invalidate();
            }
            return Some(x);
        }
        let n = self.hot.entry(key).or_insert(0);
        *n += 1;
        if *n < self.threshold {
            // 閾値に届くまでは記録→IR 解釈で走る。
            return match t.record(b, pc) {
                Some(r) => Some(self.exec_ir(b, &r)),
                None => {
                    self.cold.insert(key);
                    None
                }
            };
        }
        self.hot.remove(&key);
        let r = match t.record(b, pc) {
            Some(r) => r,
            None => {
                self.cold.insert(key);
                return None;
            }
        };
        match backend::compile(&r) {
            Some(c) => {
                self.blocks.insert(key, c);
                let c = self.blocks.get(&key).expect("直前に挿入");
                let (x, inv) = call_block(b, c);
                self.ran += 1;
                if inv {
                    self.invalidate();
                }
                Some(x)
            }
            None => Some(self.exec_ir(b, &r)),
        }
    }

    /// 記録したブロックを IR 解釈で走らせる。
    fn exec_ir(&mut self, b: &mut InterpBackend, r: &Recorded) -> BlockExit {
        self.interp += 1;
        polyisa_ir::exec(&r.ir, b, r.fall).into()
    }
}

/// コンパイル済みブロックを実行し、`RtCtx` の出口を `BlockExit` にする。
/// 2 番目の返り値はブロックの破棄要求（コードのページへの書き込み）。
fn call_block(b: &mut InterpBackend, c: &backend::Compiled) -> (BlockExit, bool) {
    let mut ctx = RtCtx {
        backend: core::ptr::from_mut(b) as usize,
        state: b.state.as_mut_ptr() as usize,
        pc: 0,
        next: 0,
        code: 0,
        exc_kind: 0,
        exc_code: 0,
        exc_flags: 0,
        exc_addr: 0,
        invalidate: 0,
    };
    // SAFETY: ctx はこの呼び出しの間だけ有効で、backend/state は
    // 生きた InterpBackend を指す。生成コードは ctx 経由だけが触る。
    unsafe { c.call(&mut ctx) };
    let x = match ctx.code {
        1 => BlockExit::Raise {
            e: read_exc(&ctx),
            pc: ctx.pc,
            next: ctx.next,
        },
        2 => BlockExit::Unimpl { pc: ctx.pc },
        _ => BlockExit::Next(ctx.pc),
    };
    (x, ctx.invalidate != 0)
}

// 生成コードを試すので、バックエンドを持つホストだけで走らせる。
#[cfg(all(test, unix, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use polyisa_ir::IrBackend;
    use polyisa_sem::{Backend, StateRef, W64};

    /// 意味論: `state[8] = state[0]*2 + 5`。インタプリタと
    /// 生成コードで同じ結果になるはず。
    fn prog<B: Backend>(b: &mut B) -> Result<(), B::Exit> {
        let a = b.get(StateRef::<W64>::from_offset(0));
        let two = b.konst::<W64>(2);
        let five = b.konst::<W64>(5);
        let m = b.mul(a, two);
        let s = b.add(m, five);
        b.set(StateRef::<W64>::from_offset(8), s);
        Ok(())
    }

    fn record() -> polyisa_ir::Recorded {
        let mut irb = IrBackend::new();
        irb.cur_pc = 0x100;
        irb.cur_next = 0x104;
        if let Err(e) = prog(&mut irb) {
            irb.abort(e);
        }
        polyisa_ir::optimize(&mut irb.ir);
        polyisa_ir::Recorded {
            entry: 0x100,
            fall: 0x104,
            ir: irb.ir,
        }
    }

    #[test]
    fn compiled_block_matches_ir_exec() {
        let rec = record();
        // IR 解釈側。
        let mut want = InterpBackend::new(64);
        want.set(StateRef::<W64>::from_offset(0), 3);
        let out = polyisa_ir::exec(&rec.ir, &mut want, rec.fall);
        // 生成コード側。
        let c = backend::compile(&rec).expect("コンパイルできる");
        let mut got = InterpBackend::new(64);
        got.set(StateRef::<W64>::from_offset(0), 3);
        let (x, _inv) = call_block(&mut got, &c);
        assert_eq!(
            got.get(StateRef::<W64>::from_offset(8)),
            want.get(StateRef::<W64>::from_offset(8)),
        );
        assert_eq!(got.get(StateRef::<W64>::from_offset(8)), 11);
        assert!(matches!(x, BlockExit::Next(0x104)), "{x:?}");
        assert!(matches!(out, polyisa_ir::IrOutcome::Next(0x104)), "{out:?}");
    }

    #[test]
    fn compiled_block_raise() {
        // 例外で抜けるブロック: code=raise で BlockExit::Raise。
        let mut irb = IrBackend::new();
        irb.cur_pc = 0x100;
        irb.cur_next = 0x104;
        let e: Result<(), _> = Err(irb.raise(polyisa_sem::GuestException {
            kind: polyisa_sem::ExceptionKind::Undefined,
            code: 7,
            addr: None,
            in_delay_slot: false,
        }));
        if let Err(x) = e {
            irb.abort(x);
        }
        let rec = polyisa_ir::Recorded {
            entry: 0x100,
            fall: 0x104,
            ir: irb.ir,
        };
        let c = backend::compile(&rec).expect("コンパイルできる");
        let mut b = InterpBackend::new(64);
        let (x, _inv) = call_block(&mut b, &c);
        match x {
            BlockExit::Raise { e, pc, next } => {
                assert_eq!(e.kind, polyisa_sem::ExceptionKind::Undefined);
                assert_eq!(e.code, 7);
                assert_eq!(pc, 0x100);
                assert_eq!(next, 0x104);
            }
            _ => panic!("Raise で抜けるはず: {x:?}"),
        }
    }
}
