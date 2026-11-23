// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 複数ハードウェアスレッドの交互実行（段階22 HX10 のタイミングモデル）。
//!
//! コアは N 本の HW スレッドを束ねる。各スレッドは独立した
//! `CpuState` 一式（汎用・述語・制御の建築状態とパケット未確定域）を
//! 持ち、アドレス空間はコア内で共有する（正本の「共有メモリを持つ
//! 別個のプロセッサ」の構造）。発行はパケット単位でスレッドを切り
//! 替える交互実行で、本モデルの 1 サイクル = 1 パケットの発行枠。
//! 各枠は直前に発行したスレッドの次の番号から順に、最初の実行可能な
//! スレッドへ渡す（単純 IMT のラウンドロビン）。
//!
//! `pause(#u)` は意味論側が `CpuState::hwt` に休眠要求を残し、
//! コアがそのスレッドを発行対象から外す。期間は #u+8 発行枠の近似
//! （正本は #u サイクル・最大 255+8 とする）。割込みによる早期復帰、
//! 優先度スケジューリング、版・製品ごとのスレッド数の違い、特権側の
//! スレッド制御（start/stop/resume）は近似として GAP-0072 に記録。
//!
//! `run::step`/`run` の単スレッド経路は変えず、ユーザーモード単一
//! プロセスは `Core::new(1, ..)` の退化形で同じパケット列を辿る。
//! Ref: SPEC-HEXAGON-PRM (V79) program flow.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{Outcome, TrapHandler};
use polyisa_timing::VirtualTime;

use crate::{CpuState, run};

/// `CpuState::hwt` の割り当て。下位は発行中スレッドの番号
/// （モデル識別。OS パーソナリティは trap したスレッドをここ
/// から知る）、上位は `pause(#u)` が残す休眠要求（意味論が立て、
/// コアが読んで消す）。
pub mod hwt {
    /// スレッド番号（bits[15:0]）。
    pub const TID: u32 = 0xffff;
    /// 休眠期間 #u の位置（bits[25:16]。符号化の u10 場）。
    pub const COUNT: u32 = 16;
    /// 休眠要求の標識（bit31）。
    pub const PAUSE: u32 = 1 << 31;
}

/// 休眠期間の下駄（正本: pause の期間は #u+8 サイクルまで）。
// Gap: GAP-0072
const PAUSE_BASE: u32 = 8;

/// `state` 内の hwt を読む。
fn hwt_of(state: &[u8]) -> u32 {
    let off = core::mem::offset_of!(CpuState, hwt);
    u32::from_le_bytes(state[off..off + 4].try_into().expect("hwt"))
}

/// `state` 内の hwt を書く。
fn hwt_set(state: &mut [u8], v: u32) {
    let off = core::mem::offset_of!(CpuState, hwt);
    state[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// 1 本の HW スレッド。`state` は `CpuState` のバイト列で、
/// 発行時だけ `env.backend.state` に載る。
#[derive(Clone)]
struct HwThread {
    state: Vec<u8>,
    /// 次に実行するパケットの先頭アドレス。
    pc: u64,
    /// 実行可能になるまでの残り発行枠。0 で実行可能。
    sleep: u32,
    /// OS パーソナリティが待ちに置いた（`wake` で復帰）。
    blocked: bool,
    /// 終了した（trap の Exit を `take_exit` が引き取った）。
    done: bool,
    /// 発行したパケット数。
    issued: u64,
}

/// N 本の HW スレッドをパケット単位で交互に発行するコア。
pub struct Core {
    /// 共有メモリと、発行中スレッドの状態を載せる実行環境。
    env: BareEnv,
    threads: Vec<HwThread>,
    /// 直前に発行したスレッド（走査は次の番号から）。
    last: usize,
    /// デコードの機能旗（`run::step` に渡す）。
    feats: u128,
    /// 経過した発行枠（発行と休眠アイドルの合計）。
    cycles: u64,
    /// `take_exit` が引き取った最新の終了コード。
    last_exit: Option<u32>,
}

impl Core {
    /// `n` 本の HW スレッドを持つコア。`feats` はデコードの機能旗。
    /// スレッド数は版・製品で異なるため外から与える。
    #[must_use]
    pub fn new(n: usize, feats: u128) -> Self {
        let state_len = core::mem::size_of::<CpuState>();
        Self {
            env: BareEnv::new(state_len),
            threads: (0..n)
                .map(|_| HwThread {
                    state: vec![0; state_len],
                    pc: 0,
                    sleep: 0,
                    blocked: false,
                    done: false,
                    issued: 0,
                })
                .collect(),
            last: usize::MAX,
            feats,
            cycles: 0,
            last_exit: None,
        }
    }

    /// スレッド数。
    #[must_use]
    pub fn threads(&self) -> usize {
        self.threads.len()
    }

    /// 共有アドレス空間を持つ実行環境（写像・コードの書き込み用）。
    /// `backend.state`/`pc` は次の発行・`with_thread` で上書きされる。
    #[must_use]
    pub fn env_mut(&mut self) -> &mut BareEnv {
        &mut self.env
    }

    /// 経過した発行枠を仮想時間として返す（発行と休眠アイドルの
    /// 合計。1 枠 = 1 サイクル）。
    #[must_use]
    pub fn now(&self) -> VirtualTime {
        VirtualTime(self.cycles)
    }

    /// スレッド i が発行したパケット数。
    #[must_use]
    pub fn issued(&self, i: usize) -> u64 {
        self.threads[i].issued
    }

    /// 待ち（Blocked）のスレッド i を実行可能に戻す。
    /// OS パーソナリティの起床に使う。
    pub fn wake(&mut self, i: usize) {
        self.threads[i].blocked = false;
    }

    /// スレッド i の状態を `env` に載せて `f` を呼ぶ
    /// （レジスタ・pc の設定と読み出しに使う）。
    pub fn with_thread<T>(&mut self, i: usize, f: impl FnOnce(&mut BareEnv) -> T) -> T {
        self.load(i);
        let v = f(&mut self.env);
        self.save(i);
        v
    }

    /// スレッド i の状態を実行面に載せ、発行中の番号を刻む。
    fn load(&mut self, i: usize) {
        self.env
            .backend
            .state
            .copy_from_slice(&self.threads[i].state);
        self.env.pc = self.threads[i].pc;
        let h = hwt_of(&self.env.backend.state) & !hwt::TID;
        hwt_set(&mut self.env.backend.state, h | i as u32);
    }

    /// 実行面の状態をスレッド i へ戻す。
    fn save(&mut self, i: usize) {
        self.threads[i]
            .state
            .copy_from_slice(&self.env.backend.state);
        self.threads[i].pc = self.env.pc;
    }

    /// 次の実行可能スレッド（`last` の次からラウンドロビン）。
    fn pick(&self) -> Option<usize> {
        let n = self.threads.len();
        (0..n)
            .map(|k| self.last.wrapping_add(1 + k) % n)
            .find(|&i| {
                let t = &self.threads[i];
                !t.done && !t.blocked && t.sleep == 0
            })
    }

    /// 1 発行枠ぶん進める。返すのは発行したスレッドの番号で、
    /// `None` は全スレッド休眠中のアイドル枠。枠の先頭で各
    /// スレッドの休眠カウンタを 1 つ進める。
    ///
    /// 発行したスレッドが trap の Exit で止まったとき、
    /// `sys.take_exit` が真ならそのスレッドを終了扱いにして
    /// `Some(i)` を返し（枠は終了したスレッドが消費した）、全
    /// スレッドの終了で最後のコードの `Exit` を返す。ハンドラが
    /// Blocked を返したスレッドは `sys.on_block` が真なら待ちに
    /// 置く（`wake` で復帰）。
    pub fn step(&mut self, sys: &mut impl TrapHandler) -> Result<Option<usize>, Outcome> {
        if self.threads.is_empty() {
            return Err(Outcome::Deadlock);
        }
        self.cycles += 1;
        for t in &mut self.threads {
            t.sleep = t.sleep.saturating_sub(1);
        }
        let Some(i) = self.pick() else {
            if self.threads.iter().all(|t| t.done) {
                return Err(Outcome::Exit(u64::from(self.last_exit.unwrap_or(0))));
            }
            if self.threads.iter().any(|t| !t.done && !t.blocked) {
                // 全員休眠中。時間だけが進むアイドル枠。
                return Ok(None);
            }
            // 実行可能なスレッドが残っていない。
            return Err(Outcome::Deadlock);
        };
        self.load(i);
        let r = run::step(&mut self.env, sys, self.feats);
        self.save(i);
        let t = &mut self.threads[i];
        // `pause(#u)` が残した休眠要求を回収する。発行が例外で
        // 中断したパケットの要求は捨てる（pause は単独命令で、
        // 棄却されたパケットは休眠を始めない）。
        let h = hwt_of(&t.state);
        if h & hwt::PAUSE != 0 {
            if r.is_ok() {
                t.sleep = (h >> hwt::COUNT & 0x3ff).saturating_add(PAUSE_BASE);
            }
            hwt_set(&mut t.state, h & hwt::TID);
        }
        self.last = i;
        // パケットを実行した（trap/待ちで止まったものを含む）もの
        // だけを発行数に数える。
        if !matches!(
            r,
            Err(Outcome::Unimplemented { .. } | Outcome::StepLimit { .. })
        ) {
            t.issued += 1;
        }
        match r {
            Ok(()) => Ok(Some(i)),
            Err(Outcome::Exit(code)) => {
                t.done = true;
                let code = code as u32;
                if sys.take_exit(&mut self.env, code) {
                    self.last_exit = Some(code);
                    return Ok(Some(i));
                }
                Err(Outcome::Exit(u64::from(code)))
            }
            Err(Outcome::Deadlock) => {
                // ハンドラが待ち（Blocked）を報告した。
                t.blocked = true;
                if sys.on_block(&mut self.env) {
                    return Ok(Some(i));
                }
                Err(Outcome::Deadlock)
            }
            Err(o) => Err(o),
        }
    }

    /// `limit` 発行枠まで回す。
    pub fn run(&mut self, sys: &mut impl TrapHandler, limit: u64) -> Outcome {
        for _ in 0..limit {
            if let Err(o) = self.step(sys) {
                return o;
            }
        }
        Outcome::StepLimit { pc: self.env.pc }
    }
}
