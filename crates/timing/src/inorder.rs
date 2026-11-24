// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! インオーダー・マルチイシューの汎用モデル。
//!
//! `ExactModel` の ready_at スコアボードを発展させ、U7 系のような
//! インオーダーのスーパースカラを表す。命令イベントをプログラム順に
//! 1 つずつ消費し、各命令の発行時刻を再帰式で求める近似シミュレータ。
//! 完全なサイクル正確のシミュレータではない。
//!
//! 命令 i の発行時刻は次で求める。
//!
//! - `iss = max(発行スロットの空き, iss[i-width]+1, 読むレジスタの ready_at
//!   （uses_ag で生産者がロードなら +ag_load_delay）, 排他グループの前回発行+占有,
//!   直前命令とのペア内ハザードなら 直前発行+1)`
//! - 結果の準備 = `iss + ready（hint_latency かつ hint≠0 なら hint）+ d$ の応答（ロードのみ）`
//!
//! 分岐の誤予測・フェッチバブル・フラッシュ・i$ の応答は、仮想時間と発行
//! スロットの両方に足し、パイプが空になるまで後続が進まない近似とする。

use crate::branch::{BranchInfo, Predictor};
use crate::cache::CacheHierarchy;
use crate::ooo::{Hist, MemKind};
use crate::{BranchKind, InstrEvent, TimingModel, VirtualTime};

/// 分類ごとの発行コストと制約。`InOrderParams::classes` の表の行。
#[derive(Clone, Copy, Debug)]
pub struct IoClass {
    /// タイミング表の項目名。
    pub class: &'static str,
    /// 発行のコスト。1 なら発行スロットをそのサイクルだけ占有し、
    /// 次の命令は同じサイクルに並べられる。2 以上は発行側の占有が延びる近似。
    pub issue: u64,
    /// 発行から結果が使えるまでのサイクル数。
    pub ready: u64,
    /// 演算器を占有するサイクル数。1 以下なら完全パイプライン化として扱う。
    /// 占有は `group` のビットで追うので、busy が 1 より大きい分類は
    /// group にビットを持たせる。
    pub busy: u64,
    /// 同一サイクルに 1 個まで発行できる排他グループのビット。
    /// 0 は制約なし。ビットの割り当ては呼び出し側が決める。
    pub group: u32,
    /// メモリへの触れ方。ロードは d$ の応答時間を結果に足し、
    /// 書いたレジスタはロード生産として追跡される。ストアは
    /// d$ の状態の更新だけを行う（バッファ化の近似）。
    pub mem: MemKind,
    /// アドレス生成にオペランドを使う（ロード・ストア・間接ジャンプ）。
    /// true の命令は、読むオペランドの生産者がロードだったとき
    /// `ag_load_delay` だけ余分に待つ。
    pub uses_ag: bool,
    /// 分岐として予測器へ渡すか。
    pub is_branch: bool,
    /// 発行後に仮想時間へ足す定数のペナルティ（パイプラインフラッシュ等）。
    pub flush: u64,
    /// `InstrEvent::hint` が非 0 のとき `ready` の代わりに hint を
    /// 結果レイテンシとして使う（除算など値依存のもの向け）。
    pub hint_latency: bool,
}

/// `InOrderModel` のパラメータ。
#[derive(Clone, Debug)]
pub struct InOrderParams {
    /// 発行幅（同一サイクルあたりの命令数）。
    pub width: u32,
    /// 分類の表。表にない分類は issue 1・ready 1・制約なし。
    pub classes: &'static [IoClass],
    /// `uses_ag` の命令がロード生産のオペランドを読むときの追加の待ち。
    pub ag_load_delay: u64,
    /// データ側のキャッシュ階層。無ければロードは表の `ready` のみ。
    pub mem: Option<CacheHierarchy>,
    /// 命令フェッチ側のキャッシュ階層。無ければフェッチは数えない。
    pub icache: Option<CacheHierarchy>,
    /// 分岐予測器。無ければ分岐は `issue` コストのみ。
    pub pred: Option<Predictor>,
    /// 方向の誤予測でパイプを止めるサイクル数。
    pub mispredict: u64,
    /// 間接ジャンプの誤予測でパイプを止めるサイクル数。
    pub indirect_mispredict: u64,
    /// BTB ミスや予測器の不一致が畳む小さいフェッチバブル。
    pub fetch_bubble: u64,
    /// `ready_at` スコアボードの大きさ。reads/writes のビット位置に対応する。
    pub reg_count: usize,
}

/// インオーダーのモデル。`TimingModel` を実装する。
#[derive(Clone, Debug)]
pub struct InOrderModel {
    params: InOrderParams,
    /// 次の命令が発行できる最早サイクル。前の命令の占有と
    /// フラッシュ系のペナルティを畳んだ順序制約。
    slot: u64,
    /// 発行時刻+1 の履歴。幅の制約（同一サイクルに width 個まで）に使う。
    issued: Hist,
    /// レジスタごとの結果の準備時刻。
    ready_at: Vec<u64>,
    /// 各レジスタを最後に書いた命令がロード系かのビット。
    produced_by_load: u64,
    /// 排他グループのビットごとの次に発行できる時刻。
    group_next: [u64; 32],
    /// 直前命令の発行時刻と書き込み。ペア内ハザードの検査に使う。
    prev_issue: u64,
    prev_writes: u64,
    /// 最後に取り込んだ i$ ライン。
    last_iline: u64,
    iline_shift: u32,
    time: u64,
}

impl InOrderModel {
    /// `approx` の CPU モデルがこのモデルで主張してよい相対誤差の上限。
    pub const DECLARED_ERR: f64 = 0.25;

    #[must_use]
    pub fn new(params: InOrderParams) -> Self {
        assert!(params.width > 0);
        Self {
            iline_shift: params.icache.as_ref().map_or(0, |c| c.line_shift()),
            ready_at: vec![0; params.reg_count],
            issued: Hist::new(params.width as usize),
            params,
            slot: 0,
            produced_by_load: 0,
            group_next: [0; 32],
            prev_issue: 0,
            prev_writes: 0,
            last_iline: u64::MAX,
            time: 0,
        }
    }

    fn uop(&self, class: &str) -> IoClass {
        const DEFAULT: IoClass = IoClass {
            class: "",
            issue: 1,
            ready: 1,
            busy: 1,
            group: 0,
            mem: MemKind::None,
            uses_ag: false,
            is_branch: false,
            flush: 0,
            hint_latency: false,
        };
        for row in self.params.classes {
            if row.class == class {
                return *row;
            }
        }
        DEFAULT
    }

    /// 仮想時間と発行スロットを `p` だけ止める。パイプが空になるまで
    /// 後続の命令が進まない近似。
    fn stall(&mut self, p: u64) {
        self.time += p;
        self.slot += p;
    }
}

impl TimingModel for InOrderModel {
    fn observe(&mut self, ev: &InstrEvent) {
        let u = self.uop(ev.class);

        // 新しい i$ ラインは応答時間だけフェッチを止める近似。
        if let Some(icache) = &mut self.params.icache {
            let iline = ev.pc >> self.iline_shift;
            if iline != self.last_iline {
                let latency = icache.access(ev.pc).latency;
                self.stall(latency);
                self.last_iline = iline;
            }
        }

        // 発行。スロットの順序制約と、幅・レジスタ準備・排他グループを待つ。
        let mut iss = self
            .slot
            .max(self.issued.back(self.params.width as usize - 1));
        let mut r = ev.reads;
        while r != 0 {
            let b = r.trailing_zeros() as usize;
            if b < self.ready_at.len() {
                let mut t = self.ready_at[b];
                if u.uses_ag && self.produced_by_load & (1 << b) != 0 {
                    t += self.params.ag_load_delay;
                }
                iss = iss.max(t);
            }
            r &= r - 1;
        }
        // ペア内のデータハザードは同サイクル発行不可。
        // 直前 1 命令との組だけ検査する近似。
        if ev.reads & self.prev_writes != 0 {
            iss = iss.max(self.prev_issue + 1);
        }
        let mut g = u.group;
        while g != 0 {
            iss = iss.max(self.group_next[g.trailing_zeros() as usize]);
            g &= g - 1;
        }
        let mut g = u.group;
        while g != 0 {
            let b = g.trailing_zeros() as usize;
            self.group_next[b] = iss + u.busy.max(1);
            g &= g - 1;
        }

        // ロードは d$ の応答時間を結果に足す。ストアは状態の更新だけ。
        let mut mem_extra = 0;
        if let Some(mem) = &mut self.params.mem {
            if u.mem.loads() && !ev.mem_addrs.is_empty() {
                for &(addr, _) in &ev.mem_addrs {
                    mem_extra = mem_extra.max(mem.access(addr).latency);
                }
            } else if u.mem.stores() {
                for &(addr, _) in &ev.mem_addrs {
                    mem.access(addr);
                }
            }
        }

        let ready = if u.hint_latency && ev.hint != 0 {
            ev.hint
        } else {
            u.ready
        };
        let done = iss + ready + mem_extra;

        self.time = self.time.max(iss + u.issue);
        self.slot = iss + u.issue.saturating_sub(1);
        self.stall(u.flush);

        if u.is_branch
            && let Some(taken) = ev.branch_taken
            && let Some(pred) = &mut self.params.pred
        {
            let info = BranchInfo {
                taken,
                target: ev.branch_target,
                is_call: ev.branch_kind == BranchKind::Call,
                is_ret: ev.branch_kind == BranchKind::Ret,
                is_indirect: ev.branch_kind == BranchKind::Indirect,
            };
            let out = pred.predict_and_update(ev.pc, &info);
            if out.mispredict_dir {
                let p = if info.is_indirect {
                    self.params.indirect_mispredict
                } else {
                    self.params.mispredict
                };
                self.stall(p);
            }
            if out.btb_miss || out.disagree_bubble {
                self.stall(self.params.fetch_bubble);
            }
        }

        let mut w = ev.writes;
        while w != 0 {
            let b = w.trailing_zeros() as usize;
            if b < self.ready_at.len() {
                self.ready_at[b] = done;
            }
            w &= w - 1;
        }
        if u.mem.loads() {
            self.produced_by_load |= ev.writes;
        } else {
            self.produced_by_load &= !ev.writes;
        }

        self.issued.push(iss + 1);
        self.prev_issue = iss;
        self.prev_writes = ev.writes;
    }

    fn now(&self) -> VirtualTime {
        VirtualTime(self.time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branch::{Btb, DirPred};
    use crate::cache::{CacheLevel, Repl, WriteKind};

    const MEM: u32 = 1;
    const BR: u32 = 2;
    const MD: u32 = 4;

    const I: CacheLevel = CacheLevel {
        name: "l1i",
        sets: 8,
        ways: 2,
        line_shift: 6,
        repl: Repl::RoundRobin,
        write: WriteKind::WriteBack,
        hit_latency: 1,
    };
    const D: CacheLevel = CacheLevel {
        name: "l1d",
        sets: 8,
        ways: 2,
        line_shift: 6,
        repl: Repl::Plru,
        write: WriteKind::WriteBack,
        hit_latency: 2,
    };

    const CLASSES: &[IoClass] = &[
        IoClass {
            class: "alu",
            issue: 1,
            ready: 1,
            busy: 1,
            group: 0,
            mem: MemKind::None,
            uses_ag: false,
            is_branch: false,
            flush: 0,
            hint_latency: false,
        },
        IoClass {
            class: "imm",
            issue: 1,
            ready: 0,
            busy: 1,
            group: 0,
            mem: MemKind::None,
            uses_ag: false,
            is_branch: false,
            flush: 0,
            hint_latency: false,
        },
        IoClass {
            class: "load",
            issue: 1,
            ready: 1,
            busy: 1,
            group: MEM,
            mem: MemKind::Load,
            uses_ag: true,
            is_branch: false,
            flush: 0,
            hint_latency: false,
        },
        IoClass {
            class: "store",
            issue: 1,
            ready: 1,
            busy: 1,
            group: MEM,
            mem: MemKind::Store,
            uses_ag: true,
            is_branch: false,
            flush: 0,
            hint_latency: false,
        },
        IoClass {
            class: "branch",
            issue: 1,
            ready: 1,
            busy: 1,
            group: BR,
            mem: MemKind::None,
            uses_ag: false,
            is_branch: true,
            flush: 0,
            hint_latency: false,
        },
        IoClass {
            class: "jump",
            issue: 1,
            ready: 1,
            busy: 1,
            group: BR,
            mem: MemKind::None,
            uses_ag: true,
            is_branch: true,
            flush: 0,
            hint_latency: false,
        },
        IoClass {
            class: "div",
            issue: 1,
            ready: 34,
            busy: 34,
            group: MD,
            mem: MemKind::None,
            uses_ag: false,
            is_branch: false,
            flush: 0,
            hint_latency: true,
        },
        IoClass {
            class: "csr",
            issue: 1,
            ready: 1,
            busy: 1,
            group: 0,
            mem: MemKind::None,
            uses_ag: false,
            is_branch: false,
            flush: 7,
            hint_latency: false,
        },
    ];

    fn params() -> InOrderParams {
        InOrderParams {
            width: 2,
            classes: CLASSES,
            ag_load_delay: 2,
            mem: Some(CacheHierarchy::new(&[D], 50)),
            icache: None,
            pred: Some(Predictor::new(
                DirPred::Bimodal { entries: 64 },
                Some(Btb::new(16, 2)),
                None,
                None,
            )),
            mispredict: 4,
            indirect_mispredict: 6,
            fetch_bubble: 1,
            reg_count: 64,
        }
    }

    fn alu(i: u64) -> InstrEvent {
        InstrEvent::new(i * 4, "alu")
    }

    #[test]
    fn independent_pair_issues_same_cycle() {
        let run = |width: u32| {
            let mut p = params();
            p.width = width;
            let mut m = InOrderModel::new(p);
            for i in 0..8u64 {
                m.observe(&alu(i));
            }
            m.now()
        };
        // 8 命令: 2 幅なら 2 個ずつ 4 サイクル、1 幅なら 8。
        assert_eq!(run(2), VirtualTime(4));
        assert_eq!(run(1), VirtualTime(8));
    }

    #[test]
    fn exclusive_group_limits_same_cycle() {
        let run = |class: &'static str| {
            let mut m = InOrderModel::new(params());
            for i in 0..4u64 {
                m.observe(&InstrEvent::new(i * 4, class));
            }
            m.now()
        };
        // メモリ系は同時に 1 個まで: 4 連は毎サイクル 1 個ずつ進む。
        assert_eq!(run("load"), VirtualTime(4));
        // 制約なしなら 2 幅で詰まる。
        assert_eq!(run("alu"), VirtualTime(2));
    }

    #[test]
    fn pair_raw_serializes() {
        // 依存のある 2 命令は同じサイクルに出ない。
        let mut dep = InOrderModel::new(params());
        dep.observe(&alu(0).writes(1));
        dep.observe(&alu(1).reads(1).writes(2));
        assert_eq!(dep.now(), VirtualTime(2));
        // 結果がすぐ準備できる生産者でも、ペア内ハザードは直列化する。
        let mut zero = InOrderModel::new(params());
        zero.observe(&InstrEvent::new(0, "imm").writes(1));
        zero.observe(&alu(1).reads(1));
        assert_eq!(zero.now(), VirtualTime(2));
        // 独立なら同じサイクルに出る。
        let mut free = InOrderModel::new(params());
        free.observe(&alu(0).writes(1));
        free.observe(&alu(1).reads(2));
        assert_eq!(free.now(), VirtualTime(1));
    }

    #[test]
    fn load_address_operand_waits_for_ag_delay() {
        let run = |producer: &'static str, consumer: &'static str| {
            let mut m = InOrderModel::new(params());
            m.observe(&InstrEvent::new(0, producer).writes(1));
            m.observe(&InstrEvent::new(4, consumer).reads(1));
            m.now()
        };
        // ロード結果をアドレス生成に使うと ready_at に ag_load_delay が乗る。
        assert_eq!(run("load", "load"), VirtualTime(4));
        // 演算器への利用は delay なし。
        assert_eq!(run("load", "alu"), VirtualTime(2));
        // 生産者がロードでなければ delay なし。
        assert_eq!(run("alu", "load"), VirtualTime(2));
    }

    #[test]
    fn load_result_includes_dcache_latency() {
        let mut m = InOrderModel::new(params());
        m.observe(
            &InstrEvent {
                mem_addrs: vec![(0x1000, 8)],
                ..InstrEvent::new(0, "load")
            }
            .writes(1),
        );
        m.observe(&alu(1).reads(1));
        // ミスは 2 + 50 の応答時間が結果に乗る。
        assert_eq!(m.now(), VirtualTime(54));
    }

    #[test]
    fn branch_mispredict_adds_penalty() {
        // 常に取らない予測に、常に取る分岐を食わせる。
        let run = |kind: BranchKind| {
            let mut p = params();
            p.fetch_bubble = 0;
            p.pred = Some(Predictor::new(
                DirPred::Static {
                    backward_taken: false,
                },
                None,
                None,
                None,
            ));
            let mut m = InOrderModel::new(p);
            let class = if kind == BranchKind::Indirect {
                "jump"
            } else {
                "branch"
            };
            m.observe(&InstrEvent::new(0, class).branch(true, 0x80, kind));
            for i in 0..4u64 {
                m.observe(&InstrEvent::new(0x80 + i * 4, "alu"));
            }
            m.now()
        };
        // 直接分岐は 4、間接ジャンプは 6 の誤予測。
        assert_eq!(run(BranchKind::Direct), VirtualTime(6));
        assert_eq!(run(BranchKind::Indirect), VirtualTime(8));
    }

    #[test]
    fn flush_stalls_following() {
        let run = |class: &'static str| {
            let mut m = InOrderModel::new(params());
            m.observe(&InstrEvent::new(0, class));
            for i in 1..5u64 {
                m.observe(&alu(i));
            }
            m.now()
        };
        // フラッシュ 7 は発行後の時間に足され、後続の発行も遅れる。
        assert_eq!(run("csr"), VirtualTime(9));
        assert_eq!(run("alu"), VirtualTime(3));
    }

    #[test]
    fn hint_overrides_table_latency() {
        let run = |hint: u64| {
            let mut m = InOrderModel::new(params());
            m.observe(
                &InstrEvent {
                    hint,
                    ..InstrEvent::new(0, "div")
                }
                .writes(1),
            );
            m.observe(&alu(1).reads(1));
            m.now()
        };
        // hint があれば表の 34 ではなく hint をレイテンシに使う。
        assert_eq!(run(10), VirtualTime(11));
        // hint=0 は表にフォールバック。
        assert_eq!(run(0), VirtualTime(35));
    }

    #[test]
    fn deterministic_for_same_sequence() {
        let mk = || {
            let mut p = params();
            p.icache = Some(CacheHierarchy::new(&[I], 10));
            InOrderModel::new(p)
        };
        let (mut a, mut b) = (mk(), mk());
        let mut x = 0x9e37_79b9u64;
        for i in 0..300u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let pc = i * 4 % 0x400;
            let ev = match x % 5 {
                0 => InstrEvent {
                    mem_addrs: vec![((x % 0x800) & !63, 8)],
                    ..InstrEvent::new(pc, "load")
                }
                .reads(x % 4)
                .writes(1 << (x % 63)),
                1 => InstrEvent {
                    mem_addrs: vec![((x % 0x800) & !63, 8)],
                    ..InstrEvent::new(pc, "store")
                },
                2 => InstrEvent::new(pc, "branch").branch(
                    x & 0x100 == 0,
                    (x % 0x400) & !3,
                    BranchKind::Direct,
                ),
                3 => InstrEvent::new(pc, "csr"),
                _ => alu(i).reads(x % 8).writes(1 << (x % 63)),
            };
            a.observe(&ev);
            b.observe(&ev);
            assert_eq!(a.now(), b.now());
        }
    }
}
