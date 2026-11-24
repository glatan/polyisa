// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! アウトオブオーダー実行の汎用モデル。
//!
//! 命令イベントをプログラム順に 1 つずつ消費し、各命令の dispatch・issue・
//! complete・retire の時刻を再帰式で求める近似シミュレータ。イベントキューや
//! サイクル駆動の状態遷移は持たず、資源の空きは有限の履歴リングと「次に空く
//! 時刻」の表で近似する。完全なサイクル正確のシミュレータではない。
//!
//! 命令 i（プログラム順）の時刻は次で求める。
//!
//! - `disp = max(disp[i-1], disp[i-width]+1, front, retire[i-rob], キュー空き)`
//! - `issue = max(disp, 読むレジスタの ready_at, 使えるポートの空き, issue[i-sched],
//!   排他グループの前回発行+1, 先行ストアとの衝突)`
//! - `complete = issue + latency + d$ の応答時間（ロードのみ。複数アドレスは最大値）`
//! - `retire = max(complete, retire[i-1], retire[i-retire_width]+1)`

use std::collections::VecDeque;

use crate::branch::{BranchInfo, Predictor};
use crate::cache::CacheHierarchy;
use crate::{BranchKind, InstrEvent, TimingModel, VirtualTime};

/// メモリへの触れ方。ロード/ストアキューと d$ レイテンシの扱いを決める。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum MemKind {
    /// 触れない。
    #[default]
    None,
    /// ロード。LQ に入り、d$ の応答時間を complete に足す。
    Load,
    /// ストア。SQ に入り、退役でコミットする近似。d$ の応答時間は足さない。
    Store,
    /// 読み書き両方（read-modify-write の近似）。LQ・SQ 両方に入る。
    Both,
}

impl MemKind {
    pub(crate) fn loads(self) -> bool {
        matches!(self, Self::Load | Self::Both)
    }

    pub(crate) fn stores(self) -> bool {
        matches!(self, Self::Store | Self::Both)
    }
}

/// 分類ごとのレイテンシと発行の制約。`OooParams::classes` の表の行。
#[derive(Clone, Copy, Debug)]
pub struct ClassUop {
    /// タイミング表の項目名。
    pub class: &'static str,
    /// 発行から結果が使えるまでのサイクル数。
    pub latency: u64,
    /// 演算器（ポート）を占有するサイクル数。
    pub busy: u64,
    /// 使えるポートのビットマスク。0 は全ポートを使える。
    pub ports: u32,
    /// 同一サイクルに 1 個まで発行できる排他グループのビット。
    /// 0 は制約なし。ビットの割り当ては呼び出し側が決める。
    pub group: u32,
    /// メモリへの触れ方。
    pub mem: MemKind,
    /// 分岐として予測器へ渡すか。
    pub is_branch: bool,
}

/// `OooModel` のパラメータ。
#[derive(Clone, Debug)]
pub struct OooParams {
    /// フロントエンド/ディスパッチの最大幅（同一サイクルあたりの命令数）。
    pub width: u32,
    /// ROB の容量。
    pub rob: u32,
    /// スケジューラ（RS）の容量。発行で解放する近似。
    pub sched: u32,
    /// ロードキューの容量。complete で解放する近似。0 はキューを持たない。
    pub lq: u32,
    /// ストアキューの容量。retire で解放する近似。0 はキューを持たない。
    /// ストア→ロードの衝突検査の窓としても使う。
    pub sq: u32,
    /// 退役の最大幅。
    pub retire_width: u32,
    /// 方向の誤予測時のフロントエンド再充填コスト。
    pub mispredict: u64,
    /// BTB ミスや予測器の不一致が畳む小さいフェッチバブル。
    pub fetch_bubble: u64,
    /// 分類の表。表にない分類は latency 1・busy 1・全ポート・制約なし。
    pub classes: &'static [ClassUop],
    /// ポートの数。0 はポートの制約を持たない。
    pub ports: u32,
    /// データ側のキャッシュ階層。
    pub mem: CacheHierarchy,
    /// 命令フェッチ側のキャッシュ階層。
    pub icache: CacheHierarchy,
    /// 分岐予測器。
    pub pred: Predictor,
    /// メモリ依存予測。true ならアドレスが合わない先行ストアの後ろを
    /// ロードが通る。false なら未退役ストアのアドレス確定をすべて待つ。
    pub mem_disambig: bool,
    /// `ready_at` スコアボードの大きさ。reads/writes のビット位置に対応する。
    pub reg_count: usize,
}

/// 時刻の履歴リング。`back(k)` は k 個前（0 が直前）の値、無ければ 0。
#[derive(Clone, Debug)]
pub(crate) struct Hist {
    q: VecDeque<u64>,
    cap: usize,
}

impl Hist {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            q: VecDeque::with_capacity(cap + 1),
            cap: cap + 1,
        }
    }

    pub(crate) fn push(&mut self, v: u64) {
        if self.q.len() == self.cap {
            self.q.pop_front();
        }
        self.q.push_back(v);
    }

    pub(crate) fn back(&self, k: usize) -> u64 {
        if self.q.len() > k {
            self.q[self.q.len() - 1 - k]
        } else {
            0
        }
    }

    fn last(&self) -> u64 {
        self.q.back().copied().unwrap_or(0)
    }
}

/// 発行中のストア。ロードとの衝突検査に使う。
#[derive(Clone, Debug)]
struct PendingStore {
    /// 触れたライン（`mem` 階層の最上位のラインサイズで割った値）。
    lines: Vec<u64>,
    /// アドレスが確定する時刻（ストアの発行の近似）。
    addr_at: u64,
    /// データが確定する時刻。
    complete: u64,
    /// 退役（コミット）の時刻。過ぎたストアは衝突検査から外す。
    retire: u64,
}

/// アウトオブオーダーのモデル。`TimingModel` を実装する。
// Gap: GAP-0092 再帰式の近似であり、サイクルごとの資源仲裁・誤経路の実行・
// 発行順でのキャッシュ状態の変化・ストアのコミット占有はモデルしない。
#[derive(Clone, Debug)]
pub struct OooModel {
    params: OooParams,
    /// フロントエンドが次の命令を供給できる最早時刻。
    front: u64,
    /// 最後に取り込んだ i$ ライン。
    last_iline: u64,
    iline_shift: u32,
    dline_shift: u32,
    /// レジスタごとの結果の準備時刻。
    ready_at: Vec<u64>,
    /// ポートごとの次に空く時刻。
    port_free: Vec<u64>,
    /// 排他グループのビットごとの次に発行できる時刻。
    group_next: [u64; 32],
    disp: Hist,
    issue: Hist,
    retire: Hist,
    /// 直近のロードの complete。LQ の空きの近似。
    load_done: VecDeque<u64>,
    /// 直近のストア。SQ の空きと衝突検査に使う。
    stores: VecDeque<PendingStore>,
    time: u64,
}

impl OooModel {
    /// `approx` の CPU モデルがこのモデルで主張してよい相対誤差の上限。
    pub const DECLARED_ERR: f64 = 0.25;

    #[must_use]
    pub fn new(params: OooParams) -> Self {
        // `ports` は `pick_port` の `1 << p` が u32 に収まる範囲に限る。
        assert!(
            params.width > 0
                && params.rob > 0
                && params.sched > 0
                && params.retire_width > 0
                && params.ports <= 32
        );
        Self {
            iline_shift: params.icache.line_shift(),
            dline_shift: params.mem.line_shift(),
            ready_at: vec![0; params.reg_count],
            port_free: vec![0; params.ports as usize],
            group_next: [0; 32],
            disp: Hist::new(params.width as usize),
            issue: Hist::new(params.sched as usize),
            retire: Hist::new(params.rob.max(params.retire_width) as usize),
            load_done: VecDeque::new(),
            stores: VecDeque::new(),
            params,
            front: 0,
            last_iline: u64::MAX,
            time: 0,
        }
    }

    fn uop(&self, class: &str) -> ClassUop {
        const DEFAULT: ClassUop = ClassUop {
            class: "",
            latency: 1,
            busy: 1,
            ports: 0,
            group: 0,
            mem: MemKind::None,
            is_branch: false,
        };
        for row in self.params.classes {
            if row.class == class {
                return *row;
            }
        }
        DEFAULT
    }

    /// `reads` のビットが指す準備時刻の最大値。`reg_count` 外のビットは無視。
    fn ready_max(&self, mut reads: u64) -> u64 {
        let mut m = 0;
        while reads != 0 {
            let b = reads.trailing_zeros() as usize;
            if b < self.ready_at.len() {
                m = m.max(self.ready_at[b]);
            }
            reads &= reads - 1;
        }
        m
    }

    /// `disp` 時点で未退役の先行ストアに対し、ロードが待つ時刻。
    // Gap: GAP-0092 メモリ依存予測の外れ（通したロードが実は衝突していた
    // 場合のやり直し）は誤差に含め、時刻としては足さない。
    fn store_wait(&self, disp: u64, addrs: &[(u64, u32)]) -> u64 {
        let mut wait = 0;
        for st in &self.stores {
            if st.retire <= disp {
                continue;
            }
            let hit = addrs
                .iter()
                .any(|&(a, _)| st.lines.contains(&(a >> self.dline_shift)));
            // 保守的なときは全ストアのアドレス確定を待つ。
            if !self.params.mem_disambig {
                wait = wait.max(st.addr_at);
            }
            if hit {
                // 同一ラインなら転送できるまで待つ。
                wait = wait.max(st.complete);
            }
        }
        wait
    }

    /// `mask` で使えるポートのうち `base` に最も早く空くものを貪欲に選ぶ。
    fn pick_port(&self, mask: u32, base: u64) -> (u64, Option<usize>) {
        let mask = if mask == 0 { u32::MAX } else { mask };
        let mut best = (u64::MAX, None);
        for (p, &free) in self.port_free.iter().enumerate() {
            if mask & (1 << p) == 0 {
                continue;
            }
            let t = base.max(free);
            if t < best.0 {
                best = (t, Some(p));
            }
        }
        if best.0 == u64::MAX {
            (base, None)
        } else {
            best
        }
    }
}

impl TimingModel for OooModel {
    fn observe(&mut self, ev: &InstrEvent) {
        let u = self.uop(ev.class);

        // フロントエンド。新しい i$ ラインはその応答時間だけ供給が遅れる。
        let iline = ev.pc >> self.iline_shift;
        if iline != self.last_iline {
            self.front += self.params.icache.access(ev.pc).latency;
            self.last_iline = iline;
        }

        // ディスパッチ。幅の制約は i-width 番目の +1、ROB/LQ/SQ は古い占有の解放。
        // disp/retire の Hist には時刻+1 を積む。幅・退役幅の項は back(k) を
        // そのまま使い（空履歴の下限は 0 で制約なしに対応）、順序・占有解放の
        // 項は積んだ値から 1 を引いて元の時刻に戻す。
        let mut disp = self
            .front
            .max(self.disp.last().saturating_sub(1))
            .max(self.disp.back(self.params.width as usize - 1))
            .max(
                self.retire
                    .back(self.params.rob as usize - 1)
                    .saturating_sub(1),
            );
        if self.params.lq > 0 && self.load_done.len() == self.params.lq as usize {
            disp = disp.max(self.load_done[0]);
        }
        if self.params.sq > 0 && self.stores.len() == self.params.sq as usize {
            disp = disp.max(self.stores[0].retire);
        }

        // 発行。RS の空き・レジスタの準備・排他グループ・ストアとの衝突を待つ。
        let mut iss = disp
            .max(self.issue.back(self.params.sched as usize - 1))
            .max(self.ready_max(ev.reads));
        let mut g = u.group;
        while g != 0 {
            iss = iss.max(self.group_next[g.trailing_zeros() as usize]);
            g &= g - 1;
        }
        if u.mem.loads() {
            iss = iss.max(self.store_wait(disp, &ev.mem_addrs));
        }
        let (iss, port) = self.pick_port(u.ports, iss);
        let mut g = u.group;
        while g != 0 {
            let b = g.trailing_zeros() as usize;
            self.group_next[b] = iss + 1;
            g &= g - 1;
        }
        if let Some(port) = port {
            self.port_free[port] = iss + u.busy;
        }

        // d$ のアクセスはプログラム順に行い、ロードは応答時間を complete に足す。
        // ストアはパイプライン化され、階層の状態の更新だけを行う。
        let mut mem_extra = 0;
        if u.mem.loads() {
            for &(addr, _) in &ev.mem_addrs {
                mem_extra = mem_extra.max(self.params.mem.access(addr).latency);
            }
        } else if u.mem.stores() {
            for &(addr, _) in &ev.mem_addrs {
                self.params.mem.access(addr);
            }
        }
        let complete = iss + u.latency + mem_extra;

        let ret = complete
            .max(self.retire.last().saturating_sub(1))
            .max(self.retire.back(self.params.retire_width as usize - 1));
        self.time = ret;

        if u.is_branch
            && let Some(taken) = ev.branch_taken
        {
            let info = BranchInfo {
                taken,
                target: ev.branch_target,
                is_call: ev.branch_kind == BranchKind::Call,
                is_ret: ev.branch_kind == BranchKind::Ret,
                is_indirect: ev.branch_kind == BranchKind::Indirect,
            };
            let out = self.params.pred.predict_and_update(ev.pc, &info);
            if out.mispredict_dir {
                // 解決からの再充填。誤経路の影響は含めない。
                self.front = self.front.max(iss + self.params.mispredict);
                self.last_iline = u64::MAX;
            }
            if out.btb_miss || out.disagree_bubble {
                self.front += self.params.fetch_bubble;
            }
        }

        let mut w = ev.writes;
        while w != 0 {
            let b = w.trailing_zeros() as usize;
            if b < self.ready_at.len() {
                self.ready_at[b] = complete;
            }
            w &= w - 1;
        }

        self.disp.push(disp + 1);
        self.issue.push(iss);
        self.retire.push(ret + 1);
        if u.mem.loads() {
            if self.load_done.len() == self.params.lq.max(1) as usize {
                self.load_done.pop_front();
            }
            self.load_done.push_back(complete);
        }
        if u.mem.stores() {
            if self.stores.len() == self.params.sq.max(1) as usize {
                self.stores.pop_front();
            }
            let lines = ev
                .mem_addrs
                .iter()
                .map(|&(a, _)| a >> self.dline_shift)
                .collect();
            self.stores.push_back(PendingStore {
                lines,
                addr_at: iss,
                complete,
                retire: ret,
            });
        }
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

    const CLASSES: &[ClassUop] = &[
        ClassUop {
            class: "alu",
            latency: 1,
            busy: 1,
            ports: 0,
            group: 0,
            mem: MemKind::None,
            is_branch: false,
        },
        ClassUop {
            class: "load",
            latency: 1,
            busy: 1,
            ports: 0,
            group: 0,
            mem: MemKind::Load,
            is_branch: false,
        },
        ClassUop {
            class: "store",
            latency: 1,
            busy: 1,
            ports: 0,
            group: 0,
            mem: MemKind::Store,
            is_branch: false,
        },
        ClassUop {
            class: "branch",
            latency: 1,
            busy: 1,
            ports: 0,
            group: 0,
            mem: MemKind::None,
            is_branch: true,
        },
        ClassUop {
            class: "slow",
            latency: 20,
            busy: 1,
            ports: 0,
            group: 0,
            mem: MemKind::None,
            is_branch: false,
        },
    ];

    // i$ はミスでも 1 サイクルにして、フェッチの冷えをテストから除く。
    fn params() -> OooParams {
        OooParams {
            width: 4,
            rob: 64,
            sched: 32,
            lq: 16,
            sq: 16,
            retire_width: 4,
            mispredict: 0,
            fetch_bubble: 0,
            classes: CLASSES,
            ports: 4,
            mem: CacheHierarchy::new(&[D], 50),
            icache: CacheHierarchy::new(&[I], 0),
            pred: Predictor::new(
                DirPred::Bimodal { entries: 64 },
                Some(Btb::new(16, 2)),
                None,
                None,
            ),
            mem_disambig: true,
            reg_count: 64,
        }
    }

    fn alu(i: u64) -> InstrEvent {
        InstrEvent::new(i * 4, "alu")
    }

    fn load(i: u64, addr: u64, reads: u64, writes: u64) -> InstrEvent {
        InstrEvent {
            mem_addrs: vec![(addr, 8)],
            ..InstrEvent::new(i * 4, "load")
        }
        .reads(reads)
        .writes(writes)
    }

    #[test]
    fn independent_stream_runs_at_width() {
        let mut m = OooModel::new(params());
        for i in 0..64u64 {
            m.observe(&alu(i));
        }
        // 4 幅: disp は 4 命令/サイクルで進み、retire も追いつく。
        assert_eq!(m.now(), VirtualTime(17));
    }

    #[test]
    fn dependency_chain_adds_latencies() {
        let mut m = OooModel::new(params());
        for i in 0..8u64 {
            m.observe(&alu(i).reads(u64::from(i > 0)).writes(1));
        }
        // ready_at 待ちで 1 命令ごとに latency 1 ずつ伸びる。
        assert_eq!(m.now(), VirtualTime(9));
        // 独立列なら同じ 8 命令は 3。
        let mut free = OooModel::new(params());
        for i in 0..8u64 {
            free.observe(&alu(i));
        }
        assert_eq!(free.now(), VirtualTime(3));
    }

    #[test]
    fn rob_capacity_stalls_dispatch() {
        let run = |rob: u32| {
            let mut p = params();
            p.rob = rob;
            let mut m = OooModel::new(p);
            m.observe(&InstrEvent::new(0, "slow"));
            for i in 1..4u64 {
                m.observe(&alu(i));
            }
            m.observe(&InstrEvent::new(16, "slow"));
            for i in 5..8u64 {
                m.observe(&alu(i));
            }
            m.now()
        };
        // 先頭の遅い命令が退役するまで i-rob 番目は ROB に入れず、
        // その位置の遅い命令の complete がずれ込む。
        assert_eq!(run(4), VirtualTime(41));
        assert_eq!(run(64), VirtualTime(22));
    }

    #[test]
    fn load_hit_and_miss_change_complete() {
        // 同じラインへの 2 本目のロードはヒットし、別ラインへの 2 本目はミス。
        let mut hit = OooModel::new(params());
        let mut miss = OooModel::new(params());
        for (m, addr) in [(&mut hit, 0x1000u64), (&mut miss, 0x2000u64)] {
            m.observe(&load(0, 0x1000, 0, 1));
            m.observe(&load(1, addr, 1, 2));
        }
        // ミスは 50、ヒットは 2 の応答時間が鎖に乗る。
        assert_eq!(hit.now(), VirtualTime(57));
        assert_eq!(miss.now(), VirtualTime(107));
    }

    #[test]
    fn mispredicted_branch_delays_following() {
        // 「常に取らない」の静的予測に、常に取る分岐を食わせる。
        let run = |mispredict: u64| {
            let mut p = params();
            p.mispredict = mispredict;
            p.pred = Predictor::new(
                DirPred::Static {
                    backward_taken: false,
                },
                None,
                None,
                None,
            );
            let mut m = OooModel::new(p);
            m.observe(&InstrEvent::new(0, "branch").branch(true, 0x80, BranchKind::Direct));
            for i in 0..8u64 {
                m.observe(&InstrEvent::new(0x80 + i * 4, "alu"));
            }
            m.now()
        };
        assert_eq!(run(8).0 - run(0).0, 8);
    }

    #[test]
    fn store_waits_reach_same_line_load() {
        // 先行する未退役ストアとの衝突検査。同一ラインのロードはストアの
        // complete まで、保守的（mem_disambig=false）なら全ストアの
        // アドレス確定（発行）まで待つ。
        let run = |disambig: bool, load_addr: u64| {
            let mut p = params();
            p.mem_disambig = disambig;
            let mut m = OooModel::new(p);
            // 遅い生産者の結果をアドレスに使い、ストアの発行を 21 まで遅らせる。
            m.observe(&InstrEvent::new(0, "slow").writes(1));
            m.observe(
                &InstrEvent {
                    mem_addrs: vec![(0x1000, 8)],
                    ..InstrEvent::new(4, "store")
                }
                .reads(1),
            );
            m.observe(&InstrEvent {
                mem_addrs: vec![(load_addr, 8)],
                ..InstrEvent::new(8, "load")
            });
            m.now()
        };
        // 同一ラインはストアの complete=22 まで待つ。d$ はストアが充填済み
        // なので応答はヒットの 2 で、25 に着く。別ラインは依存予測で通り、
        // ミス分だけ。
        assert_eq!(run(true, 0x1000), VirtualTime(25));
        assert_eq!(run(true, 0x1040), VirtualTime(54));
        // 保守的なときは別ラインでもアドレス確定（発行 21）まで待つ。
        assert_eq!(run(false, 0x1000), VirtualTime(25));
        assert_eq!(run(false, 0x1040), VirtualTime(74));
    }

    #[test]
    fn full_load_queue_stalls_dispatch() {
        let run = |lq: u32| {
            let mut p = params();
            p.lq = lq;
            let mut m = OooModel::new(p);
            for i in 0..3u64 {
                m.observe(&load(i, 0x1000 + i * 64, 0, 1 << (i + 1)));
            }
            m.now()
        };
        // LQ 2 では 3 本目のディスパッチが先頭ロードの complete=54 を待つ。
        assert_eq!(run(16), VirtualTime(54));
        assert_eq!(run(2), VirtualTime(107));
    }

    #[test]
    fn read_modify_write_uses_both_queues() {
        // `MemKind::Both` は LQ と SQ の両方を消費する。
        const RMW: &[ClassUop] = &[ClassUop {
            class: "rmw",
            latency: 1,
            busy: 1,
            ports: 0,
            group: 0,
            mem: MemKind::Both,
            is_branch: false,
        }];
        let run = |lq: u32, sq: u32| {
            let mut p = params();
            p.classes = RMW;
            p.lq = lq;
            p.sq = sq;
            let mut m = OooModel::new(p);
            for i in 0..2u64 {
                m.observe(&InstrEvent {
                    mem_addrs: vec![(0x1000 + i * 64, 8)],
                    ..InstrEvent::new(i * 4, "rmw")
                });
            }
            m.now()
        };
        // どちらかのキューを 1 に絞ると 2 個目は 1 個目の解放（54）を待つ。
        assert_eq!(run(16, 16), VirtualTime(54));
        assert_eq!(run(1, 16), VirtualTime(107));
        assert_eq!(run(16, 1), VirtualTime(107));
    }

    #[test]
    fn retire_width_limits_drain() {
        let run = |retire_width: u32| {
            let mut p = params();
            p.retire_width = retire_width;
            let mut m = OooModel::new(p);
            for i in 0..8u64 {
                m.observe(&alu(i));
            }
            m.now()
        };
        assert_eq!(run(1), VirtualTime(9));
        assert_eq!(run(4), VirtualTime(3));
    }

    #[test]
    fn deterministic_for_same_sequence() {
        let (mut a, mut b) = (OooModel::new(params()), OooModel::new(params()));
        let mut x = 0x9e37_79b9u64;
        for i in 0..300u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let pc = i * 4 % 0x400;
            let ev = match x % 4 {
                0 => load(i, (x % 0x800) & !63, x % 4, 1 << (x % 63)),
                1 => InstrEvent {
                    mem_addrs: vec![((x % 0x800) & !63, 8)],
                    ..InstrEvent::new(pc, "store")
                },
                2 => InstrEvent::new(pc, "branch").branch(
                    x & 0x100 == 0,
                    (x % 0x400) & !3,
                    BranchKind::Direct,
                ),
                _ => alu(i).reads(x % 8).writes(1 << (x % 63)),
            };
            a.observe(&ev);
            b.observe(&ev);
            assert_eq!(a.now(), b.now());
        }
    }
}
