// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! タイミングモデル。命令イベントを受け、仮想時間を進める。
//!
//! 詳しくは [タイミングモデル](../../docs/design/timing.md) を見る。

#![forbid(unsafe_code)]

pub mod branch;
pub mod cache;
pub mod inorder;
pub mod ooo;

/// CPU モデルが宣言する正確さの水準。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fidelity {
    /// 数えない。仮想時間はステップ数から換算する。
    None,
    /// 分類ごとの固定値を足す。
    Cpi,
    /// 資料で確定した値を再現する。
    Exact,
    /// 近似し、誤差を宣言する。
    Approx,
    /// `approx` のうち未較正のもの。
    ApproxUncalibrated,
}

/// 分岐の種別。`InstrEvent::branch_taken` が `Some` のときに参照する。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum BranchKind {
    /// 直接分岐・直接ジャンプ。
    #[default]
    Direct,
    /// 呼出し。
    Call,
    /// リターン。
    Ret,
    /// 間接ジャンプ。
    Indirect,
}

/// 退役した命令の記録。
#[derive(Clone, Debug)]
pub struct InstrEvent {
    /// 命令のアドレス。
    pub pc: u64,
    /// 命令の分類（タイミング表の項目名）。
    pub class: &'static str,
    /// 触れたメモリ（アドレス、大きさ）。
    pub mem_addrs: Vec<(u64, u32)>,
    /// 分岐の成否。
    pub branch_taken: Option<bool>,
    /// 分岐の飛び先。予測器の照合に使う。
    pub branch_target: u64,
    /// 分岐の種別。
    pub branch_kind: BranchKind,
    /// 意味論が渡した手がかり（例：乗数の 1 の数）。
    pub hint: u64,
    /// 読むレジスタ。ビットの割り当ては送り手が決める。
    pub reads: u64,
    /// 書くレジスタ。ビットの割り当ては送り手が決める。
    pub writes: u64,
}

impl InstrEvent {
    #[must_use]
    pub fn new(pc: u64, class: &'static str) -> Self {
        Self {
            pc,
            class,
            mem_addrs: Vec::new(),
            branch_taken: None,
            branch_target: 0,
            branch_kind: BranchKind::Direct,
            hint: 0,
            reads: 0,
            writes: 0,
        }
    }

    #[must_use]
    pub fn branch(mut self, taken: bool, target: u64, kind: BranchKind) -> Self {
        self.branch_taken = Some(taken);
        self.branch_target = target;
        self.branch_kind = kind;
        self
    }

    #[must_use]
    pub fn reads(mut self, reads: u64) -> Self {
        self.reads = reads;
        self
    }

    #[must_use]
    pub fn writes(mut self, writes: u64) -> Self {
        self.writes = writes;
        self
    }
}

/// 仮想時間（サイクル数）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct VirtualTime(pub u64);

/// タイミングモデルの共通操作。
pub trait TimingModel {
    /// 命令イベントを消費し、仮想時間を進める。
    fn observe(&mut self, ev: &InstrEvent);
    /// 現在の仮想時間。
    fn now(&self) -> VirtualTime;
}

/// 何も数えないモデル（`none`）。
#[derive(Clone, Debug, Default)]
pub struct NullModel {
    steps: u64,
}

impl TimingModel for NullModel {
    fn observe(&mut self, _ev: &InstrEvent) {
        self.steps += 1;
    }

    fn now(&self) -> VirtualTime {
        VirtualTime(self.steps)
    }
}

/// 分類ごとの CPI。`CpiModel` の表の行。
#[derive(Clone, Copy, Debug)]
pub struct ClassCpi {
    pub class: &'static str,
    pub cpi: u64,
}

/// 分類ごとの固定値を足すモデル（`cpi`）。
/// 表にない分類は `default_cpi` を使う。
#[derive(Clone, Debug)]
pub struct CpiModel {
    cycles: u64,
    default_cpi: u64,
    table: &'static [ClassCpi],
}

impl CpiModel {
    /// 分類表のない均一 CPI。
    #[must_use]
    pub const fn new(default_cpi: u64) -> Self {
        Self::with_table(default_cpi, &[])
    }

    /// 分類ごとの CPI 表を使う。
    #[must_use]
    pub const fn with_table(default_cpi: u64, table: &'static [ClassCpi]) -> Self {
        Self {
            cycles: 0,
            default_cpi,
            table,
        }
    }

    fn cpi(&self, class: &str) -> u64 {
        for row in self.table {
            if row.class == class {
                return row.cpi;
            }
        }
        self.default_cpi
    }
}

impl TimingModel for CpiModel {
    fn observe(&mut self, ev: &InstrEvent) {
        self.cycles += self.cpi(ev.class);
    }

    fn now(&self) -> VirtualTime {
        VirtualTime(self.cycles)
    }
}

/// 分類ごとの発行コストと、結果が使えるまでの距離。
/// `ready` は命令の開始時点からのサイクル数。発行コストと同じなら、次の命令は待たない。
#[derive(Clone, Copy, Debug)]
pub struct ClassCost {
    pub class: &'static str,
    pub issue: u64,
    pub ready: u64,
}

/// 発行コストを足し、結果を待つ命令だけを止める。パイプラインの重なりはモデルしない。
#[derive(Clone, Debug)]
pub struct ExactModel {
    time: u64,
    ready_at: [u64; 64],
    costs: &'static [ClassCost],
}

/// 設計文書の R3000 の例。ロードは開始+2、乗算は開始+12、除算は開始+35、syscall は 0。
/// Ref: SPEC-MIPS-R3000 (Rev 1.0).
pub const R3000_COSTS: &[ClassCost] = &[
    ClassCost {
        class: "alu",
        issue: 1,
        ready: 1,
    },
    ClassCost {
        class: "store",
        issue: 1,
        ready: 1,
    },
    ClassCost {
        class: "branch",
        issue: 1,
        ready: 1,
    },
    ClassCost {
        class: "jump",
        issue: 1,
        ready: 1,
    },
    ClassCost {
        class: "load",
        issue: 1,
        ready: 2,
    },
    ClassCost {
        class: "mult",
        issue: 1,
        ready: 12,
    },
    ClassCost {
        class: "div",
        issue: 1,
        ready: 35,
    },
    ClassCost {
        class: "system",
        issue: 0,
        ready: 0,
    },
];

impl ExactModel {
    #[must_use]
    pub const fn new(costs: &'static [ClassCost]) -> Self {
        Self {
            time: 0,
            ready_at: [0; 64],
            costs,
        }
    }

    /// 設計文書の R3000 の表。
    #[must_use]
    pub const fn r3000() -> Self {
        Self::new(R3000_COSTS)
    }

    fn cost(&self, class: &str) -> (u64, u64) {
        for row in self.costs {
            if row.class == class {
                return (row.issue, row.ready);
            }
        }
        (1, 1)
    }
}

impl TimingModel for ExactModel {
    fn observe(&mut self, ev: &InstrEvent) {
        let mut start = self.time;
        let mut bit = 0;
        let mut reads = ev.reads;
        while reads != 0 {
            if reads & 1 != 0 {
                start = start.max(self.ready_at[bit]);
            }
            reads >>= 1;
            bit += 1;
        }
        let (issue, ready) = self.cost(ev.class);
        self.time = start + issue;
        let mut writes = ev.writes;
        bit = 0;
        while writes != 0 {
            if writes & 1 != 0 {
                self.ready_at[bit] = start + ready;
            }
            writes >>= 1;
            bit += 1;
        }
    }

    fn now(&self) -> VirtualTime {
        VirtualTime(self.time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_counts_steps() {
        let mut m = NullModel::default();
        m.observe(&InstrEvent::new(0x1000, "alu"));
        m.observe(&InstrEvent::new(0x1004, "alu"));
        assert_eq!(m.now(), VirtualTime(2));
    }

    #[test]
    fn cpi_accumulates() {
        let mut m = CpiModel::new(2);
        m.observe(&InstrEvent::new(0, "alu"));
        m.observe(&InstrEvent::new(4, "load"));
        assert_eq!(m.now(), VirtualTime(4));
    }

    #[test]
    fn cpi_uses_class_table() {
        static TABLE: &[ClassCpi] = &[
            ClassCpi {
                class: "alu",
                cpi: 1,
            },
            ClassCpi {
                class: "mult",
                cpi: 4,
            },
        ];
        let mut m = CpiModel::with_table(2, TABLE);
        m.observe(&InstrEvent::new(0, "alu"));
        m.observe(&InstrEvent::new(4, "mult"));
        // 表にない分類は既定値。
        m.observe(&InstrEvent::new(8, "load"));
        assert_eq!(m.now(), VirtualTime(7));
    }

    #[test]
    fn r3000_stalls_only_for_a_result_that_is_not_ready() {
        let mut load_use = ExactModel::r3000();
        load_use.observe(&InstrEvent::new(0, "load").writes(1 << 1));
        load_use.observe(&InstrEvent::new(4, "alu").reads(1 << 1).writes(1 << 2));
        assert_eq!(load_use.now(), VirtualTime(3));

        let mut load_other = ExactModel::r3000();
        load_other.observe(&InstrEvent::new(0, "load").writes(1 << 1));
        load_other.observe(&InstrEvent::new(4, "alu").reads(1 << 2).writes(1 << 3));
        assert_eq!(load_other.now(), VirtualTime(2));

        let mut mult = ExactModel::r3000();
        mult.observe(&InstrEvent::new(0, "mult").writes(1 << 33));
        mult.observe(&InstrEvent::new(4, "alu").reads(1 << 33).writes(1 << 2));
        assert_eq!(mult.now(), VirtualTime(13));

        let mut div = ExactModel::r3000();
        div.observe(&InstrEvent::new(0, "div").writes(1 << 33));
        div.observe(&InstrEvent::new(4, "alu").reads(1 << 33));
        assert_eq!(div.now(), VirtualTime(36));

        let mut sys = ExactModel::r3000();
        sys.observe(&InstrEvent::new(0, "system"));
        assert_eq!(sys.now(), VirtualTime(0));
    }
}
