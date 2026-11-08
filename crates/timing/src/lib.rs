//! タイミングモデル。命令イベントを受け、仮想時間を進める。
//!
//! 詳しくは [タイミングモデル](../../docs/design/timing.md) を見る。

#![forbid(unsafe_code)]

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
    /// 意味論が渡した手がかり（例：乗数の 1 の数）。
    pub hint: u64,
}

impl InstrEvent {
    #[must_use]
    pub fn new(pc: u64, class: &'static str) -> Self {
        Self {
            pc,
            class,
            mem_addrs: Vec::new(),
            branch_taken: None,
            hint: 0,
        }
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

/// 分類ごとの固定値を足すモデル（`cpi`）。
#[derive(Clone, Debug)]
pub struct CpiModel {
    cycles: u64,
    default_cpi: u64,
}

impl CpiModel {
    #[must_use]
    pub const fn new(default_cpi: u64) -> Self {
        Self {
            cycles: 0,
            default_cpi,
        }
    }
}

impl TimingModel for CpiModel {
    fn observe(&mut self, _ev: &InstrEvent) {
        self.cycles += self.default_cpi;
    }

    fn now(&self) -> VirtualTime {
        VirtualTime(self.cycles)
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
}
