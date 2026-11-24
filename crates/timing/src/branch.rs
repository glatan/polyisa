// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 分岐予測器のモデル。
//!
//! 方向予測・分岐先バッファ・リターンスタック・間接ジャンプ表を組み合わせ、
//! 予測と実績のずれを種別で返す。ずれに課すペナルティ値は呼び出し側が決める。

/// 方向予測器の構成。
#[derive(Clone, Copy, Debug)]
pub enum DirPred {
    /// 静的。`backward_taken` なら飛び先が PC より前の分岐を取ると予測する。
    Static { backward_taken: bool },
    /// 2 ビットカウンタのバイモーダル。`entries` は表の大きさ。
    Bimodal { entries: usize },
    /// グローバル履歴を PC と XOR して引く。`ghr_bits` は履歴の長さ、`sets` は表の大きさ。
    Gshare { ghr_bits: u32, sets: usize },
}

/// 分岐先バッファ。「その PC が登録済みか」だけを持つ集合。
/// 間接ジャンプ表（IJTP）としても使う。
// Gap: GAP-0091 飛び先の中身は持たないので、登録済みの飛び先誤りは検えない。
#[derive(Clone, Debug)]
pub struct Btb {
    entries: usize,
    ways: usize,
    tags: Vec<u64>,
    next: Vec<u32>,
}

impl Btb {
    /// `entries` は `ways` の倍数。
    #[must_use]
    pub fn new(entries: usize, ways: usize) -> Self {
        assert!(ways > 0 && entries >= ways && entries.is_multiple_of(ways));
        Self {
            entries,
            ways,
            tags: vec![u64::MAX; entries],
            next: vec![0; entries / ways],
        }
    }

    fn sets(&self) -> usize {
        self.entries / self.ways
    }

    fn set_of(&self, pc: u64) -> usize {
        // u64 のまま剰余してから cast し、32 ビットホストでも決定的にする。
        ((pc >> 2) % self.sets() as u64) as usize
    }

    fn contains(&self, pc: u64) -> bool {
        let base = self.set_of(pc) * self.ways;
        self.tags[base..base + self.ways].contains(&pc)
    }

    fn insert(&mut self, pc: u64) {
        if self.contains(pc) {
            return;
        }
        let set = self.set_of(pc);
        let way = self.next[set] as usize;
        self.tags[set * self.ways + way] = pc;
        self.next[set] = (way + 1) as u32 % self.ways as u32;
    }
}

/// リターンアドレススタック。
#[derive(Clone, Debug)]
pub struct Ras {
    stack: Vec<u64>,
    depth: usize,
}

impl Ras {
    #[must_use]
    pub fn new(depth: usize) -> Self {
        assert!(depth > 0);
        Self {
            stack: Vec::with_capacity(depth),
            depth,
        }
    }

    fn push(&mut self, addr: u64) {
        if self.stack.len() == self.depth {
            self.stack.remove(0);
        }
        self.stack.push(addr);
    }

    fn pop(&mut self) -> Option<u64> {
        self.stack.pop()
    }
}

/// 命令の分岐の実績。
#[derive(Clone, Copy, Debug)]
pub struct BranchInfo {
    /// 分岐を取ったか。
    pub taken: bool,
    /// 飛び先。直接分岐は即値の先、間接とリターンは実績の値。
    /// 取らなかった分岐でも、方向予測の判定に使うので計算済みの値を渡す。
    pub target: u64,
    /// 呼出しか。RAS に `pc + 4` を積む。
    pub is_call: bool,
    /// リターンか。RAS から取り出した値と `target` を照合する。
    pub is_ret: bool,
    /// 間接ジャンプか。IJTP（無ければ BTB）を引く。
    pub is_indirect: bool,
}

/// 予測と実績のずれの種別。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PredOutcome {
    /// 方向の予測が外れた（取ると予測したが実際は違う、またはその逆）。
    pub mispredict_dir: bool,
    /// ターゲットを出せる構造にその PC がなかった。フェッチバブルの種。
    pub btb_miss: bool,
    /// 構造の出したターゲットが実績と違った。予測器同士の不一致バブルの種。
    pub disagree_bubble: bool,
}

#[derive(Clone, Debug)]
enum Dir {
    Static {
        backward_taken: bool,
    },
    Bimodal {
        ctr: Vec<u8>,
    },
    Gshare {
        ctr: Vec<u8>,
        ghr: u64,
        ghr_bits: u32,
    },
}

/// 分岐予測器全体。
#[derive(Clone, Debug)]
pub struct Predictor {
    dir: Dir,
    btb: Option<Btb>,
    ras: Option<Ras>,
    ijtp: Option<Btb>,
}

impl Predictor {
    /// `dir` は方向予測器の構成。`btb` を持たないとき、ターゲット不明の直接分岐は
    /// 常に取らないと予測する。`ijtp` は間接ジャンプ用の小さな表で、無ければ BTB を引く。
    #[must_use]
    pub fn new(dir: DirPred, btb: Option<Btb>, ras: Option<Ras>, ijtp: Option<Btb>) -> Self {
        let dir = match dir {
            DirPred::Static { backward_taken } => Dir::Static { backward_taken },
            DirPred::Bimodal { entries } => Dir::Bimodal {
                ctr: vec![0; entries.max(1)],
            },
            DirPred::Gshare { ghr_bits, sets } => {
                assert!(ghr_bits > 0 && ghr_bits < 64);
                Dir::Gshare {
                    ctr: vec![0; sets.max(1)],
                    ghr: 0,
                    ghr_bits,
                }
            }
        };
        Self {
            dir,
            btb,
            ras,
            ijtp,
        }
    }

    /// 予測してから実績で更新し、ずれの種別を返す。
    pub fn predict_and_update(&mut self, pc: u64, info: &BranchInfo) -> PredOutcome {
        let mut btb_miss = false;
        let mut disagree_bubble = false;
        let predicted_taken;
        if info.is_ret {
            match self.ras.as_mut().and_then(Ras::pop) {
                Some(t) => {
                    predicted_taken = true;
                    disagree_bubble = t != info.target;
                }
                None => {
                    predicted_taken = self.knows_indirect(pc);
                    btb_miss = !predicted_taken;
                }
            }
        } else if info.is_indirect {
            predicted_taken = self.knows_indirect(pc);
            btb_miss = !predicted_taken;
        } else {
            // 取ると予測するには分岐先が要るので、BTB 未登録なら取らない側に倒れる。
            let has_target = self.btb.as_ref().is_some_and(|b| b.contains(pc));
            predicted_taken = self.dir_predict(pc, info) && has_target;
            btb_miss = info.taken && !has_target;
        }
        let out = PredOutcome {
            mispredict_dir: predicted_taken != info.taken,
            btb_miss,
            disagree_bubble,
        };
        self.dir_update(pc, info.taken);
        if info.is_indirect && !info.is_ret {
            match &mut self.ijtp {
                Some(ijtp) => ijtp.insert(pc),
                None => {
                    if let Some(btb) = &mut self.btb {
                        btb.insert(pc);
                    }
                }
            }
        } else if info.taken
            && !info.is_ret
            && let Some(btb) = &mut self.btb
        {
            btb.insert(pc);
        }
        if info.is_call
            && let Some(ras) = &mut self.ras
        {
            ras.push(pc + 4);
        }
        out
    }

    fn knows_indirect(&self, pc: u64) -> bool {
        self.ijtp
            .as_ref()
            .or(self.btb.as_ref())
            .is_some_and(|b| b.contains(pc))
    }

    fn dir_predict(&self, pc: u64, info: &BranchInfo) -> bool {
        match &self.dir {
            Dir::Static { backward_taken } => *backward_taken && info.target < pc,
            Dir::Bimodal { ctr } => ctr[((pc >> 2) % ctr.len() as u64) as usize] >= 2,
            Dir::Gshare { ctr, ghr, .. } => {
                ctr[(((pc >> 2) ^ ghr) % ctr.len() as u64) as usize] >= 2
            }
        }
    }

    fn dir_update(&mut self, pc: u64, taken: bool) {
        match &mut self.dir {
            Dir::Static { .. } => {}
            Dir::Bimodal { ctr } => {
                let i = ((pc >> 2) % ctr.len() as u64) as usize;
                bump(&mut ctr[i], taken);
            }
            Dir::Gshare { ctr, ghr, ghr_bits } => {
                let i = (((pc >> 2) ^ *ghr) % ctr.len() as u64) as usize;
                bump(&mut ctr[i], taken);
                let mask = (1u64 << *ghr_bits) - 1;
                *ghr = (*ghr << 1 | u64::from(taken)) & mask;
            }
        }
    }
}

fn bump(ctr: &mut u8, taken: bool) {
    if taken {
        *ctr = (*ctr).min(2) + 1;
    } else {
        *ctr = ctr.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIRECT: BranchInfo = BranchInfo {
        taken: true,
        target: 0,
        is_call: false,
        is_ret: false,
        is_indirect: false,
    };

    #[test]
    fn static_predicts_backward_taken() {
        let mut p = Predictor::new(
            DirPred::Static {
                backward_taken: true,
            },
            Some(Btb::new(8, 1)),
            None,
            None,
        );
        // 後方分岐。初見は BTB ミスで取らない側に倒れる。
        let back = BranchInfo {
            target: 0x100,
            ..DIRECT
        };
        let first = p.predict_and_update(0x200, &back);
        assert!((first.mispredict_dir, first.btb_miss) == (true, true));
        let again = p.predict_and_update(0x200, &back);
        assert!((again.mispredict_dir, again.btb_miss) == (false, false));
        // 前方分岐は取らない予測。
        let fwd_taken = BranchInfo {
            target: 0x300,
            ..DIRECT
        };
        assert!(p.predict_and_update(0x200, &fwd_taken).mispredict_dir);
        let fwd_not = BranchInfo {
            taken: false,
            ..fwd_taken
        };
        assert!(!p.predict_and_update(0x200, &fwd_not).mispredict_dir);
    }

    #[test]
    fn bimodal_converges() {
        let mut p = Predictor::new(
            DirPred::Bimodal { entries: 64 },
            Some(Btb::new(16, 2)),
            None,
            None,
        );
        let info = BranchInfo {
            target: 0x40,
            ..DIRECT
        };
        let mut late_misses = 0;
        for i in 0..8 {
            let out = p.predict_and_update(0x80, &info);
            if i >= 3 && out.mispredict_dir {
                late_misses += 1;
            }
        }
        assert_eq!(late_misses, 0);
    }

    #[test]
    fn gshare_learns_alternating_pattern() {
        let mut p = Predictor::new(
            DirPred::Gshare {
                ghr_bits: 4,
                sets: 64,
            },
            Some(Btb::new(16, 2)),
            None,
            None,
        );
        let mut late_misses = 0;
        for i in 0..64 {
            let info = BranchInfo {
                taken: i % 2 == 0,
                target: 0x40,
                ..DIRECT
            };
            let out = p.predict_and_update(0x80, &info);
            if i >= 40 && out.mispredict_dir {
                late_misses += 1;
            }
        }
        assert_eq!(late_misses, 0);
    }

    #[test]
    fn btb_miss_only_once() {
        let mut p = Predictor::new(
            DirPred::Static {
                backward_taken: true,
            },
            Some(Btb::new(4, 1)),
            None,
            None,
        );
        let info = BranchInfo {
            target: 0x40,
            ..DIRECT
        };
        assert!(p.predict_and_update(0x80, &info).btb_miss);
        assert!(!p.predict_and_update(0x80, &info).btb_miss);
        // BTB を持たない予測器は毎回ミス。
        let mut bare = Predictor::new(DirPred::Bimodal { entries: 8 }, None, None, None);
        assert!(bare.predict_and_update(0x80, &info).btb_miss);
        assert!(bare.predict_and_update(0x80, &info).btb_miss);
    }

    #[test]
    fn ras_matches_call_and_ret() {
        let mut p = Predictor::new(
            DirPred::Bimodal { entries: 16 },
            None,
            Some(Ras::new(4)),
            None,
        );
        let call = BranchInfo {
            is_call: true,
            target: 0x900,
            ..DIRECT
        };
        p.predict_and_update(0x100, &call);
        let ret = BranchInfo {
            is_ret: true,
            target: 0x104,
            ..DIRECT
        };
        let ok = p.predict_and_update(0x900, &ret);
        assert_eq!(
            ok,
            PredOutcome {
                mispredict_dir: false,
                btb_miss: false,
                disagree_bubble: false,
            }
        );
        // 違う戻り先は不一致バブル。
        p.predict_and_update(0x200, &call);
        let bad = BranchInfo {
            target: 0x999,
            ..ret
        };
        assert!(p.predict_and_update(0x900, &bad).disagree_bubble);
        // 空の RAS はターゲット不明としてミス。
        let mut empty = Predictor::new(
            DirPred::Bimodal { entries: 16 },
            None,
            Some(Ras::new(4)),
            None,
        );
        let out = empty.predict_and_update(0x900, &ret);
        assert!((out.mispredict_dir, out.btb_miss) == (true, true));
    }

    #[test]
    fn ras_drops_oldest_past_depth() {
        let mut p = Predictor::new(
            DirPred::Bimodal { entries: 16 },
            None,
            Some(Ras::new(2)),
            None,
        );
        // 深さ 2 に 3 呼出しを積むと、最古の戻り先は捨てられる。
        for pc in [0x100u64, 0x200, 0x300] {
            let call = BranchInfo {
                is_call: true,
                target: 0x900,
                ..DIRECT
            };
            p.predict_and_update(pc, &call);
        }
        let ret = |target: u64| BranchInfo {
            is_ret: true,
            target,
            ..DIRECT
        };
        // 新しい 2 件はそのまま照合できる。
        let ok = p.predict_and_update(0x900, &ret(0x304));
        assert!((ok.mispredict_dir, ok.disagree_bubble) == (false, false));
        let ok = p.predict_and_update(0x900, &ret(0x204));
        assert!((ok.mispredict_dir, ok.disagree_bubble) == (false, false));
        // 3 件目はスタックが空で、ターゲット不明のミスに倒れる。
        let out = p.predict_and_update(0x900, &ret(0x104));
        assert!((out.mispredict_dir, out.btb_miss) == (true, true));
    }

    #[test]
    fn indirect_uses_ijtp() {
        let mut p = Predictor::new(
            DirPred::Bimodal { entries: 16 },
            Some(Btb::new(4, 1)),
            None,
            Some(Btb::new(2, 1)),
        );
        let jmp = BranchInfo {
            is_indirect: true,
            target: 0x500,
            ..DIRECT
        };
        assert!(p.predict_and_update(0x80, &jmp).btb_miss);
        let hit = p.predict_and_update(0x80, &jmp);
        assert!((hit.mispredict_dir, hit.btb_miss) == (false, false));
    }

    #[test]
    fn deterministic_for_same_sequence() {
        let mk = || {
            Predictor::new(
                DirPred::Gshare {
                    ghr_bits: 6,
                    sets: 32,
                },
                Some(Btb::new(8, 2)),
                Some(Ras::new(4)),
                Some(Btb::new(4, 1)),
            )
        };
        let (mut a, mut b) = (mk(), mk());
        let mut x = 0x1234_5678u64;
        for _ in 0..300 {
            // 決定的な疑似乱数列で分岐の列を作る。
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let info = BranchInfo {
                taken: x & 1 == 0,
                target: x % 0x1000,
                is_call: x.is_multiple_of(17),
                is_ret: x.is_multiple_of(19),
                is_indirect: x.is_multiple_of(23),
            };
            assert_eq!(
                a.predict_and_update(x, &info),
                b.predict_and_update(x, &info)
            );
        }
    }
}
