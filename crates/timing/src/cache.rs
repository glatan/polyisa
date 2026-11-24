// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! キャッシュ階層のモデル。
//!
//! 段ごとの形状・置換・書き込み方式・応答時間を持ち、アドレスの列に対して
//! 合計レイテンシを返す。`access` に渡すアドレスは呼び出し側が近似した物理
//! アドレス（ページフレーム識別子由来）とし、仮→物理の変換は本モジュールの
//! 契約に含めない。

/// 置換方式。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Repl {
    /// ツリー PLRU。way 数は 2 の冪に限る（`CacheHierarchy::new` が検査する）。
    Plru,
    /// 巡回。ランダム置換の決定的近似としても使う。
    RoundRobin,
}

/// 書き込み方式。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WriteKind {
    /// ライトバック。
    WriteBack,
    /// ライトスルー。
    WriteThrough,
}

/// 一段の形状。
#[derive(Clone, Copy, Debug)]
pub struct CacheLevel {
    /// 段の名前（表示用）。
    pub name: &'static str,
    /// セット数。
    pub sets: usize,
    /// 連想度。1 以上 64 以下。
    pub ways: usize,
    /// ラインサイズの log2。
    pub line_shift: u32,
    /// 置換方式。
    pub repl: Repl,
    /// 書き込み方式。
    pub write: WriteKind,
    /// その段に届いたときの応答時間。
    pub hit_latency: u64,
}

/// アクセスの結果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AccessReport {
    /// 合計レイテンシ。ヒット段までの各段の `hit_latency` の和。
    /// 全段ミスなら全段の和に `mem_latency` を足した値。
    pub latency: u64,
    /// ヒットした段の番号。全段ミスなら `None`。
    pub hit_level: Option<usize>,
}

#[derive(Clone, Debug)]
struct Set {
    tags: Vec<u64>,
    valid: u64,
    state: u64,
}

#[derive(Clone, Debug)]
struct Level {
    cfg: CacheLevel,
    sets: Vec<Set>,
}

impl Level {
    /// ヒットなら true、ミスなら充填して false を返す。
    fn lookup(&mut self, addr: u64) -> bool {
        let line = addr >> self.cfg.line_shift;
        // u64 のまま剰余してから cast し、32 ビットホストでも決定的にする。
        let idx = (line % self.sets.len() as u64) as usize;
        let set = &mut self.sets[idx];
        for way in 0..set.tags.len() {
            if (set.valid >> way) & 1 == 1 && set.tags[way] == line {
                mark_used(self.cfg.repl, self.cfg.ways, set, way);
                return true;
            }
        }
        let way = pick_victim(self.cfg.repl, self.cfg.ways, set);
        set.tags[way] = line;
        set.valid |= 1 << way;
        mark_used(self.cfg.repl, self.cfg.ways, set, way);
        false
    }
}

/// 充填先を選ぶ。空き way があれば最若番、なければ置換方式に従う。
fn pick_victim(repl: Repl, ways: usize, set: &mut Set) -> usize {
    let free = set.valid.trailing_ones() as usize;
    if free < ways {
        return free;
    }
    match repl {
        Repl::Plru => {
            // 内部節点を二分木（ヒープ配置）とみなし、bit が指す側へ降りる。
            let mut node = 0usize;
            while node + 1 < ways {
                node = 2 * node + 1 + ((set.state >> node) & 1) as usize;
            }
            node + 1 - ways
        }
        Repl::RoundRobin => {
            let way = (set.state % ways as u64) as usize;
            set.state = set.state.wrapping_add(1);
            way
        }
    }
}

/// アクセス・充填した way を「最近使った側」に倒す。巡回は指しを動かさない。
fn mark_used(repl: Repl, ways: usize, set: &mut Set, way: usize) {
    if repl != Repl::Plru {
        return;
    }
    let mut leaf = way + ways - 1;
    while leaf > 0 {
        let parent = (leaf - 1) / 2;
        if leaf % 2 == 1 {
            set.state |= 1 << parent;
        } else {
            set.state &= !(1 << parent);
        }
        leaf = parent;
    }
}

/// キャッシュ階層。先頭の段が最上位。
/// データ用と命令用は共有せず、呼び出し側が別インスタンスを持つ。
#[derive(Clone, Debug)]
pub struct CacheHierarchy {
    levels: Vec<Level>,
    mem_latency: u64,
}

impl CacheHierarchy {
    /// `params` は最上位の段から順に並べる。
    /// `mem_latency` は全段ミスの先（主記憶の近似）の応答時間。
    #[must_use]
    pub fn new(params: &[CacheLevel], mem_latency: u64) -> Self {
        let levels = params
            .iter()
            .map(|cfg| {
                assert!(cfg.sets > 0 && (1..=64).contains(&cfg.ways));
                // ツリー PLRU は内部節点を完全二分木に置くので way 数は 2 の冪。
                assert!(cfg.repl != Repl::Plru || cfg.ways.is_power_of_two());
                Level {
                    cfg: *cfg,
                    sets: (0..cfg.sets)
                        .map(|_| Set {
                            tags: vec![0; cfg.ways],
                            valid: 0,
                            state: 0,
                        })
                        .collect(),
                }
            })
            .collect();
        Self {
            levels,
            mem_latency,
        }
    }

    /// 最上位段のラインサイズの log2。段がなければ 0。
    #[must_use]
    pub fn line_shift(&self) -> u32 {
        self.levels.first().map_or(0, |l| l.cfg.line_shift)
    }

    /// 物理アドレス近似 `addr` で全段を順に引き、合計レイテンシを返す。
    // Gap: GAP-0091 立ち退いたラインの汚れの書き戻し時間は数えない。
    pub fn access(&mut self, addr: u64) -> AccessReport {
        let mut latency = 0;
        for (i, level) in self.levels.iter_mut().enumerate() {
            latency += level.cfg.hit_latency;
            if level.lookup(addr) {
                return AccessReport {
                    latency,
                    hit_level: Some(i),
                };
            }
        }
        AccessReport {
            latency: latency + self.mem_latency,
            hit_level: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const L1: CacheLevel = CacheLevel {
        name: "l1",
        sets: 4,
        ways: 2,
        line_shift: 4,
        repl: Repl::Plru,
        write: WriteKind::WriteBack,
        hit_latency: 2,
    };

    fn line(n: u64) -> u64 {
        n << 4
    }

    #[test]
    fn hit_after_fill() {
        let mut h = CacheHierarchy::new(&[L1], 50);
        let miss = h.access(0);
        assert_eq!((miss.latency, miss.hit_level), (52, None));
        let hit = h.access(0);
        assert_eq!((hit.latency, hit.hit_level), (2, Some(0)));
        // 同じラインの別オフセットもヒット。
        assert_eq!(h.access(8).hit_level, Some(0));
    }

    #[test]
    fn miss_falls_to_memory() {
        let l2 = CacheLevel {
            name: "l2",
            sets: 8,
            hit_latency: 10,
            ..L1
        };
        let mut h = CacheHierarchy::new(&[L1, l2], 100);
        let r = h.access(0);
        assert_eq!((r.latency, r.hit_level), (112, None));
        // 下位段まで落ちたラインは全段に充填される。
        assert_eq!(h.access(0).hit_level, Some(0));
        // L1 の同じ set に 2 本足すと 2way の L1 からは溢れるが、L2 には残る。
        h.access(line(4));
        h.access(line(8));
        let r = h.access(0);
        assert_eq!((r.latency, r.hit_level), (12, Some(1)));
        assert_eq!(h.access(0).hit_level, Some(0));
    }

    #[test]
    fn same_set_overflow_evicts() {
        let mut h = CacheHierarchy::new(&[L1], 50);
        // 4 sets・2way: ライン 0, 4, 8 は同じ set。3 本目で 1 本目が溢れる。
        h.access(line(0));
        h.access(line(4));
        h.access(line(8));
        assert_eq!(h.access(line(0)).hit_level, None);
        assert_eq!(h.access(line(8)).hit_level, Some(0));
    }

    #[test]
    fn plru_and_round_robin_evict_differently() {
        const W4: CacheLevel = CacheLevel {
            name: "w4",
            sets: 1,
            ways: 4,
            line_shift: 4,
            repl: Repl::Plru,
            write: WriteKind::WriteBack,
            hit_latency: 1,
        };
        // アクセス順 0,1,2,3,0,4。PLRU は way2（ライン2）、巡回は way0（ライン0）を追い出す。
        let mut plru = CacheHierarchy::new(&[W4], 100);
        for n in [0, 1, 2, 3, 0, 4] {
            plru.access(line(n));
        }
        assert_eq!(plru.access(line(0)).hit_level, Some(0));
        assert_eq!(plru.access(line(2)).hit_level, None);

        let mut rr = CacheHierarchy::new(
            &[CacheLevel {
                repl: Repl::RoundRobin,
                ..W4
            }],
            100,
        );
        for n in [0, 1, 2, 3, 0, 4] {
            rr.access(line(n));
        }
        assert_eq!(rr.access(line(0)).hit_level, None);
        assert_eq!(rr.access(line(2)).hit_level, Some(0));
    }

    #[test]
    fn deterministic_for_same_sequence() {
        let mk = || {
            CacheHierarchy::new(
                &[
                    L1,
                    CacheLevel {
                        name: "l2",
                        sets: 8,
                        ways: 4,
                        repl: Repl::RoundRobin,
                        hit_latency: 10,
                        ..L1
                    },
                ],
                30,
            )
        };
        let (mut a, mut b) = (mk(), mk());
        for i in 0..500u64 {
            let addr = line(i * 37 % 97);
            assert_eq!(a.access(addr), b.access(addr));
        }
    }
}
