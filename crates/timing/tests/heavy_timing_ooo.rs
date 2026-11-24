// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OoO 汎用モデルの較正検査（層5・approx の宣言誤差）。
//!
//! Skylake 級の `OooParams` に合成した `InstrEvent` の列を流し、各測点の
//! 等価レイテンシ/スループットが実測値に対し `OooModel::DECLARED_ERR` 以内に
//! 収まることを見る。実測値のアンカーは命令のレイテンシとスループットが
//! MEAS-UOPS-INFO（uops.info の SKL 実測）、L2 応答と分岐誤予測のコストが
//! MEAS-AGNER（SKL 章の計測値）。比較する値は次のとおり（実測はすべて
//! 上記の計測データを自前表現した値）。
//!
//! | 測点 | 実測 | 内容 |
//! |---|---|---|
//! | ADD r64,r64 | lat 1 / TP 0.25 | 1*p0156 |
//! | SHL r64,imm | lat 1 / TP 0.50 | 1*p06 |
//! | LEA（ベース+オフセット） | lat 1 / TP 0.50 | 1*p15 |
//! | IMUL r64,r64 | lat 3 / TP 1.00 | 1*p1 |
//! | MOV ロード（L1 ヒット） | lat 5 / TP 0.50 | 1*p23 |
//! | MOV ストア | TP 1.00 | STA+データで 2 uops、p4 律速 |
//! | IDIV r64 | lat ~40（最小 38–41）/ TP 24.40 | 除算器占有 |
//! | ロード依存鎖（L2 ヒット） | ~14 | L1 ミス→L2 応答 |
//! | Jcc（取らない・正予測） | TP 0.50 | p06 に 1 uops |
//! | Jcc 誤予測 | ~18（実測 16–20） | フロントエンド再充填 |

use polyisa_timing::branch::{Btb, DirPred, Predictor};
use polyisa_timing::cache::{CacheHierarchy, CacheLevel, Repl, WriteKind};
use polyisa_timing::ooo::{ClassUop, MemKind, OooModel, OooParams};
use polyisa_timing::{BranchKind, InstrEvent, TimingModel};

const P0156: u32 = (1 << 0) | (1 << 1) | (1 << 5) | (1 << 6);
const P06: u32 = (1 << 0) | (1 << 6);
const P15: u32 = (1 << 1) | (1 << 5);
const P1: u32 = 1 << 1;
const P23: u32 = (1 << 2) | (1 << 3);
const P4: u32 = 1 << 4;

// Ref: MEAS-UOPS-INFO（レイテンシ・ポート使用）。ports は SKL の 8 ポートに対応する。
// Gap: GAP-0098 div は 56 uops・複数ポートの実命令を「p0 を busy で占有する
// 1 イベント」に畳む近似。
const CLASSES: &[ClassUop] = &[
    ClassUop {
        class: "alu",
        latency: 1,
        busy: 1,
        ports: P0156,
        group: 0,
        mem: MemKind::None,
        is_branch: false,
    },
    ClassUop {
        class: "shift",
        latency: 1,
        busy: 1,
        ports: P06,
        group: 0,
        mem: MemKind::None,
        is_branch: false,
    },
    ClassUop {
        class: "lea",
        latency: 1,
        busy: 1,
        ports: P15,
        group: 0,
        mem: MemKind::None,
        is_branch: false,
    },
    ClassUop {
        class: "mul",
        latency: 3,
        busy: 1,
        ports: P1,
        group: 0,
        mem: MemKind::None,
        is_branch: false,
    },
    ClassUop {
        class: "div",
        latency: 40,
        busy: 24,
        ports: 1,
        group: 0,
        mem: MemKind::None,
        is_branch: false,
    },
    ClassUop {
        class: "load",
        latency: 1,
        busy: 1,
        ports: P23,
        group: 0,
        mem: MemKind::Load,
        is_branch: false,
    },
    ClassUop {
        class: "store",
        latency: 1,
        busy: 1,
        ports: P4,
        group: 0,
        mem: MemKind::Store,
        is_branch: false,
    },
    ClassUop {
        class: "branch",
        latency: 1,
        busy: 1,
        ports: P06,
        group: 0,
        mem: MemKind::None,
        is_branch: true,
    },
];

// Ref: MEAS-AGNER（SKL 章のキャッシュ表）。L1I/L1D 32KiB 8way 64B、
// L2 256KiB 4way 1024 セット 64B。
// Gap: GAP-0098 L2 の hit_latency は「L1 のタグ照査を抜けた先の追加応答」として
// 10（合計 14）に較正した代表値。L1I の hit_latency は直列充填近似の代表値、
// mem_latency 60 は未較正の仮値。
const L1D: CacheLevel = CacheLevel {
    name: "l1d",
    sets: 64,
    ways: 8,
    line_shift: 6,
    repl: Repl::Plru,
    write: WriteKind::WriteBack,
    hit_latency: 4,
};
const L2: CacheLevel = CacheLevel {
    name: "l2",
    sets: 1024,
    ways: 4,
    line_shift: 6,
    repl: Repl::RoundRobin,
    write: WriteKind::WriteBack,
    hit_latency: 10,
};
const L1I: CacheLevel = CacheLevel {
    name: "l1i",
    sets: 64,
    ways: 8,
    line_shift: 6,
    repl: Repl::RoundRobin,
    write: WriteKind::WriteBack,
    hit_latency: 2,
};

fn params(pred: Predictor, mem: CacheHierarchy, icache: CacheHierarchy) -> OooParams {
    OooParams {
        width: 4,
        rob: 224,
        sched: 97,
        lq: 72,
        sq: 56,
        retire_width: 8,
        // Gap: GAP-0098 誤予測コストは mispredict 16＋i$ ヒットで実測 16–20 に
        // 収める較正値。正予測で「取る」分岐の帯域はポート制約の 0.5/clk のまま。
        mispredict: 16,
        fetch_bubble: 1,
        classes: CLASSES,
        ports: 8,
        mem,
        icache,
        pred,
        mem_disambig: true,
        reg_count: 64,
    }
}

fn bimodal_pred() -> Predictor {
    Predictor::new(
        DirPred::Bimodal { entries: 4096 },
        Some(Btb::new(4096, 4)),
        None,
        None,
    )
}

/// 実測値に対する相対誤差が DECLARED_ERR 以内か検査する。
fn check(name: &str, got: f64, measured: f64) {
    let err = (got - measured).abs() / measured;
    println!("{name}: model {got:.3} measured {measured} rel_err {err:.3}");
    assert!(
        err <= OooModel::DECLARED_ERR,
        "{name}: model {got:.3} vs measured {measured} (rel err {err:.3})"
    );
}

/// i$/d$ を列の触れる範囲で温めてから列を 1 回流し、1 命令あたりの
/// 仮想サイクルを返す（実測のループ測定に相当する温まった状態で見る）。
/// `evict_l1` を立てると、温めたあと別領域を掃いて L1 だけを冷やす
/// （L2 ヒットの測点用）。
fn per_insn(evs: &[InstrEvent], pred: Predictor, evict_l1: bool) -> f64 {
    let mut mem = CacheHierarchy::new(&[L1D, L2], 60);
    let mut icache = CacheHierarchy::new(&[L1I], 60);
    for ev in evs {
        icache.access(ev.pc);
        for &(addr, _) in &ev.mem_addrs {
            mem.access(addr);
        }
    }
    if evict_l1 {
        // 64 セット×8 way の L1 を別領域で全て追い出す。
        for i in 0..768u64 {
            mem.access(0x800000 + i * 64);
        }
    }
    let mut m = OooModel::new(params(pred, mem, icache));
    for ev in evs {
        m.observe(ev);
    }
    m.now().0 as f64 / evs.len() as f64
}

fn ev(i: u64, class: &'static str) -> InstrEvent {
    InstrEvent::new(i * 4, class)
}

/// `reg` を読み書きする依存鎖。先頭だけ独立。
fn chain(class: &'static str, n: u64, reg: u64) -> Vec<InstrEvent> {
    (0..n)
        .map(|i| {
            let e = ev(i, class).writes(1 << reg);
            if i == 0 { e } else { e.reads(1 << reg) }
        })
        .collect()
}

#[test]
fn add_latency() {
    // Ref: MEAS-UOPS-INFO ADD (R64,R64) SKL: レイテンシ 1。
    check(
        "add lat",
        per_insn(&chain("alu", 128, 1), bimodal_pred(), false),
        1.0,
    );
}

#[test]
fn add_throughput() {
    // Ref: MEAS-UOPS-INFO ADD (R64,R64) SKL: TP_loop 0.25（4 命令/サイクル）。
    let evs: Vec<_> = (0..512u64).map(|i| ev(i, "alu")).collect();
    check("add tput", per_insn(&evs, bimodal_pred(), false), 0.25);
}

#[test]
fn shl_latency() {
    // Ref: MEAS-UOPS-INFO SHL (R64,I8) SKL: レイテンシ 1。
    check(
        "shl lat",
        per_insn(&chain("shift", 128, 2), bimodal_pred(), false),
        1.0,
    );
}

#[test]
fn shl_throughput() {
    // Ref: MEAS-UOPS-INFO SHL (R64,I8) SKL: TP_loop 0.50（p06）。
    let evs: Vec<_> = (0..512u64).map(|i| ev(i, "shift")).collect();
    check("shl tput", per_insn(&evs, bimodal_pred(), false), 0.5);
}

#[test]
fn lea_throughput() {
    // Ref: MEAS-UOPS-INFO LEA_B (R64) SKL: TP_loop 0.50（p15）。
    let evs: Vec<_> = (0..512u64).map(|i| ev(i, "lea")).collect();
    check("lea tput", per_insn(&evs, bimodal_pred(), false), 0.5);
}

#[test]
fn imul_latency() {
    // Ref: MEAS-UOPS-INFO IMUL (R64,R64) SKL: レイテンシ 3。
    check(
        "imul lat",
        per_insn(&chain("mul", 128, 3), bimodal_pred(), false),
        3.0,
    );
}

#[test]
fn imul_throughput() {
    // Ref: MEAS-UOPS-INFO IMUL (R64,R64) SKL: TP_loop 1.00（p1 のみ）。
    let evs: Vec<_> = (0..512u64).map(|i| ev(i, "mul")).collect();
    check("imul tput", per_insn(&evs, bimodal_pred(), false), 1.0);
}

/// `base` から `n` 個のラインを `stride` 間隔で辿るロード依存鎖
/// （次のアドレスは前のロードの結果に依存する近似として reads を積む）。
fn load_chain(base: u64, n: u64, stride: u64, reg: u64) -> Vec<InstrEvent> {
    (0..n)
        .map(|i| {
            let e = InstrEvent {
                mem_addrs: vec![(base + i * stride, 8)],
                ..ev(i, "load")
            }
            .writes(1 << reg);
            if i == 0 { e } else { e.reads(1 << reg) }
        })
        .collect()
}

#[test]
fn load_latency_l1_hit() {
    // Ref: MEAS-UOPS-INFO MOV (R64,M64) SKL: アドレス→結果のレイテンシ 5。
    // 同一ラインを繰り返す鎖は常に L1 ヒット。
    check(
        "load l1 lat",
        per_insn(&load_chain(0x8000, 128, 8, 4), bimodal_pred(), false),
        5.0,
    );
}

#[test]
fn load_throughput_l1_hit() {
    // Ref: MEAS-UOPS-INFO MOV (R64,M64) SKL: TP_loop 0.50（p23 の 2 ポート）。
    let evs: Vec<_> = (0..512u64)
        .map(|i| InstrEvent {
            mem_addrs: vec![(0x8000 + (i % 16) * 8, 8)],
            ..ev(i, "load")
        })
        .collect();
    check("load l1 tput", per_insn(&evs, bimodal_pred(), false), 0.5);
}

#[test]
fn load_latency_l2_hit() {
    // Ref: MEAS-AGNER（SKL の L2 応答 14）。128KiB を 64B ストライドで辿るので
    // L1（32KiB）には収まらず L2（256KiB）にヒットする。
    check(
        "load l2 lat",
        per_insn(&load_chain(0x40000, 2048, 64, 4), bimodal_pred(), true),
        14.0,
    );
}

#[test]
fn store_throughput() {
    // Ref: MEAS-UOPS-INFO MOV (M64,R64) SKL: TP_loop 1.00。
    let evs: Vec<_> = (0..512u64)
        .map(|i| InstrEvent {
            mem_addrs: vec![(0x8000 + (i % 64) * 64, 8)],
            ..ev(i, "store")
        })
        .collect();
    check("store tput", per_insn(&evs, bimodal_pred(), false), 1.0);
}

#[test]
fn idiv_latency() {
    // Ref: MEAS-UOPS-INFO IDIV (R64) SKL: レイテンシ最小 38–41（値依存で最大 ~96）。
    check(
        "idiv lat",
        per_insn(&chain("div", 64, 5), bimodal_pred(), false),
        40.0,
    );
}

#[test]
fn idiv_throughput() {
    // Ref: MEAS-UOPS-INFO IDIV (R64) SKL: TP_loop 24.40。
    let evs: Vec<_> = (0..128u64).map(|i| ev(i, "div")).collect();
    check("idiv tput", per_insn(&evs, bimodal_pred(), false), 24.4);
}

#[test]
fn branch_not_taken_throughput() {
    // Ref: MEAS-UOPS-INFO JZ (Rel8) SKL: TP_loop 0.50（p06 に 1 uops）。
    // 常に取らない分岐はバイモーダルで正予測に収束する。
    let evs: Vec<_> = (0..512u64)
        .map(|i| ev(i, "branch").branch(false, 0x400, BranchKind::Direct))
        .collect();
    check("jcc nt tput", per_insn(&evs, bimodal_pred(), false), 0.5);
}

#[test]
fn branch_mispredict_cost() {
    // Ref: MEAS-AGNER（SKL の誤予測ペナルティ実測 16–20、代表 18）。
    // 「常に取らない」静的予測に常に取る分岐を流し、1 分岐あたりのコストを見る。
    let run = |pred: Predictor| {
        let mut m = OooModel::new(params(
            pred,
            CacheHierarchy::new(&[L1D, L2], 60),
            CacheHierarchy::new(&[L1I], 60),
        ));
        for i in 0..128u64 {
            m.observe(&ev(i % 8, "branch").branch(true, 0, BranchKind::Direct));
        }
        m.now().0 as f64 / 128.0
    };
    let mispred = run(Predictor::new(
        DirPred::Static {
            backward_taken: false,
        },
        None,
        None,
        None,
    ));
    let correct = run(Predictor::new(
        DirPred::Static {
            backward_taken: true,
        },
        Some(Btb::new(16, 1)),
        None,
        None,
    ));
    check("jcc mispredict", mispred - correct, 18.0);
}
