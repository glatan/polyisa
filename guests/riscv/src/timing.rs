// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SiFive U74 のタイミング表とインオーダーモデルのパラメータ。
//!
//! 値は U74-MC コアの資料から写した（Ref: SPEC-SIFIVE-U74）。
//! レイテンシは発行から結果が使えるまでのサイクル数。可変域は代表値に
//! 畳んでおり（GAP-0097）、較正待ちの仮値は `TODO(calibrate)` で示す。

use polyisa_timing::branch::{Btb, DirPred, Predictor, Ras};
use polyisa_timing::cache::{CacheHierarchy, CacheLevel, Repl, WriteKind};
use polyisa_timing::inorder::{InOrderModel, InOrderParams, IoClass};
use polyisa_timing::ooo::MemKind;

/// 同時発行の排他グループのビット。
/// 1 つのデータメモリアクセス・1 つの分岐/ジャンプ・1 つの FP 演算・
/// 1 つの整数乗除算・CSR は単独発行、という組合せ制約を表す。
/// Ref: SPEC-SIFIVE-U74 §4.2.2.
pub const U74_GRP_MEM: u32 = 1 << 0;
/// 分岐・ジャンプの排他ビット。
pub const U74_GRP_BR: u32 = 1 << 1;
/// FP 演算の排他ビット。
pub const U74_GRP_FP: u32 = 1 << 2;
/// 整数乗除算の排他ビット。
pub const U74_GRP_MD: u32 = 1 << 3;
/// CSR 命令の排他ビット。
pub const U74_GRP_CSR: u32 = 1 << 4;

const N: MemKind = MemKind::None;
const L: MemKind = MemKind::Load;
const S: MemKind = MemKind::Store;
const B: MemKind = MemKind::Both;

/// U74 の分類表。`class` は spec の `timing` 列の値。
/// Ref: SPEC-SIFIVE-U74 §4.2.2・§4.3・App. D Table 187/188.
pub const U74_CLASSES: &[IoClass] = &[
    // 整数演算は 1 サイクル結果・完全バイパス。
    IoClass {
        class: "alu",
        issue: 1,
        ready: 1,
        busy: 1,
        group: 0,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // ロードは L1 ヒットで 3 サイクル（ready 1 + d$ 応答 2）。
    // Ref: SPEC-SIFIVE-U74 §4.3.
    IoClass {
        class: "load",
        issue: 1,
        ready: 1,
        busy: 1,
        group: U74_GRP_MEM,
        mem: L,
        uses_ag: true,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // ストアはバッファ化され 1 サイクル。
    // Gap: GAP-0096 ストアパイプ衝突の 5 サイクル・未完了フィル 1 本は畳む。
    IoClass {
        class: "store",
        issue: 1,
        ready: 1,
        busy: 1,
        group: U74_GRP_MEM,
        mem: S,
        uses_ag: true,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // flw/fld はヒットで 2 サイクル（ready 0 + d$ 応答 2）。
    // Ref: SPEC-SIFIVE-U74 App. D Table 187/188.
    IoClass {
        class: "fload",
        issue: 1,
        ready: 0,
        busy: 1,
        group: U74_GRP_MEM,
        mem: L,
        uses_ag: true,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // fsw/fsd は 4。ストアはパイプライン化なので占有は 1。
    // `ready` は consumer に伝わらない（ストアの結果を読む命令はない。
    // 表の完全性のための値）。
    // Ref: SPEC-SIFIVE-U74 App. D Table 187/188.
    IoClass {
        class: "fstore",
        issue: 1,
        ready: 4,
        busy: 1,
        group: U74_GRP_MEM,
        mem: S,
        uses_ag: true,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // 分岐は AG または M2 で解決、1 サイクル。誤予測のコストはモデル側。
    // Ref: SPEC-SIFIVE-U74 §4.2.2・§4.4.1.
    IoClass {
        class: "branch",
        issue: 1,
        ready: 1,
        busy: 1,
        group: U74_GRP_BR,
        mem: N,
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
        group: U74_GRP_BR,
        mem: N,
        uses_ag: true,
        is_branch: true,
        flush: 0,
        hint_latency: false,
    },
    // 整数乗算は AG→M2 で 3 サイクル、完全パイプライン化。
    // Ref: SPEC-SIFIVE-U74 §4.3.
    IoClass {
        class: "mult",
        issue: 1,
        ready: 3,
        busy: 1,
        group: U74_GRP_MD,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // 整数除算は反復式で 6–68 サイクル。代表値は資料の下限の 6
    //（被除数と除数が同程度で符号補正がないとき）。hint 規約:
    // 呼び出し側が `div_latency` で計算した値を `InstrEvent::hint`
    // に入れる。hint=0 は代表値 6 にフォールバック。
    // Ref: SPEC-SIFIVE-U74 §4.3.
    IoClass {
        class: "div",
        issue: 1,
        ready: 6,
        busy: 6,
        group: U74_GRP_MD,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: true,
    },
    // ecall/ebreak/fence。資料に値がなく近似。
    IoClass {
        class: "system",
        issue: 1,
        ready: 1,
        busy: 1,
        group: 0,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // CSR は M2 で実行し読みは 1 サイクル。多くの CSR 書き込みは
    // パイプラインフラッシュで 7 サイクルかかるため全 CSR に畳む近似。
    // Gap: GAP-0097 読みだけの CSR もフラッシュ扱い、単独発行は
    // フラッシュ分で近似し先行ペアの禁止はモデルにない。
    // Ref: SPEC-SIFIVE-U74 §4.3.
    IoClass {
        class: "csr",
        issue: 1,
        ready: 1,
        busy: 1,
        group: U74_GRP_CSR,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 7,
        hint_latency: false,
    },
    // 不可分操作は D$ 内処理としてロード相当＋占有の近似。資料に値なし。
    IoClass {
        class: "atomic",
        issue: 1,
        ready: 1,
        busy: 2,
        group: U74_GRP_MEM,
        mem: B,
        uses_ag: true,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // 単精度の加減加減乗・積和は 5。Ref: SPEC-SIFIVE-U74 App. D Table 187.
    IoClass {
        class: "falu_s",
        issue: 1,
        ready: 5,
        busy: 1,
        group: U74_GRP_FP,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // 倍精度の加減乗・積和は 7。Ref: SPEC-SIFIVE-U74 App. D Table 188.
    IoClass {
        class: "falu_d",
        issue: 1,
        ready: 7,
        busy: 1,
        group: U74_GRP_FP,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // fsgnj 系・fmv 系は 2（fmv.d 系の 1–2 は上位側を採る）。
    // Ref: SPEC-SIFIVE-U74 App. D Table 187/188.
    IoClass {
        class: "fsj",
        issue: 1,
        ready: 2,
        busy: 1,
        group: U74_GRP_FP,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // feq/fle/flt/fclass は 4。Ref: SPEC-SIFIVE-U74 App. D Table 187/188.
    IoClass {
        class: "fcmp",
        issue: 1,
        ready: 4,
        busy: 1,
        group: U74_GRP_FP,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // fmin/fmax は 2。Ref: SPEC-SIFIVE-U74 App. D Table 187/188.
    IoClass {
        class: "fminmax",
        issue: 1,
        ready: 2,
        busy: 1,
        group: U74_GRP_FP,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // fcvt 系は 2–4（単精度）・2–6（倍精度）で代表 4。
    // Gap: GAP-0097 変換先ごとの差は畳む。
    // Ref: SPEC-SIFIVE-U74 App. D Table 187/188.
    IoClass {
        class: "fcvt",
        issue: 1,
        ready: 4,
        busy: 1,
        group: U74_GRP_FP,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // fdiv.s は 9–36（リピート 8–33）。代表はレンジ中央の近似。
    // Gap: GAP-0097 可変域を固定代表値に畳む。
    // Ref: SPEC-SIFIVE-U74 App. D Table 187.
    IoClass {
        class: "fdiv_s",
        issue: 1,
        ready: 22,
        busy: 20,
        group: U74_GRP_FP,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // fdiv.d は 9–58（リピート 8–58）。Ref: SPEC-SIFIVE-U74 App. D Table 188.
    IoClass {
        class: "fdiv_d",
        issue: 1,
        ready: 33,
        busy: 33,
        group: U74_GRP_FP,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // fsqrt.s は 9–28（リピート 8–33）。Ref: SPEC-SIFIVE-U74 App. D Table 187.
    IoClass {
        class: "fsqrt_s",
        issue: 1,
        ready: 18,
        busy: 20,
        group: U74_GRP_FP,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
    // fsqrt.d は 9–57（リピート 8–58）。Ref: SPEC-SIFIVE-U74 App. D Table 188.
    IoClass {
        class: "fsqrt_d",
        issue: 1,
        ready: 33,
        busy: 33,
        group: U74_GRP_FP,
        mem: N,
        uses_ag: false,
        is_branch: false,
        flush: 0,
        hint_latency: false,
    },
];

/// 整数除算のレイテンシ（サイクル）。
/// Latency = 2 + log2(dividend) − log2(divisor) + 1(被除数が負) + 1(商が負)。
/// 呼び出し側は戻り値を `InstrEvent::hint` に入れる（hint=0 は
/// `U74_CLASSES` の `div` 代表値にフォールバック）。
/// 結果は資料の範囲 6–68 に収める。divisor=0 は商が即座に決まる
/// 早期終了として下限に畳む近似。
/// Ref: SPEC-SIFIVE-U74 §4.3.
#[must_use]
pub fn div_latency(dividend: u64, divisor: u64, dividend_neg: bool, quotient_neg: bool) -> u64 {
    if divisor == 0 {
        return 6;
    }
    let l = |v: u64| i64::from(63 - v.leading_zeros());
    let lat =
        2 + l(dividend.max(1)) - l(divisor) + i64::from(dividend_neg) + i64::from(quotient_neg);
    lat.clamp(6, 68) as u64
}

/// U74 のインオーダーモデル。`ModelDef` の `timing` 句（`inorder` +
/// 表 `sifive_u74`）に対応する。未較正（fidelity `approx_uncalibrated`）。
/// Ref: SPEC-SIFIVE-U74 §4.2.2・§4.4.1.
#[must_use]
pub fn sifive_u74() -> InOrderModel {
    // L1 I$: 32KiB・2way・64B ライン・ランダム置換・1 サイクル。
    // ランダム置換は巡回の決定的近似で表す。
    const L1I: CacheLevel = CacheLevel {
        name: "u74_l1i",
        sets: 256, // 32KiB / 64B / 2way
        ways: 2,
        line_shift: 6,
        repl: Repl::RoundRobin,
        write: WriteKind::WriteBack,
        hit_latency: 1,
    };
    // L1 D$: 32KiB・4way・64B ライン・PLRU・ライトバック。
    // Gap: GAP-0094 ヒットは word/dword で 2・より小さい単位で 3 だが、
    // `CacheLevel` は単一値しか持てないため 2 を採る。
    const L1D: CacheLevel = CacheLevel {
        name: "u74_l1d",
        sets: 128, // 32KiB / 64B / 4way
        ways: 4,
        line_shift: 6,
        repl: Repl::Plru,
        write: WriteKind::WriteBack,
        hit_latency: 2,
    };
    // L2: 2MiB・16way・64B ライン・ランダム置換・ライトバック・2 バンク。
    // バンク数は応答時間の形に表れないモデルなので形状にだけ残す。
    const L2: CacheLevel = CacheLevel {
        name: "u74_l2",
        sets: 2048, // 2MiB / 64B / 16way
        ways: 16,
        line_shift: 6,
        repl: Repl::RoundRobin,
        write: WriteKind::WriteBack,
        // TODO(calibrate): ヒットレイテンシは資料に明示なし。未較正の仮値。
        hit_latency: 12,
    };
    // TODO(calibrate): 主記憶の応答時間も資料に値がなく未較正の仮値。
    const MEM_LAT: u64 = 60;
    InOrderModel::new(InOrderParams {
        width: 2, // デュアルイシュー・インオーダー。Ref: SPEC-SIFIVE-U74 §4.2.2
        classes: U74_CLASSES,
        ag_load_delay: 2, // load-use の AG 入力で 2 サイクル。Ref: SPEC-SIFIVE-U74 §4.3
        mem: Some(CacheHierarchy::new(&[L1D, L2], MEM_LAT)),
        icache: Some(CacheHierarchy::new(&[L1I, L2], MEM_LAT)),
        pred: Some(Predictor::new(
            // 相関 BHT（3.6KiB）を gshare で近似。2bit カウンタとみなすと
            // 約 1.8k 項目なので 2^11 に丸める。履歴長は資料に値なし。
            DirPred::Gshare {
                ghr_bits: 8,
                sets: 2048,
            },
            Some(Btb::new(16, 4)), // BTB 16 エントリ（連想度は近似）
            Some(Ras::new(6)),     // RAS 6 エントリ
            Some(Btb::new(8, 2)),  // IJTP 8 エントリ（連想度は近似）
        )),
        mispredict: 4,          // 分岐誤予測 4（場合により 6）
        indirect_mispredict: 6, // 間接ジャンプ誤予測 6
        fetch_bubble: 1,        // BTB ミス・予測器不一致のバブル
        reg_count: 64,          // x0–x31 と f0–f31 のビット割当を想定
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_timing::{BranchKind, InstrEvent, TimingModel, VirtualTime};

    fn class(name: &str) -> IoClass {
        U74_CLASSES
            .iter()
            .find(|c| c.class == name)
            .copied()
            .unwrap()
    }

    fn ev(pc: u64, class: &'static str) -> InstrEvent {
        InstrEvent::new(pc, class)
    }

    #[test]
    fn table_matches_u74_facts() {
        // Ref: SPEC-SIFIVE-U74 App. D Table 187/188・§4.3.
        assert_eq!(class("falu_s").ready, 5);
        assert_eq!(class("falu_d").ready, 7);
        assert_eq!(class("fsj").ready, 2);
        assert_eq!(class("fcmp").ready, 4);
        assert_eq!(class("fminmax").ready, 2);
        assert_eq!(class("fcvt").ready, 4);
        assert!((9..=36).contains(&class("fdiv_s").ready));
        assert!((9..=58).contains(&class("fdiv_d").ready));
        assert!((9..=28).contains(&class("fsqrt_s").ready));
        assert!((9..=57).contains(&class("fsqrt_d").ready));
        assert_eq!(class("fload").ready + 2, 2); // ready 0 + d$ 応答 2
        assert_eq!(class("load").ready + 2, 3); // ready 1 + d$ 応答 2
        assert_eq!(class("fstore").ready, 4);
        assert_eq!(class("mult").ready, 3);
        assert_eq!(class("csr").flush, 7);
        assert!(class("div").hint_latency && (6..=68).contains(&class("div").ready));
        // 発行制約のグループビット。
        assert_eq!(class("load").group, U74_GRP_MEM);
        assert_eq!(class("store").group, U74_GRP_MEM);
        assert_eq!(class("fload").group, U74_GRP_MEM);
        assert_eq!(class("fstore").group, U74_GRP_MEM);
        assert_eq!(class("branch").group, U74_GRP_BR);
        assert_eq!(class("jump").group, U74_GRP_BR);
        assert_eq!(class("mult").group, U74_GRP_MD);
        assert_eq!(class("div").group, U74_GRP_MD);
        assert_eq!(class("csr").group, U74_GRP_CSR);
        assert_eq!(class("falu_s").group, U74_GRP_FP);
        assert_eq!(class("falu_d").group, U74_GRP_FP);
    }

    #[test]
    fn div_latency_matches_formula() {
        // Ref: SPEC-SIFIVE-U74 §4.3.
        assert_eq!(div_latency(1 << 10, 1 << 5, false, false), 7);
        assert_eq!(div_latency(1 << 10, 1 << 5, true, true), 9);
        // 同程度の値どうしは下限、範囲外は資料の 6–68 に収める。
        assert_eq!(div_latency(100, 100, false, false), 6);
        assert_eq!(div_latency(1, 1 << 60, false, false), 6);
        assert_eq!(div_latency(u64::MAX, 1, true, true), 67);
        // ゼロ除算は早期終了の近似。
        assert_eq!(div_latency(10, 0, false, false), 6);
    }

    #[test]
    fn load_use_delay_applies_to_ag_operand() {
        // ロード結果をアドレス生成に使うと 2 サイクル余分に待つ。
        let run = |consumer: &'static str| {
            let mut m = sifive_u74();
            m.observe(
                &InstrEvent {
                    mem_addrs: vec![(0x1000, 8)],
                    ..ev(0, "load")
                }
                .writes(1 << 1),
            );
            m.observe(
                &InstrEvent {
                    mem_addrs: vec![(0x2000, 8)],
                    ..ev(4, consumer)
                }
                .reads(1 << 1),
            );
            m.now()
        };
        assert_eq!(run("alu"), VirtualTime(149));
        assert_eq!(run("load"), VirtualTime(151));
    }

    #[test]
    fn mem_group_limits_dual_issue() {
        let run = |class: &'static str, addr: bool| {
            let mut m = sifive_u74();
            for i in 0..4u64 {
                let mut e = ev(i * 4, class);
                if addr {
                    e.mem_addrs.push((0x3000 + i * 64, 8));
                }
                m.observe(&e);
            }
            m.now()
        };
        // メモリ系は同時に 1 個まで。alu は 2 幅で詰まる。
        assert_eq!(run("alu", false), VirtualTime(75));
        assert_eq!(run("load", true), VirtualTime(77));
    }

    #[test]
    fn csr_flush_and_branch_penalties() {
        // CSR 書き込みはフラッシュ 7。
        let mut m = sifive_u74();
        m.observe(&ev(0, "csr"));
        assert_eq!(m.now(), VirtualTime(81));

        // 取った分岐の初見は方向誤予測 4 + BTB ミスのバブル 1。
        let run = |class: &'static str, kind: BranchKind| {
            let mut m = sifive_u74();
            m.observe(&ev(0, "alu"));
            m.observe(&ev(4, class).branch(true, 0x80, kind));
            m.now()
        };
        // alu 2 個の基準に対する増分で見る。
        let mut base = sifive_u74();
        base.observe(&ev(0, "alu"));
        base.observe(&ev(4, "alu"));
        let base = base.now();
        assert_eq!(run("branch", BranchKind::Direct).0 - base.0, 5);
        assert_eq!(run("jump", BranchKind::Indirect).0 - base.0, 7);
    }
}
