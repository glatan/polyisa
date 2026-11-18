// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! CPUID のリーフ値の導出（段階13、C2a）。
//!
//! `--cpu` で選んだモデルの機能集合と識別情報から、CPUID が返す
//! リーフごとの (EAX,EBX,ECX,EDX) を計算する。機能→報告ビットの対応は
//! 生成した `IDENT_BITS`（spec/x86cpu.rs の `cpuid_bit` 相当）が持つ。
//! 実行開始時に `CpuState.cpuid` へ書き込み、`sem::cpuid` が参照する。
//! 出典は SPEC-X86-INTEL-SDM Combined v093 (2026-09-24) である。
// Ref: SPEC-X86-INTEL-SDM (v093).

use std::collections::{BTreeMap, BTreeSet};

use crate::IDENT_BITS;

/// CPUID が報告する (リーフ, サブリーフ) の一覧。
/// `CpuState.cpuid` の添え字順。ベーシックは 0・1・7.0・0xD.0・
/// 0xD.1・0xD.2、拡張は 0x8000_0000・0x8000_0001・0x8000_0008。
pub const LEAF_IDS: [(u32, u32); 9] = [
    (0, 0),
    (1, 0),
    (7, 0),
    (0xD, 0),
    (0xD, 1),
    (0xD, 2),
    (0x8000_0000, 0),
    (0x8000_0001, 0),
    (0x8000_0008, 0),
];

/// 最大ベーシックリーフの既定（leaf 0 の EAX）。`xsave` 機能が
/// あれば leaf D を含む 0xD、なければ 7。`cpuid.max_basic`
/// で上書きできる。
const MAX_BASIC: u32 = 7;
const MAX_BASIC_XSAVE: u32 = 0xD;
/// 最大拡張リーフ（leaf 0x8000_0000 の EAX）。
const MAX_EXT: u32 = 0x8000_0008;

fn get_ident<'a>(ident: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    ident.get(key).map(String::as_str)
}

/// ベンダ文字列（12 バイト）を EBX/EDX/ECX の並びの u32 に分ける。
fn vendor_regs(v: &str) -> (u32, u32, u32) {
    let mut b = [b' '; 12];
    let n = v.len().min(12);
    b[..n].copy_from_slice(&v.as_bytes()[..n]);
    let rd = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    (rd(0), rd(8), rd(4))
}

fn num(ident: &BTreeMap<String, String>, key: &str, default: u32) -> u32 {
    get_ident(ident, key)
        .and_then(|v| {
            v.strip_prefix("0x")
                .map_or_else(|| v.parse().ok(), |h| u32::from_str_radix(h, 16).ok())
        })
        .unwrap_or(default)
}

/// 機能名の集合と識別情報からリーフ値の表を導出する。
/// `features` は `CpuSel.features`（モデル＋`--cpu` の足し引きと
/// `implies` 閉包を解決した名前の集合）。`ident` が空なら既定の
/// ベンダと版を使う。最大リーフ番号は ident の `cpuid.max_basic`/
/// `cpuid.max_ext` で上書きでき、既定は 7 と 0x8000_0008。
#[must_use]
pub fn derive(features: &BTreeSet<String>, ident: &BTreeMap<String, String>) -> [[u32; 4]; 9] {
    // IDENT_BITS をリーフ・レジスタごとに畳む。
    let mut leaf_regs: BTreeMap<(u32, u32, &str), u32> = BTreeMap::new();
    for (f, leaf, subleaf, reg, bit) in IDENT_BITS {
        debug_assert!(
            matches!(*reg, "eax" | "ebx" | "ecx" | "edx"),
            "ident_bits の reg は eax/ebx/ecx/edx: {reg}"
        );
        if features.contains(*f) {
            *leaf_regs.entry((*leaf, *subleaf, *reg)).or_default() |= 1 << bit;
        }
    }
    let reg_of = |leaf: u32, subleaf: u32, reg: &str| -> u32 {
        leaf_regs.get(&(leaf, subleaf, reg)).copied().unwrap_or(0)
    };

    let (ebx_v, ecx_v, edx_v) = vendor_regs(
        ident
            .get("cpuid.vendor")
            .map_or("GenuineIntel", String::as_str),
    );
    // 出力は (EAX,EBX,ECX,EDX) の順。vendor_regs は (EBX,ECX,EDX) を返す。
    // leaf 1 の EAX。family/model/stepping を詰める（拡張版数は
    // family 15 のみのため、今のモデル群では未使用）。
    let family = num(ident, "cpuid.family", 6);
    let model = num(ident, "cpuid.model", 15);
    let stepping = num(ident, "cpuid.stepping", 0);
    let l1_eax = (stepping & 0xf)
        | ((model & 0xf) << 4)
        | ((family & 0xf) << 8)
        | (((model >> 4) & 0xf) << 16)
        | (((family >> 4) & 0xff) << 20);

    let def_max = if features.contains("xsave") {
        MAX_BASIC_XSAVE
    } else {
        MAX_BASIC
    };
    let max_basic = num(ident, "cpuid.max_basic", def_max);
    let max_ext = num(ident, "cpuid.max_ext", MAX_EXT);
    let mut tbl = [
        // leaf 0: 最大リーフ + ベンダ。
        [max_basic, ebx_v, ecx_v, edx_v],
        // leaf 1: 版数と機能ビット。
        [l1_eax, 0, reg_of(1, 0, "ecx"), reg_of(1, 0, "edx")],
        // leaf 7 サブリーフ 0: 最大サブリーフと機能ビット。
        [
            0,
            reg_of(7, 0, "ebx"),
            reg_of(7, 0, "ecx"),
            reg_of(7, 0, "edx"),
        ],
        // leaf D サブリーフ 0: XCR0 対応成分（`xcomp_supp` と同じ
        // マスク）、現在有効サイズ・最大サイズ。成分の保存実装は
        // x87/SSE/AVX の上位 512+64+256=832 バイトまで（近似。
        // 実機は AMX 成分ぶん大きい値と leaf D.17/D.18 を報告する）。
        if features.contains("xsave") {
            let sz = if features.contains("avx") {
                0x340
            } else {
                0x240
            };
            [xcomp_supp(features) as u32, sz, sz, 0]
        } else {
            [0; 4]
        },
        // leaf D サブリーフ 1: 拡張保存機能ビット。bit0=XSAVEOPT、
        // bit1/3 の XSAVEC/XSAVES は未実装。EBX 以降は
        // XSAVES 領域サイズで 0。
        if features.contains("xsaveopt") {
            [1, 0, 0, 0]
        } else {
            [0; 4]
        },
        // leaf D サブリーフ 2: YMMH 成分のサイズとオフセット
        // （XSAVE レイアウトの +576、16 エントリ×16 バイト）。
        // D.0 の EAX に bit2 を立てるモデルだけ報告する。
        if features.contains("avx") {
            [0x100, 0x240, 0, 0]
        } else {
            [0; 4]
        },
        // leaf 0x8000_0000: 最大拡張リーフ。
        [max_ext, 0, 0, 0],
        // leaf 0x8000_0001: 拡張機能ビット。
        [
            0,
            0,
            reg_of(0x8000_0001, 0, "ecx"),
            reg_of(0x8000_0001, 0, "edx"),
        ],
        // leaf 0x8000_0008: アドレスサイズ（32/48 ビット固定）と
        // EBX の拡張機能ビット（CLZERO/RDPRU 等）。
        [0x0000_3020, reg_of(0x8000_0008, 0, "ebx"), 0, 0],
    ];
    // モデルが報告する最大リーフを超える行は 0 に潰す。leaf 0 と
    // 0x8000_0000 の EAX は最大値そのものを運ぶので残す。
    for (i, (leaf, _)) in LEAF_IDS.iter().enumerate() {
        let beyond = if *leaf >= 0x8000_0000 {
            *leaf > max_ext
        } else {
            *leaf > max_basic
        };
        if *leaf != 0 && *leaf != 0x8000_0000 && beyond {
            tbl[i] = [0; 4];
        }
    }
    tbl
}

/// Linux `arch_prctl(ARCH_GET_XCOMP_SUPP)` が返す「OS が
/// 対応する拡張状態」の成分マスク。bit0=x87, bit1=SSE は常に、
/// bit17=XTILECFG, bit18=XTILEDATA は `amx_tile` 宣言時に含む。
/// bit2 (YMM) 以降はその成分の XSAVE 実装が入ってから足す。
/// leaf D.0 の EAX が報告する成分と同じマスクを返す（実機の
/// XCOMP_SUPP は leaf D の uabi 成分と一致する）。
#[must_use]
pub fn xcomp_supp(features: &BTreeSet<String>) -> u64 {
    let mut m = 0x3u64;
    if features.contains("avx") {
        m |= 0x4;
    }
    if features.contains("amx_tile") {
        m |= 0x6_0000;
    }
    m
}
