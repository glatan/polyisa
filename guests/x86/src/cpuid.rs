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
/// `CpuState.cpuid` の添え字順。ベーシックは 0・1・7.0・7.1・0xD.0・
/// 0xD.1・0xD.2・0x1D.0・0x1D.1・0x1E.0・0x1E.1、拡張は
/// 0x8000_0000・0x8000_0001・0x8000_0008。
pub const LEAF_IDS: [(u32, u32); 26] = [
    (0, 0),
    (1, 0),
    (7, 0),
    (7, 1),
    (0xD, 0),
    (0xD, 1),
    (0xD, 2),
    (0xD, 5),
    (0xD, 6),
    (0xD, 7),
    (0xD, 17),
    (0xD, 18),
    (0xD, 19),
    (0x1D, 0),
    (0x1D, 1),
    (0x1E, 0),
    (0x1E, 1),
    (0x8000_0000, 0),
    (0x8000_0001, 0),
    (0x8000_0008, 0),
    (0xC000_0000, 0),
    (0xC000_0001, 0),
    (0x24, 0),
    (0x24, 1),
    (0x1D, 2),
    (0xD, 20),
];

/// 最大ベーシックリーフの既定（leaf 0 の EAX）。`xsave` 機能が
/// あれば leaf D を含む 0xD、なければ 7。`cpuid.max_basic`
/// で上書きできる。
const MAX_BASIC: u32 = 7;
const MAX_BASIC_XSAVE: u32 = 0xD;
/// 最大拡張リーフ（leaf 0x8000_0000 の EAX）。
const MAX_EXT: u32 = 0x8000_0008;

// XSAVE 標準（非圧縮）レイアウトの固定オフセット。MPX が
// 使っていた 0x3c0-0x43f は APX EGPR が再利用する。0x340-0x3bf
// と 0xa80-0xabf は予約/他成分の間隙で、polyisa が実装しない
// PKRU・CET 等があっても AVX-512/AMX/APX の位置は変わらない。
pub const XSAVE_YMM_OFF: u32 = 0x240;
pub const XSAVE_APX_OFF: u32 = 0x3c0;
pub const XSAVE_APX_SIZE: u32 = 0x80;
pub const XSAVE_OPMASK_OFF: u32 = 0x440;
pub const XSAVE_ZMMHI_OFF: u32 = 0x480;
pub const XSAVE_HI16ZMM_OFF: u32 = 0x680;
pub const XSAVE_TILECFG_OFF: u32 = 0xac0;
pub const XSAVE_TILEDATA_OFF: u32 = 0xb00;
pub const XSAVE_AMX_END: u32 = XSAVE_TILEDATA_OFF + 0x2000;
pub const XSAVE_SCALEDATA_OFF: u32 = XSAVE_AMX_END;
pub const XSAVE_SCALEDATA_END: u32 = XSAVE_SCALEDATA_OFF + 0x80;

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
pub fn derive(features: &BTreeSet<String>, ident: &BTreeMap<String, String>) -> [[u32; 4]; 26] {
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

    let def_max = if features.contains("avx10") {
        // AVX10 の converged vector ISA leaf 0x24 まで報告する。
        0x24
    } else if features.contains("amx_tile") {
        // AMX の情報葉 0x1D/0x1E まで報告する。
        0x1E
    } else if features.contains("xsave") {
        MAX_BASIC_XSAVE
    } else {
        MAX_BASIC
    };
    let max_basic = num(ident, "cpuid.max_basic", def_max).max(def_max);
    let max_ext = num(ident, "cpuid.max_ext", MAX_EXT);
    let max_via = if features.contains("via_padlock_rng") {
        0xC000_0001
    } else {
        0
    };
    // leaf D.1 EBX: XSAVEC の圧縮レイアウトで全対応成分を
    // 保存したときのサイズ。先頭 576 バイト（legacy+header）の後に、
    // 成分を昇順で必要なものだけ詰める。polyisa が報告する成分では
    // AMX の XTILECFG/XTILEDATA だけが 64 バイト整列（leaf D.i ECX[1]）。
    let compact_size = if features.contains("xsavec") {
        let mut off = 576u32;
        for (bit, size, align64) in [
            (2u64, 0x100u32, false),
            (5, 0x40, false),
            (6, 0x200, false),
            (7, 0x400, false),
            (17, 0x40, true),
            (18, 0x2000, true),
            (19, XSAVE_APX_SIZE, true),
            (20, 0x80, true),
        ] {
            if xcomp_supp(features) & (1u64 << bit) != 0 {
                if align64 {
                    off = off.next_multiple_of(64);
                }
                off += size;
            }
        }
        off
    } else {
        0
    };
    // leaf 7 EAX は最大サブリーフ番号。いま宣言があるのは 1 まで。
    let max7sub = leaf_regs
        .keys()
        .filter_map(|(leaf, subleaf, _)| (*leaf == 7).then_some(*subleaf))
        .max()
        .unwrap_or(0);
    let mut tbl = [
        // leaf 0: 最大リーフ + ベンダ。
        [max_basic, ebx_v, ecx_v, edx_v],
        // leaf 1: 版数と機能ビット。
        [l1_eax, 0, reg_of(1, 0, "ecx"), reg_of(1, 0, "edx")],
        // leaf 7 サブリーフ 0: 最大サブリーフと機能ビット。
        [
            max7sub,
            reg_of(7, 0, "ebx"),
            reg_of(7, 0, "ecx"),
            reg_of(7, 0, "edx"),
        ],
        // leaf 7 サブリーフ 1: SHA512/SM3/SM4・RAO-INT・MOVRS・
        // USER_MSR などの新しい機能ビット。
        [
            reg_of(7, 1, "eax"),
            reg_of(7, 1, "ebx"),
            reg_of(7, 1, "ecx"),
            reg_of(7, 1, "edx"),
        ],
        // leaf D サブリーフ 0: XCR0 対応成分（`xcomp_supp` と同じ
        // マスク）、現在有効サイズ・最大サイズ。EBX は実機では
        // 現在の XCR0 に依存するが、polyisa の CPUID 表は静的なので
        // ECX と同じく対応成分全体の末尾を返す近似とする。
        if features.contains("xsave") {
            let mut sz = if features.contains("avx") {
                XSAVE_YMM_OFF + 0x100
            } else {
                0x240
            };
            if features.contains("apx") {
                sz = sz.max(XSAVE_APX_OFF + XSAVE_APX_SIZE);
            }
            if features.contains("avx512f") {
                sz = sz.max(XSAVE_HI16ZMM_OFF + 0x400);
            }
            if features.contains("amx_tile") {
                sz = sz.max(XSAVE_AMX_END);
            }
            if features.contains("ace") {
                sz = sz.max(XSAVE_SCALEDATA_END);
            }
            [xcomp_supp(features) as u32, sz, sz, 0]
        } else {
            [0; 4]
        },
        // leaf D サブリーフ 1: 拡張保存機能ビット。bit0=XSAVEOPT、
        // bit1=XSAVEC。bit3 の XSAVES は CPL0 専用で未実装。
        [reg_of(0xd, 1, "eax"), compact_size, 0, 0],
        // leaf D サブリーフ 2: YMMH 成分のサイズとオフセット
        // （XSAVE レイアウトの +576、16 エントリ×16 バイト）。
        // D.0 の EAX に bit2 を立てるモデルだけ報告する。
        if features.contains("avx") {
            [0x100, 0x240, 0, 0]
        } else {
            [0; 4]
        },
        // leaf D サブリーフ 5-7: AVX-512 成分。実機の標準
        // レイアウトは opmask=0x440、ZMM_Hi256=0x480、
        // Hi16_ZMM=0x680。
        if features.contains("avx512f") {
            [0x40, XSAVE_OPMASK_OFF, 0, 0]
        } else {
            [0; 4]
        },
        if features.contains("avx512f") {
            [0x200, XSAVE_ZMMHI_OFF, 0, 0]
        } else {
            [0; 4]
        },
        if features.contains("avx512f") {
            [0x400, XSAVE_HI16ZMM_OFF, 0, 0]
        } else {
            [0; 4]
        },
        // leaf D サブリーフ 17/18: AMX XTILECFG/XTILEDATA。
        // XTILEDATA は 8192 バイトで、CPUID leaf 1D.1 の形状と一致する。
        if features.contains("amx_tile") {
            [0x40, XSAVE_TILECFG_OFF, 2, 0]
        } else {
            [0; 4]
        },
        if features.contains("amx_tile") {
            [0x2000, XSAVE_TILEDATA_OFF, 2, 0]
        } else {
            [0; 4]
        },
        // leaf D サブリーフ 19: APX EGPR（r16-r31、16×8 バイト）。
        // 非圧縮形式では廃止された MPX 領域 0x3c0-0x43f を再利用する。
        if features.contains("apx") {
            [XSAVE_APX_SIZE, XSAVE_APX_OFF, 2, 0]
        } else {
            [0; 4]
        },
        // leaf 1D サブリーフ 0/1: AMX tile palette 情報。
        // palette 1 は 8 枚×最大 16 行×64 バイト（計 8192 バイト、
        // 1 枚 1024 バイト）。AMX-TILE がなければ葉全体を 0 にする。
        if features.contains("amx_tile") {
            [if features.contains("ace") { 2 } else { 1 }, 0, 0, 0]
        } else {
            [0; 4]
        },
        if features.contains("amx_tile") {
            [0x0400_2000, 0x0008_0040, 0x10, 0]
        } else {
            [0; 4]
        },
        // leaf 1E サブリーフ 0: TMUL の形状（maxk=16、maxn=64）。
        // EAX は reserved。サブリーフ 1 は AMX 機能の mirror と
        // AMX-MOVRS を EAX に持つ。
        if features.contains("amx_tile") {
            [0, 16 | (64 << 8), 0, 0]
        } else {
            [0; 4]
        },
        if features.contains("amx_tile") {
            [
                reg_of(0x1e, 1, "eax"),
                reg_of(0x1e, 1, "ebx"),
                reg_of(0x1e, 1, "ecx"),
                reg_of(0x1e, 1, "edx"),
            ]
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
        // VIA/Zhaoxin の拡張葉。C000_0000 は最大葉、C000_0001
        // EDX[2:3] が PadLock RNG の present/enabled。
        [max_via, 0, 0, 0],
        [
            0,
            0,
            reg_of(0xC000_0001, 0, "ecx"),
            reg_of(0xC000_0001, 0, "edx"),
        ],
        // leaf 0x24 subleaf 0: AVX10 Converged Vector ISA Main Leaf。
        // EBX[7:0] は累積版番号。現行仕様では全実装が 128/256/512
        // ビット幅を持つため EBX[18:16] は 111 固定。
        if features.contains("avx10") {
            let version = if features.contains("avx10_3") {
                3
            } else if features.contains("avx10_2") {
                2
            } else {
                1
            };
            [1, version | 0x7_0000, 0, 0]
        } else {
            [0; 4]
        },
        // leaf 0x24 subleaf 1: AVX10 auxiliary feature leaf。
        // ECX[1]=AVX10_BMM、ECX[2]=AVX10_V1_AUX、ECX[3]=AVX10_V2_AUX。
        if features.contains("avx10") {
            let mut ecx = 0;
            if features.contains("avx10_bmm") {
                ecx |= 1 << 1;
            }
            if features.contains("avx10_v1_aux") {
                ecx |= 1 << 2;
            }
            if features.contains("avx10_v2_aux") {
                ecx |= 1 << 3;
            }
            if features.contains("avx10_vpmldsabflydq") {
                ecx |= 1 << 7;
            }
            [0, 0, ecx, 0]
        } else {
            [0; 4]
        },
        // leaf 1D subleaf 2: ACE palette。EAX[7:0] は ACE の major
        // version、EAX[16:18] は ACE v2 の任意 outer product。
        if features.contains("ace") {
            let mut eax = if features.contains("ace_v2") { 2 } else { 1 };
            if features.contains("ace_op_fp16") {
                eax |= 1 << 16;
            }
            if features.contains("ace_op_fp32") {
                eax |= 1 << 17;
            }
            if features.contains("ace_op_fp64") {
                eax |= 1 << 18;
            }
            [eax, 0, 0, 0]
        } else {
            [0; 4]
        },
        // leaf D subleaf 20: ACE SCALEDATA（128 バイト）。
        if features.contains("ace") {
            [0x80, XSAVE_SCALEDATA_OFF, 2, 0]
        } else {
            [0; 4]
        },
    ];
    // モデルが報告する最大リーフを超える行は 0 に潰す。leaf 0 と
    // 0x8000_0000 の EAX は最大値そのものを運ぶので残す。
    for (i, (leaf, _)) in LEAF_IDS.iter().enumerate() {
        let beyond = if (0xC000_0000..=0xC000_FFFF).contains(leaf) {
            *leaf > max_via
        } else if *leaf >= 0x8000_0000 {
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

/// XSAVE 標準レイアウトで、成分マスク `mask` を収めるのに必要な
/// ユーザー領域サイズ。先頭 576 バイト（legacy 512 + xsave header 64）
/// を最低値とし、各成分の固定末尾まで拡げる。Linux の sigframe の
/// `xstate_size` と CPUID.0D.0:EBX の現在サイズ計算に対応する。
#[must_use]
pub fn xstate_size(mask: u64) -> u64 {
    let mut size = 576u64;
    for (bit, end) in [
        (2u64, 0x340u64),
        (5, 0x480),
        (6, 0x680),
        (7, 0xa80),
        (17, 0xb00),
        (18, 0x2b00),
        (19, 0x440),
        (20, 0x2b80),
    ] {
        if mask & (1u64 << bit) != 0 {
            size = size.max(end);
        }
    }
    size
}

/// Linux `arch_prctl(ARCH_GET_XCOMP_SUPP)` が返す「OS が
/// 対応する拡張状態」の成分マスク。bit0=x87, bit1=SSE は常に、
/// bit17=XTILECFG, bit18=XTILEDATA は `amx_tile`、bit19=APX EGPR は
/// `apx` 宣言時に含む。
/// bit2 (YMM) 以降はその成分の XSAVE 実装が入ってから足す。
/// leaf D.0 の EAX が報告する成分と同じマスクを返す（実機の
/// XCOMP_SUPP は leaf D の uabi 成分と一致する）。
#[must_use]
pub fn xcomp_supp(features: &BTreeSet<String>) -> u64 {
    let mut m = 0x3u64;
    if features.contains("avx") {
        m |= 0x4;
    }
    if features.contains("avx512f") {
        m |= 0xe0;
    }
    if features.contains("amx_tile") {
        m |= 0x6_0000;
    }
    if features.contains("apx") {
        m |= 0x8_0000;
    }
    if features.contains("ace") {
        m |= 0x10_0000;
    }
    m
}
