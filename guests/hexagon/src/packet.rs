// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon のパケット層。フェッチ単位である 1–4 語のパケットを
//! Parse 桁（bits[15:14]）で切り出し、duplex 語の分解・constant
//! extender の併合・スロット組立の規則を適用する。
//!
//! ia64 の `bundle` と同じく、生成した固定長命令デコーダの外側に
//! ある層。32 ビット命令は `decode_model_ex` にそのまま渡し、
//! duplex の subinsn（13 ビット語）はグループ文脈旗 `FEAT_DX_*`
//! を立てて同じ関数に渡す（ia64 のスロット文脈旗と同型）。
//!
//! 主な構造:
//! - `split`: 語列 → `Packet`（Parse 終端・duplex 位置・ループ終端
//!   標識の検査を含む）。消費した語数も返す。
//! - `expand`: extender 対結合とスロット割当てを行い、実行順
//!   （slot 3 → 0、低アドレス語から順にスロットが減る）の
//!   `SlotInsn` 列を返す。
//! - `word_class`/`class_slots`: ICLASS → 許容スロットの手書き表
//!   （PRM Table 10-6）。パケット組立規則は ISADL の命令宣言に
//!   表せないため実行側の表として持つ（docs/gaps.md 参照）。
//!
//! Ref: SPEC-HEXAGON-PRM (V79) instruction encoding.

use crate::{FEAT_DX_A, FEAT_DX_L1, FEAT_DX_L2, FEAT_DX_S1, FEAT_DX_S2, Insn, decode_model_ex};

/// 語の Parse 桁（bits[15:14]）。値は `crate::parse`。
fn parse_bits(word: u32) -> u32 {
    (word >> 14) & 0x3
}

/// 語の ICLASS（bits[31:28]）。0 は constant extender。
pub fn iclass(word: u32) -> u32 {
    word >> 28
}

/// duplex subinsn のグループ。Table 10-5 の 4 ビット ICLASS が
/// 低/高 subinsn それぞれのグループを指す。
/// Ref: SPEC-HEXAGON-PRM (V79) Table 10-5.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Group {
    /// L1-type（w:2・ub:0 の load、u4 即値）。
    L1,
    /// L2-type（h:1・b:0・r29 相対の load、deallocframe、
    /// jumpr R31、dealloc_return）。
    L2,
    /// S1-type（w:2・b:0 の store、u4 即値）。
    S1,
    /// S2-type（h:1・r29 相対・即値ストア・allocframe）。
    S2,
    /// A-type（ALU 系 subinsn）。
    A,
}

/// duplex ICLASS（bits{31:29,13}）の値 → (slot0, slot1) グループ。
/// 0xF は予約。
/// Ref: SPEC-HEXAGON-PRM (V79) Table 10-5.
const DUP_GROUPS: [(Group, Group); 16] = {
    use Group::*;
    [
        (L1, L1),
        (L2, L1),
        (L2, L2),
        (A, A),
        (L1, A),
        (L2, A),
        (S1, A),
        (S2, A),
        (S1, L1),
        (S1, L2),
        (S1, S1),
        (S2, S1),
        (S2, L1),
        (S2, L2),
        (S2, S2),
        (A, A), // 0xF 予約。groups() で弾く
    ]
};

/// duplex 語の 4 ビット ICLASS 値。
pub fn duplex_iclass(word: u32) -> u32 {
    ((word >> 29) << 1) | ((word >> 13) & 1)
}

/// duplex 語の (slot0, slot1) グループ。予約値は None。
/// Ref: SPEC-HEXAGON-PRM (V79) Table 10-5.
pub fn duplex_groups(word: u32) -> Option<(Group, Group)> {
    if parse_bits(word) != crate::parse::DUPLEX {
        return None;
    }
    let d = duplex_iclass(word);
    if d == 0xF {
        return None;
    }
    Some(DUP_GROUPS[d as usize])
}

/// duplex 語の subinsn 語（13 ビット値）。`hi` は slot1、
/// `lo` は slot0。
/// Ref: SPEC-HEXAGON-PRM (V79) Table 10-4.
pub fn duplex_subs(word: u32) -> (u16, u16) {
    let lo = (word & 0x1fff) as u16;
    let hi = ((word >> 16) & 0x1fff) as u16;
    (lo, hi)
}

/// グループに対応するデコード文脈旗。
pub fn group_feat(g: Group) -> u128 {
    match g {
        Group::L1 => FEAT_DX_L1,
        Group::L2 => FEAT_DX_L2,
        Group::S1 => FEAT_DX_S1,
        Group::S2 => FEAT_DX_S2,
        Group::A => FEAT_DX_A,
    }
}

/// 13 ビット subinsn 語 `sub` をグループ `g` の文脈でデコードする。
pub fn decode_sub(g: Group, sub: u16, cpu_feats: u128) -> Option<Insn> {
    decode_model_ex(u128::from(sub), 13, true, cpu_feats | group_feat(g))
}

/// duplex 同一グループ規則の比較キー。「レジスタ・即値桁を 0 と
/// みなした 13 ビット値」（Table 10-5 脚注）。各形のフィールド桁
/// だけを落としたオペコード部分を返す。比較キーには述語選択桁
/// （dprd/dprd3）と combine の第 1 即値桁（du2a）も残す
/// （実符号の正規化はこれらを区別する）。
/// Ref: SPEC-HEXAGON-PRM (V79) Table 10-5 note.
fn order_key(g: Group, sub: u16) -> u16 {
    let keep = |m: u16| sub & m;
    match g {
        // オペコードは bit12（w:2/ub:0・b:0）。u4+base+reg は
        // フィールド。
        Group::L1 | Group::S1 => keep(0x1000),
        Group::L2 => {
            if sub >> 11 != 0b11 {
                // memh/memuh/memb（[12:11]=00/01/10）: オペコードは
                // [12:11]。du3+base+dst はフィールド。
                keep(0x1800)
            } else if sub >> 9 == 0b1110 {
                // ldwsp（1110）: オペコードは [12:9]。u5+dst は
                // フィールド。
                keep(0x1e00)
            } else if sub >> 8 == 0b11110 {
                // lddsp（11110）: オペコードは [12:8]。u5+ddp は
                // フィールド。
                keep(0x1f00)
            } else {
                // deallocframe/dealloc_return/jumpr（111110x/
                // 111111x）: [12:6] がオペコード。[5:3] は未使用、
                // dprd3（述語選択）は残す。
                keep(0x1fc7)
            }
        }
        Group::S2 => {
            if sub >> 11 == 0 {
                // memh（[12:11]=00）: オペコードは [12:11]。
                keep(0x1800)
            } else {
                // stwsp/stdsp（010x）・stwi/stbi（100x）・
                // allocframe（1110）: オペコードは [12:9]。
                // 即値・base・data はすべてフィールド。
                keep(0x1e00)
            }
        }
        Group::A => {
            if sub >> 11 == 0 {
                // `Rx=add(Rx,#s7)`（[12:11]=00）: s7 はフィールド。
                keep(0x1800)
            } else if sub >> 10 == 0b010 || sub >> 10 == 0b011 {
                // `Rd=#u6`/`add(r29,#u6:2)`（[12:10]=010/011）: u6 は
                // フィールド。
                keep(0x1c00)
            } else {
                match sub >> 8 {
                    // 条件クリア（[12:7]=110100）: [6:4] は述語選択で
                    // 比較に残し、[3:0] はデスティネーション。
                    0x1a => keep(0x1ff0),
                    // combine(#u2,#U2)（11100）: du2a[4:3] は比較に
                    // 残し、du2b/ddp はフィールド。
                    0x1c => keep(0x1f18),
                    // combine(#0,Rs)/(Rs,#0)（11101）: bit3 は
                    // オペコード。
                    0x1d => keep(0x1f08),
                    // その他（mov/add1/and1/sub1/sxt/zxt/addr/cmp.eq）
                    // は [12:8] がオペコードで [7:0] はフィールド。
                    _ => keep(0x1f00),
                }
            }
        }
    }
}

/// グループが memory アクセス系か（SLOT_MASK 適用用）。
fn group_class(g: Group) -> Class {
    match g {
        Group::L1 | Group::L2 => Class::Ld,
        Group::S1 | Group::S2 => Class::St,
        Group::A => Class::Alu32,
    }
}

/// 命令クラス（ICLAS → 実行スロット表の索引）。
/// Ref: SPEC-HEXAGON-PRM (V79) Table 10-6.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// J 系（slots 2,3）。
    J,
    /// JR 系（間接ジャンプ。slot 2。duplex の jumpr R31 は
    /// slot 0 に置ける）。
    Jr,
    /// LDST 系（slots 0,1）。
    Ldst,
    /// LD 系（slots 0,1）。
    Ld,
    /// ST 系（slot 0。dual store では slot 1、:mem_noshuf 形の
    /// slot1 store + slot0 load でも slot 1 に置ける）。
    St,
    /// CR 系（slot 3）。
    Cr,
    /// ALU32 系（slots 0-3）。
    Alu32,
    /// XTYPE 系（slots 2,3）。
    Xtype,
}

/// NV クラス（`.new` 値ストア + memop）の判定。これらは
/// slot 0 専用（PRM の実行スロット表）。
/// Ref: SPEC-HEXAGON-PRM (V79) Table 10-6 / new-value stores.
fn nv_slot0(w: u32) -> bool {
    match iclass(w) {
        // memop は `0011 111x`。ro 系 `.new` ストアは
        // `0011 1n11 01` / `0011 01nv 101`（[23:21]=101 が
        // `.new` 値標識）。
        3 => (w >> 24) & 0xf >= 0xe || ((w >> 21) & 7 == 5 && matches!((w >> 25) & 7, 2 | 3 | 5)),
        // V2LDST 述語付 io `.new` ストア（bit27=0 で述語付、
        // bit24=0 でストア、[23:21]=101）。
        4 => w >> 27 & 1 == 0 && w >> 24 & 1 == 0 && (w >> 21) & 7 == 5,
        // ICLASS10 の `.new` ストアはすべて [23:21]=101 かつ
        // bit24=1。[27:24]=0000 は memw_locked 等の別命令
        // （HX11。LL/SC は slot 0 専用でもあるが `.new` 値
        // 消費ではない）。
        10 => (w >> 21) & 7 == 5 && w >> 24 & 1 != 0,
        _ => false,
    }
}

/// `.new` 値消費命令の生産距離（命令数単位）。`.new` 値ストア
/// の Nt（通常形は bits[10:9] の nt2、reg-offset 形は
/// bits[2:1] の nt2r）と、HX7 の new-value compare-jump の
/// N.t（bits[18:16] = 距離の 2 倍）。消費命令でなければ None。
fn nt_of(w: u32) -> Option<u32> {
    match iclass(w) {
        3 if (w >> 21) & 7 == 5 && matches!((w >> 25) & 7, 2 | 3 | 5) => Some((w >> 1) & 3),
        4 if w >> 27 & 1 == 0 && w >> 24 & 1 == 0 && (w >> 21) & 7 == 5 => Some((w >> 9) & 3),
        // memw_locked（[27:24]=0000）は `.new` 値消費ではない。
        10 if (w >> 21) & 7 == 5 && w >> 24 & 1 != 0 => Some((w >> 9) & 3),
        // NVJ（`001000`/`001001`）: N.t = 生産距離 × 2。
        // imm 比較形（001001）も NVJ（HX11）。
        2 if matches!((w >> 26) & 0x3f, 8 | 9) => Some(((w >> 16) & 7) >> 1),
        _ => None,
    }
}

/// slot 0 専用の命令語。`.new` 値ストア・memop（`nv_slot0`）に
/// 加え、HX7 で new-value compare-jump（ICLASS 2 の
/// [27:26]=00）と 32 ビット dealloc_return 系（LD_tc_SLOT0、
/// `1001 0110`）が該当する。
/// Ref: SPEC-HEXAGON-PRM (V79) execution slot table.
fn slot0_only(w: u32) -> bool {
    nv_slot0(w)
        || (iclass(w) == 9 && (w >> 24) & 0xf == 6)
        // HX11: LL/SC（memw_locked）は slot 0 専用。
        || (iclass(w) == 9 && (w >> 24) & 0xf == 2 && (w >> 21) & 7 == 0)
        || (iclass(w) == 10 && (w >> 24) & 0xf == 0 && (w >> 21) & 7 == 5)
}

/// 32 ビット述語付きメモリ形の `pX.new` 消費判定。`.new`
/// 条件を読む述語番号を返す（非 `.new` 条件や無条件は None）。
/// qualifier の配置は形ごとに異なるためパターン別に拾う
/// （実符号は参照アセンブラの V73 プロファイルと照合済み）。
/// Ref: SPEC-HEXAGON-PRM (V79) conditional load/store.
fn pred_new32(w: u32) -> Option<u8> {
    let p = match iclass(w) {
        // V2LDST io 述語付形（new=bit25。load なら bit24=1 で
        // 述語は [12:11]、store なら bit24=0 で述語は [1:0]）。
        4 if w >> 27 & 1 == 0 && w >> 25 & 1 != 0 => {
            if w >> 24 & 1 != 0 {
                (w >> 11) & 3
            } else {
                w & 3
            }
        }
        // LD post-inc（`1001 1011` + bit13=1）・LD abs 述語付形
        // （`1001 1111` + bit13=1 + bit7=1）。new=bit12、述語は
        // [10:9]。
        9 if matches!((w >> 24) & 0xf, 0xb | 0xf) && w >> 13 & 1 != 0 && w >> 12 & 1 != 0 => {
            (w >> 9) & 3
        }
        // ST post-inc 述語付形（`1010 1011` + bit13=1）。
        // new=bit7、述語は [1:0]。
        10 if (w >> 24) & 0xf == 0xb && w >> 13 & 1 != 0 && w >> 7 & 1 != 0 => w & 3,
        // ST abs 述語付形（`1010 1111` + bit7=1）。new=bit13、
        // 述語は [1:0]。
        10 if (w >> 24) & 0xf == 0xf && w >> 7 & 1 != 0 && w >> 13 & 1 != 0 => w & 3,
        // V4LDST ro 述語付形（`0011 0xnv` → new=bit25 で
        // [27:24]∈{2,3,6,7}）と st_ip（`0011 100n` → new=
        // bit24 で [27:24]=9）。述語はどちらも [6:5]。
        3 if matches!((w >> 24) & 0xf, 2 | 3 | 6 | 7 | 9) => (w >> 5) & 3,
        // HX7: `if ([!]Pu.new)` 消費。J 述語付 jump
        // （`0101 1100`）、述語付 jumpr（`0101 0011`）は
        // bit11=1 が .new で述語は [9:8]。
        5 if (w >> 24) & 0xf == 0xc && w >> 11 & 1 != 0 => (w >> 8) & 3,
        5 if (w >> 22) & 0x3f == 0b001101 && w >> 11 & 1 != 0 => (w >> 8) & 3,
        // 述語付 dealloc_return（`1001 0110`、bit11=1 が .new、
        // 述語は [9:8]）。
        9 if (w >> 24) & 0xf == 6 && w >> 11 & 1 != 0 => (w >> 8) & 3,
        // HX11: 条件付き ALU（`1111 1x01`/`1111 1x11` 系の
        // `if ([!]Pu[.new]) Rd = op(Rs,Rt)`）。new=bit13、
        // 述語は [6:5]。
        15 if matches!((w >> 24) & 0xf, 0x9 | 0xb | 0xd) && w >> 13 & 1 != 0 => (w >> 5) & 3,
        // HX11: 条件付き add(#s8)/mov(#s12)（`0111 0100`/
        // `0111 1110`）。new=bit13、述語は [22:21]。
        7 if matches!((w >> 24) & 0xf, 0x4 | 0xe) && w >> 13 & 1 != 0 => (w >> 21) & 3,
        _ => return None,
    };
    Some(p as u8)
}

/// `.new` 述語の生成側判定。述語 p を生産する命令なら
/// Some(p)。duplex subinsn（len=13・group 付き）と 32 ビット語
/// の両方を見る。`expand` の生成側規則と `run` の生成側先行
/// 評価が共用する。
/// Ref: SPEC-HEXAGON-PRM (V79) dot-new predicates.
pub(crate) fn pred_prod_cand(len: u32, group: Option<Group>, word: u128) -> Option<u8> {
    match (len, group) {
        // A-type cmp.eq は p0 固定。
        (13, Some(Group::A)) if (word >> 8) & 0x1f == 0b11001 => Some(0),
        // 32 ビット述語書き込み形。宛先はすべて pd2
        // （bits[1:0]）。Pd=[!]cmp.* は
        // Pd=cmp.*(Rs,Rt)（ICLASS 15、bits[27:24]=0010）と
        // Pd=cmp.*(Rs,#imm)（ICLASS 7、bits[27:24]=0101）で、
        // bits[4:2]=000 が cmp.*、100 が !cmp.*。
        // HX11: cmp 系以外の述語生産も拾う — cmp64
        // （`1101 0010 100`）、cmpb/cmph 即値形（`1101 1101`）、
        // bitsclr/bitsset/tstbit・cmpb/cmph レジスタ形
        // （`1100 0111`）、tstbit_i/bitsclr_i/pd_rs
        // （`1000 0101`）、述語論理 p{d}=op(p{s},p{t})
        // （`0110 1011`）。
        (32, _) => {
            let w = word as u32;
            let ic = w >> 28;
            let hi = (w >> 24) & 0xf;
            let is_cmp = matches!((w >> 2) & 7, 0 | 4)
                && ((ic == 0xf && hi == 0b0010) || (ic == 0x7 && hi == 0b0101));
            let is_pwrite = is_cmp
                || (ic == 0xd && matches!(hi, 0b1101 | 0b0010))
                || (ic == 0xc && hi == 0b0111)
                || (ic == 0x8 && hi == 0b0101)
                || (ic == 0x6 && hi == 0b1011);
            if is_pwrite { Some((w & 3) as u8) } else { None }
        }
        _ => None,
    }
}

/// ICLASS → 命令クラス。
/// Gap: GAP-0069（パケット組立規則は手書き表で持つ）
/// Ref: SPEC-HEXAGON-PRM (V79) Table 10-6.
pub fn word_class(word: u32) -> Option<Class> {
    Some(match iclass(word) {
        0 => return None, // constant extender
        // ICLASS 1 は J（[27:24]=0,1,6,7 の分岐系）と HVX の
        // ベクトル演算系が同居する。HVX は slot 制約が緩い
        // Alu32 側に寄せる（実機の HVX スロット配置は語彙
        // 棚卸しの対象外）。
        // Gap: GAP-0071
        1 => match (word >> 24) & 0xf {
            0 | 1 | 6 | 7 => Class::J,
            _ => Class::Alu32,
        },
        2 => match (word >> 24) & 0xf {
            // HX9: vmem 系は ICLASS 2 の [27:24]=8,9,a,b。
            // [23:21]=0/2 はロード（:nt 含む）、他はストア。
            8..=0xb => {
                if matches!((word >> 21) & 7, 0 | 2) {
                    Class::Ld
                } else {
                    Class::St
                }
            }
            _ => Class::J,
        },
        // ICLASS 5 は J（PC 相対）と JR（間接）が混在し、ICLASS 桁
        // だけでは切り分けられない。JR（slot 2 固定）は
        // bits[27:21] のオペコード値で判定する: 0000101=callr、
        // 0000110=callrh、000100x=if([!]Pu)callr、0010100=jumpr、
        // 0010110=jumprh、001101x=jumpr:{t,nt}。0010101=hintjr は
        // JR クラスだが slots 2,3 なので J 側に含める。
        5 => {
            if matches!(
                (word >> 21) & 0x7f,
                0x05 | 0x06 | 0x08 | 0x09 | 0x14 | 0x16 | 0x1a | 0x1b
            ) {
                Class::Jr
            } else {
                Class::J
            }
        }
        3 | 4 => Class::Ldst,
        6 => Class::Cr,
        7 | 11 | 15 => Class::Alu32,
        8 | 12 | 13 | 14 => Class::Xtype,
        9 => Class::Ld,
        10 => Class::St,
        _ => return None,
    })
}

/// 命令クラス → 許容スロットのビットマスク（bit i = slot i 可）。
/// Ref: SPEC-HEXAGON-PRM (V79) Table 10-6.
pub fn class_slots(c: Class) -> u8 {
    match c {
        Class::J => 0b1100,
        Class::Jr => 0b0100,
        Class::Ldst | Class::Ld => 0b0011,
        Class::St => 0b0011,
        Class::Cr => 0b1000,
        Class::Alu32 => 0b1111,
        Class::Xtype => 0b1100,
    }
}

/// パケット 1 語の分類。
/// Ref: SPEC-HEXAGON-PRM (V79) Table 10-4/10-5.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// 通常の 32 ビット命令。
    Insn,
    /// constant extender 語（直後の命令の即値を拡張する接頭辞。
    /// 実行スロットを消費しない）。
    Extender,
    /// duplex 語（slot0/slot1 の subinsn 2 個を持つ）。
    Duplex {
        /// slot0 subinsn のグループ。
        lo: Group,
        /// slot1 subinsn のグループ。
        hi: Group,
    },
}

/// パケット 1 語。`raw` はフェッチしたままの 32 ビット値。
#[derive(Clone, Copy, Debug)]
pub struct Word {
    /// フェッチしたままの 32 ビット値。
    pub raw: u32,
    /// 語の分類。
    pub kind: Kind,
}

/// 切り出したパケット。`words` は低アドレス側から並ぶ
/// （実行スロット番号は大きい側から割る）。
#[derive(Clone, Debug)]
pub struct Packet {
    /// パケットの語列（低アドレス順）。
    pub words: Vec<Word>,
    /// ハードウェアループ終端の標識（bit0 = endloop0、
    /// bit1 = endloop1）。
    pub endloop: u8,
}

/// `split` の失敗。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SplitError {
    /// 終端語（Parse 11 または 00）なしで語列が尽きた、または
    /// 4 語連続で終端が出なかった。
    Unterminated,
    /// 予約の duplex ICLASS 値 0xF。
    BadDuplexClass,
    /// Parse 10 が 3 語目以降に立った（ループ終端の標識は
    /// パケットの 1・2 語目にだけ置ける）。
    BadLoopMarker,
    /// endloop0 の標識があるのに語数が 2 未満、または
    /// endloop1 の標識があるのに語数が 3 未満。
    ShortLoop,
}

/// 語列 `words`（低アドレス順）からパケットを切り出す。
/// `words` はフェッチ先のメモリ上の連続語で、最初の終端語
/// （Parse 11 または 00）までがパケット。終端語のあとに続く語は
/// 次のパケットとして残る（`rest` で語数を返す）。
///
/// 規則（Ref: SPEC-HEXAGON-PRM (V79) Section 10.5/10.6）:
/// - Parse 00 は duplex でパケットの終端（必ず最後の語）。
/// - Parse 01/10 は非終端、11 は終端。
/// - 4 語連続で 11/00 が無ければ illegal。
/// - Parse 10 はループ終端の標識（1 語目=endloop0、2 語目=
///   endloop1）で、3 語目以降に置けない。
/// - endloop0 は 2 語以上、endloop1 は 3 語以上のパケットに限る。
pub fn split(words: &[u32]) -> Result<(Packet, usize), SplitError> {
    let mut out = Vec::with_capacity(4);
    let mut endloop = 0u8;
    let mut n = 0usize;
    loop {
        if n >= 4 || n >= words.len() {
            return Err(SplitError::Unterminated);
        }
        let raw = words[n];
        let pp = parse_bits(raw);
        match pp {
            crate::parse::NEXT => {}
            crate::parse::ENDLOOP => {
                if n >= 2 {
                    return Err(SplitError::BadLoopMarker);
                }
                endloop |= 1 << n;
            }
            crate::parse::END => {
                out.push(Word {
                    raw,
                    kind: if iclass(raw) == 0 {
                        Kind::Extender
                    } else {
                        Kind::Insn
                    },
                });
                n += 1;
                break;
            }
            _ => {
                let Some((lo, hi)) = duplex_groups(raw) else {
                    return Err(SplitError::BadDuplexClass);
                };
                out.push(Word {
                    raw,
                    kind: Kind::Duplex { lo, hi },
                });
                n += 1;
                break;
            }
        }
        // 非終端語は通常命令か extender（ICLASS=0）。
        out.push(Word {
            raw,
            kind: if iclass(raw) == 0 {
                Kind::Extender
            } else {
                Kind::Insn
            },
        });
        n += 1;
    }
    if (endloop & 1) != 0 && out.len() < 2 {
        return Err(SplitError::ShortLoop);
    }
    if (endloop & 2) != 0 && out.len() < 3 {
        return Err(SplitError::ShortLoop);
    }
    Ok((
        Packet {
            words: out,
            endloop,
        },
        n,
    ))
}

/// 1 命令の実行スロット割当て結果。`word` は 32 ビット命令語か
/// 13 ビット subinsn 語（`len` で区別）。
#[derive(Clone, Copy, Debug)]
pub struct SlotInsn {
    /// 命令語（`len` = 13 のとき subinsn 語の値）。
    pub word: u128,
    /// 語長（ビット）。
    pub len: u32,
    /// 実行スロット（0-3）。
    pub slot: u8,
    /// 直前の extender が供給した 26 ビット即値。
    pub ext: Option<u32>,
    /// subinsn のグループ（duplex 由来のときだけ Some）。
    pub group: Option<Group>,
    /// `.new` 距離計算用の命令位置（パケット先頭からの
    /// 命令番号。extender は命令を消費しないので数えない）。
    pub pos: u8,
}

/// `Packet::expand` の失敗。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ComposeError {
    /// extender の直後に対象命令がない（パケット末尾の extender）。
    TrailingExtender,
    /// extender が 2 連続した。
    DoubleExtender,
    /// extender が duplex 語の直前に立ったが、duplex の slot1
    /// subinsn が拡張可能な形（A-type の add(Rx,#s7)/Rd=#u6）で
    /// ない。
    ExtenderBeforeDuplex,
    /// 命令数が 4 を超えた（duplex の subinsn 2 個を含む）。
    TooManyInsns,
    /// スロット割当てが組めない（各命令の許容スロットが
    /// 単調減少列として割り当てられない）。
    NoSlotAssign,
    /// パケット内にメモリ命令が 1 つだけあるが slot 0 に置けない
    /// （単独の LD/ST は slot 0 が必須）。
    LoneMemNotSlot0,
    /// slot 1 に ST 系があるのに slot 0 が ST（dual store）でも
    /// LD（:mem_noshuf 形）でもない。
    StorePairRequired,
    /// プログラムフロー命令の個数・組合せが dual-jump 表を
    /// 満たさない（Section 9.7。3 個以上、先頭が無条件系、
    /// または JR 系を含む組合せ）。
    BadJumpCombo,
    /// 同じグループの duplex subinsn で、13 ビット値の小さい側が
    /// slot 1 にない（Table 10-5 の数値順規則）。
    DuplexOrder,
    /// jumpr R31 相当の subinsn（deallocframe/jumpr/
    /// dealloc_return 系のフレーム命令）が slot 1 に置かれた。
    JumpRSlot,
    /// `.new` 消費命令（述語の .new を読む条件形）に対応する
    /// 生成側命令が同じパケット内にない。
    NewProducer,
    /// ループ終端（endloop 標識）のパケットにプログラム
    /// フロー命令がある。
    LoopEndFlow,
    /// ループ終端パケットに対応する SA/LC を書く命令がある
    /// （endloop0 で SA0/LC0、endloop1 で SA1/LC1。loopN 宣言と
    /// `c{0-3}=Rs` 転送を符号パターンで検査する）。
    LoopEndWrite,
    /// loopN 宣言を含むパケットに投機的間接ジャンプ・
    /// new-value compare jump・dealloc_return がある。
    LoopSetupFlow,
}

/// プログラムフロー命令の dual-jump 適格（dual-jump 表の分類）。
/// Ref: SPEC-HEXAGON-PRM (V79) Section 9.7.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// フロー命令ではない。
    None,
    /// dual jump を組めない（JR 系）。
    Never,
    /// 2 個目のジャンプにだけなれる（無条件 jump/call）。
    Second,
    /// 先頭・2 個目どちらにもなれる（条件付き jump・
    /// compare-jump）。
    Both,
}

/// loopN 宣言命令の判定。CR クラスで bits[27:22]=000000 が
/// レジスタカウント形、100100 が即値形。bit21 が loop1 を
/// 選ぶ。戻り値はそのループが書く SA/LC の面（bit0 = SA0/LC0、
/// bit1 = SA1/LC1。endloop 制限の比較にそのまま使う）。
fn loop_insn(w: u32) -> Option<u8> {
    if iclass(w) == 6 && matches!((w >> 22) & 0x3f, 0 | 0b100100) {
        Some(1 << ((w >> 21) & 1))
    } else {
        None
    }
}

/// その語が SA/LC を書くかを返す（bit0 = SA0/LC0、bit1 =
/// SA1/LC1 への書き込み）。loopN 宣言と `c{0-3}=Rs` 転送
/// （wrcr、c5 = 0-3 がループレジスタ）が対象。
/// Ref: SPEC-HEXAGON-PRM (V79) loop restrictions.
fn loop_reg_write(w: u32) -> u8 {
    let mut m = 0u8;
    if let Some(n) = loop_insn(w) {
        m |= n;
    }
    // `Cd=Rs`（bits[31:21]=01100010001）の宛先 d5（bits[4:0]）
    // が c0-3（SA0/LC0/SA1/LC1）。
    if iclass(w) == 6 && (w >> 21) & 0x7ff == 0b011_0001_0001 && w & 0x1c == 0 {
        m |= 1 << ((w >> 1) & 1);
    }
    m
}

/// loopN 宣言を含むパケットに置けない命令（投機的間接
/// ジャンプ・new-value compare jump・dealloc_return）。
/// `group` が `Some` のとき `word` は 13 ビット subinsn 語。
/// Ref: SPEC-HEXAGON-PRM (V79) loop restrictions.
fn loop_setup_bad(len: u32, group: Option<Group>, word: u128) -> bool {
    if len == 13 {
        // L2 の dealloc_return（1111101x）と投機的 jumpr
        // （1111111x で述語選択 dprd3 が p0.new/!p0.new の 6/7）。
        return group == Some(Group::L2)
            && (word >> 6 == 0b1111101 || (word >> 6 == 0b1111111 && word & 7 >= 6));
    }
    let w = word as u32;
    match iclass(w) {
        // new-value compare jump（ICLASS 2 の [27:26]=00）。
        2 => (w >> 26) & 3 == 0,
        // 投機的間接ジャンプ（`if ([!]Pu.new) jumpr`。
        // 述語付 jumpr 形 [27:22]=001101 で bit11 が .new）。
        5 => (w >> 22) & 0x3f == 0b001101 && w >> 11 & 1 != 0,
        // 32 ビット dealloc_return 系（[27:24]=0110）。
        9 => (w >> 24) & 0xf == 6,
        _ => false,
    }
}

/// 命令のフロー種別。`group` が `Some` のとき `word` は
/// 13 ビット subinsn 語。
/// Gap: GAP-0069（ICLASS 6 のフロー形・NVJ の一部は
/// 未分離）。
fn flow_of(len: u32, group: Option<Group>, word: u128, class: Class) -> Flow {
    if len == 13 {
        // L2 の dealloc_return/jumpr（フレーム命令）は JR 系で
        // dual を組めない。deallocframe はフロー命令ではない。
        return match (group, word >> 6) {
            (Some(Group::L2), 0x7d | 0x7f) => Flow::Never,
            _ => Flow::None,
        };
    }
    match class {
        Class::Jr => Flow::Never,
        Class::J => {
            let w = word as u32;
            match iclass(w) {
                // ICLASS 1: compare-jump 複合は条件付き相当。
                // 転送ジャンプ（`Rd=#U6; jump`/`Rd=Rs; jump`、
                // [27:25]=011）は無条件相当で 2 個目専用。
                1 => {
                    if (w >> 25) & 7 == 0b011 {
                        Flow::Second
                    } else {
                        Flow::Both
                    }
                }
                // ICLASS 2: NVJ は dual を組めない。
                2 => Flow::Never,
                5 => match (w >> 24) & 0xf {
                    // `0101 1100` = if ([!]Pu[.new]) jump（条件付き）。
                    0b1100 => Flow::Both,
                    // `0101 1101` = if ([!]Pu) call。dual-jump の
                    // 2 個目は無条件 jump/call だけなので組めない。
                    0b1101 => Flow::Never,
                    _ => Flow::Second,
                },
                _ => Flow::Second,
            }
        }
        // 32 ビット dealloc_return 系（ICLASS 9, [27:24]=0110）も
        // JR 相当で dual を組めない。
        Class::Ld if iclass(word as u32) == 9 && (word as u32 >> 24) & 0xf == 6 => Flow::Never,
        // `if (Rs {!=,==,>=,<=} #0) jump`（ICLASS 6,
        // [27:22]=000100）は条件付きジャンプ。
        Class::Cr if (word as u32 >> 22) & 0x3f == 0b000100 => Flow::Both,
        _ => Flow::None,
    }
}

/// パケットの extender 対結合とスロット割当てを行い、実行順
/// （slot 3 → 0、低アドレス語から順にスロットが減る）の
/// `SlotInsn` 列を返す。失敗時は `ComposeError`。
///
/// 規則（Ref: SPEC-HEXAGON-PRM (V79) Section 10.2/10.3/10.9）:
/// - 実行スロットは 4 つまで。duplex は slot0/slot1 の 2 命令に展開
///   され、extender はスロットを消費しない。
/// - 命令のスロットは低アドレス語から高アドレス語へ単調減少
///   （語の並びは slot 3 → 0 順）。
/// - 各命令は命令クラスの許容スロットにだけ置ける。
/// - メモリ命令が 1 つだけのパケットではそれは slot 0。
/// - ST が slot 1 に置かれるのは dual store（slot 0 も ST）か
///   slot1 store + slot0 load（:mem_noshuf 形）のときだけ。
/// - プログラムフロー命令は最大 2 個で、先頭（低アドレス側）は
///   条件付き jump/compare-jump、2 個目は無条件も可。JR 系は
///   dual を組めない（Section 9.7 の dual-jump 表）。
/// - duplex の同一グループ subinsn は 13 ビット値が小さい側が
///   slot 1（jumpr R31 は slot 0 固定）。
/// - extender は直後の 1 命令にだけ適用し、duplex コンテナには
///   適用できない（duplex 内の適用は subinsn 層の問題で、
///   本関数はコンテナ直前の extender を拒否する）。
pub fn expand(pkt: &Packet) -> Result<Vec<SlotInsn>, ComposeError> {
    // 1. 命令単位に展開（extender は次の命令の ext として吸収）。
    //    slot はこの時点では未確定（許容マスクだけ持つ）。
    struct Cand {
        word: u128,
        len: u32,
        class: Class,
        /// duplex subinsn は slot 固定（hi=1、lo=0）。
        /// `Some(slot)` ならそのスロットで確定。
        fixed: Option<u8>,
        ext: Option<u32>,
        group: Option<Group>,
        pos: u8,
    }
    let mut cands: Vec<Cand> = Vec::with_capacity(4);
    let mut ext: Option<u32> = None;
    let mut pos = 0u8;
    for w in &pkt.words {
        match w.kind {
            Kind::Insn => {
                let Some(class) = word_class(w.raw) else {
                    return Err(ComposeError::NoSlotAssign);
                };
                cands.push(Cand {
                    word: u128::from(w.raw),
                    len: 32,
                    class,
                    fixed: None,
                    ext: ext.take(),
                    group: None,
                    pos,
                });
                pos += 1;
            }
            Kind::Extender => {
                if ext.is_some() {
                    return Err(ComposeError::DoubleExtender);
                }
                let imm26 = ((w.raw >> 16) << 14) | (w.raw & 0x3fff);
                ext = Some(imm26 & 0x3ff_ffff);
            }
            Kind::Duplex { lo, hi } => {
                let (lo_word, hi_word) = duplex_subs(w.raw);
                // extender は slot1（hi）subinsn にだけ適用でき、
                // 対象は A-type の add(Rx,#s7)（[12:11]=00）と
                // Rd=#u6（[12:10]=010）に限る。
                let mut e_hi = None;
                if let Some(e) = ext.take() {
                    let top = hi_word >> 10;
                    let ok = hi == Group::A && (top >> 1 == 0 || top == 0b010);
                    if !ok {
                        return Err(ComposeError::ExtenderBeforeDuplex);
                    }
                    e_hi = Some(e);
                }
                cands.push(Cand {
                    word: u128::from(hi_word),
                    len: 13,
                    class: group_class(hi),
                    fixed: Some(1),
                    ext: e_hi,
                    group: Some(hi),
                    pos,
                });
                pos += 1;
                cands.push(Cand {
                    word: u128::from(lo_word),
                    len: 13,
                    class: group_class(lo),
                    fixed: Some(0),
                    ext: None,
                    group: Some(lo),
                    pos,
                });
                pos += 1;
            }
        }
    }
    if ext.is_some() {
        return Err(ComposeError::TrailingExtender);
    }
    if cands.len() > 4 {
        return Err(ComposeError::TooManyInsns);
    }

    // 2. 組立規則。
    // 2a. duplex 同一グループの数値順（小さい側が slot1）。比較は
    //     「レジスタ・即値桁を 0 とみなした値」で行う（Table 10-5
    //     脚注）。オペコード桁を残すマスクはグループごとに持つ。
    //     HX11: 実符号照合で、この正規化が働くのは A/A だけと参照アセンブラ実符号で確認
    //     した（参照アセンブラは A/A の書いた順を符号化時に入れ替える
    //     が、L/S 系の同組対は書いた順のまま符号化する =
    //     どちらの順も実在しうる）。そのため規則の適用は A/A に
    //     限る。
    if let Some(last) = pkt.words.last()
        && let Kind::Duplex { lo, hi } = last.kind
        && lo == hi
        && lo == Group::A
    {
        let (lo_w, hi_w) = duplex_subs(last.raw);
        if order_key(lo, lo_w) < order_key(hi, hi_w) {
            return Err(ComposeError::DuplexOrder);
        }
    }
    // 2b. jumpr R31 は slot 0 固定。duplex の hi（slot1）subinsn が
    //     L2 の jumpr（[12:6]=1111111 → 0x1fc0–0x1fff）なら拒否。
    if let Some(last) = pkt.words.last()
        && let Kind::Duplex { hi, .. } = last.kind
        && hi == Group::L2
    {
        let (_, hi_w) = duplex_subs(last.raw);
        if hi_w & 0x1fc0 == 0x1fc0 {
            return Err(ComposeError::JumpRSlot);
        }
    }
    // 2c. slot1 の ST 系には slot0 の ST 系（dual store）または
    //     LD 系（:mem_noshuf 形）が要る。duplex では ICLASS の
    //     値域が hi∈{S1,S2} ⟹ lo∈{S1,S2} を満たす組だけを持つ
    //     ため構造的に保たれる（Table 10-5）。通常命令については
    //     3b で割当て後に検査する。
    if let Some(last) = pkt.words.last()
        && let Kind::Duplex { lo, hi } = last.kind
    {
        let s = |g: Group| matches!(g, Group::S1 | Group::S2);
        if s(hi) && !s(lo) {
            return Err(ComposeError::StorePairRequired);
        }
    }
    // 2d. 単独メモリ命令は slot 0 固定。duplex subinsn のスロットは
    //     固定（hi=1、lo=0）なので通常命令にだけ絞り込む。
    //     現行の class_slots では memory 系は必ず slot0 を含むので
    //     LoneMemNotSlot0 は発火しない防衛的検査。
    let is_mem = |c: &Cand| matches!(c.class, Class::Ldst | Class::Ld | Class::St);
    let mem_count = cands.iter().filter(|c| is_mem(c)).count();
    let mut masks: Vec<u8> = cands
        .iter()
        .map(|c| c.fixed.map_or_else(|| class_slots(c.class), |s| 1 << s))
        .collect();
    if mem_count == 1 {
        let i = cands.iter().position(is_mem).expect("mem");
        if cands[i].fixed.is_none() {
            masks[i] &= 0b0001;
            if masks[i] == 0 {
                return Err(ComposeError::LoneMemNotSlot0);
            }
        }
    }
    // 2f. slot 0 専用の命令（NV クラスの `.new` 値ストア +
    //     memop、HX7 の NVJ・32 ビット dealloc_return 系）。
    for (i, c) in cands.iter().enumerate() {
        if c.len == 32 && c.fixed.is_none() && slot0_only(c.word as u32) {
            // slot 0 専用はクラス表の mask（J=slots2,3）と交差
            // しないことがあるので交差ではなく {0} に置き換える。
            masks[i] = 0b0001;
        }
    }
    // pause(#u10) は solo 命令で他の命令とパケットを組めない。
    if cands.len() > 1
        && cands
            .iter()
            .any(|c| c.len == 32 && (c.word as u32 >> 22) == 0b01_0101_0001)
    {
        return Err(ComposeError::NoSlotAssign);
    }
    // 2e. プログラムフロー命令の個数・組合せ（Section 9.7 の
    //     dual-jump 表）。先頭（アドレスが小さい側）のジャンプは
    //     条件付き jump・compare-jump に限り、JR 系は dual を
    //     組めない。
    let mut flows = cands
        .iter()
        .map(|c| flow_of(c.len, c.group, c.word, c.class))
        .filter(|f| *f != Flow::None);
    match (flows.next(), flows.next(), flows.next()) {
        (Some(Flow::Both), Some(second), None) if second != Flow::Never => {}
        (Some(_), None, _) => {}
        (None, _, _) => {}
        _ => return Err(ComposeError::BadJumpCombo),
    }
    // 2g. ハードウェアループの規則（PRM loop restrictions）。
    //     - ループ終端（endloop 標識）のパケットにはプログラム
    //       フロー命令を置けない。
    //     - ループ終端パケットには対応する SA/LC を書く命令を
    //       置けない（endloop0 → SA0/LC0、endloop1 → SA1/LC1。
    //       反対側のループレジスタは書ける）。
    //     - loopN 宣言を含むパケットには投機的間接ジャンプ・
    //       new-value compare jump・dealloc_return を置けない。
    for c in &cands {
        if pkt.endloop != 0 && flow_of(c.len, c.group, c.word, c.class) != Flow::None {
            return Err(ComposeError::LoopEndFlow);
        }
        if c.len == 32 && loop_reg_write(c.word as u32) & pkt.endloop != 0 {
            return Err(ComposeError::LoopEndWrite);
        }
    }
    if cands
        .iter()
        .any(|c| c.len == 32 && loop_insn(c.word as u32).is_some())
    {
        for c in &cands {
            if loop_setup_bad(c.len, c.group, c.word) {
                return Err(ComposeError::LoopSetupFlow);
            }
        }
    }

    // 3. 貪欲に上位スロットから割当て（低アドレス側の命令ほど
    //    大きいスロット番号）。各候補は「直前の候補より小さい
    //    最大の許容スロット」を取る。
    //    例外: NVJ（new-value compare jump）は消費する `.new`
    //    値の生産命令より後に置かねばならず、パケット最後の命令
    //    として順序規則の例外が認められる（J クラスだが最後に
    //    来てよい）。HX11: `{ld; nvj}` 形が musl/busybox に実在。
    //    Ref: SPEC-HEXAGON-PRM (V79) packet constraints.
    let mut slots = vec![0u8; cands.len()];
    let mut upper = 4i8; // 直前の命令のスロット。最初は未使用=4。
    let mut ordered_ok = true;
    for (i, mask_i) in masks.iter().enumerate() {
        let mask = mask_i & ((1 << upper.max(0)) - 1) as u8;
        if mask == 0 {
            ordered_ok = false;
            break;
        }
        let s = (7 - mask.leading_zeros()) as u8;
        slots[i] = s;
        upper = s as i8;
    }
    if !ordered_ok {
        // 順序付き割当てが失敗したら順序を外した全探索に落とす。
        // パケット内の命令列はスロット単調を必ずしも満たさない
        // （NVJ はパケット最後、`{alu; alu; alu; jump}` 形も
        // musl/busybox に実在）。エミュレーションでは命令の
        // 実行順は語の位置で決まるため、各命令の許容スロットに
        // 空きがあれば受理する。候補・スロットとも 4 個以内。
        fn assign(masks: &[u8], i: usize, used: u8, slots: &mut [u8]) -> bool {
            if i == masks.len() {
                return true;
            }
            let mut rest = masks[i] & !used;
            while rest != 0 {
                let s = rest.trailing_zeros() as u8;
                rest &= rest - 1;
                slots[i] = s;
                if assign(masks, i + 1, used | (1 << s), slots) {
                    return true;
                }
            }
            false
        }
        slots.fill(0);
        if !assign(&masks, 0, 0, &mut slots) {
            return Err(ComposeError::NoSlotAssign);
        }
    }
    // 3b. slot1 の ST 系には slot0 に ST（dual store）か LD
    //     （:mem_noshuf 形）が要る。memory 系の許容スロットは
    //     {0,1} なので、slot1 を ST が埋めて割当てが成功するなら
    //     slot0 は必ず他の memory 命令が埋まる。現行マスクでは
    //     発火しない防衛的検査として規則を明示する。
    for (i, c) in cands.iter().enumerate() {
        if slots[i] != 1 || c.class != Class::St {
            continue;
        }
        let ok = cands
            .iter()
            .zip(&slots)
            .any(|(c, &s)| s == 0 && matches!(c.class, Class::St | Class::Ld | Class::Ldst));
        if !ok {
            return Err(ComposeError::StorePairRequired);
        }
    }

    // 4. `.new` 述語の生成側規則（Section 6.1.4 / 3.3.4）:
    //    dot-new 条件命令は、同じパケット内にその述語を書く命令を
    //    要する。消費側は dprd/dprd3 の .new 値（4/5 または 6/7）で
    //    判定し、生成側は述語レジスタを書く命令で判定する。
    //    HX3 の語彙で消費側は A-type 条件クリア（dprd=4/5 → p0.new）
    //    と L2 jumpr/dealloc_return（dprd3=6/7 → p0.new）。
    //    生成側は Pd=cmp.*（pd2）と A-type cmp.eq（p0 固定）。
    let pred_new = |c: &Cand| -> Option<u8> {
        match (c.len, c.group) {
            // A-type 条件クリア: dprd 4/5 = p0.new / !p0.new。
            (13, Some(Group::A)) if (c.word >> 7) & 0x3f == 0b110100 => match (c.word >> 4) & 7 {
                4 | 5 => Some(0),
                _ => None,
            },
            // L2 jumpr/dealloc_return: dprd3 6/7 = p0.new / !p0.new。
            (13, Some(Group::L2)) if matches!(c.word >> 6, 0b1111101 | 0b1111111) => {
                match c.word & 7 {
                    6 | 7 => Some(0),
                    _ => None,
                }
            }
            // 32 ビット述語付きメモリ形（HX6）: 形ごとの
            // qualifier 桁から `pX.new` 消費を拾う。
            (32, _) => pred_new32(c.word as u32),
            _ => None,
        }
    };
    for c in &cands {
        // 生成側はパケット内のどこにあってもよい（実機は同時
        // 発行。`.new` 述語には位置規則がない）。
        if let Some(p) = pred_new(c)
            && !cands
                .iter()
                .any(|d| d.pos != c.pos && pred_prod_cand(d.len, d.group, d.word) == Some(p))
        {
            return Err(ComposeError::NewProducer);
        }
    }
    // `.new` ストアの生産距離 Nt。消費命令の pos より前に
    // 生産命令が要る（pos < nt なら生産側がパケット先頭を
    // 遡って存在しない）。生産命令が gpr を書くかどうかは
    // 実行時の pkt_prod ログで確かめる。
    for c in &cands {
        if c.len == 32
            && let Some(nt) = nt_of(c.word as u32)
            && u32::from(c.pos) < nt
        {
            return Err(ComposeError::NewProducer);
        }
    }

    Ok(cands
        .into_iter()
        .zip(slots)
        .map(|(c, slot)| SlotInsn {
            word: c.word,
            len: c.len,
            slot,
            ext: c.ext,
            group: c.group,
            pos: c.pos,
        })
        .collect())
}

/// extender の 26 ビット値と基底命令の即値桁（下位 6 ビット）を
/// 併合して拡張即値を返す。拡張後の値は `ext26 << 6 | imm6`。
/// Ref: SPEC-HEXAGON-PRM (V79) Section 10.9.
pub fn apply_ext(ext26: u32, imm6: u32) -> u32 {
    (ext26 << 6) | (imm6 & 0x3f)
}

/// duplex 語を組み立てる。`lo`/`hi` は 13 ビット subinsn 語、
/// `lo_grp`/`hi_grp` はそれぞれのグループ。組み合わせに対応する
/// ICLASS 値がなければ None（0xF=予約を含む）。
/// 結果の語の Parse 桁は 00。
pub fn pack_duplex(lo: u16, hi: u16, lo_grp: Group, hi_grp: Group) -> Option<u32> {
    let d = DUP_GROUPS
        .iter()
        .position(|&(l, h)| l == lo_grp && h == hi_grp)? as u32;
    // 4 ビット ICLASS は {31:29}+{13}。上位 3 ビットが [31:29]、
    // 最下位が bit13。
    Some(((d >> 1) << 29) | (sub_bits(hi) << 16) | ((d & 1) << 13) | sub_bits(lo))
}

fn sub_bits(v: u16) -> u32 {
    u32::from(v & 0x1fff)
}
