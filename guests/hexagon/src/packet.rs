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

/// ICLASS → 命令クラス。
/// Gap: GAP-0069（パケット組立規則は手書き表で持つ）
/// Ref: SPEC-HEXAGON-PRM (V79) Table 10-6.
pub fn word_class(word: u32) -> Option<Class> {
    Some(match iclass(word) {
        0 => return None, // constant extender
        1 | 2 => Class::J,
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

/// 命令のフロー種別。`group` が `Some` のとき `word` は
/// 13 ビット subinsn 語。
/// Gap: GAP-0069（ICLASS 6 のフロー形・NVJ・endloop 制限は
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
        Class::J => match iclass(word as u32) {
            // ICLASS 1/2 は compare-jump 複合（条件付き相当）。
            1 | 2 => Flow::Both,
            // ICLASS 5 では 0101 1100 が if(Pu) jump（条件付き）。
            // if(Pu) call や無条件 jump/call は 2 個目専用。
            5 if (word as u32 >> 24) & 0xf == 0b1100 => Flow::Both,
            _ => Flow::Second,
        },
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
    if let Some(last) = pkt.words.last()
        && let Kind::Duplex { lo, hi } = last.kind
        && lo == hi
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

    // 3. 貪欲に上位スロットから割当て（低アドレス側の命令ほど
    //    大きいスロット番号）。各候補は「直前の候補より小さい
    //    最大の許容スロット」を取る。
    let mut slots = vec![0u8; cands.len()];
    let mut upper = 4i8; // 直前の命令のスロット。最初は未使用=4。
    for (i, mask_i) in masks.iter().enumerate() {
        let mask = mask_i & ((1 << upper.max(0)) - 1) as u8;
        if mask == 0 {
            return Err(ComposeError::NoSlotAssign);
        }
        let s = (7 - mask.leading_zeros()) as u8;
        slots[i] = s;
        upper = s as i8;
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
            _ => None,
        }
    };
    let pred_prod = |c: &Cand| -> Option<u8> {
        match (c.len, c.group) {
            // A-type cmp.eq は p0 固定。
            (13, Some(Group::A)) if (c.word >> 8) & 0x1f == 0b11001 => Some(0),
            // 32 ビット Pd=[!]cmp.* は pd2（bits[1:0]）が
            // デスティネーション。比較族は
            // Pd=cmp.*(Rs,Rt)（ICLASS 15、bits[27:24]=0010）と
            // Pd=cmp.*(Rs,#imm)（ICLASS 7、bits[27:24]=0101）で、
            // bits[4:2]=000 が cmp.*、100 が !cmp.*。
            (32, _) => {
                let w = c.word as u32;
                let is_cmp = matches!((w >> 2) & 7, 0 | 4)
                    && ((w >> 28 == 0xf && (w >> 24) & 0xf == 0b0010)
                        || (w >> 28 == 0x7 && (w >> 24) & 0xf == 0b0101));
                if is_cmp { Some((w & 3) as u8) } else { None }
            }
            _ => None,
        }
    };
    for c in &cands {
        if let Some(p) = pred_new(c)
            && !cands.iter().any(|d| pred_prod(d) == Some(p))
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
