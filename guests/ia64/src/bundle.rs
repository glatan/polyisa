// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 のバンドル・テンプレート・スロット語の取り扱い。
//!
//! IA-64 は 128 ビットバンドルをフェッチ単位とし、バンドル語の
//! bits[4:0] がテンプレート値（bits[4:1]）とストップビット（bit 0）
//! になる。残り 123 ビットを 41 ビットスロット 3 個に割る。
//! テンプレートは各スロットに要求する実行ユニットを決め、MLX では
//! slot1=L・slot2=X が 82 ビット長の L+X 命令語を構成する。
//! Ref: SPEC-IA64-SDM (Rev 2.3).

use crate::{
    FEAT_UNIT_A, FEAT_UNIT_B, FEAT_UNIT_F, FEAT_UNIT_I, FEAT_UNIT_M, FEAT_UNIT_X, Insn,
    decode_model_ex, disasm_word_ex,
};

/// 実行ユニット種別。テンプレートのスロット要求と命令型の
/// 両方を表す。`A` は命令型のみ（A 型は I/M スロット共用）、
/// `L` はスロット側のみ（MLX の即値拡張半分）。
/// Ref: SPEC-IA64-SDM (Rev 2.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Unit {
    /// A 型（整数 ALU 型。I/M スロットのどちらにも置ける）。
    A,
    /// I ユニット。
    I,
    /// M ユニット。
    M,
    /// F ユニット。
    F,
    /// B ユニット。
    B,
    /// X スロット（MLX の 82 ビット語で major 番号を持つ側）。
    X,
    /// L スロット（MLX の即値拡張半分。命令としては解釈しない）。
    L,
}

/// Insn（ISADL の命令型）がどのユニット型か。A 型は `Unit::A` を
/// 返し、テンプレート検証では `fits_slot` で I/M 両方に収まる
/// 判定にする。生成コード側から属性を吐く拡張は GAP-0023 に
/// 記した通り後回しで、現段階は手書き表とする。
pub fn insn_unit(insn: Insn) -> Unit {
    match insn {
        // A 型（整数 ALU・比較・multimedia。I/M スロット共用）。
        Insn::Shladd
        | Insn::Shladdp4
        | Insn::Adds
        | Insn::Addp4I
        | Insn::Addl
        | Insn::Add
        | Insn::Add1
        | Insn::Sub
        | Insn::Sub1
        | Insn::And
        | Insn::Andcm
        | Insn::Or
        | Insn::Xor
        | Insn::Addp4
        | Insn::SubImm8
        | Insn::AndImm8
        | Insn::AndcmImm8
        | Insn::OrImm8
        | Insn::XorImm8
        | Insn::CmpLt
        | Insn::CmpLtUnc
        | Insn::CmpEqAnd
        | Insn::CmpNeAnd
        | Insn::CmpLtAnd
        | Insn::CmpGeAnd
        | Insn::CmpLeAnd
        | Insn::CmpGtAnd
        | Insn::Cmp4Lt
        | Insn::Cmp4LtUnc
        | Insn::Cmp4EqAnd
        | Insn::Cmp4NeAnd
        | Insn::Cmp4LtAnd
        | Insn::Cmp4GeAnd
        | Insn::Cmp4LeAnd
        | Insn::Cmp4GtAnd
        | Insn::CmpLtI
        | Insn::CmpLtUncI
        | Insn::CmpEqAndI
        | Insn::CmpNeAndI
        | Insn::Cmp4LtI
        | Insn::Cmp4LtUncI
        | Insn::Cmp4EqAndI
        | Insn::Cmp4NeAndI
        | Insn::CmpLtu
        | Insn::CmpLtuUnc
        | Insn::CmpEqOr
        | Insn::CmpNeOr
        | Insn::CmpLtOr
        | Insn::CmpGeOr
        | Insn::CmpLeOr
        | Insn::CmpGtOr
        | Insn::Cmp4Ltu
        | Insn::Cmp4LtuUnc
        | Insn::Cmp4EqOr
        | Insn::Cmp4NeOr
        | Insn::Cmp4LtOr
        | Insn::Cmp4GeOr
        | Insn::Cmp4LeOr
        | Insn::Cmp4GtOr
        | Insn::CmpLtuI
        | Insn::CmpLtuUncI
        | Insn::CmpEqOrI
        | Insn::CmpNeOrI
        | Insn::Cmp4LtuI
        | Insn::Cmp4LtuUncI
        | Insn::Cmp4EqOrI
        | Insn::Cmp4NeOrI
        | Insn::CmpEq
        | Insn::CmpEqUnc
        | Insn::CmpEqOrAndcm
        | Insn::CmpNeOrAndcm
        | Insn::CmpLtOrAndcm
        | Insn::CmpGeOrAndcm
        | Insn::CmpLeOrAndcm
        | Insn::CmpGtOrAndcm
        | Insn::Cmp4Eq
        | Insn::Cmp4EqUnc
        | Insn::Cmp4EqOrAndcm
        | Insn::Cmp4NeOrAndcm
        | Insn::Cmp4LtOrAndcm
        | Insn::Cmp4GeOrAndcm
        | Insn::Cmp4LeOrAndcm
        | Insn::Cmp4GtOrAndcm
        | Insn::CmpEqI
        | Insn::CmpEqUncI
        | Insn::CmpEqOrAndcmI
        | Insn::CmpNeOrAndcmI
        | Insn::Cmp4EqI
        | Insn::Cmp4EqUncI
        | Insn::Cmp4EqOrAndcmI
        | Insn::Cmp4NeOrAndcmI
        | Insn::Padd1
        | Insn::Padd2
        | Insn::Padd4
        | Insn::Psub1
        | Insn::Psub2
        | Insn::Psub4
        | Insn::Pavg1
        | Insn::Pavg2
        | Insn::Pavg1Raz
        | Insn::Pavg2Raz
        | Insn::Pavgsub1
        | Insn::Pavgsub2
        | Insn::Pcmp1Eq
        | Insn::Pcmp2Eq
        | Insn::Pcmp4Eq
        | Insn::Pcmp1Gt
        | Insn::Pcmp2Gt
        | Insn::Pcmp4Gt
        | Insn::Pshladd2
        | Insn::Pshradd2 => Unit::A,
        // I 型（整数・制御・シフト・multimedia・テスト）。
        Insn::ChkSI
        | Insn::Mux1
        | Insn::Mux2
        | Insn::Shrp
        | Insn::Extr
        | Insn::ExtrU
        | Insn::DepZ
        | Insn::DepZImm
        | Insn::Dep
        | Insn::DepImm
        | Insn::BreakI
        | Insn::NopI
        | Insn::HintI
        | Insn::MovIp
        | Insn::MovPr
        | Insn::MovFromBr
        | Insn::MovIToAr
        | Insn::MovIArImm
        | Insn::MovIFromAr
        | Insn::MovToPr
        | Insn::MovPrRot
        | Insn::MovBr
        | Insn::MovRet
        | Insn::Zxt1
        | Insn::Zxt2
        | Insn::Zxt4
        | Insn::Sxt1
        | Insn::Sxt2
        | Insn::Sxt4
        | Insn::Czx1L
        | Insn::Czx2L
        | Insn::Czx1R
        | Insn::Czx2R
        | Insn::Clz
        | Insn::Popcnt
        | Insn::Mix1R
        | Insn::Mix1L
        | Insn::Mix2R
        | Insn::Mix2L
        | Insn::Mix4R
        | Insn::Mix4L
        | Insn::Pack2Uss
        | Insn::Pack2Sss
        | Insn::Pack4Sss
        | Insn::Unpack1H
        | Insn::Unpack1L
        | Insn::Unpack2H
        | Insn::Unpack2L
        | Insn::Unpack4H
        | Insn::Unpack4L
        | Insn::Pmin1U
        | Insn::Pmax1U
        | Insn::Pmin2
        | Insn::Pmax2
        | Insn::Psad1
        | Insn::Pmpy2R
        | Insn::Pmpy2L
        | Insn::Pmpyshr2
        | Insn::Pmpyshr2U
        | Insn::Mpy4
        | Insn::Mpyshl4
        | Insn::Pshl2
        | Insn::Pshl4
        | Insn::Shl
        | Insn::Pshr2
        | Insn::Pshr4
        | Insn::Shr
        | Insn::Pshr2U
        | Insn::Pshr4U
        | Insn::ShrU
        | Insn::Pshl2I
        | Insn::Pshl4I
        | Insn::Pshr2I
        | Insn::Pshr4I
        | Insn::Pshr2UI
        | Insn::Pshr4UI
        | Insn::TbitZ
        | Insn::TbitZUnc
        | Insn::TbitZAnd
        | Insn::TbitNzAnd
        | Insn::TbitZOr
        | Insn::TbitNzOr
        | Insn::TbitZOrAndcm
        | Insn::TbitNzOrAndcm
        | Insn::TnatZ
        | Insn::TnatZUnc
        | Insn::TnatZAnd
        | Insn::TnatNzAnd
        | Insn::TnatZOr
        | Insn::TnatNzOr
        | Insn::TnatZOrAndcm
        | Insn::TnatNzOrAndcm
        | Insn::TfZ
        | Insn::TfZUnc
        | Insn::TfZAnd
        | Insn::TfNzAnd
        | Insn::TfZOr
        | Insn::TfNzOr
        | Insn::TfZOrAndcm
        | Insn::TfNzOrAndcm => Unit::I,
        Insn::Ld8R
        | Insn::Ld8I
        | Insn::St8I
        | Insn::BreakM
        | Insn::NopM
        | Insn::HintM
        | Insn::Xchg4
        | Insn::Fetchadd4Acq
        | Insn::ProbeR
        | Insn::ProbeWFault
        | Insn::LdfsR
        | Insn::LdfsI
        | Insn::Stf8I
        | Insn::Ldfp8
        | Insn::LfetchR
        | Insn::LfetchI
        | Insn::GetfSig
        | Insn::GetfD
        | Insn::SetfSig
        | Insn::SetfD
        | Insn::SetfExp
        | Insn::Alloc
        | Insn::ChkSM
        | Insn::ChkS
        | Insn::ChkANc
        | Insn::ChkANcF
        | Insn::Fc
        | Insn::Sum
        | Insn::Rum
        | Insn::Ld1
        | Insn::Ld2
        | Insn::Ld4
        | Insn::Ld8
        | Insn::Ld8Fill
        | Insn::Ld1A
        | Insn::Ld1CNc
        | Insn::Ld16
        | Insn::Ld1S
        | Insn::Ld2S
        | Insn::Ld4S
        | Insn::Ld8S
        | Insn::Ld2A
        | Insn::Ld4A
        | Insn::Ld8A
        | Insn::Ld1Sa
        | Insn::Ld2Sa
        | Insn::Ld4Sa
        | Insn::Ld8Sa
        | Insn::Ld1Bias
        | Insn::Ld2Bias
        | Insn::Ld4Bias
        | Insn::Ld8Bias
        | Insn::Ld1Acq
        | Insn::Ld2Acq
        | Insn::Ld4Acq
        | Insn::Ld8Acq
        | Insn::Ld1CClr
        | Insn::Ld2CClr
        | Insn::Ld4CClr
        | Insn::Ld8CClr
        | Insn::Ld2CNc
        | Insn::Ld4CNc
        | Insn::Ld8CNc
        | Insn::Ld1CClrAcq
        | Insn::Ld2CClrAcq
        | Insn::Ld4CClrAcq
        | Insn::Ld8CClrAcq
        | Insn::Ld1R
        | Insn::Ld2R
        | Insn::Ld4R
        | Insn::Ld1SR
        | Insn::Ld2SR
        | Insn::Ld4SR
        | Insn::Ld8SR
        | Insn::Ld1AR
        | Insn::Ld2AR
        | Insn::Ld4AR
        | Insn::Ld8AR
        | Insn::Ld1SaR
        | Insn::Ld2SaR
        | Insn::Ld4SaR
        | Insn::Ld8SaR
        | Insn::Ld1BiasR
        | Insn::Ld2BiasR
        | Insn::Ld4BiasR
        | Insn::Ld8BiasR
        | Insn::Ld1AcqR
        | Insn::Ld2AcqR
        | Insn::Ld4AcqR
        | Insn::Ld8AcqR
        | Insn::Ld1CClrR
        | Insn::Ld2CClrR
        | Insn::Ld4CClrR
        | Insn::Ld8CClrR
        | Insn::Ld1CNcR
        | Insn::Ld2CNcR
        | Insn::Ld4CNcR
        | Insn::Ld8CNcR
        | Insn::Ld1CClrAcqR
        | Insn::Ld2CClrAcqR
        | Insn::Ld4CClrAcqR
        | Insn::Ld8CClrAcqR
        | Insn::Ld1I
        | Insn::Ld2I
        | Insn::Ld4I
        | Insn::Ld1SI
        | Insn::Ld2SI
        | Insn::Ld4SI
        | Insn::Ld8SI
        | Insn::Ld1AI
        | Insn::Ld2AI
        | Insn::Ld4AI
        | Insn::Ld8AI
        | Insn::Ld1SaI
        | Insn::Ld2SaI
        | Insn::Ld4SaI
        | Insn::Ld8SaI
        | Insn::Ld1BiasI
        | Insn::Ld2BiasI
        | Insn::Ld4BiasI
        | Insn::Ld8BiasI
        | Insn::Ld1AcqI
        | Insn::Ld2AcqI
        | Insn::Ld4AcqI
        | Insn::Ld8AcqI
        | Insn::Ld1CClrI
        | Insn::Ld2CClrI
        | Insn::Ld4CClrI
        | Insn::Ld8CClrI
        | Insn::Ld1CNcI
        | Insn::Ld2CNcI
        | Insn::Ld4CNcI
        | Insn::Ld8CNcI
        | Insn::Ld1CClrAcqI
        | Insn::Ld2CClrAcqI
        | Insn::Ld4CClrAcqI
        | Insn::Ld8CClrAcqI
        | Insn::Ld8FillR
        | Insn::Ld8FillI
        | Insn::Ld16Acq
        | Insn::St1
        | Insn::St2
        | Insn::St4
        | Insn::St8
        | Insn::St8Spill
        | Insn::St16
        | Insn::St1Rel
        | Insn::St2Rel
        | Insn::St4Rel
        | Insn::St8Rel
        | Insn::St1I
        | Insn::St2I
        | Insn::St4I
        | Insn::St1RelI
        | Insn::St2RelI
        | Insn::St4RelI
        | Insn::St8RelI
        | Insn::St8SpillI
        | Insn::St16Rel
        | Insn::Xchg1
        | Insn::Xchg2
        | Insn::Xchg8
        | Insn::Cmpxchg1Acq
        | Insn::Cmpxchg2Acq
        | Insn::Cmpxchg4Acq
        | Insn::Cmpxchg8Acq
        | Insn::Cmpxchg1Rel
        | Insn::Cmpxchg2Rel
        | Insn::Cmpxchg4Rel
        | Insn::Cmpxchg8Rel
        | Insn::Fetchadd4Rel
        | Insn::Fetchadd8Acq
        | Insn::Fetchadd8Rel
        | Insn::Cmp8xchg16Acq
        | Insn::Cmp8xchg16Rel
        | Insn::ChkAClr
        | Insn::ChkAClrF
        | Insn::FcI
        | Insn::Ldfe
        | Insn::Ldf8
        | Insn::Ldfs
        | Insn::Ldfd
        | Insn::LdfFill
        | Insn::Stfe
        | Insn::Stf8
        | Insn::Stfs
        | Insn::Stfd
        | Insn::StfSpill
        | Insn::Lfetch
        | Insn::LfetchExcl
        | Insn::LfetchFault
        | Insn::MovMToAr
        | Insn::MovMArImm
        | Insn::MovMFromAr
        | Insn::MovPsrUm
        | Insn::MovCpuid
        | Insn::Flushrs
        | Insn::Loadrs
        | Insn::Invala
        | Insn::Fwb
        | Insn::Mf
        | Insn::MfA
        | Insn::SrlzD
        | Insn::SrlzI
        | Insn::SyncI => Unit::M,
        Insn::FclassM
        | Insn::FrcpaS0
        | Insn::FrsqrtaS0
        | Insn::FsetcS0
        | Insn::FclrfS0
        | Insn::FchkfS0
        | Insn::FmaS0
        | Insn::FmaDS0
        | Insn::FmsS0
        | Insn::FnmaS0
        | Insn::Fselect
        | Insn::XmaL
        | Insn::XmaH
        | Insn::XmaHu
        | Insn::FminS0
        | Insn::FmaxS0
        | Insn::FaminS0
        | Insn::FamaxS0
        | Insn::FmergeS
        | Insn::FmergeNs
        | Insn::FmergeSe
        | Insn::Fand
        | Insn::Fandcm
        | Insn::For
        | Insn::Fxor
        | Insn::Fpack
        | Insn::Fswap
        | Insn::FswapNl
        | Insn::FmixL
        | Insn::FmixR
        | Insn::FsxtL
        | Insn::FsxtR
        | Insn::FpcmpEqS0
        | Insn::FcmpEqS0
        | Insn::FcmpLtS0
        | Insn::FcmpEqUncS0
        | Insn::FcvtFxS0
        | Insn::FcvtFxTruncS0
        | Insn::FcvtXf
        | Insn::FpcvtFxS0
        | Insn::BreakF
        | Insn::NopF
        | Insn::HintF => Unit::F,
        Insn::BrCondSptkFew
        | Insn::BrCloopSptkFew
        | Insn::BrCallSptkFew
        | Insn::BrRetSptkFew
        | Insn::BrCallIndSptkFew
        | Insn::BrpSptk
        | Insn::BreakB
        | Insn::NopB
        | Insn::HintB
        | Insn::Cover
        | Insn::Clrrb
        | Insn::ClrrbPr => Unit::B,
        Insn::Movl
        | Insn::BrlCondSptkFew
        | Insn::BrlCallSptkFew
        | Insn::BreakX
        | Insn::NopX
        | Insn::HintX => Unit::X,
    }
}

/// 命令型 `i` がスロット要求 `slot` に収まるか。A 型は I/M 両
/// スロットに置ける。
pub fn fits_slot(i: Unit, slot: Unit) -> bool {
    if i == slot {
        return true;
    }
    i == Unit::A && matches!(slot, Unit::I | Unit::M)
}

/// スロット要求に対応する ISADL 文脈フィーチャ（`decode_model_ex`
/// に渡す feat ビット）。I/M スロットでは A 型も有効にする。
/// `Unit::L` は命令を持たず 0。
pub fn slot_feats(slot: Unit) -> u128 {
    match slot {
        Unit::I => FEAT_UNIT_I | FEAT_UNIT_A,
        Unit::M => FEAT_UNIT_M | FEAT_UNIT_A,
        Unit::F => FEAT_UNIT_F,
        Unit::B => FEAT_UNIT_B,
        Unit::X => FEAT_UNIT_X,
        Unit::A | Unit::L => 0,
    }
}

/// スロット語のビット長。X スロット（L+X）のみ 82、他は 41。
pub fn slot_len(slot: Unit) -> u32 {
    match slot {
        Unit::X => 82,
        _ => 41,
    }
}

/// スロット要求 `slot` と CPU フィーチャ `cpu_feats` でスロット語を
/// デコードする。41 ビットスロットは `word` を `u64` で渡し、X は
/// `bundle_x_word` で組み立てた 82 ビット語を `word` に入れる
/// （`decode_x_slot` 参照）。
pub fn decode_slot(slot: Unit, word: u128, cpu_feats: u128) -> Option<Insn> {
    let len = slot_len(slot);
    if slot == Unit::L || slot == Unit::A {
        return None;
    }
    decode_model_ex(word, len, true, cpu_feats | slot_feats(slot))
}

/// `decode_slot` の逆アセンブル版。
pub fn disasm_slot(slot: Unit, word: u128, cpu_feats: u128) -> Option<String> {
    let len = slot_len(slot);
    if slot == Unit::L || slot == Unit::A {
        return None;
    }
    disasm_word_ex(word, len, true, cpu_feats | slot_feats(slot))
}

/// テンプレート記述子。`slots` は slot0..2 の要求ユニット、
/// `boundary` はテンプレート固有のストップ位置
/// （0=なし、n>0 は slot n-1 の直後にストップ）。
/// Ref: SPEC-IA64-SDM (Rev 2.3).
#[derive(Clone, Copy, Debug)]
pub struct TemplateDesc {
    /// 短い表示名（"MII" など）。
    pub name: &'static str,
    /// slot0..2 の要求ユニット。MLX では [M, L, X]。
    pub slots: [Unit; 3],
    /// テンプレート内ストップ。0=なし、1=slot0 後、2=slot1 後。
    pub boundary: u8,
}

use Unit::*;

/// テンプレート値（バンドル bits[4:1]）からスロット構成への表。
/// `None` は SDM で予約（illegal）の値 3/a/d/f。
/// Ref: SPEC-IA64-SDM (Rev 2.3).
pub const TEMPLATES: [Option<TemplateDesc>; 16] = [
    Some(TemplateDesc {
        name: "MII",
        slots: [M, I, I],
        boundary: 0,
    }), // 0
    Some(TemplateDesc {
        name: "MII",
        slots: [M, I, I],
        boundary: 2,
    }), // 1
    Some(TemplateDesc {
        name: "MLX",
        slots: [M, L, X],
        boundary: 0,
    }), // 2
    None, // 3
    Some(TemplateDesc {
        name: "MMI",
        slots: [M, M, I],
        boundary: 0,
    }), // 4
    Some(TemplateDesc {
        name: "MMI",
        slots: [M, M, I],
        boundary: 1,
    }), // 5
    Some(TemplateDesc {
        name: "MFI",
        slots: [M, F, I],
        boundary: 0,
    }), // 6
    Some(TemplateDesc {
        name: "MMF",
        slots: [M, M, F],
        boundary: 0,
    }), // 7
    Some(TemplateDesc {
        name: "MIB",
        slots: [M, I, B],
        boundary: 0,
    }), // 8
    Some(TemplateDesc {
        name: "MBB",
        slots: [M, B, B],
        boundary: 0,
    }), // 9
    None, // a
    Some(TemplateDesc {
        name: "BBB",
        slots: [B, B, B],
        boundary: 0,
    }), // b
    Some(TemplateDesc {
        name: "MMB",
        slots: [M, M, B],
        boundary: 0,
    }), // c
    None, // d
    Some(TemplateDesc {
        name: "MFB",
        slots: [M, F, B],
        boundary: 0,
    }), // e
    None, // f
];

/// スロット語の 41 ビットマスク。
pub const SLOT_MASK: u64 = (1u64 << 41) - 1;

/// バンドル bits[4:1] のテンプレート値。
pub fn template_index(bundle: u128) -> usize {
    ((bundle >> 1) & 0xf) as usize
}

/// バンドル bit 0 のストップビット（slot2 後のグループ境界）。
pub fn bundle_stop(bundle: u128) -> bool {
    bundle & 1 != 0
}

/// バンドルのテンプレート記述子。予約値なら `None`。
pub fn template_desc(bundle: u128) -> Option<&'static TemplateDesc> {
    TEMPLATES[template_index(bundle)].as_ref()
}

/// バンドルの `slot` 番目（0..3）の 41 ビットスロット語。
/// Ref: SPEC-IA64-SDM (Rev 2.3).
pub fn bundle_slot(bundle: u128, slot: usize) -> u64 {
    let t0 = bundle as u64;
    let t1 = (bundle >> 64) as u64;
    match slot {
        0 => (t0 >> 5) & SLOT_MASK,
        1 => ((t0 >> 46) & 0x3ffff) | ((t1 & 0x7fffff) << 18),
        _ => (t1 >> 23) & SLOT_MASK,
    }
}

/// MLX バンドルの 82 ビット X 命令語。word[40:0]=X スロット
/// （slot2）、word[81:41]=L スロット（slot1）。
/// Ref: SPEC-IA64-SDM (Rev 2.3).
pub fn bundle_x_word(bundle: u128) -> u128 {
    ((bundle_slot(bundle, 1) as u128) << 41) | bundle_slot(bundle, 2) as u128
}

/// スロットごとのストップ位置。[slot0後, slot1後, slot2後]。
/// slot2 後はバンドルのストップビット。
pub fn template_stops(bundle: u128) -> Option<[bool; 3]> {
    let d = template_desc(bundle)?;
    Some([d.boundary == 1, d.boundary == 2, bundle_stop(bundle)])
}

/// バンドル内の 1 命令。`slot` は開始スロット（X 型は常に 2 で
/// `word` は 82 ビット語）。
#[derive(Clone, Copy, Debug)]
pub struct SlotInsn {
    /// スロット番号（0-2。MLX の長命令は 2）。
    pub slot: usize,
    /// デコードした命令。
    pub insn: Insn,
    /// スロット語（41 または 82 ビット）。
    pub word: u128,
}

/// バンドルをテンプレートに従ってデコードする。戻り値はスロット
/// 順の命令列。予約テンプレート、要求ユニットと型の不一致、
/// デコード失敗のいずれでも `None`。
/// Ref: SPEC-IA64-SDM (Rev 2.3).
pub fn decode_bundle(bundle: u128, cpu_feats: u128) -> Option<Vec<SlotInsn>> {
    let d = template_desc(bundle)?;
    let mut out = Vec::with_capacity(3);
    for (slot, &unit) in d.slots.iter().enumerate() {
        if unit == L {
            continue;
        }
        let word = if unit == X {
            bundle_x_word(bundle)
        } else {
            bundle_slot(bundle, slot) as u128
        };
        let insn = decode_slot(unit, word, cpu_feats)?;
        if !fits_slot(insn_unit(insn), unit) {
            return None;
        }
        out.push(SlotInsn { slot, insn, word });
    }
    Some(out)
}
