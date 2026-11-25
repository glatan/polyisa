// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS の CPU モデル宣言の検査。Release 1/2 の命令層分けが
//! モデル解決に表れることを見る。

use polyisa_guest_mips::*;

#[test]
fn release_layering() {
    // Release 1 は R2 追加命令を持たない。
    assert_ne!(model_feats("mips32r1") & FEAT_MIPS32R1, 0);
    assert_eq!(model_feats("mips32r1") & FEAT_MIPS32R2, 0);
    // R2・R6 は R1 の層を含意で含む。
    assert_ne!(model_feats("mips32r2") & FEAT_MIPS32R1, 0);
    assert_ne!(model_feats("r6") & FEAT_MIPS32R1, 0);
    // R3000 はどちらの層も持たない。
    assert_eq!(model_feats("r3000") & FEAT_MIPS32R1, 0);
    // mips64r1 は 64 ビットと R1 層を持つ。
    assert_ne!(model_feats("mips64r1") & FEAT_MIPS32R1, 0);
    assert_ne!(model_feats("mips64r1") & FEAT_MIPS64, 0);
}

#[test]
fn mips_historical_layering() {
    // SPEC-MIPS-IV Rev 3.2 の ISA レベル表記に基づく層。
    // R1 層は MIPS IV（mips4）を含意し、さらに MIPS II（mips2）を引く。
    assert_ne!(model_feats("mips32r1") & FEAT_MIPS4, 0);
    assert_ne!(model_feats("mips32r1") & FEAT_MIPS2, 0);
    // r4000（MIPS III）は mips2 を持つが mips4 は持たない。
    assert_ne!(model_feats("r4000") & FEAT_MIPS2, 0);
    assert_eq!(model_feats("r4000") & FEAT_MIPS4, 0);
    // r10000（MIPS IV）は mips4 まで持つ。
    assert_ne!(model_feats("r10000") & FEAT_MIPS4, 0);
    assert_ne!(model_feats("r10000") & FEAT_MIPS2, 0);
}
