// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sifive_u74` CPU モデルの解決の検査。
//!
//! 機能ビット・親モデルの命令・タイミング宣言が、モデル名から
//! 正しく解決されることを確かめる。

use polyisa_guest_riscv::{
    FEAT_BITS, FEAT_D, FEAT_RV64, FEAT_ZBA, FEAT_ZBB, FEATURE_DEFS, Insn, MODEL_DEFS, MODEL_TIMING,
    decode_model_ex,
};

fn sifive_u74() -> polyisa_isadl::select::CpuSel {
    polyisa_isadl::select::resolve(MODEL_DEFS, FEATURE_DEFS, FEAT_BITS, "sifive_u74", &[], &[])
        .expect("sifive_u74 resolves")
}

#[test]
fn sifive_u74_resolves_features() {
    let sel = sifive_u74();
    // 親 rv64gc の機能を引き、zba/zbb が足される。
    // Ref: SPEC-SIFIVE-U74 §4.4.1 Table 11 (RV64GC_Zba_Zbb).
    assert!(sel.features.contains("rv64"));
    assert!(sel.features.contains("d"));
    assert!(sel.features.contains("zba"));
    assert!(sel.features.contains("zbb"));
    assert_ne!(sel.feats & FEAT_RV64, 0);
    assert_ne!(sel.feats & FEAT_D, 0);
    assert_ne!(sel.feats & FEAT_ZBA, 0);
    assert_ne!(sel.feats & FEAT_ZBB, 0);
}

#[test]
fn sifive_u74_inherits_rv64gc_insns() {
    let feats = sifive_u74().feats;
    // 親 rv64gc の命令がそのままデコードできる。
    assert_eq!(
        decode_model_ex(0x0020_8133, 32, true, feats),
        Some(Insn::Add)
    );
    assert_eq!(
        decode_model_ex(0x0220_f1d3, 32, true, feats),
        Some(Insn::FaddD)
    );
    assert_eq!(
        decode_model_ex(0x0220_c4b3, 32, true, feats),
        Some(Insn::Div)
    );
}

#[test]
fn sifive_u74_declares_timing() {
    assert!(MODEL_TIMING.contains(&("sifive_u74", "approx_uncalibrated", "inorder", "sifive_u74")));
}
