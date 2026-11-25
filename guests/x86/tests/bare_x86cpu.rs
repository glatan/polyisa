// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 の CPU モデル宣言の検査。世代継承の機能構成が実機の世代差と
//! 矛盾しないことを見る。

use polyisa_guest_x86::*;

#[test]
fn pentium_family_mmx_split() {
    // P54C（pentium）は MMX を持たず、P55C（pentium_mmx）で入る。
    assert_eq!(model_feats("pentium") & FEAT_MMX, 0);
    assert_ne!(model_feats("pentium_mmx") & FEAT_MMX, 0);
    // Pentium Pro は MMX を実装しない。Pentium II で復帰する。
    assert_eq!(model_feats("pentium_pro") & FEAT_MMX, 0);
    assert_ne!(model_feats("pentium_ii") & FEAT_MMX, 0);
    // Pentium III は SSE を持ち、Pentium II は持たない。
    assert_eq!(model_feats("pentium_ii") & FEAT_SSE, 0);
    assert_ne!(model_feats("pentium_iii") & FEAT_SSE, 0);
}

#[test]
fn amd_generation_features() {
    // K6-2 は 3DNow! を持ち、SSE は持たない。Athlon XP で SSE が入る。
    assert_ne!(model_feats("k6_2") & FEAT_DNOW, 0);
    assert_eq!(model_feats("k6_2") & FEAT_SSE, 0);
    assert_ne!(model_feats("athlon_xp") & FEAT_SSE, 0);
    // Bulldozer は 3DNow! を廃し AVX と FMA4 を持つ。
    assert_eq!(model_feats("bulldozer") & FEAT_DNOW, 0);
    assert_ne!(model_feats("bulldozer") & FEAT_AVX, 0);
    assert_ne!(model_feats("bulldozer") & FEAT_FMA4, 0);
    // Zen は FMA4 を廃し AVX2 を持つ。
    assert_eq!(model_feats("zen") & FEAT_FMA4, 0);
    assert_ne!(model_feats("zen") & FEAT_AVX2, 0);
    // K6 はローカル APIC を持たず K6-2 で入る。
    assert_eq!(model_feats("k6") & FEAT_APIC, 0);
    assert_ne!(model_feats("k6_2") & FEAT_APIC, 0);
}

#[test]
fn intel_generation_chain() {
    // 64 ビット化は Core 2 から。Haswell で AVX2/BMI 系が入る。
    assert_eq!(model_feats("pentium4") & FEAT_LM, 0);
    assert_ne!(model_feats("core2") & FEAT_LM, 0);
    assert_eq!(model_feats("core2") & FEAT_AVX2, 0);
    assert_ne!(model_feats("haswell") & FEAT_AVX2, 0);
    assert_ne!(model_feats("haswell") & FEAT_BMI1, 0);
    // Core 2 は HT を持たない。
    assert_eq!(model_feats("core2") & FEAT_HTT, 0);
    assert_ne!(model_feats("pentium4") & FEAT_HTT, 0);
}
