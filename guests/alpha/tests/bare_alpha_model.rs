// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Alpha の CPU モデル宣言の検査。EV 世代と拡張（BWX/FIX/CIX/MVI）
//! の対応が SPEC-ALPHA-ARM の AMASK 対応と矛盾しないことを見る。

use polyisa_guest_alpha::*;

#[test]
fn ev_generation_extension() {
    // EV56（21164A）は BWX を持ち MVI を持たない。
    assert_ne!(model_feats("21164a") & FEAT_BWX, 0);
    assert_eq!(model_feats("21164a") & FEAT_MVI, 0);
    // 21164PC（PCA56）は MVI を足す。
    assert_ne!(model_feats("21164pc") & FEAT_MVI, 0);
    // EV6（21264）は FIX を持つが CIX は EV67（21264A）から。
    assert_ne!(model_feats("21264") & FEAT_FIX, 0);
    assert_eq!(model_feats("21264") & FEAT_CIX, 0);
    assert_ne!(model_feats("21264a") & FEAT_CIX, 0);
    // EV4/EV5 は BWX を持たない。
    assert_eq!(model_feats("21064") & FEAT_BWX, 0);
    assert_eq!(model_feats("21164") & FEAT_BWX, 0);
}
