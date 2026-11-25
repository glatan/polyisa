// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 の CPU モデル宣言の検査。Poulson 追加命令が itanium2 から
//! 分離されていることを見る。

use polyisa_guest_ia64::*;

#[test]
fn poulson_split() {
    assert_eq!(model_feats("itanium2") & FEAT_POULSON, 0);
    assert_ne!(model_feats("poulson") & FEAT_POULSON, 0);
    assert_ne!(model_feats("itanium2") & FEAT_ITANIUM2, 0);
    assert_eq!(model_feats("generic") & FEAT_ITANIUM2, 0);
}
