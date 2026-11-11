// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! TestFloat との比較（層5・conformance）。
//!
//! 手順は検証戦略の層5と浮動小数点の設計文書に従う。
//! 生成ベクタはリポジトリに含めず `.testdata/testfloat` に取得する。
//! データがなければスキップして通す（未実行扱い）。
//!
//! 対象データは台帳 TEST-TESTFLOAT（Release 3e）.

use std::path::PathBuf;

fn testdata_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.join(".testdata").join("testfloat")
}

#[test]
fn testfloat_vectors_presence() {
    let root = testdata_root();
    if !root.exists() {
        // Gap: GAP-0005
        eprintln!("skip: .testdata/testfloat がないため未実行");
        return;
    }
    assert!(root.is_dir(), "{}", root.display());
}
