// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! TestFloat との比較（層5・conformance）。
//!
//! 手順は検証戦略の層5と浮動小数点の設計文書に従う。
//! 生成ベクタはリポジトリに含めず `.testdata/testfloat` に取得する。
//! データがなければ `devtool test:plan` がこのバイナリを実行対象から外す。
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
    assert!(
        root.exists(),
        ".testdata/testfloat がない（未実行の決定は devtool test:plan が担う）"
    );
    assert!(root.is_dir(), "{}", root.display());
}
