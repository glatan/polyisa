// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! riscv-tests と riscv-arch-test の適合実行（層5・conformance）。
//!
//! 手順は検証戦略の層5に従う。テストデータはリポジトリに含めず
//! `.testdata/` に取得する。データがなければスキップして通す（未実行扱い）。
//!
//! 対象データは台帳 TEST-RISCV-TESTS（commit 3df703c）と
//! TEST-RISCV-ARCH-TEST（commit 7569d06）。取得定義は tools/testdata/manifest.txt
//! の実装後にそちらへ移す。

use std::path::PathBuf;

fn testdata_root() -> PathBuf {
    // ワークスペース直下の `.testdata/` を指す。
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.join(".testdata")
}

#[test]
fn riscv_tests_presence() {
    let root = testdata_root();
    let a = root.join("riscv-tests");
    let b = root.join("riscv-arch-test");
    if !a.exists() || !b.exists() {
        // Gap: GAP-0005
        eprintln!("skip: .testdata/riscv-tests か riscv-arch-test がないため未実行");
        return;
    }
    // 取得済みの場合は最低限の配置を検査する。以降の実行は後の段階で足す。
    assert!(a.is_dir(), "{}", a.display());
    assert!(b.is_dir(), "{}", b.display());
}
