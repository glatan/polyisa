// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! インポートテーブルと初期化式つき定義テーブルが同居するモジュールの
//! 回帰テスト。`m.table_inits` は定義テーブル（`m.tables`）の並びだが
//! `inst.tables` はインポートを含む指標空間なので、添字をずらさないと
//! 初期化式がインポート側のテーブルに書き込まれるバグがあった。
//! Ref: SPEC-WASM-CORE (2.0) 4.5.4（インスタンス化）.

use polyisa_guest_wasm::wast::Runner;

#[test]
fn table_init_expr_targets_defined_table_not_import() {
    // インポートテーブル（指標 0）の前に定義テーブル（指標 1）があり、
    // 後者だけが `(ref.func $f)` 初期化式を持つ形。
    let src = r#"
(module $exp
  (table (export "t") 1 funcref)
)
(register "exp" $exp)
(module
  (import "exp" "t" (table 1 funcref))
  (type $sig (func (result i32)))
  (func $f (type $sig) i32.const 42)
  (func (export "def_null") (param i32) (result i32)
    local.get 0 table.get 1 ref.is_null)
  (func (export "imp_null") (param i32) (result i32)
    local.get 0 table.get 0 ref.is_null)
  (func (export "call") (param i32) (result i32)
    local.get 0 call_indirect 1 (type $sig))
  (table 4 funcref (ref.func $f))
)
;; 定義テーブルは初期化式で全要素が $f になる。
(assert_return (invoke "def_null" (i32.const 0)) (i32.const 0))
(assert_return (invoke "def_null" (i32.const 3)) (i32.const 0))
;; インポートテーブルは初期化式の対象ではないので null のまま。
(assert_return (invoke "imp_null" (i32.const 0)) (i32.const 1))
;; 定義テーブル経由の call_indirect は $f を呼ぶ。
(assert_return (invoke "call" (i32.const 0)) (i32.const 42))
"#;
    let mut r = Runner::new();
    let st = r.run_str(src);
    assert_eq!(st.failed, 0, "failures: {:?}", st.failures);
    assert_eq!(st.skipped, 0, "failures: {:?}", st.failures);
    assert_eq!(st.passed, 7);
}
