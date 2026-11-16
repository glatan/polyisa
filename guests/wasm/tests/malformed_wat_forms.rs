// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WAT テキスト形式の malformed/頑健性テスト。
//! フラット `br_table` の終端、はぐれ `end`/`else`、フラット定数式、
//! パラメータ/ローカルの名前規則、`\u{..}` 桁溢れ、深い入れ子を検査する.
//! Ref: SPEC-WASM-CORE (2.0) 6.5（テキスト形式の構文）.

use polyisa_guest_wasm::wat::module_from_str;

#[test]
fn malformed_and_edge_forms() {
    // flat br_table は `end`/次の命令キーワードでラベル列が終わる。
    assert!(
        module_from_str("(module (func block i32.const 0 br_table 0 0 end))").is_ok(),
        "flat br_table"
    );
    assert!(
        module_from_str("(module (func block i32.const 0 br_table 0 0 else end))").is_err(),
        "br_table at else without matching if"
    );
    // 関数本体末尾の裸の end/else は文法エラー（残りを捨てない）。
    assert!(
        module_from_str("(module (func nop end nop))").is_err(),
        "stray end"
    );
    assert!(
        module_from_str("(module (func nop else nop))").is_err(),
        "stray else"
    );
    // 畳み if: (then) の後は (else) 1 つだけ。重複・順序違反はエラー。
    assert!(
        module_from_str("(module (func i32.const 0 (if (then nop) (then nop))))").is_err(),
        "dup then"
    );
    assert!(
        module_from_str("(module (func i32.const 0 (if (else nop) (then nop))))").is_err(),
        "else before then"
    );
    assert!(
        module_from_str("(module (func i32.const 0 (if (then nop) (else nop) (then nop))))")
            .is_err(),
        "dup then after else"
    );
    // 定数式は expr = instr* なのでフラット形も受理する。
    assert!(
        module_from_str("(module (memory 1) (data (offset i32.const 0) \"x\"))").is_ok(),
        "flat offset"
    );
    assert!(
        module_from_str("(module (global i32 i32.const 0))").is_ok(),
        "flat global init"
    );
    // 型指標の参照は範囲チェックつき（パニックではなく unknown type）。
    let e = module_from_str(
        "(module (table 1 funcref) (func i32.const 0 call_indirect (type 999) (param i32)))",
    );
    assert!(
        matches!(e, Err(ref m) if m.0 == "unknown type"),
        "call_indirect type 999 should give 'unknown type', got {e:?}"
    );
    // param/local の $名 はグループ先頭の1個だけ。
    assert!(
        module_from_str("(module (func (param $x $y i32)))").is_err(),
        "two names one type"
    );
    assert!(
        module_from_str("(module (func (param $x)))").is_err(),
        "name no type"
    );
    assert!(
        module_from_str("(module (func (local i32 $l i64)))").is_err(),
        "misplaced local name"
    );
    assert!(
        module_from_str("(module (func (param $x i32)))").is_ok(),
        "valid named param"
    );
    assert!(
        module_from_str("(module (func (local $l i32)))").is_ok(),
        "valid named local"
    );
    // インポート記述子の後の余分な項は文法エラー。
    assert!(
        module_from_str("(module (import \"a\" \"b\" (func) junk))").is_err(),
        "import trailing"
    );
    // \u{...} の桁溢れは panic/巻き戻りではなくエラー。
    assert!(
        module_from_str("(module (func (export \"\\u{ffffffffffff}\")))").is_err(),
        "unicode overflow"
    );
    // 異常に深い入れ子はスタック溢れではなくパースエラー。
    let deep = format!("(module {})", "(".repeat(2000));
    assert!(module_from_str(&deep).is_err(), "deep nesting");
    // 文字列中の生制御文字はエスケープなしでは書けない。
    assert!(
        module_from_str("(module (func (export \"a\x07b\")))").is_err(),
        "raw control in string"
    );
}
