// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// WebAssembly 最小の ISADL モデル（段階2の試作）。
//
// 整数スタックマシンの8件に絞る。関数本体の検証は validate が行う。
// メモリ・テーブル・グローバル・関数呼び出し・GC は試作に含まない。
// imm（LEB128）/labelidx の切り出しは本格実装で足す。
// 出典は SPEC-WASM-CORE 3.0 (Release 3.0) である。
// Ref: SPEC-WASM-CORE (3.0).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// WebAssembly 最小の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "trap", "branch"] {
        m.timing_classes.push(class.to_string());
    }

    // Ref: SPEC-WASM-CORE (3.0).
    m.features.push(Feature {
        name: "mvp".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    // Core 2.0 で入った提案機能。実装・when 接続はこれからで、
    // カバレッジ表ではゼロ件として見える。
    for name in [
        "sign_ext",
        "bulk_memory",
        "simd128",
        "threads",
        "reference_types",
        "multi_value",
        "tail_call",
        "nontrapping_fptoint",
    ] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: vec![],
            conflicts: vec![],
        });
    }
    // wasm1 は Core 1.0（MVP のみ）、wasm2 は Core 2.0 の機能を足す。
    // generic は実装の和集合として残す。
    for (name, parent, add) in [
        ("generic", "", &["mvp"][..]),
        ("wasm1", "", &["mvp"][..]),
        (
            "wasm2",
            "wasm1",
            &[
                "sign_ext",
                "bulk_memory",
                "simd128",
                "threads",
                "reference_types",
                "multi_value",
                "tail_call",
                "nontrapping_fptoint",
            ][..],
        ),
    ] {
        m.models.push(ModelDef {
        timing: None,
        params: vec![],
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: vec![],
            ident: vec![],
        });
    }

    m.regclasses.push(RegClass {
        name: "local".to_string(),
        dynamic: false,
        prefix: None,
    });

    // F1: オペランドを取り出さない形式（imm/labelidx は本格実装で足す）。
    m.formats.push(Format {
        name: "F1".to_string(),
        fields: vec![],
        operands: vec![],
    });

    // (名前, 形式, パターン, 構文, 分類)
    // 8ビットのオペコードで区別する。
    // Ref: SPEC-WASM-CORE (3.0).
    let insns: &[(&str, &str, &str, &str, &str)] = &[
        ("unreachable", "F1", "00000000", "unreachable", "trap"),
        ("nop", "F1", "00000001", "nop", "alu"),
        ("br", "F1", "00001100", "br {imm}", "branch"),
        ("drop", "F1", "00011010", "drop", "alu"),
        ("local_get", "F1", "00100000", "local.get {imm}", "alu"),
        ("local_set", "F1", "00100001", "local.set {imm}", "alu"),
        ("i32_const", "F1", "01000001", "i32.const {imm}", "alu"),
        ("i32_add", "F1", "01101010", "i32.add", "alu"),
    ];
    for (name, format, pattern, syntax, timing) in insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: vec![],
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }
    m
}
