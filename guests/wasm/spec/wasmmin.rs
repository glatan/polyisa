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
    m.models.push(ModelDef {
        name: "generic".to_string(),
        parent: String::new(),
        add_features: vec!["mvp".to_string()],
        remove_features: vec![],
        ident: vec![],
    });

    m.regclasses.push(RegClass {
        name: "local".to_string(),
        dynamic: false,
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
