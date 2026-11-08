// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Hexagon 最小の ISADL モデル（段階2の試作）。
//
// スロット整数6件に絞る。試作パターンは実符号化の簡略化であり、
// parse ビット・duplex・imm 拡張・HW ループは本格実装で足す。
// パケットのステップ構成と .new 転送の検証が目的である。
// 出典は SPEC-HEXAGON-PRM V73 (80-N2040-53) である。
// Ref: SPEC-HEXAGON-PRM (V73).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// Hexagon 最小の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "jump"] {
        m.timing_classes.push(class.to_string());
    }

    // Ref: SPEC-HEXAGON-PRM (V73).
    m.features.push(Feature {
        name: "v73".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    m.models.push(ModelDef {
        name: "generic".to_string(),
        parent: String::new(),
        add_features: vec!["v73".to_string()],
        remove_features: vec![],
    });

    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: false,
    });

    for (name, hi, lo) in [("rd", 20, 16), ("rs1", 15, 11), ("rs2", 10, 6)] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    let gpr = |name: &str, access: Access| Operand {
        name: name.to_string(),
        regclass: Some("gpr".to_string()),
        access,
    };
    // F3: スロット形式（rd 書き込み）。
    m.formats.push(Format {
        name: "F3".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "rs2".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
        ],
    });
    // F1: ジャンプ形式（試作ではオペランドを取り出さない）。
    m.formats.push(Format {
        name: "F1".to_string(),
        fields: vec![],
        operands: vec![],
    });

    // (名前, 形式, パターン, 構文, 分類)
    // 試作の簡略パターン：上位8ビットで区別する。
    // 実符号化の parse/duplex/imm 拡張は本格実装で足す。
    // Ref: SPEC-HEXAGON-PRM (V73).
    let insns: &[(&str, &str, &str, &str, &str)] = &[
        ("add", "F3", "00000001 ........................", "r{rd} = add(r{rs1}, r{rs2})", "alu"),
        ("sub", "F3", "00000010 ........................", "r{rd} = sub(r{rs1}, r{rs2})", "alu"),
        ("and", "F3", "00000011 ........................", "r{rd} = and(r{rs1}, r{rs2})", "alu"),
        ("or", "F3", "00000100 ........................", "r{rd} = or(r{rs1}, r{rs2})", "alu"),
        ("mov_imm", "F3", "00000101 ........................", "r{rd} = #{imm}", "alu"),
        ("jump", "F1", "00000110 ........................", "jump {imm}", "jump"),
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
