// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Gap: GAP-0014
// IA-64 最小の ISADL モデル（段階2の試作）。
//
// バンドル6件に絞る。試作パターンは実符号化の簡略化であり、
// 41ビットスロット・テンプレート割り当て・MLX・F系・B系・回転の
// 全組み合わせは試作に含まない。述語、回転、3 スロットのバンドルを sem で確かめる。
// 出典は SPEC-IA64-SDM Rev 2.3 (2010-05) である。
// Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// IA-64 最小の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "branch"] {
        m.timing_classes.push(class.to_string());
    }

    // Ref: SPEC-IA64-SDM (Rev 2.3).
    m.features.push(Feature {
        name: "itanium".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    m.models.push(ModelDef {
            params: vec![],
        name: "generic".to_string(),
        parent: String::new(),
        add_features: vec!["itanium".to_string()],
        remove_features: vec![],
        ident: vec![],
    });

    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: false,
    });

    for (name, hi, lo) in [("qp", 127, 122), ("rd", 60, 54), ("r1", 30, 24), ("r2", 22, 16)] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    let gpr = |name: &str, access: Access| Operand {
        name: name.to_string(),
        field: None,
        regclass: Some("gpr".to_string()),
        access,
    };
    // FB: バンドル形式（試作では rd/qp/r1/r2 のみ取り出す）。
    // 書き込み先 rd を Write で宣言する（sem の write_gpr と対応）。
    m.formats.push(Format {
        name: "FB".to_string(),
        fields: vec!["qp".to_string(), "rd".to_string(), "r1".to_string(), "r2".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("r1", Access::Read),
            gpr("r2", Access::Read),
        ],
    });
    // F1: 分岐形式（試作ではオペランドを取り出さない）。
    m.formats.push(Format {
        name: "F1".to_string(),
        fields: vec![],
        operands: vec![],
    });

    // (名前, 形式, パターン, 構文, 分類)
    // 試作の簡略パターン：上位8ビットで区別する。128ビット固定。
    // 実符号化のテンプレート/スロット分割は本格実装で足す。
    // Ref: SPEC-IA64-SDM (Rev 2.3).
    let insns: &[(&str, &str, &str, &str, &str)] = &[
        ("add", "FB", "00000001 ........................................................................................................................", "(p0) add r{rd} = r{r1}, r{r2}", "alu"),
        ("sub", "FB", "00000010 ........................................................................................................................", "(p0) sub r{rd} = r{r1}, r{r2}", "alu"),
        ("add_pred", "FB", "00000011 ........................................................................................................................", "(qp) add r{rd} = r{r1}, r{r2}", "alu"),
        ("add_rot", "FB", "00000100 ........................................................................................................................", "(p0) add.rot r{rd} = r{r1}, r{r2}", "alu"),
        ("nop", "FB", "00000101 ........................................................................................................................", "nop", "alu"),
        ("br", "F1", "00000110 ........................................................................................................................", "br {imm}", "branch"),
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
