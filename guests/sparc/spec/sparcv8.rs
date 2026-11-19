// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// SPARC V8 試作の ISADL モデル（段階2）。
//
// 段階2の試作は裸実行で遅延スロットのステップを確かめることが目的であり、
// レジスタウィンドウの切り替えは sem の SAVE/RESTORE で行う。命令パターンは整数 10 件のまま。
// パターンは rd/rs1/rs2 を可変とし、op/op3/op2/i/予約域を固定する。
// imm22/disp22 の切り出しと逆アセンブラの即値表示は本格実装で足す。
// 出典の版は SPEC-SPARC-V8 (Version 8, 1992) である。
// Ref: SPEC-SPARC-V8 (Version 8).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// SPARC V8 試作の検査済みモデルを作る。整数の10件に絞る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "load", "store", "branch", "jump"] {
        m.timing_classes.push(class.to_string());
    }

    // 機能と汎用CPUモデル。試作では V8 の整数基本だけを持つ。
    // Ref: SPEC-SPARC-V8 (Version 8).
    m.features.push(Feature {
        name: "v8".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    m.models.push(ModelDef {
            params: vec![],
        name: "generic".to_string(),
        parent: String::new(),
        add_features: vec!["v8".to_string()],
        remove_features: vec![],
        ident: vec![],
    });

    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: false,
    });

    for (name, hi, lo) in [
        ("rd", 29, 25),
        ("op3", 24, 19),
        ("rs1", 18, 14),
        ("rs2", 4, 0),
    ] {
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
    // F3: 3オペランド形式（rd 書き込み。整数演算・ロード・jmpl）。
    m.formats.push(Format {
        name: "F3".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "rs2".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
        ],
    });
    // F3S: ストア形式（rd も読み出し。格納元）。
    m.formats.push(Format {
        name: "F3S".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "rs2".to_string()],
        operands: vec![
            gpr("rd", Access::Read),
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
        ],
    });
    // F1: sethi 形式（試作では rd のみ取り出す。imm22 は本格実装で足す）。
    m.formats.push(Format {
        name: "F1".to_string(),
        fields: vec!["rd".to_string()],
        operands: vec![gpr("rd", Access::Write)],
    });
    // F2B: 分岐形式（試作ではオペランドを取り出さない。disp22 は本格実装で足す）。
    m.formats.push(Format {
        name: "F2B".to_string(),
        fields: vec![],
        operands: vec![],
    });

    // (名前, 形式, パターン, 構文, 分類)
    // F3 は op[31:30] + rd[29:25] + op3[24:19] + rs1[18:14] + i=0[13] + 予約0[12:5] + rs2[4:0]。
    // F1 は op=00 + rd + op2=100 + imm22。F2B は op=00 + a=0 + cond=1000 + op2=010 + disp22。
    // Ref: SPEC-SPARC-V8 (Version 8).
    let insns: &[(&str, &str, &str, &str, &str)] = &[
        ("add", "F3", "10 ..... 000000 ..... 0 00000000 .....", "add {rd}, {rs1}, {rs2}", "alu"),
        ("sub", "F3", "10 ..... 000100 ..... 0 00000000 .....", "sub {rd}, {rs1}, {rs2}", "alu"),
        ("and", "F3", "10 ..... 000001 ..... 0 00000000 .....", "and {rd}, {rs1}, {rs2}", "alu"),
        ("or", "F3", "10 ..... 000010 ..... 0 00000000 .....", "or {rd}, {rs1}, {rs2}", "alu"),
        ("sll", "F3", "10 ..... 100101 ..... 0 00000000 .....", "sll {rd}, {rs1}, {rs2}", "alu"),
        ("jmpl", "F3", "10 ..... 111000 ..... 0 00000000 .....", "jmpl {rd}, {rs1}, {rs2}", "jump"),
        ("ld", "F3", "11 ..... 000000 ..... 0 00000000 .....", "ld {rd}, [{rs1} + {rs2}]", "load"),
        ("st", "F3S", "11 ..... 000100 ..... 0 00000000 .....", "st {rd}, [{rs1} + {rs2}]", "store"),
        ("sethi", "F1", "00 ..... 100 ......................", "sethi {rd}, {imm}", "alu"),
        ("ba", "F2B", "00 0 1000 010 ......................", "ba {imm}", "branch"),
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
