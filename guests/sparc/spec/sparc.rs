// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// SPARC の ISADL モデル（段階15）。
//
// 版の範囲は V7、V8、V9 と VIS（1・2）。命令語は 32 ビット固定長。
// 遅延スロットは実行ループが pc/npc で表す。分岐の annul ビットと
// ウィンドウのあふれと不足は OS パーソナリティが担う部分もある。
// V7 は整数の乗除命令を持たず MULScc で乗算段を行う。V8 が整数の
// 乗除命令と STBAR を足す。V9 は 64 ビット化・movcc/movr・cas 系を
// 足し、VIS は V9 のマルチメディア拡張である。
// 出典は SPEC-SPARC-V7 (Solbourne 101482-00)、SPEC-SPARC-V8 (Version 8)、
// SPEC-SPARC-V9 (SAV09R1459912) である。
// Ref: SPEC-SPARC-V7.
// Ref: SPEC-SPARC-V8 (Version 8).
// Ref: SPEC-SPARC-V9.

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// SPARC の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in [
        "alu", "load", "store", "branch", "jump", "call", "misc", "trap", "float", "vis",
    ] {
        m.timing_classes.push(class.to_string());
    }

    // 版ごとの命令集合。後続の版は先行の版の追加で表す。
    // VIS 2 は VIS の追加である。
    // Ref: SPEC-SPARC-V9.
    for (name, implies) in [
        ("v7", &[][..]),
        ("v8", &["v7"][..]),
        ("v9", &["v8"][..]),
        ("vis", &["v9"][..]),
        ("vis2", &["vis"][..]),
    ] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: vec![],
        });
    }

    // 世代ごとの挙動差は挙動パラメータで表す（cpu-models.md の param）。
    m.param(
        "nwindows",
        ParamKind::Int(32),
        "8",
        "レジスタウィンドウの枚数。実装定義で 2 から 32 まで（SPEC-SPARC-V8 §Register Windows）",
    );
    m.param(
        "word64",
        ParamKind::Bool,
        "false",
        "整数レジスタと演算の幅が 64 ビット。V9 のみ true（SPEC-SPARC-V9）",
    );

    // CPU モデル。親チェーンで機能を累積し、モデル差は params で上書きする。
    // v7/v8/v9 は版の骨格モデル。ultrasparc 系と leon3 は実在の実装を表す。
    for (name, parent, add, params) in [
        ("v7", "", &["v7"][..], &[][..]),
        ("v8", "v7", &["v8"][..], &[][..]),
        (
            "v9",
            "v8",
            &["v9"][..],
            &[("word64", "true")][..],
        ),
        ("ultrasparc", "v9", &["vis"][..], &[][..]),
        ("ultrasparc3", "ultrasparc", &["vis2"][..], &[][..]),
        ("leon3", "v8", &[][..], &[][..]),
    ] {
        m.models.push(ModelDef {
            params: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: Vec::new(),
            ident: vec![],
        });
    }

    // 整数レジスタはウィンドウ付きの動的クラス。物理位置は CWP と
    // nwindows から sem が計算する（semantics.md の動的なレジスタ参照）。
    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: true,
        prefix: Some("r".to_string()),
    });
    // 浮動小数点レジスタ f0-31。V7/V8 は 32 ビットの直列、V9 は 64 ビット。
    m.regclasses.push(RegClass {
        name: "fpr".to_string(),
        dynamic: false,
        prefix: Some("f".to_string()),
    });

    for (name, hi, lo) in [
        ("a", 29, 29),
        ("cond", 28, 25),
        ("rd", 29, 25),
        ("op3", 24, 19),
        ("op2", 24, 22),
        ("rs1", 18, 14),
        ("i", 13, 13),
        ("asi", 12, 5),
        ("rs2", 4, 0),
        ("shcnt", 5, 0),
        ("simm13", 12, 0),
        ("disp22", 21, 0),
        ("imm22", 21, 0),
        ("disp30", 29, 0),
        ("p", 19, 19),
        ("cc", 21, 20),
        ("disp19", 18, 0),
        ("fs", 18, 14),
        ("fd", 29, 25),
        ("opf", 13, 5),
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
    let val = |name: &str| Operand {
        name: name.to_string(),
        field: None,
        regclass: None,
        access: Access::Read,
    };

    // CALL 形式（op=01 + disp30）。
    m.formats.push(Format {
        name: "F1CALL".to_string(),
        fields: vec!["disp30".to_string()],
        operands: vec![val("disp30")],
    });
    // SETHI/UNIMP 形式（op=00 + rd + op2 + imm22）。
    m.formats.push(Format {
        name: "F1SETHI".to_string(),
        fields: vec!["rd".to_string(), "imm22".to_string()],
        operands: vec![gpr("rd", Access::Write), val("imm22")],
    });
    // UNIMP 形式（op=00 + 予約 + op2=000 + imm22）。
    m.formats.push(Format {
        name: "F1UNIMP".to_string(),
        fields: vec!["imm22".to_string()],
        operands: vec![val("imm22")],
    });
    // Bicc 形式（op=00 + a + cond + op2=010 + disp22）。
    m.formats.push(Format {
        name: "F2B".to_string(),
        fields: vec!["a".to_string(), "cond".to_string(), "disp22".to_string()],
        operands: vec![val("a"), val("cond"), val("disp22")],
    });
    // F3 レジスタ形（rd 書き込み。整数演算・ロード・jmpl・save/restore）。
    m.formats.push(Format {
        name: "F3R".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "rs2".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
        ],
    });
    // F3 即値形（i=1、simm13）。
    m.formats.push(Format {
        name: "F3I".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "simm13".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            val("simm13"),
        ],
    });
    // F3 ストア・レジスタ形（rd も読み出し。格納元）。
    m.formats.push(Format {
        name: "F3SR".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "rs2".to_string()],
        operands: vec![
            gpr("rd", Access::Read),
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
        ],
    });
    // F3 ストア・即値形。
    m.formats.push(Format {
        name: "F3SI".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "simm13".to_string()],
        operands: vec![
            gpr("rd", Access::Read),
            gpr("rs1", Access::Read),
            val("simm13"),
        ],
    });

    // 骨格の命令集合。命令群は SP5 以降で足す。ここでは各形式を
    // 一通りデコードできる組を宣言する。
    // (名前, 形式, パターン, 構文, 分類)
    // Ref: SPEC-SPARC-V8 (Version 8) §Instruction Formats, §Instruction Descriptions.
    let insns: &[(&str, &str, &str, &str, &str)] = &[
        ("call", "F1CALL", "01 ..............................", "call {disp30}", "call"),
        ("sethi", "F1SETHI", "00 ..... 100 ......................", "sethi {imm22}, {rd}", "alu"),
        ("unimp", "F1UNIMP", "00 00000 000 ......................", "unimp {imm22}", "misc"),
        ("bicc", "F2B", "00 . .... 010 ......................", "b{cond} {disp22}", "branch"),
        ("add", "F3R", "10 ..... 000000 ..... 0 00000000 .....", "add {rs1}, {rs2}, {rd}", "alu"),
        ("add_i", "F3I", "10 ..... 000000 ..... 1 .............", "add {rs1}, {simm13}, {rd}", "alu"),
        ("sub", "F3R", "10 ..... 000100 ..... 0 00000000 .....", "sub {rs1}, {rs2}, {rd}", "alu"),
        ("sub_i", "F3I", "10 ..... 000100 ..... 1 .............", "sub {rs1}, {simm13}, {rd}", "alu"),
        ("and", "F3R", "10 ..... 000001 ..... 0 00000000 .....", "and {rs1}, {rs2}, {rd}", "alu"),
        ("and_i", "F3I", "10 ..... 000001 ..... 1 .............", "and {rs1}, {simm13}, {rd}", "alu"),
        ("or", "F3R", "10 ..... 000010 ..... 0 00000000 .....", "or {rs1}, {rs2}, {rd}", "alu"),
        ("or_i", "F3I", "10 ..... 000010 ..... 1 .............", "or {rs1}, {simm13}, {rd}", "alu"),
        ("sll", "F3R", "10 ..... 100101 ..... 0 00000000 .....", "sll {rs1}, {rs2}, {rd}", "alu"),
        ("ld", "F3R", "11 ..... 000000 ..... 0 00000000 .....", "ld [{rs1} + {rs2}], {rd}", "load"),
        ("ld_i", "F3I", "11 ..... 000000 ..... 1 .............", "ld [{rs1} + {simm13}], {rd}", "load"),
        ("st", "F3SR", "11 ..... 000100 ..... 0 00000000 .....", "st {rd}, [{rs1} + {rs2}]", "store"),
        ("st_i", "F3SI", "11 ..... 000100 ..... 1 .............", "st {rd}, [{rs1} + {simm13}]", "store"),
        ("jmpl", "F3R", "10 ..... 111000 ..... 0 00000000 .....", "jmpl {rs1} + {rs2}, {rd}", "jump"),
        ("jmpl_i", "F3I", "10 ..... 111000 ..... 1 .............", "jmpl {rs1} + {simm13}, {rd}", "jump"),
        ("save", "F3R", "10 ..... 111100 ..... 0 00000000 .....", "save {rs1}, {rs2}, {rd}", "alu"),
        ("save_i", "F3I", "10 ..... 111100 ..... 1 .............", "save {rs1}, {simm13}, {rd}", "alu"),
        ("restore", "F3R", "10 ..... 111101 ..... 0 00000000 .....", "restore {rs1}, {rs2}, {rd}", "alu"),
        ("restore_i", "F3I", "10 ..... 111101 ..... 1 .............", "restore {rs1}, {simm13}, {rd}", "alu"),
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
