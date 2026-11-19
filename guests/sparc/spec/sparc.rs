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
    // (名前, 形式, パターン, 構文, 分類, 機能)
    // 機能が空でなければ、その feature があるモデルでのみデコードする
    // （V8 の umul/smul/udiv/sdiv は V7 にはない）。
    // Ref: SPEC-SPARC-V8 (Version 8) §Instruction Formats, §Instruction Descriptions.
    let insns: &[(&str, &str, &str, &str, &str, &str)] = &[
        ("call", "F1CALL", "01 ..............................", "call {disp30}", "call", ""),
        ("sethi", "F1SETHI", "00 ..... 100 ......................", "sethi {imm22}, {rd}", "alu", ""),
        ("unimp", "F1UNIMP", "00 00000 000 ......................", "unimp {imm22}", "misc", ""),
        ("bicc", "F2B", "00 . .... 010 ......................", "b{cond} {disp22}", "branch", ""),
        // 整数演算（op=10）。op3 の配置は V8 の命令表どおり。
        ("add", "F3R", "10 ..... 000000 ..... 0 00000000 .....", "add {rs1}, {rs2}, {rd}", "alu", ""),
        ("add_i", "F3I", "10 ..... 000000 ..... 1 .............", "add {rs1}, {simm13}, {rd}", "alu", ""),
        ("addcc", "F3R", "10 ..... 010000 ..... 0 00000000 .....", "addcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("addcc_i", "F3I", "10 ..... 010000 ..... 1 .............", "addcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("addx", "F3R", "10 ..... 001000 ..... 0 00000000 .....", "addx {rs1}, {rs2}, {rd}", "alu", ""),
        ("addx_i", "F3I", "10 ..... 001000 ..... 1 .............", "addx {rs1}, {simm13}, {rd}", "alu", ""),
        ("addxcc", "F3R", "10 ..... 011000 ..... 0 00000000 .....", "addxcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("addxcc_i", "F3I", "10 ..... 011000 ..... 1 .............", "addxcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("and", "F3R", "10 ..... 000001 ..... 0 00000000 .....", "and {rs1}, {rs2}, {rd}", "alu", ""),
        ("and_i", "F3I", "10 ..... 000001 ..... 1 .............", "and {rs1}, {simm13}, {rd}", "alu", ""),
        ("andcc", "F3R", "10 ..... 010001 ..... 0 00000000 .....", "andcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("andcc_i", "F3I", "10 ..... 010001 ..... 1 .............", "andcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("or", "F3R", "10 ..... 000010 ..... 0 00000000 .....", "or {rs1}, {rs2}, {rd}", "alu", ""),
        ("or_i", "F3I", "10 ..... 000010 ..... 1 .............", "or {rs1}, {simm13}, {rd}", "alu", ""),
        ("orcc", "F3R", "10 ..... 010010 ..... 0 00000000 .....", "orcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("orcc_i", "F3I", "10 ..... 010010 ..... 1 .............", "orcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("xor", "F3R", "10 ..... 000011 ..... 0 00000000 .....", "xor {rs1}, {rs2}, {rd}", "alu", ""),
        ("xor_i", "F3I", "10 ..... 000011 ..... 1 .............", "xor {rs1}, {simm13}, {rd}", "alu", ""),
        ("xorcc", "F3R", "10 ..... 010011 ..... 0 00000000 .....", "xorcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("xorcc_i", "F3I", "10 ..... 010011 ..... 1 .............", "xorcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("sub", "F3R", "10 ..... 000100 ..... 0 00000000 .....", "sub {rs1}, {rs2}, {rd}", "alu", ""),
        ("sub_i", "F3I", "10 ..... 000100 ..... 1 .............", "sub {rs1}, {simm13}, {rd}", "alu", ""),
        ("subcc", "F3R", "10 ..... 010100 ..... 0 00000000 .....", "subcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("subcc_i", "F3I", "10 ..... 010100 ..... 1 .............", "subcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("andn", "F3R", "10 ..... 000101 ..... 0 00000000 .....", "andn {rs1}, {rs2}, {rd}", "alu", ""),
        ("andn_i", "F3I", "10 ..... 000101 ..... 1 .............", "andn {rs1}, {simm13}, {rd}", "alu", ""),
        ("andncc", "F3R", "10 ..... 010101 ..... 0 00000000 .....", "andncc {rs1}, {rs2}, {rd}", "alu", ""),
        ("andncc_i", "F3I", "10 ..... 010101 ..... 1 .............", "andncc {rs1}, {simm13}, {rd}", "alu", ""),
        ("orn", "F3R", "10 ..... 000110 ..... 0 00000000 .....", "orn {rs1}, {rs2}, {rd}", "alu", ""),
        ("orn_i", "F3I", "10 ..... 000110 ..... 1 .............", "orn {rs1}, {simm13}, {rd}", "alu", ""),
        ("orncc", "F3R", "10 ..... 010110 ..... 0 00000000 .....", "orncc {rs1}, {rs2}, {rd}", "alu", ""),
        ("orncc_i", "F3I", "10 ..... 010110 ..... 1 .............", "orncc {rs1}, {simm13}, {rd}", "alu", ""),
        ("xnor", "F3R", "10 ..... 000111 ..... 0 00000000 .....", "xnor {rs1}, {rs2}, {rd}", "alu", ""),
        ("xnor_i", "F3I", "10 ..... 000111 ..... 1 .............", "xnor {rs1}, {simm13}, {rd}", "alu", ""),
        ("xnorcc", "F3R", "10 ..... 010111 ..... 0 00000000 .....", "xnorcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("xnorcc_i", "F3I", "10 ..... 010111 ..... 1 .............", "xnorcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("umul", "F3R", "10 ..... 001010 ..... 0 00000000 .....", "umul {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("umul_i", "F3I", "10 ..... 001010 ..... 1 .............", "umul {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("umulcc", "F3R", "10 ..... 011010 ..... 0 00000000 .....", "umulcc {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("umulcc_i", "F3I", "10 ..... 011010 ..... 1 .............", "umulcc {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("smul", "F3R", "10 ..... 001011 ..... 0 00000000 .....", "smul {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("smul_i", "F3I", "10 ..... 001011 ..... 1 .............", "smul {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("smulcc", "F3R", "10 ..... 011011 ..... 0 00000000 .....", "smulcc {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("smulcc_i", "F3I", "10 ..... 011011 ..... 1 .............", "smulcc {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("subx", "F3R", "10 ..... 001100 ..... 0 00000000 .....", "subx {rs1}, {rs2}, {rd}", "alu", ""),
        ("subx_i", "F3I", "10 ..... 001100 ..... 1 .............", "subx {rs1}, {simm13}, {rd}", "alu", ""),
        ("subxcc", "F3R", "10 ..... 011100 ..... 0 00000000 .....", "subxcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("subxcc_i", "F3I", "10 ..... 011100 ..... 1 .............", "subxcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("udiv", "F3R", "10 ..... 001110 ..... 0 00000000 .....", "udiv {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("udiv_i", "F3I", "10 ..... 001110 ..... 1 .............", "udiv {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("udivcc", "F3R", "10 ..... 011110 ..... 0 00000000 .....", "udivcc {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("udivcc_i", "F3I", "10 ..... 011110 ..... 1 .............", "udivcc {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("sdiv", "F3R", "10 ..... 001111 ..... 0 00000000 .....", "sdiv {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("sdiv_i", "F3I", "10 ..... 001111 ..... 1 .............", "sdiv {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("sdivcc", "F3R", "10 ..... 011111 ..... 0 00000000 .....", "sdivcc {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("sdivcc_i", "F3I", "10 ..... 011111 ..... 1 .............", "sdivcc {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("mulscc", "F3R", "10 ..... 100100 ..... 0 00000000 .....", "mulscc {rs1}, {rs2}, {rd}", "alu", ""),
        ("mulscc_i", "F3I", "10 ..... 100100 ..... 1 .............", "mulscc {rs1}, {simm13}, {rd}", "alu", ""),
        ("sll", "F3R", "10 ..... 100101 ..... 0 00000000 .....", "sll {rs1}, {rs2}, {rd}", "alu", ""),
        ("sll_i", "F3I", "10 ..... 100101 ..... 1 .............", "sll {rs1}, {simm13}, {rd}", "alu", ""),
        ("srl", "F3R", "10 ..... 100110 ..... 0 00000000 .....", "srl {rs1}, {rs2}, {rd}", "alu", ""),
        ("srl_i", "F3I", "10 ..... 100110 ..... 1 .............", "srl {rs1}, {simm13}, {rd}", "alu", ""),
        ("sra", "F3R", "10 ..... 100111 ..... 0 00000000 .....", "sra {rs1}, {rs2}, {rd}", "alu", ""),
        ("sra_i", "F3I", "10 ..... 100111 ..... 1 .............", "sra {rs1}, {simm13}, {rd}", "alu", ""),
        ("ld", "F3R", "11 ..... 000000 ..... 0 00000000 .....", "ld [{rs1} + {rs2}], {rd}", "load", ""),
        ("ld_i", "F3I", "11 ..... 000000 ..... 1 .............", "ld [{rs1} + {simm13}], {rd}", "load", ""),
        ("st", "F3SR", "11 ..... 000100 ..... 0 00000000 .....", "st {rd}, [{rs1} + {rs2}]", "store", ""),
        ("st_i", "F3SI", "11 ..... 000100 ..... 1 .............", "st {rd}, [{rs1} + {simm13}]", "store", ""),
        ("jmpl", "F3R", "10 ..... 111000 ..... 0 00000000 .....", "jmpl {rs1} + {rs2}, {rd}", "jump", ""),
        ("jmpl_i", "F3I", "10 ..... 111000 ..... 1 .............", "jmpl {rs1} + {simm13}, {rd}", "jump", ""),
        ("save", "F3R", "10 ..... 111100 ..... 0 00000000 .....", "save {rs1}, {rs2}, {rd}", "alu", ""),
        ("save_i", "F3I", "10 ..... 111100 ..... 1 .............", "save {rs1}, {simm13}, {rd}", "alu", ""),
        ("restore", "F3R", "10 ..... 111101 ..... 0 00000000 .....", "restore {rs1}, {rs2}, {rd}", "alu", ""),
        ("restore_i", "F3I", "10 ..... 111101 ..... 1 .............", "restore {rs1}, {simm13}, {rd}", "alu", ""),
    ];
    for (name, format, pattern, syntax, timing, feat) in insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: if feat.is_empty() {
                Pred::True
            } else {
                Pred::Flag((*feat).to_string())
            },
            wheres: vec![],
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }
    m
}
