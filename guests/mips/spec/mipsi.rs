// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// MIPS I 試作の ISADL モデル（段階3の最小）。
//
// MIPS I の整数9件に絞る。遅延スロットは pc/npc で表す。
// ADD/SUB（trap あり）は扱わず WRAP する ADDU/SUBU のみ持つ。trap は本格実装で足す。
// R6 の割り当て直し・microMIPS・FPU・HI/LO・ロード遅延・branch likely・LE切替は本格実装で足す。
// FI は lw/sw/beq を一形式に統合する試作の簡略化。imm16/target/shamt の切り出しは本格実装で足す。
// 出典は SPEC-MIPS-IV Rev 3.2 (1995-09) である。
// Ref: SPEC-MIPS-IV (Rev 3.2).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// MIPS I 試作の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "load", "store", "branch", "jump"] {
        m.timing_classes.push(class.to_string());
    }

    // Ref: SPEC-MIPS-IV (Rev 3.2).
    m.features.push(Feature {
        name: "mips1".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    m.models.push(ModelDef {
        name: "r3000".to_string(),
        parent: String::new(),
        add_features: vec!["mips1".to_string()],
        remove_features: vec![],
    });

    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: false,
    });

    for (name, hi, lo) in [
        ("rs", 25, 21),
        ("rt", 20, 16),
        ("rd", 15, 11),
        ("shamt", 10, 6),
        ("funct", 5, 0),
    ] {
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
    // FR: R 形式（rd 書き込み）。
    m.formats.push(Format {
        name: "FR".to_string(),
        fields: vec!["rs".to_string(), "rt".to_string(), "rd".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs", Access::Read),
            gpr("rt", Access::Read),
        ],
    });
    // FI: I 形式（rt 書き込み/読み出し。imm16 は本格実装で切り出す）。
    m.formats.push(Format {
        name: "FI".to_string(),
        fields: vec!["rs".to_string(), "rt".to_string()],
        operands: vec![
            gpr("rt", Access::ReadWrite),
            gpr("rs", Access::Read),
        ],
    });
    // FJ: J 形式（試作ではオペランドを取り出さない。target は本格実装で足す）。
    m.formats.push(Format {
        name: "FJ".to_string(),
        fields: vec![],
        operands: vec![],
    });

    // (名前, 形式, パターン, 構文, 分類)
    // R 形式は op=000000 + funct で、I/J 形式は op で区別する。
    // Ref: SPEC-MIPS-IV (Rev 3.2).
    let insns: &[(&str, &str, &str, &str, &str)] = &[
        ("addu", "FR", "000000 ..... ..... ..... ..... 100001", "addu {rd}, {rs}, {rt}", "alu"),
        ("subu", "FR", "000000 ..... ..... ..... ..... 100011", "subu {rd}, {rs}, {rt}", "alu"),
        ("and", "FR", "000000 ..... ..... ..... ..... 100100", "and {rd}, {rs}, {rt}", "alu"),
        ("or", "FR", "000000 ..... ..... ..... ..... 100101", "or {rd}, {rs}, {rt}", "alu"),
        ("sll", "FR", "000000 00000 ..... ..... ..... 000000", "sll {rd}, {rt}, {shamt}", "alu"),
        ("lw", "FI", "100011 ..... ..... ................", "lw {rt}, {imm}({rs})", "load"),
        ("sw", "FI", "101011 ..... ..... ................", "sw {rt}, {imm}({rs})", "store"),
        ("beq", "FI", "000100 ..... ..... ................", "beq {rs}, {rt}, {imm}", "branch"),
        ("j", "FJ", "000010 ..........................", "j {imm}", "jump"),
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
