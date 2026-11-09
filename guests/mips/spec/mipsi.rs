// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// MIPS I 試作の ISADL モデル（段階3の最小）。
//
// MIPS I の整数17件と ADDI、R6 の BEQZALC（計19件）に絞る。遅延スロットは pc/npc で表す。
// R6 の BEQZALC は遅延スロットを持たない。
// ADD/SUB（trap あり）は扱わず WRAP する ADDU/SUBU のみ持つ。trap は本格実装で足す。
// R6 の割り当て直しの残り・microMIPS・FPU・ロード遅延・branch likely・LE切替は本格実装で足す。
// HI/LO と乗除算は本格相当の最小形を持つ（ div-by-zero は UNPREDICTABLE のため
// HI/LO 不変とし、挙動パラメータ化は本格実装で足す）。
// FI は lw/sw/beq を一形式に統合する試作の簡略化。imm16/target/shamt の切り出しは本格実装で足す。
// 出典は SPEC-MIPS-IV Rev 3.2 (1995-09) である。
// Ref: SPEC-MIPS-IV (Rev 3.2).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// MIPS I 試作の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "load", "store", "branch", "jump", "mult", "div"] {
        m.timing_classes.push(class.to_string());
    }

    // Ref: SPEC-MIPS-IV (Rev 3.2).
    m.features.push(Feature {
        name: "mips1".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    // R6 の割り当て直しを受ける旗。branch_likely/lwl_lwr との conflicts は、
    // それらの機能を宣言する本格実装で足す。
    // Ref: SPEC-MIPS-R6 (Rev 6.06).
    m.features.push(Feature {
        name: "mips_r6".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    m.models.push(ModelDef {
        name: "r3000".to_string(),
        parent: String::new(),
        add_features: vec!["mips1".to_string()],
        remove_features: vec![],
    });
    m.models.push(ModelDef {
        name: "r6".to_string(),
        parent: String::new(),
        add_features: vec!["mips1".to_string(), "mips_r6".to_string()],
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
        ("mult", "FR", "000000 ..... ..... ..... ..... 011000", "mult {rs}, {rt}", "mult"),
        ("multu", "FR", "000000 ..... ..... ..... ..... 011001", "multu {rs}, {rt}", "mult"),
        ("div", "FR", "000000 ..... ..... ..... ..... 011010", "div {rs}, {rt}", "div"),
        ("divu", "FR", "000000 ..... ..... ..... ..... 011011", "divu {rs}, {rt}", "div"),
        ("mfhi", "FR", "000000 00000 00000 ..... 00000 010000", "mfhi {rd}", "alu"),
        ("mflo", "FR", "000000 00000 00000 ..... 00000 010010", "mflo {rd}", "alu"),
        ("mthi", "FR", "000000 ..... 00000 00000 00000 010001", "mthi {rs}", "alu"),
        ("mtlo", "FR", "000000 ..... 00000 00000 00000 010011", "mtlo {rs}", "alu"),
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
    // MIPS I の ADDI。R6 では op=001000 が割り当て直されるため、
    // pre-R6 のモデルでのみ有効にする。trap は WRAP で代用し本格実装で足す。
    // Ref: SPEC-MIPS-R6 (Rev 6.06).
    m.insns.push(Insn {
        name: "addi".to_string(),
        format: "FI".to_string(),
        pattern: Pattern::parse("001000 ..... ..... ................")
            .expect("valid pattern"),
        when: Pred::Not(Box::new(Pred::Flag("mips_r6".to_string()))),
        wheres: vec![],
        syntax: "addi {rt}, {rs}, {imm}".to_string(),
        timing: "alu".to_string(),
    });
    // R6 の BEQZALC（遅延スロットなしの分岐・リンク）。
    // BOVC/BEQC（rs と rt の大小比較）は field 間比較の where が要るため先送り。
    // Ref: SPEC-MIPS-R6 (Rev 6.06).
    m.insns.push(Insn {
        name: "beqzalc".to_string(),
        format: "FI".to_string(),
        pattern: Pattern::parse("001000 ..... ..... ................")
            .expect("valid pattern"),
        when: Pred::Flag("mips_r6".to_string()),
        wheres: vec![
            WhereClause {
                field: "rs".to_string(),
                op: WhereOp::Eq,
                value: 0,
            },
            WhereClause {
                field: "rt".to_string(),
                op: WhereOp::Ne,
                value: 0,
            },
        ],
        syntax: "beqzalc {rt}, {imm}".to_string(),
        timing: "branch".to_string(),
    });
    m
}
