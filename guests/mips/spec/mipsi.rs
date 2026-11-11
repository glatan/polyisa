// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// MIPS I の整数命令と、R6 が外した符号化のゲート、R6 の BEQZALC。
//
// 遅延スロットは pc/npc で表す。R6 の BEQZALC は遅延スロットを持たない。
// ADD/SUB は符号付き溢れでトラップする。ADDU/SUBU/ADDI/ADDIU は包む。
// 0 除算は CpuState.div_zero_writes_zero に従う。0 は HI/LO を保つ。
// ロード遅延は R3000 の実行ループだけが持つ。mips32r2 と r6 は持たない。
// フェッチとデータのエンディアンは実行ループのモデルが持つ。o32 と R6 の新しい符号化は後の回で足す。
// 出典は SPEC-MIPS-IV Rev 3.2 (1995-09) と SPEC-MIPS-R6 Rev 6.06 である。
// Ref: SPEC-MIPS-IV (Rev 3.2).
// Ref: SPEC-MIPS-R6 (Rev 6.06).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// MIPS I 試作の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "load", "store", "branch", "jump", "mult", "div", "system"] {
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
    // Release 2 は MIPS I の符号化を残し、ロード遅延は持たない。遅延の有無は実行ループが持つ。
    m.models.push(ModelDef {
        name: "mips32r2".to_string(),
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
        ("srl", "FR", "000000 00000 ..... ..... ..... 000010", "srl {rd}, {rt}, {shamt}", "alu"),
        ("sra", "FR", "000000 00000 ..... ..... ..... 000011", "sra {rd}, {rt}, {shamt}", "alu"),
        ("sllv", "FR", "000000 ..... ..... ..... 00000 000100", "sllv {rd}, {rt}, {rs}", "alu"),
        ("srlv", "FR", "000000 ..... ..... ..... 00000 000110", "srlv {rd}, {rt}, {rs}", "alu"),
        ("srav", "FR", "000000 ..... ..... ..... 00000 000111", "srav {rd}, {rt}, {rs}", "alu"),
        ("add", "FR", "000000 ..... ..... ..... ..... 100000", "add {rd}, {rs}, {rt}", "alu"),
        ("sub", "FR", "000000 ..... ..... ..... ..... 100010", "sub {rd}, {rs}, {rt}", "alu"),
        ("xor", "FR", "000000 ..... ..... ..... ..... 100110", "xor {rd}, {rs}, {rt}", "alu"),
        ("nor", "FR", "000000 ..... ..... ..... ..... 100111", "nor {rd}, {rs}, {rt}", "alu"),
        ("slt", "FR", "000000 ..... ..... ..... ..... 101010", "slt {rd}, {rs}, {rt}", "alu"),
        ("sltu", "FR", "000000 ..... ..... ..... ..... 101011", "sltu {rd}, {rs}, {rt}", "alu"),
        ("jr", "FR", "000000 ..... 00000 00000 00000 001000", "jr {rs}", "jump"),
        ("jalr", "FR", "000000 ..... 00000 ..... 00000 001001", "jalr {rd}, {rs}", "jump"),
        ("syscall", "FR", "000000 ..... ..... ..... ..... 001100", "syscall", "system"),
        ("break", "FR", "000000 ..... ..... ..... ..... 001101", "break", "system"),
        ("jal", "FJ", "000011 ..........................", "jal {imm}", "jump"),
        ("bne", "FI", "000101 ..... ..... ................", "bne {rs}, {rt}, {imm}", "branch"),
        ("blez", "FI", "000110 ..... 00000 ................", "blez {rs}, {imm}", "branch"),
        ("bgtz", "FI", "000111 ..... 00000 ................", "bgtz {rs}, {imm}", "branch"),
        ("bltz", "FI", "000001 ..... 00000 ................", "bltz {rs}, {imm}", "branch"),
        ("bgez", "FI", "000001 ..... 00001 ................", "bgez {rs}, {imm}", "branch"),
        ("bltzal", "FI", "000001 ..... 10000 ................", "bltzal {rs}, {imm}", "branch"),
        ("bgezal", "FI", "000001 ..... 10001 ................", "bgezal {rs}, {imm}", "branch"),
        ("slti", "FI", "001010 ..... ..... ................", "slti {rt}, {rs}, {imm}", "alu"),
        ("sltiu", "FI", "001011 ..... ..... ................", "sltiu {rt}, {rs}, {imm}", "alu"),
        ("andi", "FI", "001100 ..... ..... ................", "andi {rt}, {rs}, {imm}", "alu"),
        ("ori", "FI", "001101 ..... ..... ................", "ori {rt}, {rs}, {imm}", "alu"),
        ("xori", "FI", "001110 ..... ..... ................", "xori {rt}, {rs}, {imm}", "alu"),
        ("lui", "FI", "001111 ..... ..... ................", "lui {rt}, {imm}", "alu"),
        ("lb", "FI", "100000 ..... ..... ................", "lb {rt}, {imm}({rs})", "load"),
        ("lh", "FI", "100001 ..... ..... ................", "lh {rt}, {imm}({rs})", "load"),
        ("lwl", "FI", "100010 ..... ..... ................", "lwl {rt}, {imm}({rs})", "load"),
        ("lbu", "FI", "100100 ..... ..... ................", "lbu {rt}, {imm}({rs})", "load"),
        ("lhu", "FI", "100101 ..... ..... ................", "lhu {rt}, {imm}({rs})", "load"),
        ("lwr", "FI", "100110 ..... ..... ................", "lwr {rt}, {imm}({rs})", "load"),
        ("sb", "FI", "101000 ..... ..... ................", "sb {rt}, {imm}({rs})", "store"),
        ("sh", "FI", "101001 ..... ..... ................", "sh {rt}, {imm}({rs})", "store"),
        ("swl", "FI", "101010 ..... ..... ................", "swl {rt}, {imm}({rs})", "store"),
        ("swr", "FI", "101110 ..... ..... ................", "swr {rt}, {imm}({rs})", "store"),
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
    // R6 は整数の HI/LO 乗除算を廃止した（MUL/MUH/MOD 系に置換）。
    // 該当 8 件は pre-R6 のモデルのみで有効にする。
    // Ref: SPEC-MIPS-R6 (Rev 6.06).
    for insn in m.insns.iter_mut() {
        if matches!(
            insn.name.as_str(),
            "mult" | "multu" | "div" | "divu" | "mfhi" | "mflo" | "mthi" | "mtlo"
        ) {
            insn.when = Pred::Not(Box::new(Pred::Flag("mips_r6".to_string())));
        }
        // Release 6 が遅延スロット付きの分岐・ジャンプと非整列ロードを外した符号化。
        // 割り当て先の命令は、コンパイラ出力を見てから足す。
        // Ref: SPEC-MIPS-R6 (Rev 6.06).
        if matches!(
            insn.name.as_str(),
            "beq"
                | "bne"
                | "blez"
                | "bgtz"
                | "bltz"
                | "bgez"
                | "bltzal"
                | "bgezal"
                | "j"
                | "jal"
                | "jr"
                | "lwl"
                | "lwr"
                | "swl"
                | "swr"
        ) {
            insn.when = Pred::Not(Box::new(Pred::Flag("mips_r6".to_string())));
        }
    }
    // ADDIU は R6 にも残る（trap なし）。ADDI と同じく WRAP で代用する。
    // Ref: SPEC-MIPS-IV (Rev 3.2).
    m.insns.push(Insn {
        name: "addiu".to_string(),
        format: "FI".to_string(),
        pattern: Pattern::parse("001001 ..... ..... ................").expect("valid pattern"),
        when: Pred::True,
        wheres: vec![],
        syntax: "addiu {rt}, {rs}, {imm}".to_string(),
        timing: "alu".to_string(),
    });
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
