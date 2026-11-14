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
    // Release 2 の追加命令（EXT/INS/SEB/SEH/WSBH/RDHWR/SYNC/LL/SC/TEQ/MOVZ/MOVN
    // および SPECIAL2 系）。R6 でも符号化が残る命令群をこの旗で有効にする。
    // 一次根拠は台帳の SPEC-MIPS32R2（未確認・所有者確認待ち）。
    m.features.push(Feature {
        name: "mips32r2".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    // 64 ビット命令群（daddu/dsll/ld/sd など）。素の MIPS64 整数命令は
    // MIPS IV ISA が定義する。
    // Ref: SPEC-MIPS-IV (Rev 3.2).
    // MIPS64r2 拡張の一次根拠は台帳の SPEC-MIPS64（未確認・所有者確認待ち）。
    m.features.push(Feature {
        name: "mips64".to_string(),
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
        add_features: vec!["mips1".to_string(), "mips32r2".to_string()],
        remove_features: vec![],
    });
    m.models.push(ModelDef {
        name: "r6".to_string(),
        parent: String::new(),
        add_features: vec![
            "mips1".to_string(),
            "mips32r2".to_string(),
            "mips_r6".to_string(),
        ],
        remove_features: vec![],
    });
    m.models.push(ModelDef {
        name: "mips64r2".to_string(),
        parent: String::new(),
        add_features: vec![
            "mips1".to_string(),
            "mips32r2".to_string(),
            "mips64".to_string(),
        ],
        remove_features: vec![],
    });
    m.models.push(ModelDef {
        name: "mips64r6".to_string(),
        parent: String::new(),
        add_features: vec![
            "mips1".to_string(),
            "mips32r2".to_string(),
            "mips64".to_string(),
            "mips_r6".to_string(),
        ],
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
            "add"
                | "sub"
                | "beq"
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
    // R6 のコンパクト分岐群（遅延スロットなし）。オペコード共用の分解は
    // フィールド間比較の where で行う。
    // 001000: bovc(rs>=rt) / beqc(0<rs<rt) / beqzalc(rs=0,rt!=0)
    // 011000: bnvc(rs>=rt) / bnec(0<rs<rt) / bnezalc(rs=0,rt!=0)
    // 000110/000111/010110/010111: *alc/*(z)c/*uc·*c を rs==0 / rs==rt /
    // その他（rs!=0 && rs!=rt）で分ける（rt==0 は R6 では予約）。
    // Ref: SPEC-MIPS-R6 (Rev 6.06).
    let lit = |field: &str, op: WhereOp, v: u128| WhereClause {
        field: field.to_string(),
        op,
        rhs: WhereRhs::Lit(v),
    };
    let fld = |field: &str, op: WhereOp, other: &str| WhereClause {
        field: field.to_string(),
        op,
        rhs: WhereRhs::Field(other.to_string()),
    };
    // (名前, オペコード, wheres)。リンク系は syntax に rt か rs を出す。
    let cbranches: &[(&str, &str, Vec<WhereClause>, &str)] = &[
        ("bovc", "001000", vec![fld("rs", WhereOp::Ge, "rt")], "bovc {rs}, {rt}, {imm}"),
        (
            "beqc",
            "001000",
            vec![lit("rs", WhereOp::Ne, 0), fld("rs", WhereOp::Lt, "rt")],
            "beqc {rs}, {rt}, {imm}",
        ),
        (
            "beqzalc",
            "001000",
            vec![
                lit("rs", WhereOp::Eq, 0),
                lit("rt", WhereOp::Ne, 0),
                fld("rs", WhereOp::Lt, "rt"),
            ],
            "beqzalc {rt}, {imm}",
        ),
        ("bnvc", "011000", vec![fld("rs", WhereOp::Ge, "rt")], "bnvc {rs}, {rt}, {imm}"),
        (
            "bnec",
            "011000",
            vec![lit("rs", WhereOp::Ne, 0), fld("rs", WhereOp::Lt, "rt")],
            "bnec {rs}, {rt}, {imm}",
        ),
        (
            "bnezalc",
            "011000",
            vec![
                lit("rs", WhereOp::Eq, 0),
                lit("rt", WhereOp::Ne, 0),
                fld("rs", WhereOp::Lt, "rt"),
            ],
            "bnezalc {rt}, {imm}",
        ),
        // BLEZ 群。2R 形式は rs!=0 && rs!=rt のすべてを受ける
        // （QEMU gen_compute_compact_branch と同じ寛さ。rs>rt は SPEC 上
        // 予約の可能性があるので保留事項とする）。
        ("blezalc", "000110", vec![lit("rs", WhereOp::Eq, 0), lit("rt", WhereOp::Ne, 0)], "blezalc {rt}, {imm}"),
        (
            "bgezalc",
            "000110",
            vec![lit("rs", WhereOp::Ne, 0), fld("rs", WhereOp::Eq, "rt")],
            "bgezalc {rt}, {imm}",
        ),
        (
            "bgeuc",
            "000110",
            vec![lit("rs", WhereOp::Ne, 0), lit("rt", WhereOp::Ne, 0), fld("rs", WhereOp::Ne, "rt")],
            "bgeuc {rs}, {rt}, {imm}",
        ),
        ("bgtzalc", "000111", vec![lit("rs", WhereOp::Eq, 0), lit("rt", WhereOp::Ne, 0)], "bgtzalc {rt}, {imm}"),
        (
            "bltzalc",
            "000111",
            vec![lit("rs", WhereOp::Ne, 0), fld("rs", WhereOp::Eq, "rt")],
            "bltzalc {rt}, {imm}",
        ),
        (
            "bltuc",
            "000111",
            vec![lit("rs", WhereOp::Ne, 0), lit("rt", WhereOp::Ne, 0), fld("rs", WhereOp::Ne, "rt")],
            "bltuc {rs}, {rt}, {imm}",
        ),
        ("blezc", "010110", vec![lit("rs", WhereOp::Eq, 0), lit("rt", WhereOp::Ne, 0)], "blezc {rt}, {imm}"),
        (
            "bgezc",
            "010110",
            vec![lit("rs", WhereOp::Ne, 0), fld("rs", WhereOp::Eq, "rt")],
            "bgezc {rt}, {imm}",
        ),
        (
            "bgec",
            "010110",
            vec![lit("rs", WhereOp::Ne, 0), lit("rt", WhereOp::Ne, 0), fld("rs", WhereOp::Ne, "rt")],
            "bgec {rs}, {rt}, {imm}",
        ),
        ("bgtzc", "010111", vec![lit("rs", WhereOp::Eq, 0), lit("rt", WhereOp::Ne, 0)], "bgtzc {rt}, {imm}"),
        (
            "bltzc",
            "010111",
            vec![lit("rs", WhereOp::Ne, 0), fld("rs", WhereOp::Eq, "rt")],
            "bltzc {rt}, {imm}",
        ),
        (
            "bltc",
            "010111",
            vec![lit("rs", WhereOp::Ne, 0), lit("rt", WhereOp::Ne, 0), fld("rs", WhereOp::Ne, "rt")],
            "bltc {rs}, {rt}, {imm}",
        ),
    ];
    for (name, op6, wheres, syntax) in cbranches {
        m.insns.push(Insn {
            name: name.to_string(),
            format: "FI".to_string(),
            pattern: Pattern::parse(&format!("{op6} ..... ..... ................"))
                .expect("valid pattern"),
            when: Pred::Flag("mips_r6".to_string()),
            wheres: wheres.clone(),
            syntax: syntax.to_string(),
            timing: "branch".to_string(),
        });
    }

    // ---- MIPS32r2 / MIPS64 / Release 6 の命令群 ----
    // 符号化の根拠: SPEC-MIPS32R2 / SPEC-MIPS64 / SPEC-MIPS-R6。
    // 述語: "r2"=mips32r2（r2 と r6 で有効）、"r2p"=SPECIAL2（r6 で除去）、
    // "64"=mips64、"64p"=r6 で除去された 64 ビット命令、"r6"=Release 6、
    // "r64"=Release 6 の 64 ビット。
    // (名前, 形式, パターン, 述語タグ, where, 構文, 分類)
    type InsnSpec<'a> = (&'a str, &'a str, &'a str, &'a str, &'a [(&'a str, WhereOp, u64)], &'a str, &'a str);
    let ext: &[InsnSpec] = &[
        // R2 で残る SPECIAL 系。
        ("movz", "FR", "000000 ..... ..... ..... 00000 001010", "r2", &[], "movz {rd}, {rs}, {rt}", "alu"),
        ("movn", "FR", "000000 ..... ..... ..... 00000 001011", "r2", &[], "movn {rd}, {rs}, {rt}", "alu"),
        ("seleqz", "FR", "000000 ..... ..... ..... 00000 110101", "r6", &[], "seleqz {rd}, {rs}, {rt}", "alu"),
        ("selnez", "FR", "000000 ..... ..... ..... 00000 110111", "r6", &[], "selnez {rd}, {rs}, {rt}", "alu"),
        ("teq", "FR", "000000 ..... ..... ..... ..... 110100", "r2", &[], "teq {rs}, {rt}", "system"),
        ("sync", "FJ", "000000 00000 00000 00000 ..... 001111", "r2", &[], "sync", "system"),
        // ビット操作（BSHFL / EXT / INS）。bitswap は align との衝突を避けるため先に置く。
        // BSHFL/DBSHFL 群は rs=0 が必須。align/dalign は rs!=0 の where で分ける
        // （rs=0 & sa=0 は BSHFL 側が正しい復号。SPEC-MIPS-R6 参照）。
        ("bitswap", "FR", "011111 00000 ..... ..... 00000 100000", "r6", &[("rs", WhereOp::Eq, 0)], "bitswap {rd}, {rt}", "alu"),
        ("dbitswap", "FR", "011111 00000 ..... ..... 00000 100100", "r64", &[("rs", WhereOp::Eq, 0)], "dbitswap {rd}, {rt}", "alu"),
        ("align", "FR", "011111 ..... ..... ..... 000.. 100000", "r6", &[("rs", WhereOp::Ne, 0)], "align {rd}, {rs}, {rt}, {shamt}", "alu"),
        ("dalign", "FR", "011111 ..... ..... ..... 00... 100100", "r64", &[("rs", WhereOp::Ne, 0)], "dalign {rd}, {rs}, {rt}, {shamt}", "alu"),
        ("wsbh", "FR", "011111 00000 ..... ..... 00010 100000", "r2", &[("rs", WhereOp::Eq, 0)], "wsbh {rd}, {rt}", "alu"),
        ("seb", "FR", "011111 00000 ..... ..... 10000 100000", "r2", &[("rs", WhereOp::Eq, 0)], "seb {rd}, {rt}", "alu"),
        ("seh", "FR", "011111 00000 ..... ..... 11000 100000", "r2", &[("rs", WhereOp::Eq, 0)], "seh {rd}, {rt}", "alu"),
        ("dsbh", "FR", "011111 00000 ..... ..... 00010 100100", "64", &[("rs", WhereOp::Eq, 0)], "dsbh {rd}, {rt}", "alu"),
        ("dshd", "FR", "011111 00000 ..... ..... 00101 100100", "64", &[("rs", WhereOp::Eq, 0)], "dshd {rd}, {rt}", "alu"),
        ("ext", "FR", "011111 ..... ..... ..... ..... 000000", "r2", &[], "ext {rt}, {rs}, {shamt}, {rd}", "alu"),
        ("ins", "FR", "011111 ..... ..... ..... ..... 000100", "r2", &[], "ins {rt}, {rs}, {shamt}, {rd}", "alu"),
        ("dext", "FR", "011111 ..... ..... ..... ..... 000010", "64", &[], "dext {rt}, {rs}, {shamt}, {rd}", "alu"),
        ("dextm", "FR", "011111 ..... ..... ..... ..... 000001", "64", &[], "dextm {rt}, {rs}, {shamt}, {rd}", "alu"),
        ("dextu", "FR", "011111 ..... ..... ..... ..... 000011", "64", &[], "dextu {rt}, {rs}, {shamt}, {rd}", "alu"),
        ("dins", "FR", "011111 ..... ..... ..... ..... 000110", "64", &[], "dins {rt}, {rs}, {shamt}, {rd}", "alu"),
        ("dinsm", "FR", "011111 ..... ..... ..... ..... 000101", "64", &[], "dinsm {rt}, {rs}, {shamt}, {rd}", "alu"),
        ("dinsu", "FR", "011111 ..... ..... ..... ..... 000111", "64", &[], "dinsu {rt}, {rs}, {shamt}, {rd}", "alu"),
        ("daddi", "FI", "011000 ..... ..... ................", "64p", &[], "daddi {rt}, {rs}, {imm}", "alu"),
        ("rdhwr", "FI", "011111 00000 ..... ..... 00000 111011", "r2", &[], "rdhwr {rt}, {rd}", "system"),
        ("pref", "FJ", "110011 ..... ..... ................", "r2", &[], "pref", "load"),
        ("ll", "FI", "110000 ..... ..... ................", "r2", &[], "ll {rt}, {imm}({rs})", "load"),
        ("sc", "FI", "111000 ..... ..... ................", "r2", &[], "sc {rt}, {imm}({rs})", "store"),
        // SPECIAL2（R6 で除去）。
        ("mul_r2", "FR", "011100 ..... ..... ..... 00000 000010", "r2p", &[], "mul {rd}, {rs}, {rt}", "mult"),
        ("madd", "FR", "011100 ..... ..... 00000 00000 000000", "r2p", &[], "madd {rs}, {rt}", "mult"),
        ("maddu", "FR", "011100 ..... ..... 00000 00000 000001", "r2p", &[], "maddu {rs}, {rt}", "mult"),
        ("msub", "FR", "011100 ..... ..... 00000 00000 000100", "r2p", &[], "msub {rs}, {rt}", "mult"),
        ("msubu", "FR", "011100 ..... ..... 00000 00000 000101", "r2p", &[], "msubu {rs}, {rt}", "mult"),
        ("clz_r2", "FR", "011100 ..... 00000 ..... 00000 100000", "r2p", &[], "clz {rd}, {rs}", "alu"),
        ("clo_r2", "FR", "011100 ..... 00000 ..... 00000 100001", "r2p", &[], "clo {rd}, {rs}", "alu"),
        ("dclz_r2", "FR", "011100 ..... 00000 ..... 00000 100100", "64p", &[], "dclz {rd}, {rs}", "alu"),
        ("dclo_r2", "FR", "011100 ..... 00000 ..... 00000 100101", "64p", &[], "dclo {rd}, {rs}", "alu"),
        // MIPS64 の SPECIAL 系（R6 でも残る）。
        ("daddu", "FR", "000000 ..... ..... ..... ..... 101101", "64", &[], "daddu {rd}, {rs}, {rt}", "alu"),
        ("dsubu", "FR", "000000 ..... ..... ..... ..... 101111", "64", &[], "dsubu {rd}, {rs}, {rt}", "alu"),
        ("dsllv", "FR", "000000 ..... ..... ..... 00000 010100", "64", &[], "dsllv {rd}, {rt}, {rs}", "alu"),
        ("dsrlv", "FR", "000000 ..... ..... ..... 00000 010110", "64", &[], "dsrlv {rd}, {rt}, {rs}", "alu"),
        ("dsrav", "FR", "000000 ..... ..... ..... 00000 010111", "64", &[], "dsrav {rd}, {rt}, {rs}", "alu"),
        ("dsll", "FR", "000000 00000 ..... ..... ..... 111000", "64", &[], "dsll {rd}, {rt}, {shamt}", "alu"),
        ("dsrl", "FR", "000000 00000 ..... ..... ..... 111010", "64", &[], "dsrl {rd}, {rt}, {shamt}", "alu"),
        ("dsra", "FR", "000000 00000 ..... ..... ..... 111011", "64", &[], "dsra {rd}, {rt}, {shamt}", "alu"),
        ("dsll32", "FR", "000000 00000 ..... ..... ..... 111100", "64", &[], "dsll32 {rd}, {rt}, {shamt}", "alu"),
        ("dsrl32", "FR", "000000 00000 ..... ..... ..... 111110", "64", &[], "dsrl32 {rd}, {rt}, {shamt}", "alu"),
        ("dsra32", "FR", "000000 00000 ..... ..... ..... 111111", "64", &[], "dsra32 {rd}, {rt}, {shamt}", "alu"),
        ("daddiu", "FI", "011001 ..... ..... ................", "64", &[], "daddiu {rt}, {rs}, {imm}", "alu"),
        ("ld", "FI", "110111 ..... ..... ................", "64", &[], "ld {rt}, {imm}({rs})", "load"),
        ("lwu", "FI", "100111 ..... ..... ................", "64", &[], "lwu {rt}, {imm}({rs})", "load"),
        ("lld", "FI", "110100 ..... ..... ................", "64", &[], "lld {rt}, {imm}({rs})", "load"),
        ("sd", "FI", "111111 ..... ..... ................", "64", &[], "sd {rt}, {imm}({rs})", "store"),
        ("scd", "FI", "111100 ..... ..... ................", "64", &[], "scd {rt}, {imm}({rs})", "store"),
        // R6 で除去される 64 ビット命令。
        ("dadd", "FR", "000000 ..... ..... ..... ..... 101100", "64p", &[], "dadd {rd}, {rs}, {rt}", "alu"),
        ("dsub", "FR", "000000 ..... ..... ..... ..... 101110", "64p", &[], "dsub {rd}, {rs}, {rt}", "alu"),
        ("dmult", "FR", "000000 ..... ..... ..... ..... 011100", "64p", &[], "dmult {rs}, {rt}", "mult"),
        ("dmultu", "FR", "000000 ..... ..... ..... ..... 011101", "64p", &[], "dmultu {rs}, {rt}", "mult"),
        ("ddiv", "FR", "000000 ..... ..... ..... ..... 011110", "64p", &[], "ddiv {rs}, {rt}", "div"),
        ("ddivu", "FR", "000000 ..... ..... ..... ..... 011111", "64p", &[], "ddivu {rs}, {rt}", "div"),
        ("ldl", "FI", "011010 ..... ..... ................", "64p", &[], "ldl {rt}, {imm}({rs})", "load"),
        ("ldr", "FI", "011011 ..... ..... ................", "64p", &[], "ldr {rt}, {imm}({rs})", "load"),
        ("sdl", "FI", "101100 ..... ..... ................", "64p", &[], "sdl {rt}, {imm}({rs})", "store"),
        ("sdr", "FI", "101101 ..... ..... ................", "64p", &[], "sdr {rt}, {imm}({rs})", "store"),
        // R6 の乗除算（sa=00010 は下位/商、sa=00011 は上位/剰余）。
        ("mul", "FR", "000000 ..... ..... ..... 00010 011000", "r6", &[], "mul {rd}, {rs}, {rt}", "mult"),
        ("mulu", "FR", "000000 ..... ..... ..... 00010 011001", "r6", &[], "mulu {rd}, {rs}, {rt}", "mult"),
        ("div_r6", "FR", "000000 ..... ..... ..... 00010 011010", "r6", &[], "div {rd}, {rs}, {rt}", "div"),
        ("divu_r6", "FR", "000000 ..... ..... ..... 00010 011011", "r6", &[], "divu {rd}, {rs}, {rt}", "div"),
        ("muh", "FR", "000000 ..... ..... ..... 00011 011000", "r6", &[], "muh {rd}, {rs}, {rt}", "mult"),
        ("muhu", "FR", "000000 ..... ..... ..... 00011 011001", "r6", &[], "muhu {rd}, {rs}, {rt}", "mult"),
        ("mod_", "FR", "000000 ..... ..... ..... 00011 011010", "r6", &[], "mod {rd}, {rs}, {rt}", "div"),
        ("modu", "FR", "000000 ..... ..... ..... 00011 011011", "r6", &[], "modu {rd}, {rs}, {rt}", "div"),
        ("dmul", "FR", "000000 ..... ..... ..... 00010 011100", "r64", &[], "dmul {rd}, {rs}, {rt}", "mult"),
        ("dmulu", "FR", "000000 ..... ..... ..... 00010 011101", "r64", &[], "dmulu {rd}, {rs}, {rt}", "mult"),
        ("ddiv_r6", "FR", "000000 ..... ..... ..... 00010 011110", "r64", &[], "ddiv {rd}, {rs}, {rt}", "div"),
        ("ddivu_r6", "FR", "000000 ..... ..... ..... 00010 011111", "r64", &[], "ddivu {rd}, {rs}, {rt}", "div"),
        ("dmuh", "FR", "000000 ..... ..... ..... 00011 011100", "r64", &[], "dmuh {rd}, {rs}, {rt}", "mult"),
        ("dmuhu", "FR", "000000 ..... ..... ..... 00011 011101", "r64", &[], "dmuhu {rd}, {rs}, {rt}", "mult"),
        ("dmod", "FR", "000000 ..... ..... ..... 00011 011110", "r64", &[], "dmod {rd}, {rs}, {rt}", "div"),
        ("dmodu", "FR", "000000 ..... ..... ..... 00011 011111", "r64", &[], "dmodu {rd}, {rs}, {rt}", "div"),
        // R6 のシフト加算と PC 相対。
        ("lsa", "FR", "000000 ..... ..... ..... 000.. 000101", "r6", &[], "lsa {rd}, {rs}, {rt}, {shamt}", "alu"),
        ("dlsa", "FR", "000000 ..... ..... ..... 000.. 010101", "r64", &[], "dlsa {rd}, {rs}, {rt}, {shamt}", "alu"),
        ("clz", "FR", "000000 ..... 00000 ..... 00001 010000", "r6", &[], "clz {rd}, {rs}", "alu"),
        ("clo", "FR", "000000 ..... 00000 ..... 00001 010001", "r6", &[], "clo {rd}, {rs}", "alu"),
        ("dclz", "FR", "000000 ..... 00000 ..... 00001 010010", "r64", &[], "dclz {rd}, {rs}", "alu"),
        ("dclo", "FR", "000000 ..... 00000 ..... 00001 010011", "r64", &[], "dclo {rd}, {rs}", "alu"),
        ("auipc", "FI", "111011 ..... 11110 ................", "r6", &[], "auipc {rs}, {imm}", "alu"),
        ("aluipc", "FI", "111011 ..... 11111 ................", "r6", &[], "aluipc {rs}, {imm}", "alu"),
        ("addiupc", "FI", "111011 ..... 00 ...................", "r6", &[], "addiupc {rs}, {imm}", "alu"),
        // PCREL 群は [20:16] で副コードが分かれる（SPEC-MIPS-R6）。
        // auipc=11110、aluipc=11111、ldpc=[20:18]=110、lwpc/lwupc/addiupc は [20:19]=01/10/00。
        ("ldpc", "FI", "111011 ..... 110 ..................", "r64", &[], "ldpc {rs}, {imm}", "load"),
        ("lwpc", "FI", "111011 ..... 01 ...................", "r6", &[], "lwpc {rs}, {imm}", "load"),
        ("lwupc", "FI", "111011 ..... 10 ...................", "r6", &[], "lwupc {rs}, {imm}", "load"),
        // R6 の遅延スロットなし制御。JIC/JIALC とは off 上位 5 ビットで分ける
        // （[20:16]==0 が J 系、非 0 がコンパクト分岐。SPEC-MIPS-R6）。
        ("bc", "FJ", "110010 ..........................", "r6", &[], "bc {imm}", "jump"),
        ("balc", "FJ", "111010 ..........................", "r6", &[], "balc {imm}", "jump"),
        ("jic", "FI", "110110 ..... ..... ................", "r6", &[("rt", WhereOp::Eq, 0)], "jic {rs}, {imm}", "jump"),
        ("beqzc", "FI", "110110 ..... ..... ................", "r6", &[("rt", WhereOp::Ne, 0)], "beqzc {rs}, {imm}", "branch"),
        ("jialc", "FI", "111110 ..... ..... ................", "r6", &[("rt", WhereOp::Eq, 0)], "jialc {rs}, {imm}", "jump"),
        ("bnezc", "FI", "111110 ..... ..... ................", "r6", &[("rt", WhereOp::Ne, 0)], "bnezc {rs}, {imm}", "branch"),
    ];
    for (name, format, pattern, pred, wheres, syntax, timing) in ext {
        let when = match *pred {
            "r2" => Pred::Flag("mips32r2".to_string()),
            "r2p" => Pred::All(vec![
                Pred::Flag("mips32r2".to_string()),
                Pred::Not(Box::new(Pred::Flag("mips_r6".to_string()))),
            ]),
            "64" => Pred::Flag("mips64".to_string()),
            "64p" => Pred::All(vec![
                Pred::Flag("mips64".to_string()),
                Pred::Not(Box::new(Pred::Flag("mips_r6".to_string()))),
            ]),
            "r6" => Pred::Flag("mips_r6".to_string()),
            "r64" => Pred::All(vec![
                Pred::Flag("mips_r6".to_string()),
                Pred::Flag("mips64".to_string()),
            ]),
            _ => Pred::True,
        };
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when,
            wheres: wheres
                .iter()
                .map(|(field, op, value)| WhereClause {
                    field: field.to_string(),
                    op: *op,
                    rhs: WhereRhs::Lit(u128::from(*value)),
                })
                .collect(),
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }
    m
}
