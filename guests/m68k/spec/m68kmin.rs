// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// m68k 最小の ISADL モデル（段階14）。
//
// 宣言する命令は、16ビット固定の実符号化（nop/reset/rts/rtr/rte/illegal）
// と、EA フィールドを持つ move/movea/moveq（C1 追加分）。
// EA モードの解釈と拡張語の消費は `src/ea.rs`、意味論は `src/sem.rs`。
// 出典は SPEC-M68K-PRM (M68000PM/AD Rev 1) である。
// Ref: SPEC-M68K-PRM (Rev 1).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// m68k 最小の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["misc", "ctrl"] {
        m.timing_classes.push(class.to_string());
    }

    // 世代ごとの命令集合。68010 以降は先行世代の追加で表す。
    // 68040/68060 で OS 補完へ回る命令群は、世代機能の implies からは
    // 除けない（閉包で再付与される）ので、粒状の独立機能か
    // `when` の `!m68040` 形で表す。モデル確定時に決める。
    // Ref: SPEC-M68K-PRM (Rev 1).
    for (name, implies) in [
        ("m68000", &[][..]),
        ("m68010", &["m68000"][..]),
        ("m68020", &["m68010"][..]),
        ("m68030", &["m68020"][..]),
        ("m68040", &["m68030"][..]),
        ("m68060", &["m68040"][..]),
    ] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: vec![],
        });
    }
    for (name, parent, add) in [
        ("generic", "", &["m68000"][..]),
        ("i68000", "generic", &[][..]),
    ] {
        m.models.push(ModelDef {
            params: vec![],
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: Vec::new(),
            ident: vec![],
        });
    }

    m.regclasses.push(RegClass {
        name: "dreg".to_string(),
        dynamic: false,
        prefix: Some("d".to_string()),
    });
    m.regclasses.push(RegClass {
        name: "areg".to_string(),
        dynamic: false,
        prefix: Some("a".to_string()),
    });

    // EA フィールド。source は bits[5:3]/[2:0]、destination は
    // bits[8:6]/[11:9]。値の評価と拡張語消費は ea.rs が担う。
    // Ref: SPEC-M68K-PRM (Rev 1) §Effective Addressing.
    for (name, hi, lo) in [
        ("sreg", 2u32, 0u32),
        ("smode", 5, 3),
        ("dmode", 8, 6),
        ("dreg", 11, 9),
        ("qimm", 7, 0),
        // C2: 算術・比較系のフィールド。emode/ereg は EA、qsz はサイズ。
        // bits 11-9 のクイック即値・cmpm 宛先レジスタは dreg を再利用する。
        ("emode", 5, 3),
        ("ereg", 2, 0),
        ("qsz", 7, 6),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    // F0: 16ビット固定・オペランドなし（拡張語も伴わない命令）。
    m.formats.push(Format {
        name: "F0".to_string(),
        fields: vec![],
        operands: vec![],
    });
    // E2: move/movea の2EA形式。
    m.formats.push(Format {
        name: "E2".to_string(),
        fields: vec![
            "sreg".to_string(),
            "smode".to_string(),
            "dmode".to_string(),
            "dreg".to_string(),
        ],
        operands: vec![],
    });
    // Q: moveq のクイック即値形式。
    m.formats.push(Format {
        name: "Q".to_string(),
        fields: vec!["dreg".to_string(), "qimm".to_string()],
        operands: vec![],
    });
    // AE: レジスタ・サイズ・EA（add/sub/cmp 系。方向・宛先 An は
    // パターンの bit8/opm が決める）。
    m.formats.push(Format {
        name: "AE".to_string(),
        fields: vec![
            "dreg".to_string(),
            "qsz".to_string(),
            "emode".to_string(),
            "ereg".to_string(),
        ],
        operands: vec![],
    });
    // QE: クイック即値・サイズ・EA（addq/subq 系）。
    m.formats.push(Format {
        name: "QE".to_string(),
        fields: vec![
            "dreg".to_string(),
            "qsz".to_string(),
            "emode".to_string(),
            "ereg".to_string(),
        ],
        operands: vec![],
    });
    // IE: サイズ・EA（即値系。即値は拡張語が持つ）。
    m.formats.push(Format {
        name: "IE".to_string(),
        fields: vec!["qsz".to_string(), "emode".to_string(), "ereg".to_string()],
        operands: vec![],
    });
    // CM: cmpm のレジスタ2つとサイズ。emode は固定値だが、EOR
    // 宣言時の排他検証に使うので宣言する。
    m.formats.push(Format {
        name: "CM".to_string(),
        fields: vec![
            "dreg".to_string(),
            "qsz".to_string(),
            "emode".to_string(),
            "sreg".to_string(),
        ],
        operands: vec![],
    });

    // (名前, パターン, 構文, 分類)
    // いずれも拡張語を伴わない16ビット固定の実符号化。
    // Ref: SPEC-M68K-PRM (Rev 1).
    let insns: &[(&str, &str, &str, &str)] = &[
        ("nop", "0100111001110001", "nop", "misc"),
        ("reset", "0100111001110000", "reset", "ctrl"),
        ("rte", "0100111001110011", "rte", "ctrl"),
        ("rts", "0100111001110101", "rts", "ctrl"),
        ("rtr", "0100111001110111", "rtr", "ctrl"),
    ];
    for (name, pattern, syntax, timing) in insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: "F0".to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: vec![],
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }
    // illegal の符号化は tst のパターン空間（`..` が bits[7:6]=11 を
    // 含む）に内包される。qsz（bits[7:6]）が 3 であることを where で
    // 示して tst（qsz != 3）との排他を証明する。
    m.insns.push(Insn {
        name: "illegal".to_string(),
        format: "F0".to_string(),
        pattern: Pattern::parse("0100101011111100").expect("valid pattern"),
        when: Pred::True,
        wheres: vec![WhereClause {
            field: "qsz".to_string(),
            op: WhereOp::Eq,
            rhs: WhereRhs::Lit(3),
        }],
        syntax: "illegal".to_string(),
        timing: "misc".to_string(),
    });

    // movea は move.w/move.l の宛先 An 直と同じ符号化を持つので、
    // where で dmode==1（An 直）を宣言して排他を示す。move.b は
    // byte の An 直が未割当なので source/destination 両方で An を
    // 弾く。Ref: SPEC-M68K-PRM (Rev 1) §MOVE/MOVEA.
    type Cond = (&'static str, WhereOp, u128);
    type EaDecl = (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static [Cond],
    );
    let ea_insns: &[EaDecl] = &[
        (
            "movea_l",
            "E2",
            "0010 ... 001 ......",
            "movea.l",
            &[("dmode", WhereOp::Eq, 1)],
        ),
        (
            "movea_w",
            "E2",
            "0011 ... 001 ......",
            "movea.w",
            &[("dmode", WhereOp::Eq, 1)],
        ),
        (
            "move_b",
            "E2",
            "0001 ............",
            "move.b",
            &[("dmode", WhereOp::Ne, 1), ("smode", WhereOp::Ne, 1)],
        ),
        (
            "move_w",
            "E2",
            "0011 ............",
            "move.w",
            &[("dmode", WhereOp::Ne, 1)],
        ),
        (
            "move_l",
            "E2",
            "0010 ............",
            "move.l",
            &[("dmode", WhereOp::Ne, 1)],
        ),
    ];
    for (name, format, pattern, syntax, wheres) in ea_insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: wheres
                .iter()
                .map(|(field, op, rhs)| WhereClause {
                    field: field.to_string(),
                    op: *op,
                    rhs: WhereRhs::Lit(*rhs),
                })
                .collect(),
            syntax: syntax.to_string(),
            timing: "misc".to_string(),
        });
    }
    // C2: 算術・比較系。opm（bits[8:6]、bit8+qsz）が方向・サイズ・
    // An 宛てを決める。bit8=1 の空間は ADDX（emode 0/1）・
    // ADDA.L（opm 7）と分かれるので、*_dn は emode/qsz を where で
    // 弾き、*_a_l は qsz==3 を where で示す（将来の ADDX 宣言との
    // 排他検証のため）。addq/subq の qsz==3 は Scc/DBcc の空間。
    // Ref: SPEC-M68K-PRM (Rev 1) §ADD/SUB/CMP.
    let arith: &[EaDecl] = &[
        ("add", "AE", "1101 ... 0 .. ......", "add", &[]),
        (
            "add_dn",
            "AE",
            "1101 ... 1 .. ......",
            "add",
            &[("emode", WhereOp::Ne, 0), ("emode", WhereOp::Ne, 1), ("qsz", WhereOp::Ne, 3)],
        ),
        (
            "adda_l",
            "AE",
            "1101 ... 111 ......",
            "adda.l",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        ("sub", "AE", "1001 ... 0 .. ......", "sub", &[]),
        (
            "sub_dn",
            "AE",
            "1001 ... 1 .. ......",
            "sub",
            &[("emode", WhereOp::Ne, 0), ("emode", WhereOp::Ne, 1), ("qsz", WhereOp::Ne, 3)],
        ),
        (
            "suba_l",
            "AE",
            "1001 ... 111 ......",
            "suba.l",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        ("cmp", "AE", "1011 ... 0 .. ......", "cmp", &[]),
        (
            "cmpa_l",
            "AE",
            "1011 ... 111 ......",
            "cmpa.l",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        (
            "cmpm",
            "CM",
            "1011 ... 1 .. 001 ...",
            "cmpm",
            &[("qsz", WhereOp::Ne, 3), ("emode", WhereOp::Eq, 1)],
        ),
        (
            "addq",
            "QE",
            "0101 ... 0 .. ......",
            "addq",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        (
            "subq",
            "QE",
            "0101 ... 1 .. ......",
            "subq",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        (
            "addi",
            "IE",
            "0000 0110 .. ......",
            "addi",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        (
            "subi",
            "IE",
            "0000 0100 .. ......",
            "subi",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        (
            "cmpi",
            "IE",
            "0000 1100 .. ......",
            "cmpi",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        // C3: 論理系。or/and の Dn→ea 方向はサイズごとに別宣言:
        // or.b は SBCD（emode 0 と 1 の両方を占める）の空間を、
        // or.w/l は An 直のみ避ける。and.b は ABCD、and.w/l は EXG
        // （それぞれ emode 0/1）を避ける。eor は cmpm・cmpa と
        // 排他になるよう emode/qsz で絞る。
        // Ref: SPEC-M68K-PRM (Rev 1) §OR/AND/EOR.
        ("or", "AE", "1000 ... 0 .. ......", "or", &[("qsz", WhereOp::Ne, 3)]),
        (
            "or_b_dn",
            "AE",
            "1000 ... 1 00 ......",
            "or",
            &[("emode", WhereOp::Ne, 0), ("emode", WhereOp::Ne, 1)],
        ),
        (
            "or_w_dn",
            "AE",
            "1000 ... 1 01 ......",
            "or",
            &[("emode", WhereOp::Ne, 1)],
        ),
        (
            "or_l_dn",
            "AE",
            "1000 ... 1 10 ......",
            "or",
            &[("emode", WhereOp::Ne, 1)],
        ),
        (
            "and",
            "AE",
            "1100 ... 0 .. ......",
            "and",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        (
            "and_b_dn",
            "AE",
            "1100 ... 1 00 ......",
            "and",
            &[("emode", WhereOp::Ne, 0), ("emode", WhereOp::Ne, 1)],
        ),
        (
            "and_w_dn",
            "AE",
            "1100 ... 1 01 ......",
            "and",
            &[("emode", WhereOp::Ne, 0), ("emode", WhereOp::Ne, 1)],
        ),
        (
            "and_l_dn",
            "AE",
            "1100 ... 1 10 ......",
            "and",
            &[("emode", WhereOp::Ne, 1)],
        ),
        (
            "eor",
            "AE",
            "1011 ... 1 .. ......",
            "eor",
            &[("qsz", WhereOp::Ne, 3), ("emode", WhereOp::Ne, 1)],
        ),
        // 即値論理系。EA フィールドが #imm（emode7 ereg4）のとき
        // to CCR/to SR の特殊符号化になる（意味論側で振り分け）。
        ("ori", "IE", "0000 0000 .. ......", "ori", &[("qsz", WhereOp::Ne, 3)]),
        (
            "andi",
            "IE",
            "0000 0010 .. ......",
            "andi",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        (
            "eori",
            "IE",
            "0000 1010 .. ......",
            "eori",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        // 単項系。qsz=3 は tas・move to/from sr の空間として残す。
        ("not", "IE", "0100 0110 .. ......", "not", &[("qsz", WhereOp::Ne, 3)]),
        ("clr", "IE", "0100 0010 .. ......", "clr", &[("qsz", WhereOp::Ne, 3)]),
        ("tst", "IE", "0100 1010 .. ......", "tst", &[("qsz", WhereOp::Ne, 3)]),
    ];
    for (name, format, pattern, syntax, wheres) in arith {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: wheres
                .iter()
                .map(|(field, op, rhs)| WhereClause {
                    field: field.to_string(),
                    op: *op,
                    rhs: WhereRhs::Lit(*rhs),
                })
                .collect(),
            syntax: syntax.to_string(),
            timing: "misc".to_string(),
        });
    }
    m.insns.push(Insn {
        name: "moveq".to_string(),
        format: "Q".to_string(),
        pattern: Pattern::parse("0111 ... 0 ........").expect("valid pattern"),
        when: Pred::True,
        wheres: vec![],
        syntax: "moveq".to_string(),
        timing: "misc".to_string(),
    });
    m
}
