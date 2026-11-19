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

    // (名前, パターン, 構文, 分類)
    // いずれも拡張語を伴わない16ビット固定の実符号化。
    // Ref: SPEC-M68K-PRM (Rev 1).
    let insns: &[(&str, &str, &str, &str)] = &[
        ("nop", "0100111001110001", "nop", "misc"),
        ("reset", "0100111001110000", "reset", "ctrl"),
        ("rte", "0100111001110011", "rte", "ctrl"),
        ("rts", "0100111001110101", "rts", "ctrl"),
        ("rtr", "0100111001110111", "rtr", "ctrl"),
        ("illegal", "0100101011111100", "illegal", "misc"),
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

    // movea は move.w/move.l の宛先 An 直と同じ符号化を持つので、
    // where で dmode==1（An 直）を宣言して排他を示す。move.b は
    // byte の An 直が未割当なので source/destination 両方で An を
    // 弾く。Ref: SPEC-M68K-PRM (Rev 1) §MOVE/MOVEA.
    type Cond = (&'static str, WhereOp, u128);
    type EaDecl = (&'static str, &'static str, &'static str, &'static [Cond]);
    let ea_insns: &[EaDecl] = &[
        (
            "movea_l",
            "E2",
            "0010 ... 001 ......",
            &[("dmode", WhereOp::Eq, 1)],
        ),
        (
            "movea_w",
            "E2",
            "0011 ... 001 ......",
            &[("dmode", WhereOp::Eq, 1)],
        ),
        (
            "move_b",
            "E2",
            "0001 ............",
            &[("dmode", WhereOp::Ne, 1), ("smode", WhereOp::Ne, 1)],
        ),
        (
            "move_w",
            "E2",
            "0011 ............",
            &[("dmode", WhereOp::Ne, 1)],
        ),
        (
            "move_l",
            "E2",
            "0010 ............",
            &[("dmode", WhereOp::Ne, 1)],
        ),
    ];
    for (name, format, pattern, wheres) in ea_insns {
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
            syntax: name.replace('_', "."),
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
