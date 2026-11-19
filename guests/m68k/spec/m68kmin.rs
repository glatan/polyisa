// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// m68k 最小の ISADL モデル（段階14の骨格）。
//
// B1 はクレート骨格が対象なので、命令は16ビット固定の実符号化のうち
// 拡張語を伴わないもの（nop/reset/rts/rtr/rte/illegal）だけを宣言する。
// EA モードの解釈経路と拡張語の消費は B2 以降で決める。
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

    // F0: 16ビット固定・オペランドなし（拡張語も伴わない命令）。
    m.formats.push(Format {
        name: "F0".to_string(),
        fields: vec![],
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
    m
}
