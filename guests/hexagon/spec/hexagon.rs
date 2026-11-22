// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Hexagon の ISADL モデル（段階22）。
//
// Hexagon の命令語は 32 ビットで、1–4 語を束ねたパケットが
// フェッチ・実行の単位。語内の Parse 桁（bits[15:14]）が
// パケット終端（11）・非終端（01/10、10 はループ終端の標識でも
// ある）・duplex（00、1 語に 13 ビット subinsn 2 個）を識別し、
// ICLASS 桁（bits[31:28]）が命令クラスを指す（0 は constant
// extender 語）。本モデルは 32 ビット語を命令語として宣言し、
// パケットの切り出し・duplex の subinsn 分解・constant extender
// の即値併合は実行側が担う（ia64 のバンドル→スロット語と同じ
// 分割）。
//
// HX2 の骨格としてモデル宣言・機能旗・形式の枠だけを置く。
// 実命令のパターンは HX3 で足す。
// 主正本は SPEC-HEXAGON-PRM (V79, 80-N2040-60 Rev AB)。
// V5x〜V73 の版差の根拠は SPEC-HEXAGON-PRM-PREV 群
// （80-N2040-8/-33/-36/-39/-42/-45/-46/-53、-53 が V73）。
// Ref: SPEC-HEXAGON-PRM (V79), SPEC-HEXAGON-PRM-PREV.

use polyisa_isadl::model::*;

/// Hexagon の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "load", "store", "branch", "system", "misc", "hvx"] {
        m.timing_classes.push(class.to_string());
    }

    // 機能旗。
    // - `v*`: 版の系列。各版の命令集合（v5/v55/v60/v62/
    //   v65/v66/v67/v68/v69/v71/v73/v75/v79）で、新版は先行版を
    //   含意する。PREV 台帳の文書番号→版対応（-53=V73 以外の
    //   -8/-33/-36/-39/-42/-45/-46 の帰属）は各 PDF の表紙確認が
    //   要るため、版差の具体的な内容は HX3 以降で旗に写す。
    // - `tinycore`: v67t/v71t 系の tiny core 変種旗。版旗と直交。
    // - `hvx`: HVX ベクトル命令群の別旗（HVX の版差は HX9 で足す）。
    // Ref: SPEC-HEXAGON-PRM (V79), SPEC-HEXAGON-PRM-PREV.
    let versions = [
        "v5", "v55", "v60", "v62", "v65", "v66", "v67", "v68", "v69", "v71", "v73", "v75", "v79",
    ];
    for (i, name) in versions.iter().enumerate() {
        m.features.push(Feature {
            name: name.to_string(),
            implies: if i == 0 {
                vec![]
            } else {
                vec![versions[i - 1].to_string()]
            },
            conflicts: vec![],
        });
    }
    for name in ["tinycore", "hvx"] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: vec![],
            conflicts: vec![],
        });
    }

    // CPU モデル。generic は V5 系のベースライン。v73 は Linux ABI
    // の配布物が要求する版（BIN-DISTRO-HEXAGON の e_flags 0x73）、
    // v79 は主正本の最新版。
    for (name, parent, add) in [
        ("generic", "", &["v5"][..]),
        ("v73", "generic", &["v73"][..]),
        ("v79", "generic", &["v79"][..]),
    ] {
        m.models.push(ModelDef {
            params: vec![],
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: vec![],
            ident: vec![],
        });
    }

    // レジスタ類。gpr は r0-r31（対レジスタ Rdd は偶奇対）、pred は
    // p0-p3（各 8 ビット、P3:0 で 32 ビットに並ぶ）、creg は
    // 制御レジスタ c0-c31（SA0/LC0/.../USR/PC/UGP/GP/CS0/CS1 等）。
    // Ref: SPEC-HEXAGON-PRM (V79) registers.
    for (name, prefix) in [("gpr", "r"), ("pred", "p"), ("creg", "c")] {
        m.regclasses.push(RegClass {
            name: name.to_string(),
            dynamic: false,
            prefix: Some(prefix.to_string()),
        });
    }

    // ---- 桁。全形式共通の桁（ICLASS・Parse）と、duplex・constant
    // extender 語の配置だけを宣言する。命令ごとの桁は HX3 で足す。
    // Ref: SPEC-HEXAGON-PRM (V79) instruction encoding.
    for (name, hi, lo) in [
        ("iclass", 31, 28), // 命令クラス。0 は constant extender
        ("pp", 15, 14),     // Parse 桁（00=duplex, 01/10=非終端, 11=終端）
        ("sublo", 12, 0),   // duplex の slot0 subinsn
        ("subhi", 28, 16),  // duplex の slot1 subinsn
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }
    // duplex の 4 ビット ICLASS（bits{31:29,13}）と constant
    // extender の 26 ビット即値（bits{27:16}+{13:0}）。
    for (name, parts) in [
        ("diclass", vec![(31, 29), (13, 13)]),
        ("imm26", vec![(27, 16), (13, 0)]),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Parts { parts, zfill: 0 },
        });
    }

    // 形式の枠。F32 は 32 ビット命令語の基底形、FDUP は duplex 語
    //（subinsn 2 個の容器、Parse=00 でパケット終端）、FEXT は
    // constant extender 語（ICLASS=0、命令ではない前置語）。
    // 命令の宣言は HX3 で足す。
    let fmt = |name: &str, fields: &[&str]| Format {
        name: name.to_string(),
        fields: fields.iter().map(|s| s.to_string()).collect(),
        operands: vec![],
    };
    m.formats.push(fmt("F32", &["iclass", "pp"]));
    m.formats.push(fmt("FDUP", &["pp", "diclass", "subhi", "sublo"]));
    m.formats.push(fmt("FEXT", &["iclass", "pp", "imm26"]));

    m
}
