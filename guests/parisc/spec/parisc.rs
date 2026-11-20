// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// PA-RISC の ISADL モデル（段階17）。
//
// 命令語は 32 ビット固定長のビッグエンディアンで、opcode
// （HP 記法の bit 0-5＝語の最上位 6 ビット）の下に形式が決まる。
// 条件付き命令の completer（nullify の n、比較条件 c、
// フィールド選択 f 等）は opcode の下位の拡張桁とオペランドに
// 埋まる。
// PA-RISC 1.0 は公開の根拠資料がないため範囲外（段階17 の
// 着手条件で除外を決定）。対象は 1.1・2.0 と MAX 拡張。
// 出典は SPEC-PARISC-11・SPEC-PARISC-20 である。
// Ref: SPEC-PARISC-11, SPEC-PARISC-20.

use polyisa_isadl::model::*;

/// PA-RISC の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in [
        "alu", "load", "store", "branch", "system", "fp", "misc",
    ] {
        m.timing_classes.push(class.to_string());
    }

    // アーキテクチャの版。pa20 は pa11 を含む（上位版は先行版の
    // 命令を持つ）。MAX はマルチメディア拡張で、MAX-1（PA7100LC/
    // PA7300LC）と MAX-2（PA-8000 系列）は別集合（MAX-2 は
    // 64 ビット向けの書き直しで MAX-1 の上位集合ではない）。
    // Ref: SPEC-PARISC-11, SPEC-PARISC-20.
    for (name, implies) in [
        ("pa11", &[][..]),
        ("pa20", &["pa11"][..]),
        ("max1", &[][..]),
        ("max2", &[][..]),
    ] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: vec![],
        });
    }

    // CPU モデル。PA7100LC/PA7300LC は 1.1 と MAX-1、PA-8000
    // 系列は 2.0 と MAX-2 を持つ。
    // Ref: SPEC-PARISC-11, SPEC-PARISC-20.
    for (name, parent, add) in [
        ("pa7100lc", "", &["pa11", "max1"][..]),
        ("pa7300lc", "pa7100lc", &[][..]),
        ("pa8000", "pa7100lc", &["pa20", "max2"][..]),
        ("pa8500", "pa8000", &[][..]),
        ("pa8600", "pa8500", &[][..]),
        ("pa8700", "pa8600", &[][..]),
    ] {
        m.models.push(ModelDef {
            params: Default::default(),
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: Vec::new(),
            ident: vec![],
        });
    }

    // 整数レジスタ r0-31（r0 はソース読み出しで常に 0）と
    // FP レジスタ fr0-31。
    m.regclasses.push(RegClass {
        name: "gr".to_string(),
        dynamic: false,
        prefix: Some("r".to_string()),
    });
    m.regclasses.push(RegClass {
        name: "fpr".to_string(),
        dynamic: false,
        prefix: Some("fr".to_string()),
    });

    // HP の bit 記法は MSB が 0。ISADL の桁指定は LSB=0 なので
    // 翻訳して記す（HP の 0-5 は LSB の 31-26）。
    // 命令ごとの桁は PR3 のデコード実装で形式と併せて宣言する。
    // 現時点は op だけだが、PR3 で形式の桁を足すので loop の形を
    // 残す（要素が増えた時点で expect は外す）。
    #[expect(clippy::single_element_loop)]
    for (name, hi, lo) in [("op", 31, 26)] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    m
}
