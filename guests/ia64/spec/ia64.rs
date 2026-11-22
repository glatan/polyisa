// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// IA-64 の ISADL モデル（段階21）。
//
// IA-64 の命令は 41 ビットのスロット語で、3 個を束ねた 128 ビットの
// バンドル（bits[4:0] がテンプレート）をフェッチ単位とする。
// MLX テンプレートの X スロットは 2 スロットぶんの 82 ビット語を
// 占める。本モデルはスロット語を命令語として宣言し、バンドルの
// 切り出し・テンプレート解釈・stop の進行は実行側が担う
// （m68k の基底語＋拡張語と同じ分割）。
//
// IA2 の骨格としてモデル宣言・機能旗・形式の枠だけを置く。
// 実命令のパターンは IA3 で足す。
// 出典は SPEC-IA64-SDM Rev 2.3 (2010-05) である。
// Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_isadl::model::*;

/// IA-64 の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in [
        "alu", "load", "store", "branch", "system", "fp", "misc",
    ] {
        m.timing_classes.push(class.to_string());
    }

    // 機能旗。
    // - `itanium`: Itanium（初代 merced 系）のベースライン命令集合。
    // - `itanium2`: Itanium 2 以降（mckinley〜9700 系）の追加命令群
    //   （brl・追加の hint/形式）。`itanium` を含意する。
    // 世代差の粒度は正本の版差記述と IA3 の都合で確定する。
    // Ref: SPEC-IA64-SDM (Rev 2.3).
    for (name, implies) in [("itanium", &[][..]), ("itanium2", &["itanium"][..])] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: vec![],
        });
    }

    // CPU モデル。generic は Itanium 系のベースライン、itanium2 は
    // Itanium 2 系（9700 系をこの範囲の最終として含める）。
    for (name, parent, add) in [
        ("generic", "", &["itanium"][..]),
        ("itanium2", "generic", &["itanium2"][..]),
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

    // レジスタ類。gr/fr は 0-127、pr は 0-63、br は 0-7。
    for (name, prefix) in [("gr", "r"), ("fr", "f"), ("pr", "p"), ("br", "b")] {
        m.regclasses.push(RegClass {
            name: name.to_string(),
            dynamic: false,
            prefix: Some(prefix.to_string()),
        });
    }

    // 修飾述語 qp。全形式共通でスロット語の bits[5:0]。
    // 形式ごとの残りの桁は IA3 で足す。
    // Ref: SPEC-IA64-SDM (Rev 2.3).
    m.fields.push(Field {
        name: "qp".to_string(),
        kind: FieldKind::Bits { hi: 5, lo: 0 },
    });

    // 形式の枠。FSLOT は 41 ビットのスロット語（I/A/M/F/B 系）、
    // FX は MLX の X スロットが占める 82 ビット語（L+X）。
    // 命令の宣言は IA3 で足す。
    for name in ["FSLOT", "FX"] {
        m.formats.push(Format {
            name: name.to_string(),
            fields: vec!["qp".to_string()],
            operands: vec![],
        });
    }

    m
}
