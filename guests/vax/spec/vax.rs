// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// VAX の ISADL モデル（段階23）。
//
// VAX の命令は可変長で、1 バイト本体と 0xFD/0xFE/0xFF 接頭の
// 2 バイトオペコードの後に、オペランド指定子のバイト列が続く。
// 本モデルはオペコード部だけを命令語（8/16 ビット）として宣言し、
// `decode(word, 8|16)` の長さ分岐で全オペコード空間を表す
// （IA-64 のスロット語先例）。語へのバイトの詰め方はフェッチ順に
// 下位ビットから（1 バイト目が bits[7:0]、2 バイト語の上位は
// 接頭の次のバイト）。オペランド指定子の評価・消費長・読み書きは
// 指定子ストリームの設計（VX3）が担う。
//
// VX2 は骨格として、オペランド指定子を伴わない命令だけを宣言して
// 語彙の器とする。指定子を伴う命令は VX3 以降で足す。
//
// 出典は SPEC-VAX-ARM（命令エンコーディングとサブセット化の規則）
// と SPEC-VAX-MICROVAX（KA660 §3.7 の実装群/支援群/未実装群の
// 区分）である。
// Ref: SPEC-VAX-ARM, SPEC-VAX-MICROVAX.

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// VAX の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in [
        "alu", "move", "branch", "call", "fp", "decimal", "string", "queue", "system", "misc",
    ] {
        m.timing_classes.push(class.to_string());
    }

    // 機能旗。命令群の実装差（直接実行か補完経路か）を表す。
    // フル VAX はすべて持ち、MicroVAX 系は実装しない群を
    // remove_features で削る。削られた命令は補完要求（サブセット
    // 例外）として扱い、配送経路は `emul_dispatch` パラメータ。
    // - `decimal`: パック十進・数値文字列命令（movp/cmpp/addp/
    //   subp/mulp/divp/cvt*/ashp 系）。
    // - `hfp`: H 形式浮動小数点と octaword 命令。
    // - `string_ext`: 拡張文字列命令（matchc/movtc/movtuc）。
    // - `string_cmp`: 文字列の比較・走査系（cmpc3/cmpc5/locc/
    //   scanc/skpc/spanc の 6 個）。SOC 系はマイクロコードで実装
    //   するが、KA630（MicroVAX II）では補完対象だった世代差の節点。
    // - `crc`: crc。
    // - `editpc`: editpc。
    // - `compat`: PDP-11 互換モード命令。
    // Ref: SPEC-VAX-ARM（サブセット化の章）, SPEC-VAX-MICROVAX §3.7.
    for name in [
        "decimal",
        "hfp",
        "string_ext",
        "string_cmp",
        "crc",
        "editpc",
        "compat",
    ] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: vec![],
            conflicts: vec![],
        });
    }

    // 挙動パラメータ。
    // Ref: SPEC-VAX-MICROVAX §3.9（補完経路と SCB）.
    m.param(
        "emul_dispatch",
        ParamKind::Enum(vec!["hook".to_string(), "scb".to_string()]),
        "hook",
        "実装しない命令（サブセット外）の補完要求の配送経路。\
         hook=実行側のトラップハンドラへ渡す、\
         scb=SCB の補完ベクタ（FPD=0/1 で開始/継続）への実機どおりの配送",
    );
    m.param(
        "dv_hw",
        ParamKind::Bool,
        "true",
        "PSL<7> DV（十進オーバーフロー トラップ有効）をハードが扱うか。\
         KA660 では無効で、十進補完の macrocode がこの桁を使う",
    );

    // CPU モデル。11/780 はフル VAX（全機能）の基底。MicroVAX 系は
    // 実装しない群を削る。NVAX 以降の世代差（compat の有無等）の
    // 確定は VX11 で正本照合のうえ行う。
    // - microvax2（KA630・MicroVAX II）: decimal/hfp/string_ext/
    //   string_cmp/crc/editpc/compat を補完対象とする。
    // - ka660（SOC）: KA630 との差は string_cmp の 6 個を実装
    //   する点。dv_hw はハードが扱わない。
    // Ref: SPEC-VAX-ARM, SPEC-VAX-MICROVAX §3.7.
    let subset: &[&str] = &[
        "decimal",
        "hfp",
        "string_ext",
        "string_cmp",
        "crc",
        "editpc",
        "compat",
    ];
    for (name, parent, add, remove, params) in [
        ("vax11_780", "", subset, &[][..], &[][..]),
        ("microvax2", "vax11_780", &[][..], subset, &[][..]),
        (
            "ka660",
            "vax11_780",
            &[][..],
            &[
                "decimal",
                "hfp",
                "string_ext",
                "crc",
                "editpc",
                "compat",
            ][..],
            &[("dv_hw", "false")][..],
        ),
        ("nvax", "vax11_780", &[][..], &["compat"][..], &[][..]),
    ] {
        m.models.push(ModelDef {
            params: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: remove.iter().map(|s| s.to_string()).collect(),
            ident: vec![],
        });
    }

    // 汎用レジスタ r0-r15。構文上 r12-r15 は AP/FP/SP/PC と書く。
    m.regclasses.push(RegClass {
        name: "gr".to_string(),
        dynamic: false,
        prefix: Some("r".to_string()),
    });

    // 桁。2 バイトオペコードの第 2 バイト（接頭の次）。オペランド
    // 指定子の桁は命令語に含まれないためここでは宣言しない
    // （指定子ストリームの設計は VX3）。
    m.fields.push(Field {
        name: "op2".to_string(),
        kind: FieldKind::Bits { hi: 15, lo: 8 },
    });

    // 形式。O1 は 1 バイトオペコード、O2 は 0xFD/0xFE/0xFF 接頭の
    // 2 バイトオペコード。いずれもオペランド指定子を伴わない。
    m.formats.push(Format {
        name: "O1".to_string(),
        fields: vec![],
        operands: vec![],
    });
    m.formats.push(Format {
        name: "O2".to_string(),
        fields: vec!["op2".to_string()],
        operands: vec![],
    });

    // オペランド指定子を伴わない命令（骨格の検証に使う最小集合）。
    // パターンは語の上位ビットから書く。2 バイト語は bits[7:0] が
    // 接頭、bits[15:8]（op2）が次のバイト。
    // Ref: SPEC-VAX-ARM（命令エンコーディング）.
    let insns: &[(&str, &str, &str, &str)] = &[
        ("halt", "O1", "0000 0000", "halt"),
        ("nop", "O1", "0000 0001", "nop"),
        ("rei", "O1", "0000 0010", "rei"),
        ("bpt", "O1", "0000 0011", "bpt"),
        ("ret", "O1", "0000 0100", "ret"),
        ("rsb", "O1", "0000 0101", "rsb"),
        ("ldpctx", "O1", "0000 0110", "ldpctx"),
        ("svpctx", "O1", "0000 0111", "svpctx"),
        ("bugw", "O2", "1111 1111 1111 1101", "bugw"),
        ("bugl", "O2", "1111 1111 1111 1110", "bugl"),
    ];
    for (name, format, pattern, syntax) in insns {
        let timing = match *name {
            "nop" => "misc",
            "ret" | "rsb" => "call",
            _ => "system",
        };
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
