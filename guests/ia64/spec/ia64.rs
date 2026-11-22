// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// IA-64 の ISADL モデル（段階21）。
//
// IA-64 の命令は 41 ビットのスロット語で、3 個を束ねた 128 ビットの
// バンドル（bits[4:0] がテンプレート）をフェッチ単位とする。
// MLX テンプレートの X スロットは 2 スロットぶんの 82 ビット語を
// 占める。本モデルはスロット語（82 ビット語を含む）を命令語として
// 宣言し、バンドルの切り出し・テンプレート解釈・stop の進行は
// 実行側が担う（m68k の基底語＋拡張語と同じ分割）。
//
// IA-64 では同一のオペコード空間を実行ユニットごとに別命令として
// 解釈するため、符号化はスロット種別（テンプレートが与える文脈）
// なしには一意に定まらない。これを `when` の「文脈旗」
// unit_{a,i,m,f,b,x} で表す。I スロットのデコードは
// feats = unit_i|unit_a、M スロットは unit_m|unit_a のように
// 呼び出し側が文脈を渡す（A 型は I/M どちらのスロットにも置ける
// ため unit_a は unit_i/unit_m と衝突しない）。guests/ia64 の
// ライブラリ側がテンプレート表と `decode_slot` 等の殻を提供する。
//
// IA3 では A/I/M/F/B/X 各系の代表形式を収める。網羅的な語彙は
// IA5 以降で段階的に足す。出典は SPEC-IA64-SDM Rev 2.3 (2010-05)
// であり、フィールド配置は正本の形式表に合わせる。
// Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

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
    //   （brl 系など）。`itanium` を含意する。正本 Rev 2.3 の版差記述は
    //   Itanium ↔ Itanium 2 系の二世代粒度で、符号化面の追加もこの
    //   粒度に収まるため IA3 はこの二旗で確定とする（細分化が要る
    //   差異が出た時点で旗を足す）。
    // - `unit_*`: デコード文脈旗。CPU 世代ではなく、テンプレートが
    //   各スロットに割り当てる実行ユニットの文脈を `when` に写す
    //   もの（上記のモデル注記を参照）。A 型は I/M 両スロットに
    //   適合するため unit_a は unit_i/unit_m と両立し、それ以外の
    //   スロット種別は互いに衝突する。
    // Ref: SPEC-IA64-SDM (Rev 2.3).
    for (name, implies, conflicts) in [
        ("itanium", &[][..], &[][..]),
        ("itanium2", &["itanium"][..], &[][..]),
        ("unit_a", &[][..], &["unit_f", "unit_b", "unit_x"][..]),
        ("unit_i", &[][..], &["unit_m", "unit_f", "unit_b", "unit_x"][..]),
        ("unit_m", &[][..], &["unit_f", "unit_b", "unit_x"][..]),
        ("unit_f", &[][..], &["unit_b", "unit_x"][..]),
        ("unit_b", &[][..], &["unit_x"][..]),
        ("unit_x", &[][..], &[][..]),
    ] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: conflicts.iter().map(|s| s.to_string()).collect(),
        });
    }

    // CPU モデル。generic は Itanium 系のベースライン、itanium2 は
    // Itanium 2 系（9700 系をこの範囲の最終として含める）。
    // unit_* は文脈旗なのでモデルには含めない。
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

    // レジスタ類。gr/fr は 0-127、pr は 0-63、br は 0-7、ar は
    // アプリケーションレジスタ（mov.{i,m} 形式が読み書きする）。
    for (name, prefix) in [
        ("gr", "r"),
        ("fr", "f"),
        ("pr", "p"),
        ("br", "b"),
        ("ar", "ar"),
    ] {
        m.regclasses.push(RegClass {
            name: name.to_string(),
            dynamic: false,
            prefix: Some(prefix.to_string()),
        });
    }

    // ---- 桁。スロット語（41 ビット）内の配置は正本の形式表に
    // 従う。X 系（82 ビット語）は word[40:0] をバンドルの X スロット
    // （slot2、major 番号・qp・低位即値）、word[81:41] を L スロット
    // （slot1、上位即値）として組み立てる。
    // Ref: SPEC-IA64-SDM (Rev 2.3).
    for (name, hi, lo) in [
        ("qp", 5, 0),     // 修飾述語（全形式共通）
        ("r1", 12, 6),    // GR 宛先
        ("r2", 19, 13),   // GR ソース（st のデータでも使う）
        ("r3", 26, 20),   // GR ソース/アドレス基底
        ("r3_2", 21, 20), // addl の限定 r3（r0-r3）
        ("f1", 12, 6),    // FR 宛先
        ("f2", 19, 13),   // FR ソース
        ("f3", 26, 20),   // FR ソース
        ("f4", 33, 27),   // FR ソース（fma 系の加算項）
        ("p1", 11, 6),    // 述語宛先 1
        ("p2", 32, 27),   // 述語宛先 2
        ("b1", 8, 6),     // 分岐レジスタ宛先（call のリンク）
        ("b2", 15, 13),   // 分岐レジスタソース（間接分岐）
        ("ar3", 26, 20),  // AR 指定
        // 単一ビット・少数ビットの即値・制御桁。
        ("imm1", 36, 36),    // dep の 1 ビット値
        ("immu2", 14, 13),   // probe の権利指定
        ("immu5b", 18, 14),  // tf のフラグ指定
        ("immu7a", 19, 13),  // fsetc の am 制御
        ("immu7b", 26, 20),  // fsetc の sf 制御
        ("cnt2a", 28, 27),   // shladd のシフト量 1-4
        ("cnt5", 18, 14),    // shift の即値量
        ("ccnt5", 24, 20),   // pshl 系の補数シフト量
        ("cnt6", 32, 27),    // shrp のシフト量
        ("cpos6a", 25, 20),  // dep.z の補数位置
        ("cpos6b", 19, 14),  // dep 即値の補数位置
        ("cpos6c", 36, 31),  // dep の補数位置
        ("len4", 30, 27),    // dep の長さ-1
        ("len6", 32, 27),    // extr/dep.z の長さ-1
        ("pos6", 19, 14),    // extr/tbit の位置
        ("mbtype4", 23, 20), // mux のバイト型
        ("inc3", 15, 13),    // fetchadd の増分
        ("sof", 19, 13),     // alloc の size of frame
        ("sol", 26, 20),     // alloc の size of locals
        ("sor", 30, 27),     // alloc の size of rotating
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }
    // 分割即値。parts は論理値の MSB→LSB の順で語内区間を並べる。
    // zfill>0 は論理値の下位 zfill ビットが常に 0（分岐ターゲットや
    // imm44 のような左詰め値）。
    for (name, parts, zfill) in [
        ("imm8", vec![(36, 36), (19, 13)], 0),  // A2/cmp.imm 8 ビット
        ("imm9a", vec![(36, 36), (27, 27), (12, 6)], 0), // st.postinc
        ("imm9b", vec![(36, 36), (27, 27), (19, 13)], 0), // ld.postinc
        ("imm14", vec![(36, 36), (32, 27), (19, 13)], 0), // adds/addp4
        ("imm17", vec![(36, 36), (31, 24), (12, 6)], 0),  // mov pr
        ("imm22", vec![(36, 36), (35, 27), (26, 22), (19, 13)], 0), // addl
        ("immu9", vec![(34, 33), (26, 20)], 0),           // fclass
        ("immu21", vec![(36, 36), (25, 6)], 0),           // break/nop/hint
        ("immu24", vec![(36, 36), (32, 31), (26, 6)], 0), // sum/rum
        ("tag13", vec![(34, 33), (12, 6)], 4), // brp の退避タグ
        ("tag13b", vec![(32, 24)], 4),         // mov.ret の退避タグ
        ("tgt25", vec![(36, 36), (25, 6)], 4), // fchkf の分岐先
        ("tgt25b", vec![(36, 36), (32, 20), (12, 6)], 4), // chk.s 系
        ("tgt25c", vec![(36, 36), (32, 13)], 4),          // 分岐系
        ("imm44", vec![(36, 36), (32, 6)], 16),           // mov pr.rot
        // スロットをまたぐ 82 ビット形式の即値。word[40:0]=X スロット
        // （bundle の slot2）、word[81:41]=L スロット（slot1）。
        // imm64 は movl、imm62 は break.x/nop.x/hint.x、
        // tgt60 は brl 系の分岐先（下位 4 ビット 0 詰め）。
        ("imm62", vec![(81, 41), (36, 36), (25, 6)], 0),
        (
            "imm64",
            vec![(36, 36), (81, 41), (21, 21), (26, 22), (35, 27), (19, 13)],
            0,
        ),
        ("tgt60", vec![(36, 36), (81, 43), (32, 13)], 4),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Parts { parts, zfill },
        });
    }

    // ---- オペランド・形式の組み立て道具。
    let gr = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("gr".to_string()),
        access,
    };
    let fr = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("fr".to_string()),
        access,
    };
    let pr = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("pr".to_string()),
        access,
    };
    let br = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("br".to_string()),
        access,
    };
    let ar = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("ar".to_string()),
        access,
    };
    let qp = || pr("qp", "qp", Access::Read);
    let val = |name: &str, field: &str| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: None,
        access: Access::Read,
    };
    let fmt = |name: &str, fields: &[&str], operands: Vec<Operand>| Format {
        name: name.to_string(),
        fields: fields.iter().map(|s| s.to_string()).collect(),
        operands,
    };

    // ---- 形式。スロット語の実レイアウトごとに一つ。ユニットを
    // またいで同一レイアウトの形式は共有する。
    let qp_r = || vec![qp()];
    m.formats.push(fmt("F0", &["qp"], qp_r()));
    m.formats.push(fmt("F0U", &[], vec![]));
    m.formats.push(fmt(
        "FRRR",
        &["qp", "r1", "r2", "r3"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r2", "r2", Access::Read),
            gr("r3", "r3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FRIR",
        &["qp", "r1", "imm8", "r3"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            val("imm8", "imm8"),
            gr("r3", "r3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FRI14",
        &["qp", "r1", "imm14", "r3"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            val("imm14", "imm14"),
            gr("r3", "r3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FRI22",
        &["qp", "r1", "imm22", "r3_2"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            val("imm22", "imm22"),
            gr("r3_2", "r3_2", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FPPRR",
        &["qp", "p1", "p2", "r2", "r3"],
        vec![
            qp(),
            pr("p1", "p1", Access::Write),
            pr("p2", "p2", Access::Write),
            gr("r2", "r2", Access::Read),
            gr("r3", "r3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FPPIR",
        &["qp", "p1", "p2", "imm8", "r3"],
        vec![
            qp(),
            pr("p1", "p1", Access::Write),
            pr("p2", "p2", Access::Write),
            val("imm8", "imm8"),
            gr("r3", "r3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FRRCR",
        &["qp", "r1", "r2", "cnt2a", "r3"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r2", "r2", Access::Read),
            val("cnt2a", "cnt2a"),
            gr("r3", "r3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FI21",
        &["qp", "immu21"],
        vec![qp(), val("immu21", "immu21")],
    ));
    m.formats.push(fmt(
        "FRRRLL",
        &["qp", "r1", "r2", "r3", "cpos6c", "len4"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r2", "r2", Access::Read),
            gr("r3", "r3", Access::Read),
            val("cpos6c", "cpos6c"),
            val("len4", "len4"),
        ],
    ));
    m.formats.push(fmt(
        "FRIRLL",
        &["qp", "r1", "imm1", "r3", "cpos6b", "len6"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            val("imm1", "imm1"),
            gr("r3", "r3", Access::Read),
            val("cpos6b", "cpos6b"),
            val("len6", "len6"),
        ],
    ));
    m.formats.push(fmt(
        "FRRLL",
        &["qp", "r1", "r2", "cpos6a", "len6"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r2", "r2", Access::Read),
            val("cpos6a", "cpos6a"),
            val("len6", "len6"),
        ],
    ));
    m.formats.push(fmt(
        "FRILL",
        &["qp", "r1", "imm8", "cpos6a", "len6"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            val("imm8", "imm8"),
            val("cpos6a", "cpos6a"),
            val("len6", "len6"),
        ],
    ));
    m.formats.push(fmt(
        "FRRPL",
        &["qp", "r1", "r3", "pos6", "len6"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r3", "r3", Access::Read),
            val("pos6", "pos6"),
            val("len6", "len6"),
        ],
    ));
    m.formats.push(fmt(
        "FRRRC",
        &["qp", "r1", "r2", "r3", "cnt6"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r2", "r2", Access::Read),
            gr("r3", "r3", Access::Read),
            val("cnt6", "cnt6"),
        ],
    ));
    m.formats.push(fmt(
        "FRR",
        &["qp", "r1", "r3"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r3", "r3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FRRM",
        &["qp", "r1", "r2", "mbtype4"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r2", "r2", Access::Read),
            val("mbtype4", "mbtype4"),
        ],
    ));
    m.formats.push(fmt(
        "FRRC5",
        &["qp", "r1", "r2", "ccnt5"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r2", "r2", Access::Read),
            val("ccnt5", "ccnt5"),
        ],
    ));
    m.formats.push(fmt(
        "FPPRP",
        &["qp", "p1", "p2", "r3", "pos6"],
        vec![
            qp(),
            pr("p1", "p1", Access::Write),
            pr("p2", "p2", Access::Write),
            gr("r3", "r3", Access::Read),
            val("pos6", "pos6"),
        ],
    ));
    m.formats.push(fmt(
        "FPPR",
        &["qp", "p1", "p2", "r3"],
        vec![
            qp(),
            pr("p1", "p1", Access::Write),
            pr("p2", "p2", Access::Write),
            gr("r3", "r3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FR1",
        &["qp", "r1"],
        vec![qp(), gr("r1", "r1", Access::Write)],
    ));
    m.formats.push(fmt(
        "FRB",
        &["qp", "r1", "b2"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            br("b2", "b2", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FBRT",
        &["qp", "b1", "r2", "tag13b"],
        vec![
            qp(),
            br("b1", "b1", Access::Write),
            gr("r2", "r2", Access::Read),
            val("tag13b", "tag13b"),
        ],
    ));
    m.formats.push(fmt(
        "FRI17",
        &["qp", "r2", "imm17"],
        vec![qp(), gr("r2", "r2", Access::Read), val("imm17", "imm17")],
    ));
    m.formats.push(fmt(
        "FI44",
        &["qp", "imm44"],
        vec![qp(), val("imm44", "imm44")],
    ));
    m.formats.push(fmt(
        "FARR",
        &["qp", "ar3", "r2"],
        vec![
            qp(),
            ar("ar3", "ar3", Access::Write),
            gr("r2", "r2", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FARI",
        &["qp", "ar3", "imm8"],
        vec![qp(), ar("ar3", "ar3", Access::Write), val("imm8", "imm8")],
    ));
    m.formats.push(fmt(
        "FRAR",
        &["qp", "r1", "ar3"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            ar("ar3", "ar3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FRT",
        &["qp", "r2", "tgt25b"],
        vec![qp(), gr("r2", "r2", Access::Read), val("tgt25b", "tgt25b")],
    ));
    // M 系。
    m.formats.push(fmt(
        "FLDR",
        &["qp", "r1", "r3", "r2"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r3", "r3", Access::Read),
            gr("r2", "r2", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FLDI",
        &["qp", "r1", "r3", "imm9b"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r3", "r3", Access::Read),
            val("imm9b", "imm9b"),
        ],
    ));
    m.formats.push(fmt(
        "FSTR",
        &["qp", "r3", "r2"],
        vec![
            qp(),
            gr("r3", "r3", Access::Read),
            gr("r2", "r2", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FSTI",
        &["qp", "r3", "r2", "imm9a"],
        vec![
            qp(),
            gr("r3", "r3", Access::Read),
            gr("r2", "r2", Access::Read),
            val("imm9a", "imm9a"),
        ],
    ));
    m.formats.push(fmt(
        "FFLD",
        &["qp", "f1", "r3"],
        vec![
            qp(),
            fr("f1", "f1", Access::Write),
            gr("r3", "r3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FFLDR",
        &["qp", "f1", "r3", "r2"],
        vec![
            qp(),
            fr("f1", "f1", Access::Write),
            gr("r3", "r3", Access::Read),
            gr("r2", "r2", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FFLDI",
        &["qp", "f1", "r3", "imm9b"],
        vec![
            qp(),
            fr("f1", "f1", Access::Write),
            gr("r3", "r3", Access::Read),
            val("imm9b", "imm9b"),
        ],
    ));
    m.formats.push(fmt(
        "FFST",
        &["qp", "r3", "f2"],
        vec![
            qp(),
            gr("r3", "r3", Access::Read),
            fr("f2", "f2", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FFSTI",
        &["qp", "r3", "f2", "imm9a"],
        vec![
            qp(),
            gr("r3", "r3", Access::Read),
            fr("f2", "f2", Access::Read),
            val("imm9a", "imm9a"),
        ],
    ));
    m.formats.push(fmt(
        "FFLP",
        &["qp", "f1", "f2", "r3"],
        vec![
            qp(),
            fr("f1", "f1", Access::Write),
            fr("f2", "f2", Access::Write),
            gr("r3", "r3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FM3",
        &["qp", "r3"],
        vec![qp(), gr("r3", "r3", Access::Read)],
    ));
    m.formats.push(fmt(
        "FLFR",
        &["qp", "r3", "r2"],
        vec![
            qp(),
            gr("r3", "r3", Access::Read),
            gr("r2", "r2", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FLFI",
        &["qp", "r3", "imm9b"],
        vec![
            qp(),
            gr("r3", "r3", Access::Read),
            val("imm9b", "imm9b"),
        ],
    ));
    m.formats.push(fmt(
        "FFA",
        &["qp", "r1", "r3", "inc3"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r3", "r3", Access::Read),
            val("inc3", "inc3"),
        ],
    ));
    m.formats.push(fmt(
        "FRF",
        &["qp", "r1", "f2"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            fr("f2", "f2", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FFR",
        &["qp", "f1", "r2"],
        vec![
            qp(),
            fr("f1", "f1", Access::Write),
            gr("r2", "r2", Access::Read),
        ],
    ));
    // alloc。修飾述語を取らない（qp=0 が固定）。
    m.formats.push(fmt(
        "FALOC",
        &["r1", "sof", "sol", "sor"],
        vec![
            gr("r1", "r1", Access::Write),
            val("sof", "sof"),
            val("sol", "sol"),
            val("sor", "sor"),
        ],
    ));
    m.formats.push(fmt(
        "FPRI2",
        &["qp", "r3", "immu2"],
        vec![qp(), gr("r3", "r3", Access::Read), val("immu2", "immu2")],
    ));
    m.formats.push(fmt(
        "FRTC",
        &["qp", "r1", "tgt25c"],
        vec![
            qp(),
            gr("r1", "r1", Access::Read),
            val("tgt25c", "tgt25c"),
        ],
    ));
    m.formats.push(fmt(
        "FFTC",
        &["qp", "f1", "tgt25c"],
        vec![
            qp(),
            fr("f1", "f1", Access::Read),
            val("tgt25c", "tgt25c"),
        ],
    ));
    m.formats.push(fmt(
        "FFTB",
        &["qp", "f2", "tgt25b"],
        vec![
            qp(),
            fr("f2", "f2", Access::Read),
            val("tgt25b", "tgt25b"),
        ],
    ));
    m.formats.push(fmt(
        "FI24",
        &["qp", "immu24"],
        vec![qp(), val("immu24", "immu24")],
    ));
    // F 系。
    m.formats.push(fmt(
        "FFMA",
        &["qp", "f1", "f3", "f4", "f2"],
        vec![
            qp(),
            fr("f1", "f1", Access::Write),
            fr("f3", "f3", Access::Read),
            fr("f4", "f4", Access::Read),
            fr("f2", "f2", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FFF3",
        &["qp", "f1", "f2", "f3"],
        vec![
            qp(),
            fr("f1", "f1", Access::Write),
            fr("f2", "f2", Access::Read),
            fr("f3", "f3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FPPF",
        &["qp", "p1", "p2", "f2", "f3"],
        vec![
            qp(),
            pr("p1", "p1", Access::Write),
            pr("p2", "p2", Access::Write),
            fr("f2", "f2", Access::Read),
            fr("f3", "f3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FFPFF",
        &["qp", "f1", "p2", "f2", "f3"],
        vec![
            qp(),
            fr("f1", "f1", Access::Write),
            pr("p2", "p2", Access::Read),
            fr("f2", "f2", Access::Read),
            fr("f3", "f3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FFPF",
        &["qp", "f1", "p2", "f3"],
        vec![
            qp(),
            fr("f1", "f1", Access::Write),
            pr("p2", "p2", Access::Read),
            fr("f3", "f3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FPPFI",
        &["qp", "p1", "p2", "f2", "immu9"],
        vec![
            qp(),
            pr("p1", "p1", Access::Write),
            pr("p2", "p2", Access::Write),
            fr("f2", "f2", Access::Read),
            val("immu9", "immu9"),
        ],
    ));
    m.formats.push(fmt(
        "FFF2",
        &["qp", "f1", "f2"],
        vec![
            qp(),
            fr("f1", "f1", Access::Write),
            fr("f2", "f2", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FII7",
        &["qp", "immu7a", "immu7b"],
        vec![qp(), val("immu7a", "immu7a"), val("immu7b", "immu7b")],
    ));
    m.formats.push(fmt(
        "FT25",
        &["qp", "tgt25"],
        vec![qp(), val("tgt25", "tgt25")],
    ));
    // B 系。
    m.formats.push(fmt(
        "FBT25",
        &["qp", "tgt25c"],
        vec![qp(), val("tgt25c", "tgt25c")],
    ));
    m.formats.push(fmt(
        "FBBT",
        &["qp", "b1", "tgt25c"],
        vec![
            qp(),
            br("b1", "b1", Access::Write),
            val("tgt25c", "tgt25c"),
        ],
    ));
    m.formats.push(fmt(
        "FBB",
        &["qp", "b1", "b2"],
        vec![
            qp(),
            br("b1", "b1", Access::Write),
            br("b2", "b2", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FB2",
        &["qp", "b2"],
        vec![qp(), br("b2", "b2", Access::Read)],
    ));
    m.formats.push(fmt(
        "FBPT",
        &["qp", "tgt25c", "tag13"],
        vec![qp(), val("tgt25c", "tgt25c"), val("tag13", "tag13")],
    ));
    // X 系（82 ビット語。word[40:0]=X スロット、word[81:41]=L スロット）。
    m.formats.push(fmt(
        "FXI64",
        &["qp", "r1", "imm64"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            val("imm64", "imm64"),
        ],
    ));
    m.formats.push(fmt(
        "FXI62",
        &["qp", "imm62"],
        vec![qp(), val("imm62", "imm62")],
    ));
    m.formats.push(fmt(
        "FXT60",
        &["qp", "tgt60"],
        vec![qp(), val("tgt60", "tgt60")],
    ));
    m.formats.push(fmt(
        "FXBT",
        &["qp", "b1", "tgt60"],
        vec![
            qp(),
            br("b1", "b1", Access::Write),
            val("tgt60", "tgt60"),
        ],
    ));

    // ---- 命令。`when` の unit_* はスロット文脈（テンプレートが
    // 与える実行ユニット）。パターンは 41 ビットスロット語、
    // X 系のみ 82 ビット語（word[40:0]=X スロット、word[81:41]=L スロット）。
    let ins = |name: &str, format: &str, pattern: &str, when: Pred, syntax: &str, timing: &str| {
        Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when,
            wheres: vec![],
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        }
    };
    let ua = || Pred::Flag("unit_a".to_string());
    let ui = || Pred::Flag("unit_i".to_string());
    let um = || Pred::Flag("unit_m".to_string());
    let uf = || Pred::Flag("unit_f".to_string());
    let ub = || Pred::Flag("unit_b".to_string());
    let ux = || Pred::Flag("unit_x".to_string());
    let ux2 = || {
        Pred::All(vec![
            Pred::Flag("unit_x".to_string()),
            Pred::Flag("itanium2".to_string()),
        ])
    };

    // ---- A 型（I/M スロット共通の整数 ALU・multimedia 系）。
    // A1: 3 項レジスタ演算（Op=8、x2a/ve/x4/x2b が拡張）。
    for (n, pat, syn) in [
        ("add", "1000.000000000...........................", "add {r1} = {r2}, {r3}"),
        ("add_1", "1000.000000001...........................", "add {r1} = {r2}, {r3}, 1"),
        ("sub", "1000.000000101...........................", "sub {r1} = {r2}, {r3}"),
        ("sub_1", "1000.000000100...........................", "sub {r1} = {r2}, {r3}, 1"),
        ("and", "1000.000001100...........................", "and {r1} = {r2}, {r3}"),
        ("andcm", "1000.000001101...........................", "andcm {r1} = {r2}, {r3}"),
        ("or", "1000.000001110...........................", "or {r1} = {r2}, {r3}"),
        ("xor", "1000.000001111...........................", "xor {r1} = {r2}, {r3}"),
        ("addp4", "1000.000001000...........................", "addp4 {r1} = {r2}, {r3}"),
    ] {
        m.insns.push(ins(n, "FRRR", pat, ua(), &format!("({{qp}}) {syn}"), "alu"));
    }
    // A2: imm8 形。
    for (n, pat, syn) in [
        ("sub_imm8", "1000.000100101...........................", "sub {r1} = {imm8}, {r3}"),
        ("and_imm8", "1000.000101100...........................", "and {r1} = {imm8}, {r3}"),
        ("andcm_imm8", "1000.000101101...........................", "andcm {r1} = {imm8}, {r3}"),
        ("or_imm8", "1000.000101110...........................", "or {r1} = {imm8}, {r3}"),
        ("xor_imm8", "1000.000101111...........................", "xor {r1} = {imm8}, {r3}"),
    ] {
        m.insns.push(ins(n, "FRIR", pat, ua(), &format!("({{qp}}) {syn}"), "alu"));
    }
    // A8: shladd（count2a 拡張）。
    m.insns.push(ins(
        "shladd",
        "FRRCR",
        "1000.0000100.............................",
        ua(),
        "({qp}) shladd {r1} = {r2}, {cnt2a}, {r3}",
        "alu",
    ));
    // A3: imm14 形（adds/addp4.i）。A 型の mov r1 = r3 は
    // adds imm14=0 の別名形で、分割即値への where が張れない
    // 現行の ISADL では共存できないため IA5 以降で扱う。
    m.insns.push(ins(
        "adds",
        "FRI14",
        "1000.100.................................",
        ua(),
        "({qp}) adds {r1} = {imm14}, {r3}",
        "alu",
    ));
    m.insns.push(ins(
        "addp4_i",
        "FRI14",
        "1000.110.................................",
        ua(),
        "({qp}) addp4 {r1} = {imm14}, {r3}",
        "alu",
    ));
    // A4: addl（imm22、r3 は r0-r3 に限定される 2 ビット）。
    m.insns.push(ins(
        "addl",
        "FRI22",
        "1001.....................................",
        ua(),
        "({qp}) addl {r1} = {imm22}, {r3_2}",
        "alu",
    ));
    // A6/A7: cmp/cmp4（Op=c/d/e、ta が .unc/.orcm などの拡張）。
    for (n, pat, syn) in [
        ("cmp_lt", "11000000....................0............", "cmp.lt {p1}, {p2} = {r2}, {r3}"),
        ("cmp_eq", "11100000....................0............", "cmp.eq {p1}, {p2} = {r2}, {r3}"),
        ("cmp4_eq", "11100010....................0............", "cmp4.eq {p1}, {p2} = {r2}, {r3}"),
        ("cmp_lt_or", "11000010....................0............", "cmp.lt.or {p1}, {p2} = {r2}, {r3}"),
    ] {
        m.insns.push(ins(n, "FPPRR", pat, ua(), &format!("({{qp}}) {syn}"), "alu"));
    }
    m.insns.push(ins(
        "cmp_eq_i",
        "FPPIR",
        "1110.100....................0............",
        ua(),
        "({qp}) cmp.eq {p1}, {p2} = {imm8}, {r3}",
        "alu",
    ));
    // A9: multimedia ALU（A 型空間に住む並列演算）。
    for (n, pat, syn) in [
        ("padd1", "1000.010000000...........................", "padd1 {r1} = {r2}, {r3}"),
        ("psub1", "1000.010000100...........................", "psub1 {r1} = {r2}, {r3}"),
        ("pcmp4_eq", "1000.101010010...........................", "pcmp4.eq {r1} = {r2}, {r3}"),
    ] {
        m.insns.push(ins(n, "FRRR", pat, ua(), &format!("({{qp}}) {syn}"), "alu"));
    }

    // ---- I 型（整数・制御。Op=0,4,5,7）。
    // I29: break/nop/hint（x6 拡張、immu21）。
    for (n, pat, syn) in [
        ("break_i", "0000.000000000...........................", "break.i {immu21}"),
        ("nop_i", "0000.0000000010..........................", "nop.i {immu21}"),
        ("hint_i", "0000.0000000011..........................", "hint.i {immu21}"),
    ] {
        m.insns.push(ins(n, "FI21", pat, ui(), &format!("({{qp}}) {syn}"), "misc"));
    }
    // I19/I20/I21/I22: 制御・特殊レジスタ移動。
    for (n, fmt_, pat, syn) in [
        ("mov_ip", "FR1", "0000.000110000...........................", "mov {r1} = ip"),
        ("mov_pr", "FR1", "0000.000110011...........................", "mov {r1} = pr"),
        ("mov_from_br", "FRB", "0000.000110001...........................", "mov {r1} = {b2}"),
        ("mov_i_to_ar", "FARR", "0000.000101010...........................", "mov {ar3} = {r2}"),
        ("mov_i_ar_imm", "FARI", "0000.000001010...........................", "mov {ar3} = {imm8}"),
        ("mov_i_from_ar", "FRAR", "0000.000110010...........................", "mov {r1} = {ar3}"),
        ("mov_to_pr", "FRI17", "0000.011.................................", "mov pr = {r2}, {imm17}"),
        ("mov_pr_rot", "FI44", "0000.010.................................", "mov pr.rot = {imm44}"),
        ("mov_ret", "FBRT", "0000.111.........0001....................", "mov.ret {b1} = {r2}, {tag13b}"),
    ] {
        m.insns.push(ins(n, fmt_, pat, ui(), &format!("({{qp}}) {syn}"), "misc"));
    }
    // I18: chk.s.i。
    m.insns.push(ins(
        "chk_s_i",
        "FRT",
        "0000.001.................................",
        ui(),
        "({qp}) chk.s.i {r2}, {tgt25b}",
        "misc",
    ));
    // I26: 符号・ゼロ拡張、桁操作（x6b 拡張）。
    for (n, pat, syn) in [
        ("zxt1", "0000.000010000...........................", "zxt1 {r1} = {r3}"),
        ("sxt1", "0000.000010100...........................", "sxt1 {r1} = {r3}"),
        ("czx1_l", "0000.000011000...........................", "czx1.l {r1} = {r3}"),
        ("clz", "0111001101101............................", "clz {r1} = {r3}"),
        ("popcnt", "0111001101001............................", "popcnt {r1} = {r3}"),
    ] {
        m.insns.push(ins(n, "FRR", pat, ui(), &format!("({{qp}}) {syn}"), "alu"));
    }
    // I27: mux。
    m.insns.push(ins(
        "mux1",
        "FRRM",
        "0111011001010............................",
        ui(),
        "({qp}) mux1 {r1} = {r2}, {mbtype4}",
        "alu",
    ));
    // I15/I16: I-unit multimedia（unpack/mix/pshl）。
    for (n, pat, syn) in [
        ("unpack1_h", "0111010000100............................", "unpack1.h {r1} = {r2}, {r3}"),
        ("mix1_l", "0111010001010............................", "mix1.l {r1} = {r2}, {r3}"),
        ("pshl2", "0111000100100............................", "pshl2 {r1} = {r2}, {r3}"),
    ] {
        m.insns.push(ins(n, "FRRR", pat, ui(), &format!("({{qp}}) {syn}"), "alu"));
    }
    m.insns.push(ins(
        "pshl2_i",
        "FRRC5",
        "0111011100101............................",
        ui(),
        "({qp}) pshl2 {r1} = {r2}, {ccnt5}",
        "alu",
    ));
    // I10/I11/I12/I13/I14: dep/extr/shrp。
    m.insns.push(ins(
        "shrp",
        "FRRRC",
        "0101.110.................................",
        ui(),
        "({qp}) shrp {r1} = {r2}, {r3}, {cnt6}",
        "alu",
    ));
    m.insns.push(ins(
        "extr",
        "FRRPL",
        "0101.010...................1.............",
        ui(),
        "({qp}) extr {r1} = {r3}, {pos6}, {len6}",
        "alu",
    ));
    m.insns.push(ins(
        "dep_z",
        "FRRLL",
        "0101.011......0..........................",
        ui(),
        "({qp}) dep.z {r1} = {r2}, {cpos6a}, {len6}",
        "alu",
    ));
    m.insns.push(ins(
        "dep_z_imm",
        "FRILL",
        "0101.011......1..........................",
        ui(),
        "({qp}) dep.z {r1} = {imm8}, {cpos6a}, {len6}",
        "alu",
    ));
    m.insns.push(ins(
        "dep",
        "FRRRLL",
        "0100.....................................",
        ui(),
        "({qp}) dep {r1} = {r2}, {r3}, {cpos6c}, {len4}",
        "alu",
    ));
    m.insns.push(ins(
        "dep_imm",
        "FRIRLL",
        "0101.111.................................",
        ui(),
        "({qp}) dep {r1} = {imm1}, {r3}, {cpos6b}, {len6}",
        "alu",
    ));
    // I30/I31: テストビット・NaT テスト。
    m.insns.push(ins(
        "tbit_z",
        "FPPRP",
        "01010000...................00............",
        ui(),
        "({qp}) tbit.z {p1}, {p2} = {r3}, {pos6}",
        "alu",
    ));
    m.insns.push(ins(
        "tnat_z",
        "FPPR",
        "01010000...................10............",
        ui(),
        "({qp}) tnat.z {p1}, {p2} = {r3}",
        "alu",
    ));

    // ---- M 型（メモリ・システム。Op=0,1,4,5,6,7）。
    // M1: 整数ロード（x6 拡張でサイズ・完了子）。
    for (n, pat, syn) in [
        ("ld1", "01000000000000...........................", "ld1 {r1} = [{r3}]"),
        ("ld2", "01000000001000...........................", "ld2 {r1} = [{r3}]"),
        ("ld4", "01000000010000...........................", "ld4 {r1} = [{r3}]"),
        ("ld8", "01000000011000...........................", "ld8 {r1} = [{r3}]"),
        ("ld8_fill", "01000011011000...........................", "ld8.fill {r1} = [{r3}]"),
        ("ld1_a", "01000001000000...........................", "ld1.a {r1} = [{r3}]"),
        ("ld1_c_nc", "01000100100000...........................", "ld1.c.nc {r1} = [{r3}]"),
        ("ld16", "01000101000001...........................", "ld16 {r1} = ar.csd, [{r3}]"),
    ] {
        m.insns.push(ins(n, "FRR", pat, um(), &format!("({{qp}}) {syn}"), "load"));
    }
    // M2/M3: post-increment（r2 / imm9）。
    m.insns.push(ins(
        "ld8_r",
        "FLDR",
        "01001000011000...........................",
        um(),
        "({qp}) ld8 {r1} = [{r3}], {r2}",
        "load",
    ));
    m.insns.push(ins(
        "ld8_i",
        "FLDI",
        "0101.00001100............................",
        um(),
        "({qp}) ld8 {r1} = [{r3}], {imm9b}",
        "load",
    ));
    // M4: ストア。
    for (n, pat, syn) in [
        ("st1", "01000110000000...........................", "st1 [{r3}] = {r2}"),
        ("st2", "01000110001000...........................", "st2 [{r3}] = {r2}"),
        ("st4", "01000110010000...........................", "st4 [{r3}] = {r2}"),
        ("st8", "01000110011000...........................", "st8 [{r3}] = {r2}"),
        ("st8_spill", "01000111011000...........................", "st8.spill [{r3}] = {r2}"),
        ("st16", "01000110000001...........................", "st16 [{r3}] = {r2}, ar.csd"),
    ] {
        m.insns.push(ins(n, "FSTR", pat, um(), &format!("({{qp}}) {syn}"), "store"));
    }
    m.insns.push(ins(
        "st8_i",
        "FSTI",
        "0101.11001100............................",
        um(),
        "({qp}) st8 [{r3}] = {r2}, {imm9a}",
        "store",
    ));
    // M17/M16: セマフォ。
    m.insns.push(ins(
        "xchg4",
        "FLDR",
        "01000001010001...........................",
        um(),
        "({qp}) xchg4 {r1} = [{r3}], {r2}",
        "load",
    ));
    m.insns.push(ins(
        "fetchadd4_acq",
        "FFA",
        "01000010010001...........................",
        um(),
        "({qp}) fetchadd4.acq {r1} = [{r3}], {inc3}",
        "load",
    ));
    // M22/M25: probe。
    m.insns.push(ins(
        "probe_r",
        "FLDR",
        "0001.000111000...........................",
        um(),
        "({qp}) probe.r {r1} = {r3}, {r2}",
        "misc",
    ));
    m.insns.push(ins(
        "probe_w_fault",
        "FPRI2",
        "0001.000110011...........................",
        um(),
        "({qp}) probe.w.fault {r3}, {immu2}",
        "misc",
    ));
    // M5/M7/M8: FP ロード。
    for (n, pat, syn) in [
        ("ldfe", "01100000000000...........................", "ldfe {f1} = [{r3}]"),
        ("ldf8", "01100000001000...........................", "ldf8 {f1} = [{r3}]"),
        ("ldfs", "01100000010000...........................", "ldfs {f1} = [{r3}]"),
        ("ldfd", "01100000011000...........................", "ldfd {f1} = [{r3}]"),
        ("ldf_fill", "01100011011000...........................", "ldf.fill {f1} = [{r3}]"),
    ] {
        m.insns.push(ins(n, "FFLD", pat, um(), &format!("({{qp}}) {syn}"), "load"));
    }
    m.insns.push(ins(
        "ldfs_r",
        "FFLDR",
        "01101000010000...........................",
        um(),
        "({qp}) ldfs {f1} = [{r3}], {r2}",
        "load",
    ));
    m.insns.push(ins(
        "ldfs_i",
        "FFLDI",
        "0111.00001000............................",
        um(),
        "({qp}) ldfs {f1} = [{r3}], {imm9b}",
        "load",
    ));
    // M9/M11: FP ストア。
    for (n, pat, syn) in [
        ("stfe", "01100110000000...........................", "stfe [{r3}] = {f2}"),
        ("stf8", "01100110001000...........................", "stf8 [{r3}] = {f2}"),
        ("stfs", "01100110010000...........................", "stfs [{r3}] = {f2}"),
        ("stfd", "01100110011000...........................", "stfd [{r3}] = {f2}"),
        ("stf_spill", "01100111011000...........................", "stf.spill [{r3}] = {f2}"),
    ] {
        m.insns.push(ins(n, "FFST", pat, um(), &format!("({{qp}}) {syn}"), "store"));
    }
    m.insns.push(ins(
        "stf8_i",
        "FFSTI",
        "0111.11000100............................",
        um(),
        "({qp}) stf8 [{r3}] = {f2}, {imm9a}",
        "store",
    ));
    // M12: FP ペアロード。
    m.insns.push(ins(
        "ldfp8",
        "FFLP",
        "01100000001001...........................",
        um(),
        "({qp}) ldfp8 {f1}, {f2} = [{r3}]",
        "load",
    ));
    // M13-M15: lfetch。
    for (n, pat, syn) in [
        ("lfetch", "01100101100000.......0......0............", "lfetch [{r3}]"),
        ("lfetch_excl", "01100101101000..............0............", "lfetch.excl [{r3}]"),
        ("lfetch_fault", "01100101110000..............0............", "lfetch.fault [{r3}]"),
    ] {
        m.insns.push(ins(n, "FM3", pat, um(), &format!("({{qp}}) {syn}"), "load"));
    }
    m.insns.push(ins(
        "lfetch_r",
        "FLFR",
        "01101101100000..............0............",
        um(),
        "({qp}) lfetch [{r3}], {r2}",
        "load",
    ));
    m.insns.push(ins(
        "lfetch_i",
        "FLFI",
        "0111.10110000...............0............",
        um(),
        "({qp}) lfetch [{r3}], {imm9b}",
        "load",
    ));
    // M18/M19: getf/setf。
    m.insns.push(ins(
        "getf_sig",
        "FRF",
        "01000011100..1...........................",
        um(),
        "({qp}) getf.sig {r1} = {f2}",
        "misc",
    ));
    m.insns.push(ins(
        "getf_d",
        "FRF",
        "01000011111..1...........................",
        um(),
        "({qp}) getf.d {r1} = {f2}",
        "misc",
    ));
    m.insns.push(ins(
        "setf_sig",
        "FFR",
        "01100011100..1...........................",
        um(),
        "({qp}) setf.sig {f1} = {r2}",
        "misc",
    ));
    m.insns.push(ins(
        "setf_d",
        "FFR",
        "01100011111..1...........................",
        um(),
        "({qp}) setf.d {f1} = {r2}",
        "misc",
    ));
    m.insns.push(ins(
        "setf_exp",
        "FFR",
        "01100011101..1...........................",
        um(),
        "({qp}) setf.exp {f1} = {r2}",
        "misc",
    ));
    // M30/M31: mov.{m} の AR/特別レジスタ移動。
    for (n, fmt_, pat, syn) in [
        ("mov_m_to_ar", "FARR", "0001.000101010...........................", "mov {ar3} = {r2}"),
        ("mov_m_ar_imm", "FARI", "0000.000101000...........................", "mov {ar3} = {imm8}"),
        ("mov_m_from_ar", "FRAR", "0001.000100010...........................", "mov {r1} = {ar3}"),
        ("mov_psr_um", "FR1", "0001.000100001...........................", "mov {r1} = psr.um"),
        ("mov_cpuid", "FRR", "0001.000010111...........................", "mov {r1} = cpuid[{r3}]"),
    ] {
        m.insns.push(ins(n, fmt_, pat, um(), &format!("({{qp}}) {syn}"), "misc"));
    }
    // M20: alloc（修飾述語を取らず qp=0 が固定）。
    m.insns.push(ins(
        "alloc",
        "FALOC",
        "0001.110...........................000000",
        um(),
        "alloc {r1} = ar.pfs, {sof}, {sol}, {sor}",
        "misc",
    ));
    // M21/M27: RSE 制御（qp=0 が固定）。
    for (n, pat, syn) in [
        ("flushrs", "0000.000001100.....................000000", "flushrs"),
        ("loadrs", "0000.000001010.....................000000", "loadrs"),
    ] {
        m.insns.push(ins(n, "F0U", pat, um(), syn, "misc"));
    }
    // M23: chk.s.m / chk.a / chk.s(fp)。
    m.insns.push(ins(
        "chk_s_m",
        "FRT",
        "0001.001.................................",
        um(),
        "({qp}) chk.s.m {r2}, {tgt25b}",
        "misc",
    ));
    m.insns.push(ins(
        "chk_s",
        "FFTB",
        "0001.011.................................",
        um(),
        "({qp}) chk.s {f2}, {tgt25b}",
        "misc",
    ));
    m.insns.push(ins(
        "chk_a_nc",
        "FRTC",
        "0000.100.................................",
        um(),
        "({qp}) chk.a.nc {r1}, {tgt25c}",
        "misc",
    ));
    m.insns.push(ins(
        "chk_a_nc_f",
        "FFTC",
        "0000.110.................................",
        um(),
        "({qp}) chk.a.nc {f1}, {tgt25c}",
        "misc",
    ));
    // M24/M26/M28/M29/M30: システム系 misc。
    for (n, pat, syn) in [
        ("invala", "0000.000010000...........................", "invala"),
        ("fwb", "0000.000100000...........................", "fwb"),
        ("mf", "0000.000100010...........................", "mf"),
        ("mf_a", "0000.000100011...........................", "mf.a"),
        ("srlz_d", "0000.000110000...........................", "srlz.d"),
        ("srlz_i", "0000.000110001...........................", "srlz.i"),
        ("sync_i", "0000.000110011...........................", "sync.i"),
    ] {
        m.insns.push(ins(n, "F0", pat, um(), &format!("({{qp}}) {syn}"), "misc"));
    }
    m.insns.push(ins(
        "fc",
        "FM3",
        "00010000110000...........................",
        um(),
        "({qp}) fc {r3}",
        "misc",
    ));
    m.insns.push(ins(
        "sum",
        "FI24",
        "0000.000..0100...........................",
        um(),
        "({qp}) sum {immu24}",
        "system",
    ));
    m.insns.push(ins(
        "rum",
        "FI24",
        "0000.000..0101...........................",
        um(),
        "({qp}) rum {immu24}",
        "system",
    ));

    // ---- F 型（浮動小数点。Op=0,1,4,5,8,9,a-e）。
    // F10: 4 項 FP 演算（fma 系・xma 系・fselect）。
    for (n, pat, syn) in [
        ("fma_s0", "1000000..................................", "fma.s0 {f1} = {f3}, {f4}, {f2}"),
        ("fma_d_s0", "1001000..................................", "fma.d.s0 {f1} = {f3}, {f4}, {f2}"),
        ("fms_s0", "1010000..................................", "fms.s0 {f1} = {f3}, {f4}, {f2}"),
        ("fnma_s0", "1100000..................................", "fnma.s0 {f1} = {f3}, {f4}, {f2}"),
        ("fselect", "11100....................................", "fselect {f1} = {f3}, {f4}, {f2}"),
        ("xma_l", "1110100..................................", "xma.l {f1} = {f3}, {f4}, {f2}"),
        ("xma_h", "1110111..................................", "xma.h {f1} = {f3}, {f4}, {f2}"),
        ("xma_hu", "1110110..................................", "xma.hu {f1} = {f3}, {f4}, {f2}"),
    ] {
        m.insns.push(ins(n, "FFMA", pat, uf(), &format!("({{qp}}) {syn}"), "fp"));
    }
    // F7: 3 項 FP 演算・論理・マージ。
    for (n, pat, syn) in [
        ("fmin_s0", "0000.000010100...........................", "fmin.s0 {f1} = {f2}, {f3}"),
        ("fmax_s0", "0000.000010101...........................", "fmax.s0 {f1} = {f2}, {f3}"),
        ("famin_s0", "0000.000010110...........................", "famin.s0 {f1} = {f2}, {f3}"),
        ("famax_s0", "0000.000010111...........................", "famax.s0 {f1} = {f2}, {f3}"),
        ("fmerge_s", "0000...0010000...........................", "fmerge.s {f1} = {f2}, {f3}"),
        ("fmerge_se", "0000...0010001...........................", "fmerge.se {f1} = {f2}, {f3}"),
        ("fand", "0000...0101100...........................", "fand {f1} = {f2}, {f3}"),
        ("fandcm", "0000...0101101...........................", "fandcm {f1} = {f2}, {f3}"),
        ("for", "0000...0101110...........................", "for {f1} = {f2}, {f3}"),
        ("fxor", "0000...0101111...........................", "fxor {f1} = {f2}, {f3}"),
        ("fpack", "0000...0101000...........................", "fpack {f1} = {f2}, {f3}"),
        ("fswap", "0000...0110100...........................", "fswap {f1} = {f2}, {f3}"),
        ("fswap_nl", "0000...0110101...........................", "fswap.nl {f1} = {f2}, {f3}"),
        ("fmix_l", "0000...0111011...........................", "fmix.l {f1} = {f2}, {f3}"),
        ("fmix_r", "0000...0111010...........................", "fmix.r {f1} = {f2}, {f3}"),
        ("fsxt_l", "0000...0111101...........................", "fsxt.l {f1} = {f2}, {f3}"),
        ("fsxt_r", "0000...0111100...........................", "fsxt.r {f1} = {f2}, {f3}"),
        ("fpcmp_eq_s0", "0001.000110000...........................", "fpcmp.eq.s0 {f1} = {f2}, {f3}"),
    ] {
        m.insns.push(ins(n, "FFF3", pat, uf(), &format!("({{qp}}) {syn}"), "fp"));
    }
    // F8: FP 比較。
    for (n, pat, syn) in [
        ("fcmp_eq_s0", "01000000....................0............", "fcmp.eq.s0 {p1}, {p2} = {f2}, {f3}"),
        ("fcmp_lt_s0", "01001000....................0............", "fcmp.lt.s0 {p1}, {p2} = {f2}, {f3}"),
        ("fcmp_eq_unc_s0", "01000000....................1............", "fcmp.eq.unc.s0 {p1}, {p2} = {f2}, {f3}"),
    ] {
        m.insns.push(ins(n, "FPPF", pat, uf(), &format!("({{qp}}) {syn}"), "fp"));
    }
    // F5: fclass。
    m.insns.push(ins(
        "fclass_m",
        "FPPFI",
        "0101........................0............",
        uf(),
        "({qp}) fclass.m {p1}, {p2} = {f2}, {immu9}",
        "fp",
    ));
    // F6: 近似・逆数。
    m.insns.push(ins(
        "frcpa_s0",
        "FFPFF",
        "00000001.................................",
        uf(),
        "({qp}) frcpa.s0 {f1}, {p2} = {f2}, {f3}",
        "fp",
    ));
    m.insns.push(ins(
        "frsqrta_s0",
        "FFPF",
        "00001001.................................",
        uf(),
        "({qp}) frsqrta.s0 {f1}, {p2} = {f3}",
        "fp",
    ));
    // F8/F9: 変換。
    for (n, pat, syn) in [
        ("fcvt_fx_s0", "0000.000011000...........................", "fcvt.fx.s0 {f1} = {f2}"),
        ("fcvt_fx_trunc_s0", "0000.000011010...........................", "fcvt.fx.trunc.s0 {f1} = {f2}"),
        ("fcvt_xf", "0000...0011100...........................", "fcvt.xf {f1} = {f2}"),
        ("fpcvt_fx_s0", "0001.000011000...........................", "fpcvt.fx.s0 {f1} = {f2}"),
    ] {
        m.insns.push(ins(n, "FFF2", pat, uf(), &format!("({{qp}}) {syn}"), "fp"));
    }
    // F11: fsetc（am/sf 制御）。
    m.insns.push(ins(
        "fsetc_s0",
        "FII7",
        "0000.000000100...........................",
        uf(),
        "({qp}) fsetc.s0 {immu7a}, {immu7b}",
        "fp",
    ));
    // F12: fclrf。
    m.insns.push(ins(
        "fclrf_s0",
        "F0",
        "0000.000000101...........................",
        uf(),
        "({qp}) fclrf.s0",
        "fp",
    ));
    // F13: fchkf。
    m.insns.push(ins(
        "fchkf_s0",
        "FT25",
        "0000.000001000...........................",
        uf(),
        "({qp}) fchkf.s0 {tgt25}",
        "misc",
    ));
    // F14/F15: FP break/nop/hint。
    for (n, pat, syn) in [
        ("break_f", "0000...0000000...........................", "break.f {immu21}"),
        ("nop_f", "0000...00000010..........................", "nop.f {immu21}"),
        ("hint_f", "0000...00000011..........................", "hint.f {immu21}"),
    ] {
        m.insns.push(ins(n, "FI21", pat, uf(), &format!("({{qp}}) {syn}"), "misc"));
    }

    // ---- B 型（分岐。Op=0,1,2,4,5,7）。
    // B9: break/nop/hint（OpX6、immu21）。
    for (n, pat, syn) in [
        ("break_b", "0000....000000...........................", "break.b {immu21}"),
        ("nop_b", "0010....000000...........................", "nop.b {immu21}"),
        ("hint_b", "0010....000001...........................", "hint.b {immu21}"),
    ] {
        m.insns.push(ins(n, "FI21", pat, ub(), &format!("({{qp}}) {syn}"), "misc"));
    }
    // B0: cover/clrrb（qp=0 が固定、LAST を示す）。
    for (n, pat, syn) in [
        ("cover", "0000....000010.....................000000", "cover"),
        ("clrrb", "0000....000100.....................000000", "clrrb"),
        ("clrrb_pr", "0000....000101.....................000000", "clrrb.pr"),
    ] {
        m.insns.push(ins(n, "F0U", pat, ub(), syn, "system"));
    }
    // B1/B2: IP 相対分岐（btype/d/pa/wha 拡張、tgt25c）。
    m.insns.push(ins(
        "br_cond_sptk_few",
        "FBT25",
        "0100.000....................0...000......",
        ub(),
        "({qp}) br.cond.sptk.few {tgt25c}",
        "branch",
    ));
    m.insns.push(ins(
        "br_cloop_sptk_few",
        "FBT25",
        "0100.000....................0...101......",
        ub(),
        "({qp}) br.cloop.sptk.few {tgt25c}",
        "branch",
    ));
    // B3: IP 相対 call（b1 にリンク、tgt25c）。
    m.insns.push(ins(
        "br_call_sptk_few",
        "FBBT",
        "0101.000....................0............",
        ub(),
        "({qp}) br.call.sptk.few {b1} = {tgt25c}",
        "branch",
    ));
    // B4: 間接 return（x6=0x21、btype=4）。
    m.insns.push(ins(
        "br_ret_sptk_few",
        "FB2",
        "0000.000100001..............0...100......",
        ub(),
        "({qp}) br.ret.sptk.few {b2}",
        "branch",
    ));
    // B5: 間接 call（Op=1、pa/whc/d 拡張）。
    m.insns.push(ins(
        "br_call_ind_sptk_few",
        "FBB",
        "0001.0001...................0............",
        ub(),
        "({qp}) br.call.sptk.few {b1} = {b2}",
        "branch",
    ));
    // B6/B7: brp（分岐ヒント。IP 相対）。
    m.insns.push(ins(
        "brp_sptk",
        "FBPT",
        "0111.0..............................00...",
        ub(),
        "({qp}) brp.sptk {tgt25c}, {tag13}",
        "misc",
    ));

    // ---- X 型（82 ビット語。MLX テンプレートの L+X スロット。
    // word[40:0] が X スロット（slot2）、word[81:41] が L スロット
    // （slot1））。
    // X1: movl（64 ビット即値ロード）。
    m.insns.push(ins(
        "movl",
        "FXI64",
        ".........................................0110................0....................",
        ux(),
        "({qp}) movl {r1} = {imm64}",
        "alu",
    ));
    // X2: break.x/nop.x/hint.x（imm62 は X スロット全体を使う）。
    for (n, lpart, syn) in [
        ("break_x", "0000.000000000...........................", "break.x {imm62}"),
        ("nop_x", "0000.0000000010..........................", "nop.x {imm62}"),
        ("hint_x", "0000.0000000011..........................", "hint.x {imm62}"),
    ] {
        let pat = format!(".........................................{lpart}");
        m.insns.push(ins(n, "FXI62", &pat, ux(), &format!("({{qp}}) {syn}"), "misc"));
    }
    // X3/X4: 長距離分岐（Itanium 2 で追加。tgt60 は X[40:2]+
    // L の tgt 部分、word[42:41] は 0 固定）。
    m.insns.push(ins(
        "brl_cond_sptk_few",
        "FXT60",
        ".......................................001100.000....................0............",
        ux2(),
        "({qp}) brl.cond.sptk.few {tgt60}",
        "branch",
    ));
    m.insns.push(ins(
        "brl_call_sptk_few",
        "FXBT",
        ".......................................001101.000....................0............",
        ux2(),
        "({qp}) brl.call.sptk.few {b1} = {tgt60}",
        "branch",
    ));

    m
}
