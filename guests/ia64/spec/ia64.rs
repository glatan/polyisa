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
        "alu", "load", "store", "branch", "system", "fp", "misc", "mem",
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
    // - `poulson`: Itanium 9500 系（Poulson）で追加された命令群
    //   （clz, mpy4, mpyshl4）。`itanium2` を含意する。正本 Rev 2.3
    //   には未収録で、実装依存の追加命令として版差の旗を分ける。
    // - `unit_*`: デコード文脈旗。CPU 世代ではなく、テンプレートが
    //   各スロットに割り当てる実行ユニットの文脈を `when` に写す
    //   もの（上記のモデル注記を参照）。A 型は I/M 両スロットに
    //   適合するため unit_a は unit_i/unit_m と両立し、それ以外の
    //   スロット種別は互いに衝突する。衝突は対の片側に一度だけ
    //   宣言する（検査側は両方向を同じ対として扱うため、
    //   unit_f 側に unit_i/unit_m を再掲する必要はない）。
    // Ref: SPEC-IA64-SDM (Rev 2.3).
    for (name, implies, conflicts) in [
        ("itanium", &[][..], &[][..]),
        ("itanium2", &["itanium"][..], &[][..]),
        ("poulson", &["itanium2"][..], &[][..]),
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
    // Itanium 2 系（9700 系をこの範囲の最終として含め、9500 系の
    // poulson 追加命令も入れる）。
    // unit_* は文脈旗なのでモデルには含めない。
    for (name, parent, add) in [
        ("generic", "", &["itanium"][..]),
        ("itanium2", "generic", &["itanium2", "poulson"][..]),
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
        ("mbtype4", 23, 20), // mux1 のバイト型
        ("mhtype8", 27, 20), // mux2 のハーフワード型
        ("cnt2b", 28, 27),   // pshladd/pshradd のシフト量 1-3
        ("ct2d", 31, 30),    // pmpyshr2 のシフト量選択子 {0,7,15,16}
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
        // addl の imm22 は s|imm5c|imm9d|imm7b の順（imm5c が
        // 語内では imm9d より下位にあるが論理値では上位。語内
        // 位置順に並べると符号位置がずれる点に注意）。
        ("imm22", vec![(36, 36), (26, 22), (35, 27), (19, 13)], 0), // addl
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
        "FRRM8",
        &["qp", "r1", "r2", "mhtype8"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r2", "r2", Access::Read),
            val("mhtype8", "mhtype8"),
        ],
    ));
    m.formats.push(fmt(
        "FRRC2",
        &["qp", "r1", "r2", "r3", "ct2d"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r2", "r2", Access::Read),
            gr("r3", "r3", Access::Read),
            val("ct2d", "ct2d"),
        ],
    ));
    m.formats.push(fmt(
        "FRR5",
        &["qp", "r1", "r3", "cnt5"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r3", "r3", Access::Read),
            val("cnt5", "cnt5"),
        ],
    ));
    m.formats.push(fmt(
        "FRRCR2",
        &["qp", "r1", "r2", "cnt2b", "r3"],
        vec![
            qp(),
            gr("r1", "r1", Access::Write),
            gr("r2", "r2", Access::Read),
            val("cnt2b", "cnt2b"),
            gr("r3", "r3", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FPPI5",
        &["qp", "p1", "p2", "immu5b"],
        vec![
            qp(),
            pr("p1", "p1", Access::Write),
            pr("p2", "p2", Access::Write),
            val("immu5b", "immu5b"),
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
    m.formats.push(fmt(
        "FB2T",
        &["b2", "tag13"],
        vec![br("b2", "b2", Access::Read), val("tag13", "tag13")],
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
    let poulson_i = || {
        Pred::All(vec![
            Pred::Flag("unit_i".to_string()),
            Pred::Flag("poulson".to_string()),
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
    // A6/A7: cmp/cmp4（Op=c/d/e）。
    // 形式は x2 で決まる: 0=cmp レジスタ形、1=cmp4 レジスタ形、
    // 2=cmp 即値形、3=cmp4 即値形。tb=1 は並列不等号形（第一ソースが
    // 建築的に r0、r2 桁 [19:13] は 0 固定）で、imm 形では tb は
    // imm8 の符号ビットになる（区別は x2 が担う）。
    // (ta, c) の意味: 非並列形は ta=0 で正規(c=0)/.unc(c=1)、
    // ta=1 で型更新の eq(c=0)/ne(c=1)。並列形は (ta,c) が
    // r3 と 0 の符号付き関係を選ぶ（lt(0,0), ge(0,1), le(1,0),
    // gt(1,1)。建築上の左辺は 0 だが、本モデルは正本 Table2-17 の
    // 疑似形式（「a rel 0」のオペランド交換行）に合わせて
    // "cmp.X p1,p2 = r3, r0" の綴りを採る）。
    for (op, rel, ty) in [
        ("1100", "lt", "and"),       // 符号付き lt 系・.and 型
        ("1101", "ltu", "or"),       // 符号なし lt 系・.or 型
        ("1110", "eq", "or.andcm"),  // 等号系・.or.andcm 型
    ] {
        let ty_s = ty.replace('.', "_");
        for (x2s, w4) in [("00", ""), ("01", "4")] {
            let pfx = format!("cmp{w4}");
            // 非並列（tb=0）: 正規/unc（ta=0）と eq/ne 型更新（ta=1）。
            for (ta, c, rn, sfx) in [
                ("0", "0", rel, ""),
                ("0", "1", rel, ".unc"),
                ("1", "0", "eq", ty),
                ("1", "1", "ne", ty),
            ] {
                let rsfx = if sfx.is_empty() {
                    String::new()
                } else {
                    format!(".{}", sfx.trim_start_matches('.'))
                };
                let nsfx = ty_s.replace('.', "_");
                let name = if ta == "0" {
                    format!("{pfx}_{rn}{}", sfx.replace('.', "_"))
                } else {
                    format!("{pfx}_{rn}_{nsfx}")
                };
                let pat = format!("{op}0{x2s}{ta}....................{c}............");
                let syn = format!("{pfx}.{rn}{rsfx} {{p1}}, {{p2}} = {{r2}}, {{r3}}");
                m.insns.push(ins(&name, "FPPRR", &pat, ua(), &format!("({{qp}}) {syn}"), "alu"));
            }
            // 並列（tb=1、r2=0 固定）: r3 vs 0 の符号付き不等号。
            for (ta, c, prn) in [
                ("0", "0", "lt"),
                ("0", "1", "ge"),
                ("1", "0", "le"),
                ("1", "1", "gt"),
            ] {
                let name = format!("{pfx}_{prn}_{ty_s}");
                let pat = format!("{op}1{x2s}{ta}.............0000000{c}............");
                let syn = format!("{pfx}.{prn}.{ty} {{p1}}, {{p2}} = {{r3}}, r0");
                m.insns.push(ins(&name, "FPPR", &pat, ua(), &format!("({{qp}}) {syn}"), "alu"));
            }
        }
        // 即値形（x2=2,3）: tb は imm8 の一部なので '.' のまま。
        for (x2s, w4) in [("10", ""), ("11", "4")] {
            let pfx = format!("cmp{w4}");
            for (ta, c, rn, sfx) in [
                ("0", "0", rel, ""),
                ("0", "1", rel, ".unc"),
                ("1", "0", "eq", ty),
                ("1", "1", "ne", ty),
            ] {
                let rsfx = if sfx.is_empty() {
                    String::new()
                } else {
                    format!(".{}", sfx.trim_start_matches('.'))
                };
                let nsfx = ty_s.replace('.', "_");
                let name = if ta == "0" {
                    format!("{pfx}_{rn}{}_i", sfx.replace('.', "_"))
                } else {
                    format!("{pfx}_{rn}_{nsfx}_i")
                };
                let pat = format!("{op}.{x2s}{ta}....................{c}............");
                let syn = format!("{pfx}.{rn}{rsfx} {{p1}}, {{p2}} = {{imm8}}, {{r3}}");
                m.insns.push(ins(&name, "FPPIR", &pat, ua(), &format!("({{qp}}) {syn}"), "alu"));
            }
        }
    }
    // A9: multimedia ALU（A 型空間に住む並列演算）。x2a=1 固定、
    // za が要素幅（0=1/2 バイト、1=4 バイト）、zb が 1↔2 バイト、
    // x4 が演算種別、x2b が完了子。符号なし加減算・平均・比較のみ
    // （飽和形 padd.sss 等は要素幅の飽和処理を後段に譲り IA5 では
    // 宣言しない）。
    for (n, pat, syn) in [
        ("padd1", "10000010000000...........................", "padd1 {r1} = {r2}, {r3}"),
        ("padd2", "10000011000000...........................", "padd2 {r1} = {r2}, {r3}"),
        ("padd4", "10001010000000...........................", "padd4 {r1} = {r2}, {r3}"),
        ("psub1", "10000010000100...........................", "psub1 {r1} = {r2}, {r3}"),
        ("psub2", "10000011000100...........................", "psub2 {r1} = {r2}, {r3}"),
        ("psub4", "10001010000100...........................", "psub4 {r1} = {r2}, {r3}"),
        ("pavg1", "10000010001010...........................", "pavg1 {r1} = {r2}, {r3}"),
        ("pavg2", "10000011001010...........................", "pavg2 {r1} = {r2}, {r3}"),
        ("pavg1_raz", "10000010001011...........................", "pavg1.raz {r1} = {r2}, {r3}"),
        ("pavg2_raz", "10000011001011...........................", "pavg2.raz {r1} = {r2}, {r3}"),
        ("pavgsub1", "10000010001110...........................", "pavgsub1 {r1} = {r2}, {r3}"),
        ("pavgsub2", "10000011001110...........................", "pavgsub2 {r1} = {r2}, {r3}"),
        ("pcmp1_eq", "10000010100100...........................", "pcmp1.eq {r1} = {r2}, {r3}"),
        ("pcmp2_eq", "10000011100100...........................", "pcmp2.eq {r1} = {r2}, {r3}"),
        ("pcmp4_eq", "10001010100100...........................", "pcmp4.eq {r1} = {r2}, {r3}"),
        ("pcmp1_gt", "10000010100101...........................", "pcmp1.gt {r1} = {r2}, {r3}"),
        ("pcmp2_gt", "10000011100101...........................", "pcmp2.gt {r1} = {r2}, {r3}"),
        ("pcmp4_gt", "10001010100101...........................", "pcmp4.gt {r1} = {r2}, {r3}"),
    ] {
        m.insns.push(ins(n, "FRRR", pat, ua(), &format!("({{qp}}) {syn}"), "alu"));
    }
    // A5: pshladd2/pshradd2（16 ビット要素のシフト＋加算。
    // cnt2b は 1-3 の直接値）。
    for (n, pat, syn) in [
        ("pshladd2", "100000110100.............................", "pshladd2 {r1} = {r2}, {cnt2b}, {r3}"),
        ("pshradd2", "100000110110.............................", "pshradd2 {r1} = {r2}, {cnt2b}, {r3}"),
    ] {
        m.insns.push(ins(n, "FRRCR2", pat, ua(), &format!("({{qp}}) {syn}"), "alu"));
    }
    // A2: shladdp4（shladd の 32 ビットポインタ形）。
    m.insns.push(ins(
        "shladdp4",
        "FRRCR",
        "1000.0000110.............................",
        ua(),
        "({qp}) shladdp4 {r1} = {r2}, {cnt2a}, {r3}",
        "alu",
    ));

    // ---- I 型（整数・制御。Op=0,4,5,7）。
    // I29: break/nop/hint（x6 拡張、immu21）。
    for (n, pat, syn) in [
        ("break_i", "0000.000000000...........................", "break.i {immu21}"),
        ("nop_i", "0000.0000000010..........................", "nop.i {immu21}"),
        ("hint_i", "0000.0000000011..........................", "hint.i {immu21}"),
    ] {
        m.insns.push(ins(n, "FI21", pat, ui(), &format!("({{qp}}) {syn}"), "misc"));
    }
    // I21-I29: 制御・特殊レジスタ移動。x6/x3 拡張は OpX3X6/OpX3 の
    // 正本マクロに対応（b1 は [8:6]、b2 は [15:13]、tag13b は
    // [32:24] zfill4）。
    for (n, fmt_, pat, syn) in [
        ("mov_ip", "FR1", "0000.000110000...........................", "mov {r1} = ip"),
        ("mov_pr", "FR1", "0000.000110011...........................", "mov {r1} = pr"),
        ("mov_from_br", "FRB", "0000.000110001...........................", "mov {r1} = {b2}"),
        ("mov_i_to_ar", "FARR", "0000.000101010...........................", "mov {ar3} = {r2}"),
        ("mov_i_ar_imm", "FARI", "0000.000001010...........................", "mov {ar3} = {imm8}"),
        ("mov_i_from_ar", "FRAR", "0000.000110010...........................", "mov {r1} = {ar3}"),
        ("mov_to_pr", "FRI17", "0000.011.................................", "mov pr = {r2}, {imm17}"),
        ("mov_pr_rot", "FI44", "0000.010.................................", "mov pr.rot = {imm44}"),
        // OpX3XbIhWh(0,7,xb,0,1): mov to BR。xb=0 が通常 mov、
        // xb=1 が mov.ret（分岐予報タグつき復帰 mov）。ih=0・wh=1
        // を固定する。
        ("mov_br", "FBRT", "0000.111.........0001....................", "mov {b1} = {r2}, {tag13b}"),
        ("mov_ret", "FBRT", "0000.111.........0101....................", "mov.ret {b1} = {r2}, {tag13b}"),
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
    // I29: 符号・ゼロ拡張、桁操作（OpX3X6(0,0,x6) 拡張）。
    for (n, pat, syn) in [
        ("zxt1", "0000.000010000...........................", "zxt1 {r1} = {r3}"),
        ("zxt2", "0000.000010001...........................", "zxt2 {r1} = {r3}"),
        ("zxt4", "0000.000010010...........................", "zxt4 {r1} = {r3}"),
        ("sxt1", "0000.000010100...........................", "sxt1 {r1} = {r3}"),
        ("sxt2", "0000.000010101...........................", "sxt2 {r1} = {r3}"),
        ("sxt4", "0000.000010110...........................", "sxt4 {r1} = {r3}"),
        ("czx1_l", "0000.000011000...........................", "czx1.l {r1} = {r3}"),
        ("czx2_l", "0000.000011001...........................", "czx2.l {r1} = {r3}"),
        ("czx1_r", "0000.000011100...........................", "czx1.r {r1} = {r3}"),
        ("czx2_r", "0000.000011101...........................", "czx2.r {r1} = {r3}"),
        ("popcnt", "0111001101001............................", "popcnt {r1} = {r3}"),
    ] {
        m.insns.push(ins(n, "FRR", pat, ui(), &format!("({{qp}}) {syn}"), "alu"));
    }
    // clz は Itanium 9500 系（Poulson）で追加され、正本 Rev 2.3 には
    // 未収録。実装依存の追加命令として `poulson` 旗に括る。
    m.insns.push(ins(
        "clz",
        "FRR",
        "0111001111001............................",
        poulson_i(),
        "({qp}) clz {r1} = {r3}",
        "alu",
    ));
    // I3/I4: mux（x2a=3 のバイト・ハーフワード並び替え）。
    m.insns.push(ins(
        "mux1",
        "FRRM",
        "0111011001010............................",
        ui(),
        "({qp}) mux1 {r1} = {r2}, {mbtype4}",
        "alu",
    ));
    m.insns.push(ins(
        "mux2",
        "FRRM8",
        "0111011101010............................",
        ui(),
        "({qp}) mux2 {r1} = {r2}, {mhtype8}",
        "alu",
    ));
    // I1/I2: MM mpy/mix/pack/unpack（x2a=2、OpZaZbVeX2aX2bX2c）。
    for (n, pat, syn) in [
        ("mix1_r", "0111010001000............................", "mix1.r {r1} = {r2}, {r3}"),
        ("mix1_l", "0111010001010............................", "mix1.l {r1} = {r2}, {r3}"),
        ("mix2_r", "0111010101000............................", "mix2.r {r1} = {r2}, {r3}"),
        ("mix2_l", "0111010101010............................", "mix2.l {r1} = {r2}, {r3}"),
        ("mix4_r", "0111110001000............................", "mix4.r {r1} = {r2}, {r3}"),
        ("mix4_l", "0111110001010............................", "mix4.l {r1} = {r2}, {r3}"),
        ("pack2_uss", "0111010100000............................", "pack2.uss {r1} = {r2}, {r3}"),
        ("pack2_sss", "0111010100010............................", "pack2.sss {r1} = {r2}, {r3}"),
        ("pack4_sss", "0111110000010............................", "pack4.sss {r1} = {r2}, {r3}"),
        ("unpack1_h", "0111010000100............................", "unpack1.h {r1} = {r2}, {r3}"),
        ("unpack1_l", "0111010000110............................", "unpack1.l {r1} = {r2}, {r3}"),
        ("unpack2_h", "0111010100100............................", "unpack2.h {r1} = {r2}, {r3}"),
        ("unpack2_l", "0111010100110............................", "unpack2.l {r1} = {r2}, {r3}"),
        ("unpack4_h", "0111110000100............................", "unpack4.h {r1} = {r2}, {r3}"),
        ("unpack4_l", "0111110000110............................", "unpack4.l {r1} = {r2}, {r3}"),
        ("pmin1_u", "0111010000001............................", "pmin1.u {r1} = {r2}, {r3}"),
        ("pmax1_u", "0111010000101............................", "pmax1.u {r1} = {r2}, {r3}"),
        ("pmin2", "0111010100011............................", "pmin2 {r1} = {r2}, {r3}"),
        ("pmax2", "0111010100111............................", "pmax2 {r1} = {r2}, {r3}"),
        ("psad1", "0111010001011............................", "psad1 {r1} = {r2}, {r3}"),
        // pmpy2 はサイズ 2 の x2b=1/3・x2c=3 枠で .r/.l を選ぶ。
        ("pmpy2_r", "0111010101101............................", "pmpy2.r {r1} = {r2}, {r3}"),
        ("pmpy2_l", "0111010101111............................", "pmpy2.l {r1} = {r2}, {r3}"),
    ] {
        m.insns.push(ins(n, "FRRR", pat, ui(), &format!("({{qp}}) {syn}"), "alu"));
    }
    // I1: pmpyshr2（可変シフト枠 x2a=0、x2b が符号/符号なしを
    // 選ぶ。count2={0,7,15,16}）。
    for (n, pat, syn) in [
        ("pmpyshr2", "011100010..11............................", "pmpyshr2 {r1} = {r2}, {r3}, {ct2d}"),
        ("pmpyshr2_u", "011100010..01............................", "pmpyshr2.u {r1} = {r2}, {r3}, {ct2d}"),
    ] {
        m.insns.push(ins(n, "FRRC2", pat, ui(), &format!("({{qp}}) {syn}"), "alu"));
    }
    // mpy4/mpyshl4 も Poulson 追加（clz と同じ括り）。
    for (n, pat, syn) in [
        ("mpy4", "0111100001101............................", "mpy4 {r1} = {r2}, {r3}"),
        ("mpyshl4", "0111100001111............................", "mpyshl4 {r1} = {r2}, {r3}"),
    ] {
        m.insns.push(ins(n, "FRRR", pat, poulson_i(), &format!("({{qp}}) {syn}"), "alu"));
    }
    // I5/I7: MM/整数シフト（可変。pshr 系のソース順は {r3}, {r2}）。
    for (n, pat, syn) in [
        ("pshl2", "0111000100100............................", "pshl2 {r1} = {r2}, {r3}"),
        ("pshl4", "0111100000100............................", "pshl4 {r1} = {r2}, {r3}"),
        ("shl", "0111100100100............................", "shl {r1} = {r2}, {r3}"),
        ("pshr2", "0111000100010............................", "pshr2 {r1} = {r3}, {r2}"),
        ("pshr4", "0111100000010............................", "pshr4 {r1} = {r3}, {r2}"),
        ("shr", "0111100100010............................", "shr {r1} = {r3}, {r2}"),
        ("pshr2_u", "0111000100000............................", "pshr2.u {r1} = {r3}, {r2}"),
        ("pshr4_u", "0111100000000............................", "pshr4.u {r1} = {r3}, {r2}"),
        ("shr_u", "0111100100000............................", "shr.u {r1} = {r3}, {r2}"),
    ] {
        m.insns.push(ins(n, "FRRR", pat, ui(), &format!("({{qp}}) {syn}"), "alu"));
    }
    // I6/I8: MM シフト（即値。左は ccnt5=31-値、右は cnt5 直接値）。
    for (n, fmt_, pat, syn) in [
        ("pshl2_i", "FRRC5", "0111011100101............................", "pshl2 {r1} = {r2}, {ccnt5}"),
        ("pshl4_i", "FRRC5", "0111111000101............................", "pshl4 {r1} = {r2}, {ccnt5}"),
        ("pshr2_i", "FRR5", "0111001100011............................", "pshr2 {r1} = {r3}, {cnt5}"),
        ("pshr4_i", "FRR5", "0111101000011............................", "pshr4 {r1} = {r3}, {cnt5}"),
        ("pshr2_u_i", "FRR5", "0111001100001............................", "pshr2.u {r1} = {r3}, {cnt5}"),
        ("pshr4_u_i", "FRR5", "0111101000001............................", "pshr4.u {r1} = {r3}, {cnt5}"),
    ] {
        m.insns.push(ins(n, fmt_, pat, ui(), &format!("({{qp}}) {syn}"), "alu"));
    }
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
        "extr_u",
        "FRRPL",
        "0101.010...................0.............",
        ui(),
        "({qp}) extr.u {r1} = {r3}, {pos6}, {len6}",
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
    // I16/I17/I30: テストビット・NaT テスト・フィーチャテスト
    // （OpX2TaTbYa[Xc]C(5,0,ta,tb,ya,[xc],c)。tb=bit36、ta=bit33、
    // ya=bit13、c=bit12、tf では xc=bit19 も固定 1）。
    // 関係完了子 z/nz は非並列（ta=tb=0）では c が .unc でアセンブラ
    // 疑似の nz は p1/p2 交換なので宣言しない。並列形では c が関係
    // 極性（z=c0 / nz=c1）。正本の正規（TBIT/TNAT/TF）行のみを宣言
    // する。tnat は bit19=0 を固定して tf と排他にする。
    for (pfx, yaxc) in [("tbit", "0."), ("tnat", "10"), ("tf", "11")] {
        for (ta, tb, c, sfx) in [
            ("0", "0", "0", "z"),
            ("0", "0", "1", "z_unc"),
            ("0", "1", "0", "z_and"),
            ("0", "1", "1", "nz_and"),
            ("1", "0", "0", "z_or"),
            ("1", "0", "1", "nz_or"),
            ("1", "1", "0", "z_or_andcm"),
            ("1", "1", "1", "nz_or_andcm"),
        ] {
            let (y, xc) = (yaxc.chars().next().unwrap(), yaxc.chars().nth(1).unwrap());
            let pat = format!(
                "0101{tb}00{ta}.............{xc}.....{y}{c}............"
            );
            let ty_sfx = match (ta, tb) {
                ("0", "0") => if c == "0" { "" } else { ".unc" },
                ("0", "1") => ".and",
                ("1", "0") => ".or",
                _ => ".or.andcm",
            };
            let rel = if c == "0" || (ta == "0" && tb == "0") { "z" } else { "nz" };
            let syn_sfx = if pfx == "tbit" { "{r3}, {pos6}" } else if pfx == "tnat" { "{r3}" } else { "{immu5b}" };
            let syn = format!("{pfx}.{rel}{ty_sfx} {{p1}}, {{p2}} = {syn_sfx}");
            let fmt_ = if pfx == "tbit" { "FPPRP" } else if pfx == "tnat" { "FPPR" } else { "FPPI5" };
            m.insns.push(ins(
                &format!("{pfx}_{sfx}"),
                fmt_,
                &pat,
                ui(),
                &format!("({{qp}}) {syn}"),
                "alu",
            ));
        }
    }

    // ---- M 型（メモリ・システム。Op=0,1,4,5,6,7）。
    // M43: break/nop/hint（I29/F15/B9 と同じ OpX6Y 拡張、immu21）。
    for (n, pat, syn) in [
        ("break_m", "0000.000000000...........................", "break.m {immu21}"),
        ("nop_m", "0000.0000000010..........................", "nop.m {immu21}"),
        ("hint_m", "0000.0000000011..........................", "hint.m {immu21}"),
    ] {
        m.insns.push(ins(n, "FI21", pat, um(), &format!("({{qp}}) {syn}"), "misc"));
    }
    // M1-M5/M16/M17: 整数ロードストア・セマフォ（IA6）。x6a 拡張の
    // 表で一括宣言する。ヒント場（hint[29:28]・hlfa[19]・hlf[12]）は
    // 性能ヒントのみで意味を持たないため '.' にして、完了子の
    // バリエーション（.nt1/.nt2/.nta/.dN）を 1 命令として受ける
    // （逆アセンブルは正準名を出す）。
    // Ref: SPEC-IA64-SDM (Rev 2.3) opcode extension tables.
    let m_pat = |m_: u64, x6a: u64, x: u64| -> String {
        format!("0100{}{:06b}..{}", m_, x6a, x) + &".".repeat(27)
    };
    let mi_pat = |x6a: u64| -> String {
        format!("0101.{:06b}...", x6a) + &".".repeat(27)
    };
    // (insn 名接尾辞, 構文の完了子, x6a ベース)。0x18-0x1f は
    // fill/getf 系、0x2c-0x2f は ld16.acq/未使用。
    let ld_ty: [(&str, &str, u64); 9] = [
        ("", "", 0x00),
        ("_s", ".s", 0x04),
        ("_a", ".a", 0x08),
        ("_sa", ".sa", 0x0c),
        ("_bias", ".bias", 0x10),
        ("_acq", ".acq", 0x14),
        ("_c_clr", ".c.clr", 0x20),
        ("_c_nc", ".c.nc", 0x24),
        ("_c_clr_acq", ".c.clr.acq", 0x28),
    ];
    for (sz_n, sz_i) in [("1", 0u64), ("2", 1), ("4", 2), ("8", 3)] {
        for (suf, syn, base) in ld_ty {
            let x6a = base + sz_i;
            let n = format!("ld{sz_n}{suf}");
            let a = format!("ld{sz_n}{syn}");
            m.insns.push(ins(
                &n,
                "FRR",
                &m_pat(0, x6a, 0),
                um(),
                &format!("({{qp}}) {a} {{r1}} = [{{r3}}]"),
                "mem",
            ));
            m.insns.push(ins(
                &format!("{n}_r"),
                "FLDR",
                &m_pat(1, x6a, 0),
                um(),
                &format!("({{qp}}) {a} {{r1}} = [{{r3}}], {{r2}}"),
                "mem",
            ));
            m.insns.push(ins(
                &format!("{n}_i"),
                "FLDI",
                &mi_pat(x6a),
                um(),
                &format!("({{qp}}) {a} {{r1}} = [{{r3}}], {{imm9b}}"),
                "mem",
            ));
        }
    }
    // ld8.fill: RSE 連携ロード（NaT は UNAT[paddr[8:3]] から復帰）。
    for (suf, fmt_, pat, tail) in [
        ("", "FRR", m_pat(0, 0x1b, 0), ""),
        ("_r", "FLDR", m_pat(1, 0x1b, 0), ", {r2}"),
        ("_i", "FLDI", mi_pat(0x1b), ", {imm9b}"),
    ] {
        m.insns.push(ins(
            &format!("ld8_fill{suf}"),
            fmt_,
            &pat,
            um(),
            &format!("({{qp}}) ld8.fill {{r1}} = [{{r3}}]{tail}"),
            "mem",
        ));
    }
    // ld16 / ld16.acq: 16 バイトを {r1, ar.csd} に載せる（X=1）。
    for (n, syn, x6a) in [
        ("ld16", "ld16", 0x28u64),
        ("ld16_acq", "ld16.acq", 0x2c),
    ] {
        m.insns.push(ins(
            n,
            "FRR",
            &m_pat(0, x6a, 1),
            um(),
            &format!("({{qp}}) {syn} {{r1}} = ar.csd, [{{r3}}]"),
            "mem",
        ));
    }
    // ストア。.rel はリリース順序ヒント（単一スレッドでは順序のみ）。
    for (sz_n, sz_i) in [("1", 0u64), ("2", 1), ("4", 2), ("8", 3)] {
        for (suf, syn, base) in [("", "", 0x30u64), ("_rel", ".rel", 0x34)] {
            let x6a = base + sz_i;
            let n = format!("st{sz_n}{suf}");
            let a = format!("st{sz_n}{syn}");
            m.insns.push(ins(
                &n,
                "FSTR",
                &m_pat(0, x6a, 0),
                um(),
                &format!("({{qp}}) {a} [{{r3}}] = {{r2}}"),
                "mem",
            ));
            m.insns.push(ins(
                &format!("{n}_i"),
                "FSTI",
                &mi_pat(x6a),
                um(),
                &format!("({{qp}}) {a} [{{r3}}] = {{r2}}, {{imm9a}}"),
                "mem",
            ));
        }
    }
    // st8.spill: NaT を UNAT[paddr[8:3]] に書き出す。
    for (suf, fmt_, pat, tail) in [
        ("", "FSTR", m_pat(0, 0x3b, 0), ""),
        ("_i", "FSTI", mi_pat(0x3b), ", {imm9a}"),
    ] {
        m.insns.push(ins(
            &format!("st8_spill{suf}"),
            fmt_,
            &pat,
            um(),
            &format!("({{qp}}) st8.spill [{{r3}}] = {{r2}}{tail}"),
            "mem",
        ));
    }
    // st16 / st16.rel（X=1。{r2, ar.csd} の 16 バイト）。
    for (n, syn, x6a) in [
        ("st16", "st16", 0x30u64),
        ("st16_rel", "st16.rel", 0x34),
    ] {
        m.insns.push(ins(
            n,
            "FSTR",
            &m_pat(0, x6a, 1),
            um(),
            &format!("({{qp}}) {syn} [{{r3}}] = {{r2}}, ar.csd"),
            "mem",
        ));
    }
    // セマフォ（全て m=0・X=1）。xchg=0x08-0x0b、cmpxchg=サイズ|rel<<2
    // （0x00-0x07）、fetchadd4/8.acq=0x12/0x13・.rel=0x16/0x17、
    // cmp8xchg16.acq/rel=0x20/0x24。
    for (sz_n, sz_i) in [("1", 0u64), ("2", 1), ("4", 2), ("8", 3)] {
        m.insns.push(ins(
            &format!("xchg{sz_n}"),
            "FLDR",
            &m_pat(0, 0x08 + sz_i, 1),
            um(),
            &format!("({{qp}}) xchg{sz_n} {{r1}} = [{{r3}}], {{r2}}"),
            "mem",
        ));
        for (sem, soff) in [("acq", 0u64), ("rel", 4)] {
            m.insns.push(ins(
                &format!("cmpxchg{sz_n}_{sem}"),
                "FLDR",
                &m_pat(0, sz_i + soff, 1),
                um(),
                &format!(
                    "({{qp}}) cmpxchg{sz_n}.{sem} {{r1}} = [{{r3}}], {{r2}}, ar.ccv"
                ),
                "mem",
            ));
        }
    }
    for (sz_n, sz_off) in [("4", 0u64), ("8", 1)] {
        for (sem, soff) in [("acq", 0u64), ("rel", 4)] {
            m.insns.push(ins(
                &format!("fetchadd{sz_n}_{sem}"),
                "FFA",
                &m_pat(0, 0x12 + sz_off + soff, 1),
                um(),
                &format!("({{qp}}) fetchadd{sz_n}.{sem} {{r1}} = [{{r3}}], {{inc3}}"),
                "mem",
            ));
        }
    }
    for (sem, soff) in [("acq", 0u64), ("rel", 4)] {
        m.insns.push(ins(
            &format!("cmp8xchg16_{sem}"),
            "FLDR",
            &m_pat(0, 0x20 + soff, 1),
            um(),
            &format!(
                "({{qp}}) cmp8xchg16.{sem} {{r1}} = [{{r3}}], {{r2}}, ar.csd, ar.ccv"
            ),
            "mem",
        ));
    }
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
        ("ldfe", "01100000000..0...........................", "ldfe {f1} = [{r3}]"),
        ("ldf8", "01100000001..0...........................", "ldf8 {f1} = [{r3}]"),
        ("ldfs", "01100000010..0...........................", "ldfs {f1} = [{r3}]"),
        ("ldfd", "01100000011..0...........................", "ldfd {f1} = [{r3}]"),
        ("ldf_fill", "01100011011..0...........................", "ldf.fill {f1} = [{r3}]"),
    ] {
        m.insns.push(ins(n, "FFLD", pat, um(), &format!("({{qp}}) {syn}"), "load"));
    }
    // FP ロードのポストインクリメント（レジスタ形 m=1）。
    for (n, pat, syn) in [
        ("ldfe_r", "01101000000..0...........................", "ldfe {f1} = [{r3}], {r2}"),
        ("ldf8_r", "01101000001..0...........................", "ldf8 {f1} = [{r3}], {r2}"),
        ("ldfs_r", "01101000010..0...........................", "ldfs {f1} = [{r3}], {r2}"),
        ("ldfd_r", "01101000011..0...........................", "ldfd {f1} = [{r3}], {r2}"),
        ("ldf_fill_r", "01101011011..0...........................", "ldf.fill {f1} = [{r3}], {r2}"),
    ] {
        m.insns.push(ins(n, "FFLDR", pat, um(), &format!("({{qp}}) {syn}"), "load"));
    }
    // FP ロードのポストインクリメント（即値形 op=7、imm9b）。
    for (n, pat, syn) in [
        ("ldfe_i", "0111.000000..............................", "ldfe {f1} = [{r3}], {imm9b}"),
        ("ldf8_i", "0111.000001..............................", "ldf8 {f1} = [{r3}], {imm9b}"),
        ("ldfs_i", "0111.000010..............................", "ldfs {f1} = [{r3}], {imm9b}"),
        ("ldfd_i", "0111.000011..............................", "ldfd {f1} = [{r3}], {imm9b}"),
        ("ldf_fill_i", "0111.011011..............................", "ldf.fill {f1} = [{r3}], {imm9b}"),
    ] {
        m.insns.push(ins(n, "FFLDI", pat, um(), &format!("({{qp}}) {syn}"), "load"));
    }
    // M9/M11: FP ストア。
    for (n, pat, syn) in [
        ("stfe", "01100110000..0...........................", "stfe [{r3}] = {f2}"),
        ("stf8", "01100110001..0...........................", "stf8 [{r3}] = {f2}"),
        ("stfs", "01100110010..0...........................", "stfs [{r3}] = {f2}"),
        ("stfd", "01100110011..0...........................", "stfd [{r3}] = {f2}"),
        ("stf_spill", "01100111011..0...........................", "stf.spill [{r3}] = {f2}"),
    ] {
        m.insns.push(ins(n, "FFST", pat, um(), &format!("({{qp}}) {syn}"), "store"));
    }
    // FP ストアのポストインクリメント（即値形 op=7、imm9a）。
    for (n, pat, syn) in [
        ("stfe_i", "0111.110000..............................", "stfe [{r3}] = {f2}, {imm9a}"),
        ("stf8_i", "0111.110001..............................", "stf8 [{r3}] = {f2}, {imm9a}"),
        ("stfs_i", "0111.110010..............................", "stfs [{r3}] = {f2}, {imm9a}"),
        ("stfd_i", "0111.110011..............................", "stfd [{r3}] = {f2}, {imm9a}"),
        ("stf_spill_i", "0111.111011..............................", "stf.spill [{r3}] = {f2}, {imm9a}"),
    ] {
        m.insns.push(ins(n, "FFSTI", pat, um(), &format!("({{qp}}) {syn}"), "store"));
    }
    // M12: FP ペアロード。m=1・x=1 は +16 固定のポストインクリメント形。
    m.insns.push(ins(
        "ldfp8",
        "FFLP",
        "01100000001001...........................",
        um(),
        "({qp}) ldfp8 {f1}, {f2} = [{r3}]",
        "load",
    ));
    m.insns.push(ins(
        "ldfp8_i16",
        "FFLP",
        "01101000001001...........................",
        um(),
        "({qp}) ldfp8 {f1}, {f2} = [{r3}], 16",
        "load",
    ));
    // M13-M15: lfetch。
    for (n, pat, syn) in [
        ("lfetch", "01100101100..0.......0......0............", "lfetch [{r3}]"),
        ("lfetch_excl", "01100101101..0..............0............", "lfetch.excl [{r3}]"),
        ("lfetch_fault", "01100101110..0..............0............", "lfetch.fault [{r3}]"),
    ] {
        m.insns.push(ins(n, "FM3", pat, um(), &format!("({{qp}}) {syn}"), "load"));
    }
    m.insns.push(ins(
        "lfetch_r",
        "FLFR",
        "01101101100..0..............0............",
        um(),
        "({qp}) lfetch [{r3}], {r2}",
        "load",
    ));
    m.insns.push(ins(
        "lfetch_i",
        "FLFI",
        "0111.101100.................0............",
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
        "getf_s",
        "FRF",
        "01000011110..1...........................",
        um(),
        "({qp}) getf.s {r1} = {f2}",
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
        "getf_exp",
        "FRF",
        "01000011101..1...........................",
        um(),
        "({qp}) getf.exp {r1} = {f2}",
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
        "setf_s",
        "FFR",
        "01100011110..1...........................",
        um(),
        "({qp}) setf.s {f1} = {r2}",
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
        "chk_a_clr",
        "FRTC",
        "0000.101.................................",
        um(),
        "({qp}) chk.a.clr {r1}, {tgt25c}",
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
    m.insns.push(ins(
        "chk_a_clr_f",
        "FFTC",
        "0000.111.................................",
        um(),
        "({qp}) chk.a.clr {f1}, {tgt25c}",
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
        "fc_i",
        "FM3",
        "00011000110000...........................",
        um(),
        "({qp}) fc.i {r3}",
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
    // fma/fma.d/fms/fnma は sf 場（bits[35:34]）を sf0-sf3 で展開する
    // （fms は pb=1 なので「1001x」、fnma は pb=1+xb=1 の「11x」）。
    for sf in 0..4 {
        for (n, pfx, syn) in [
            ("fma", "10000", "fma"),
            ("fma_d", "10010", "fma.d"),
            ("fms", "10100", "fms"),
            ("fnma", "11000", "fnma"),
        ] {
            m.insns.push(ins(
                &format!("{n}_s{sf}"),
                "FFMA",
                &format!("{pfx}{sf:02b}.................................."),
                uf(),
                &format!("({{qp}}) {syn}.s{sf} {{f1}} = {{f3}}, {{f4}}, {{f2}}"),
                "fp",
            ));
        }
    }
    for (n, pat, syn) in [
        ("fselect", "11100....................................", "fselect {f1} = {f3}, {f4}, {f2}"),
        ("xma_l", "1110100..................................", "xma.l {f1} = {f3}, {f4}, {f2}"),
        ("xma_h", "1110111..................................", "xma.h {f1} = {f3}, {f4}, {f2}"),
        ("xma_hu", "1110110..................................", "xma.hu {f1} = {f3}, {f4}, {f2}"),
    ] {
        m.insns.push(ins(n, "FFMA", pat, uf(), &format!("({{qp}}) {syn}"), "fp"));
    }
    // F7: 3 項 FP 演算・論理・マージ。
    // fmin/fmax/famin/famax は xb=0 で sf 場（bits[35:34]）を展開する。
    for sf in 0..4 {
        for (n, x6lo, syn) in [
            ("fmin", "00", "fmin"),
            ("fmax", "01", "fmax"),
            ("famin", "10", "famin"),
            ("famax", "11", "famax"),
        ] {
            m.insns.push(ins(
                &format!("{n}_s{sf}"),
                "FFF3",
                &format!("0000.{:03b}0101{x6lo}...........................", sf << 1),
                uf(),
                &format!("({{qp}}) {syn}.s{sf} {{f1}} = {{f2}}, {{f3}}"),
                "fp",
            ));
        }
    }
    for (n, pat, syn) in [
        ("fmerge_s", "0000...0010000...........................", "fmerge.s {f1} = {f2}, {f3}"),
        ("fmerge_ns", "0000...0010001...........................", "fmerge.ns {f1} = {f2}, {f3}"),
        ("fmerge_se", "0000...0010010...........................", "fmerge.se {f1} = {f2}, {f3}"),
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
    // F8/F9: FP 比較の展開。rb（bit36）×ra（bit33）が関係
    // （eq=00, unord=01, lt=10, le=11）、bit12 が .unc、
    // bits[35:34] が sf。
    for sf in 0..4 {
        for (n, rb, ra, syn) in [
            ("fcmp_eq", 0, 0, "eq"),
            ("fcmp_unord", 0, 1, "unord"),
            ("fcmp_lt", 1, 0, "lt"),
            ("fcmp_le", 1, 1, "le"),
        ] {
            for unc in 0..2 {
                let u = if unc == 1 { ".unc" } else { "" };
                m.insns.push(ins(
                    &format!("{n}{}_s{sf}", if unc == 1 { "_unc" } else { "" }),
                    "FPPF",
                    &format!(
                        "0100{rb}{sf:02b}{ra}....................{unc}............"
                    ),
                    uf(),
                    &format!(
                        "({{qp}}) fcmp.{syn}{u}.s{sf} {{p1}}, {{p2}} = {{f2}}, {{f3}}"
                    ),
                    "fp",
                ));
            }
        }
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
    m.insns.push(ins(
        "fclass_m_unc",
        "FPPFI",
        "0101........................1............",
        uf(),
        "({qp}) fclass.m.unc {p1}, {p2} = {f2}, {immu9}",
        "fp",
    ));
    // F6: 近似・逆数。bits[35:34] が sf。
    for sf in 0..4 {
        m.insns.push(ins(
            &format!("frcpa_s{sf}"),
            "FFPFF",
            &format!("00000{sf:02b}1................................."),
            uf(),
            &format!("({{qp}}) frcpa.s{sf} {{f1}}, {{p2}} = {{f2}}, {{f3}}"),
            "fp",
        ));
        m.insns.push(ins(
            &format!("frsqrta_s{sf}"),
            "FFPF",
            &format!("00001{sf:02b}1................................."),
            uf(),
            &format!("({{qp}}) frsqrta.s{sf} {{f1}}, {{p2}} = {{f3}}"),
            "fp",
        ));
    }
    // F8/F9: 変換。fcvt.fx/fxu(.trunc) は sf 場を展開する。
    for sf in 0..4 {
        for (n, x6, syn) in [
            ("fcvt_fx", "011000", "fcvt.fx"),
            ("fcvt_fxu", "011001", "fcvt.fxu"),
            ("fcvt_fx_trunc", "011010", "fcvt.fx.trunc"),
            ("fcvt_fxu_trunc", "011011", "fcvt.fxu.trunc"),
        ] {
            m.insns.push(ins(
                &format!("{n}_s{sf}"),
                "FFF2",
                &format!("0000.{:03b}{x6}...........................", sf << 1),
                uf(),
                &format!("({{qp}}) {syn}.s{sf} {{f1}} = {{f2}}"),
                "fp",
            ));
        }
    }
    for (n, pat, syn) in [
        ("fcvt_xf", "0000...0011100...........................", "fcvt.xf {f1} = {f2}"),
        ("fpcvt_fx_s0", "0001.000011000...........................", "fpcvt.fx.s0 {f1} = {f2}"),
    ] {
        m.insns.push(ins(n, "FFF2", pat, uf(), &format!("({{qp}}) {syn}"), "fp"));
    }
    // F11/F12/F13: sf 制御。bits[35:34] が対象の sf。
    for sf in 0..4 {
        m.insns.push(ins(
            &format!("fsetc_s{sf}"),
            "FII7",
            &format!("0000.{:03b}000100...........................", sf << 1),
            uf(),
            &format!("({{qp}}) fsetc.s{sf} {{immu7a}}, {{immu7b}}"),
            "fp",
        ));
        m.insns.push(ins(
            &format!("fclrf_s{sf}"),
            "F0",
            &format!("0000.{:03b}000101...........................", sf << 1),
            uf(),
            &format!("({{qp}}) fclrf.s{sf}"),
            "fp",
        ));
        m.insns.push(ins(
            &format!("fchkf_s{sf}"),
            "FT25",
            &format!("0000.{:03b}001000...........................", sf << 1),
            uf(),
            &format!("({{qp}}) fchkf.s{sf} {{tgt25}}"),
            "misc",
        ));
    }
    // F15/F16: FP break/nop/hint（x3[35:33]=0 固定、x6/y 拡張）。
    for (n, pat, syn) in [
        ("break_f", "0000.000000000...........................", "break.f {immu21}"),
        ("nop_f", "0000.0000000010..........................", "nop.f {immu21}"),
        ("hint_f", "0000.0000000011..........................", "hint.f {immu21}"),
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
    // B0: cover/clrrrb（qp=0 が固定、LAST を示す。正本の綴りどおり
    // r が 3 つ）。
    for (n, pat, syn) in [
        ("cover", "0000....000010.....................000000", "cover"),
        ("clrrrb", "0000....000100.....................000000", "clrrrb"),
        ("clrrrb_pr", "0000....000101.....................000000", "clrrrb.pr"),
    ] {
        m.insns.push(ins(n, "F0U", pat, ub(), syn, "system"));
    }
    // B1: IP 相対分岐（Op=4、btype 拡張、tgt25c）。予測ヒント
    // （d{35}・wh{34:33}・p{12}）は受理するが意味論では無視する
    // 近似とし、完了子ごとの宣言は畳む（GAP-0068 参照）。
    m.insns.push(ins(
        "br_cond",
        "FBT25",
        "0100............................000......",
        ub(),
        "({qp}) br.cond {tgt25c}",
        "branch",
    ));
    // B2: ループ分岐（スロット 2 限定。cloop/ctop/cexit は qp 無効、
    // wtop/wexit は qp を条件に使う）。
    for (n, btype, syn) in [
        ("br_wexit", "010", "({qp}) br.wexit {tgt25c}"),
        ("br_wtop", "011", "({qp}) br.wtop {tgt25c}"),
        ("br_cloop", "101", "({qp}) br.cloop {tgt25c}"),
        ("br_cexit", "110", "({qp}) br.cexit {tgt25c}"),
        ("br_ctop", "111", "({qp}) br.ctop {tgt25c}"),
    ] {
        m.insns.push(ins(
            n,
            "FBT25",
            &format!("0100............................{btype}......"),
            ub(),
            syn,
            "branch",
        ));
    }
    // B3: IP 相対 call（Op=5、b1 にリンク、tgt25c）。
    m.insns.push(ins(
        "br_call",
        "FBBT",
        "0101.....................................",
        ub(),
        "({qp}) br.call {b1} = {tgt25c}",
        "branch",
    ));
    // B4: 間接分岐（Op=0、x6=0x20）と間接 return（x6=0x21）。
    for (n, x6, btype, syn) in [
        ("br_cond_ind", "100000", "000", "({qp}) br.cond {b2}"),
        ("br_ia", "100000", "001", "({qp}) br.ia {b2}"),
        ("br_ret", "100001", "100", "({qp}) br.ret {b2}"),
    ] {
        m.insns.push(ins(
            n,
            "FB2",
            &format!("0000....{x6}..................{btype}......"),
            ub(),
            syn,
            "branch",
        ));
    }
    // B5: 間接 call（Op=1。whc{34:32}・p{12}・d{35} は無視）。
    m.insns.push(ins(
        "br_call_ind",
        "FBB",
        "0001.....................................",
        ub(),
        "({qp}) br.call {b1} = {b2}",
        "branch",
    ));
    // B6: IP 相対分岐予測（Op=7。ih{35}・wh{4:3} は無視）。
    m.insns.push(ins(
        "brp",
        "FBPT",
        "0111.....................................",
        ub(),
        "brp {tgt25c}, {tag13}",
        "misc",
    ));
    // B7: 間接分岐予測（Op=2、x6=0x10）と return 予測（x6=0x11）。
    for (n, x6, syn) in [
        ("brp_ind", "010000", "brp {b2}, {tag13}"),
        ("brp_ret", "010001", "brp.ret {b2}, {tag13}"),
    ] {
        m.insns.push(ins(
            n,
            "FB2T",
            &format!("0010....{x6}..........................."),
            ub(),
            syn,
            "misc",
        ));
    }

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
        "brl_cond",
        "FXT60",
        ".......................................001100............................000......",
        ux2(),
        "({qp}) brl.cond {tgt60}",
        "branch",
    ));
    m.insns.push(ins(
        "brl_call",
        "FXBT",
        ".......................................001101.....................................",
        ux2(),
        "({qp}) brl.call {b1} = {tgt60}",
        "branch",
    ));

    m
}
