// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// PA-RISC の ISADL モデル（段階17）。
//
// 命令語は 32 ビット固定長のビッグエンディアンで、opcode
// （HP 記法の bit 0-5＝語の最上位 6 ビット、LSB では 31-26）の
// 下に形式が決まる。条件付き命令の completer（nullify の n、
// 比較条件 c、フィールド選択 f、64 ビット選択 d、シフト量 sh 等）
// は opcode の下位の拡張桁とオペランドに埋まる。
// PA-RISC 1.0 は公開の根拠資料がないため範囲外（段階17 の
// 着手条件で除外を決定）。対象は 1.1・2.0 と MAX 拡張。
//
// デコード表の固定ビットは SPEC-PARISC-11 付録D および
// SPEC-PARISC-20 付録C のオペコード表を正本として宣言する。
// assemble_* / low_sign_ext による即値復元は意味論側の仕事
// なので、ここでは生ビット列のフィールドとして宣言し、符号や
// 左右の転置は行わない。completer の値（cf/c/sh/d/size/ma 等）
// もそのまま値オペランドとして渡し、解釈は意味論で行う。
//
// HP の bit 記法は MSB=0 で、フィールド桁番号はこのファイルでは
// すべて LSB=0 に揃えてある。
// Ref: SPEC-PARISC-11 付録D, SPEC-PARISC-20 付録C.

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

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
    for (name, parent, add, rem) in [
        ("pa7100lc", "", &["pa11", "max1"][..], &[][..]),
        ("pa7300lc", "pa7100lc", &[][..], &[][..]),
        // PA-8000 系列は MAX-2 のみで MAX-1 を持たない（継承元の
        // pa7100lc から外す）。
        ("pa8000", "pa7100lc", &["pa20", "max2"][..], &["max1"][..]),
        ("pa8500", "pa8000", &[][..], &[][..]),
        ("pa8600", "pa8500", &[][..], &[][..]),
        ("pa8700", "pa8600", &[][..], &[][..]),
    ] {
        m.models.push(ModelDef {
            params: Default::default(),
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: rem.iter().map(|s| s.to_string()).collect(),
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
    // 主な共用桁:
    //   fa(25-21) fb(20-16) fc(4-0)  … 5 ビットレジスタ/即値桁
    //   cf(15-12) c3(15-13)          … completer（条件・fmt）
    //   b*(n)                        … 1 ビット completer（n/d/m/a/se…）
    //   sh(7-6)  … add/sub のシフト量、permh の c3
    //   im*                          … 生即値（復元は意味論）
    for (name, hi, lo) in [
        ("op", 31, 26),
        ("fa", 25, 21),
        ("fb", 20, 16),
        ("fc", 4, 0),
        ("cf", 15, 12),
        ("c3", 15, 13),
        ("sp2", 15, 14),
        ("cc2", 14, 13),
        ("b15", 15, 15),
        ("b14", 14, 14),
        ("b13", 13, 13),
        ("b12", 12, 12),
        ("b11", 11, 11),
        ("b10", 10, 10),
        ("b9", 9, 9),
        ("b6", 6, 6),
        ("b5", 5, 5),
        ("sh", 7, 6),
        ("size", 7, 6),
        ("i4", 9, 6),
        ("pm1", 11, 10),
        ("pm2", 9, 8),
        ("cp5", 9, 5),
        ("len5", 4, 0),
        ("im5", 4, 0),
        ("im13", 25, 13),
        ("im5h", 20, 16),
        ("im11", 10, 0),
        ("im16", 15, 0),
        ("im21", 20, 0),
        ("n1", 1, 1),
        ("w10", 25, 16),
        ("sm", 25, 16),
        ("fta", 15, 11),
        ("fra", 10, 6),
        ("a2m", 2, 2),
        ("im26", 25, 0),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    // 論理値が命令語の複数範囲に分かれるもの。ra64 系は
    // PA 2.0 の拡張 FP レジスタ選択（5 ビット + 1 ビット）で、
    // ma5 は index/im5 形式の modify 完語（ma_to_m の素ビット）。
    // offa は assemble_12a の素材（bit0 符号 + bits3-15）。
    // len6a/len6b/cpos6 は 64 ビット版 extract/deposit の 6 ビット長。
    // bdisp は分岐変位の素材で、assemble_12/17/22 いずれでも
    // 符号は語の bit0（pos31）。取出し値は上位 11 ビットが
    // bits12-2、最下位が符号ビット。
    for (name, parts) in [
        ("bdisp", vec![(12, 2), (0, 0)]),
        ("ma5", vec![(5, 5), (13, 13)]),
        ("offa", vec![(15, 3), (0, 0)]),
        ("len6a", vec![(8, 8), (4, 0)]),
        ("len6b", vec![(12, 12), (4, 0)]),
        ("cpos6", vec![(11, 11), (9, 5)]),
        ("r64a", vec![(7, 7), (25, 21)]),
        ("r64b", vec![(12, 12), (20, 16)]),
        ("r64c", vec![(8, 8), (15, 13), (10, 9)]),
        ("r64t", vec![(6, 6), (4, 0)]),
        ("r64m", vec![(1, 1), (20, 16)]),
        ("r32c", vec![(15, 13), (10, 9)]),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Parts { parts, zfill: 0 },
        });
    }

    let gr = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("gr".to_string()),
        access,
    };
    let fpr = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("fpr".to_string()),
        access,
    };
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

    // オペランドなし（全桁固定 or 捨てる桁だけの命令）。
    m.formats.push(fmt("FNONE", &[], vec![]));
    // break: spec レイアウトは `00 im13 00 im5`（im13 = bits25-13,
    // im5 = bits4-0、bits12-5 は固定 0）。構文順は `BREAK im5,im13`
    // なのでオペランドもその順にする。即値はトラップハンドラへの
    // ソフトウェア引数で意味論は使わないが、取出しは spec どおり。
    // Ref: SPEC-PARISC-11 §BREAK, SPEC-PARISC-20 §7-18.
    m.formats.push(fmt(
        "FBRK",
        &["im5", "im13"],
        vec![val("im5", "im5"), val("im13", "im13")],
    ));
    // mtsp/mfsp: 空間レジスタは assemble_sr3 の素の 3 ビット。
    m.formats.push(fmt(
        "FMTSP",
        &["fb", "c3"],
        vec![gr("r", "fb", Access::Read), val("sp", "c3")],
    ));
    // mtctl の fa 桁は制御レジスタ番号で GR ではない（FMFCTL と
    // 同じく regclass 無しの値オペランド）。
    m.formats.push(fmt(
        "FMTCTL",
        &["fa", "fb"],
        vec![val("t", "fa"), gr("r", "fb", Access::Read)],
    ));
    // mt* でソース 1 本だけを読むもの（mtsm/mtsarcm）。
    m.formats
        .push(fmt("F1R", &["fb"], vec![gr("r", "fb", Access::Read)]));
    // mf*/lc* で書き先 1 本だけのもの（mfia/lci）。
    m.formats
        .push(fmt("F1TW", &["fc"], vec![gr("t", "fc", Access::Write)]));
    m.formats.push(fmt(
        "FMFSP",
        &["c3", "fc"],
        vec![val("sp", "c3"), gr("t", "fc", Access::Write)],
    ));
    // mfctl は e 桁（bits14）が PA 2.0 の 64 ビット選択を兼ねる。
    m.formats.push(fmt(
        "FMFCTL",
        &["fa", "b14", "fc"],
        vec![val("r", "fa"), val("e", "b14"), gr("t", "fc", Access::Write)],
    ));
    m.formats.push(fmt(
        "FLDSID",
        &["fa", "sp2", "fc"],
        vec![
            gr("b", "fa", Access::Read),
            val("sp", "sp2"),
            gr("t", "fc", Access::Write),
        ],
    ));
    // rsm/ssm の 10 ビット即値（expand_sm_imm の素材）。
    m.formats.push(fmt(
        "FSM",
        &["sm", "fc"],
        vec![val("i", "sm"), gr("t", "fc", Access::Write)],
    ));
    m.formats
        .push(fmt("FDIAG", &["im26"], vec![val("i", "im26")]));
    // MM 系の b+x+sp+m 形（fdc/fic/pdc/pxtlb 系）。
    m.formats.push(fmt(
        "FMMX",
        &["fa", "fb", "sp2", "b5"],
        vec![
            gr("b", "fa", Access::Read),
            gr("x", "fb", Access::Read),
            val("sp", "sp2"),
            val("m", "b5"),
        ],
    ));
    // _s 形は sp が assemble_sr3x（bits15-13＝c3 の 3 ビット）。
    m.formats.push(fmt(
        "FMMXS",
        &["fa", "fb", "c3", "b5"],
        vec![
            gr("b", "fa", Access::Read),
            gr("x", "fb", Access::Read),
            val("sp", "c3"),
            val("m", "b5"),
        ],
    ));
    m.formats.push(fmt(
        "FPROBE",
        &["fa", "fb", "sp2", "b13", "b6", "fc"],
        vec![
            gr("b", "fa", Access::Read),
            val("ri", "fb"),
            val("sp", "sp2"),
            val("imm", "b13"),
            val("w", "b6"),
            gr("t", "fc", Access::Write),
        ],
    ));
    // ixtlbx（PA1.x TLB 挿入）。
    m.formats.push(fmt(
        "FIXBX",
        &["fa", "fb", "sp2", "b6"],
        vec![
            gr("b", "fa", Access::Read),
            gr("r", "fb", Access::Read),
            val("sp", "sp2"),
            val("addr", "b6"),
        ],
    ));
    // ixtlbx の `...` 形は同じく sr3x（c3）。
    m.formats.push(fmt(
        "FIXBXS",
        &["fa", "fb", "c3", "b6"],
        vec![
            gr("b", "fa", Access::Read),
            gr("r", "fb", Access::Read),
            val("sp", "c3"),
            val("addr", "b6"),
        ],
    ));
    // ixtlbt（PA 2.0 idtlbt/iitlbt）。
    m.formats.push(fmt(
        "FITBT",
        &["fa", "fb", "b12"],
        vec![gr("r2", "fa", Access::Read), gr("r1", "fb", Access::Read), val("data", "b12")],
    ));
    // lpa。
    m.formats.push(fmt(
        "FLPA",
        &["fa", "fb", "sp2", "b5", "fc"],
        vec![
            gr("b", "fa", Access::Read),
            gr("x", "fb", Access::Read),
            val("sp", "sp2"),
            val("m", "b5"),
            gr("t", "fc", Access::Write),
        ],
    ));
    // rrr 3 項演算（hadd/havg/hsub/mix*/permh 以外の sh 無し形）。
    m.formats.push(fmt(
        "FRRR",
        &["fa", "fb", "fc"],
        vec![
            gr("r2", "fa", Access::Read),
            gr("r1", "fb", Access::Read),
            gr("t", "fc", Access::Write),
        ],
    ));
    // @rrr_cf（ds）。
    m.formats.push(fmt(
        "FRRC",
        &["fa", "fb", "cf", "fc"],
        vec![
            gr("r2", "fa", Access::Read),
            gr("r1", "fb", Access::Read),
            val("cf", "cf"),
            gr("t", "fc", Access::Write),
        ],
    ));
    // @rrr_cf_d（論理/加減算の基本形。d は d_5）。
    m.formats.push(fmt(
        "FRRCD",
        &["fa", "fb", "cf", "b5", "fc"],
        vec![
            gr("r2", "fa", Access::Read),
            gr("r1", "fb", Access::Read),
            val("cf", "cf"),
            val("d", "b5"),
            gr("t", "fc", Access::Write),
        ],
    ));
    // @rrr_cf_d_sh（add/sub 系の sh 付き形。sh=00 固定のものは
    // パターン側で 0 に決まる）。
    m.formats.push(fmt(
        "FRRCDS",
        &["fa", "fb", "cf", "sh", "b5", "fc"],
        vec![
            gr("r2", "fa", Access::Read),
            gr("r1", "fb", Access::Read),
            val("cf", "cf"),
            val("sh", "sh"),
            val("d", "b5"),
            gr("t", "fc", Access::Write),
        ],
    ));
    // @rrr_sh（hshladd/hshradd）。
    m.formats.push(fmt(
        "FRRSH",
        &["fa", "fb", "sh", "fc"],
        vec![
            gr("r2", "fa", Access::Read),
            gr("r1", "fb", Access::Read),
            val("sh", "sh"),
            gr("t", "fc", Access::Write),
        ],
    ));
    // @rr_cf_d（dcor 系。pos11-15 は 00000 固定）。
    m.formats.push(fmt(
        "FDC",
        &["fa", "cf", "b5", "fc"],
        vec![
            gr("r", "fa", Access::Read),
            val("cf", "cf"),
            val("d", "b5"),
            gr("t", "fc", Access::Write),
        ],
    ));
    // hshl/hshr（4 ビットシフト量）。hshl は r が pos11-15
    // （fb）だが hshr は pos6-10（fa）と違うので別形式。
    m.formats.push(fmt(
        "FHS",
        &["fb", "i4", "fc"],
        vec![gr("r", "fb", Access::Read), val("i", "i4"), gr("t", "fc", Access::Write)],
    ));
    m.formats.push(fmt(
        "FHSA",
        &["fa", "i4", "fc"],
        vec![gr("r", "fa", Access::Read), val("i", "i4"), gr("t", "fc", Access::Write)],
    ));
    // @rri_cf（addi/subi。i は lowsign_11 の素の 11 ビット）。
    m.formats.push(fmt(
        "FRRIC",
        &["fa", "fb", "cf", "im11"],
        vec![
            gr("r", "fa", Access::Read),
            gr("t", "fb", Access::Write),
            val("cf", "cf"),
            val("i", "im11"),
        ],
    ));
    // @rri_cf_d（cmpiclr。d は d_11）。
    m.formats.push(fmt(
        "FRRICD",
        &["fa", "fb", "cf", "b11", "im11"],
        vec![
            gr("r", "fa", Access::Read),
            gr("t", "fb", Access::Write),
            val("cf", "cf"),
            val("d", "b11"),
            val("i", "im11"),
        ],
    ));
    // permh（半語選択完語 c0-c3）。
    m.formats.push(fmt(
        "FPERMH",
        &["fa", "fb", "cc2", "pm1", "pm2", "sh", "fc"],
        vec![
            gr("r1", "fa", Access::Read),
            gr("r2", "fb", Access::Read),
            val("c0", "cc2"),
            val("c1", "pm1"),
            val("c2", "pm2"),
            val("c3", "sh"),
            gr("t", "fc", Access::Write),
        ],
    ));
    // @ldim5（整数 load 即値形。disp は im5_16 の素値、ma は
    // ma_to_m の 2 ビット）。
    m.formats.push(fmt(
        "FMIL",
        &["fa", "im5h", "sp2", "size", "ma5", "fc"],
        vec![
            gr("b", "fa", Access::Read),
            val("disp", "im5h"),
            val("sp", "sp2"),
            val("size", "size"),
            val("ma", "ma5"),
            gr("t", "fc", Access::Write),
        ],
    ));
    // @ldstx（整数 load 索引形）。
    m.formats.push(fmt(
        "FMIXL",
        &["fa", "fb", "sp2", "b13", "b5", "fc"],
        vec![
            gr("b", "fa", Access::Read),
            gr("x", "fb", Access::Read),
            val("sp", "sp2"),
            val("scale", "b13"),
            val("m", "b5"),
            gr("t", "fc", Access::Write),
        ],
    ));
    // @stim5（整数 store。データは fb 桁、im5_0 の素値が disp）。
    m.formats.push(fmt(
        "FMIS",
        &["fa", "fb", "sp2", "size", "ma5", "im5"],
        vec![
            gr("b", "fa", Access::Read),
            gr("t", "fb", Access::Read),
            val("sp", "sp2"),
            val("size", "size"),
            val("ma", "ma5"),
            val("disp", "im5"),
        ],
    ));
    // ldcw/ldcd/ldaw/ldda・staw/stda は pos22-25 が完語定数で
    // あり size 桁ではない（size は insn 名で決まる）ので、
    // size オペランドを持たない別形式にする。
    m.formats.push(fmt(
        "FMILC",
        &["fa", "im5h", "sp2", "ma5", "fc"],
        vec![
            gr("b", "fa", Access::Read),
            val("disp", "im5h"),
            val("sp", "sp2"),
            val("ma", "ma5"),
            gr("t", "fc", Access::Write),
        ],
    ));
    m.formats.push(fmt(
        "FMIXC",
        &["fa", "fb", "sp2", "b13", "b5", "fc"],
        vec![
            gr("b", "fa", Access::Read),
            gr("x", "fb", Access::Read),
            val("sp", "sp2"),
            val("scale", "b13"),
            val("m", "b5"),
            gr("t", "fc", Access::Write),
        ],
    ));
    m.formats.push(fmt(
        "FMISC",
        &["fa", "fb", "sp2", "ma5", "im5"],
        vec![
            gr("b", "fa", Access::Read),
            gr("t", "fb", Access::Read),
            val("sp", "sp2"),
            val("ma", "ma5"),
            val("disp", "im5"),
        ],
    ));
    // stby/stdby（a は前後選択、m はベース更新）。
    m.formats.push(fmt(
        "FSTBY",
        &["fa", "fb", "sp2", "b13", "b5", "im5"],
        vec![
            gr("b", "fa", Access::Read),
            gr("r", "fb", Access::Read),
            val("sp", "sp2"),
            val("a", "b13"),
            val("m", "b5"),
            val("disp", "im5"),
        ],
    ));
    // @fldstwx/@fldstwi（fldw/fstw。t は rt64 で fr0-63R/L を指す）。
    m.formats.push(fmt(
        "FFWXL",
        &["fa", "fb", "sp2", "b13", "b5", "r64t"],
        vec![
            gr("b", "fa", Access::Read),
            gr("x", "fb", Access::Read),
            val("sp", "sp2"),
            val("scale", "b13"),
            val("m", "b5"),
            fpr("t", "r64t", Access::Write),
        ],
    ));
    m.formats.push(fmt(
        "FFWXS",
        &["fa", "fb", "sp2", "b13", "b5", "r64t"],
        vec![
            gr("b", "fa", Access::Read),
            gr("x", "fb", Access::Read),
            val("sp", "sp2"),
            val("scale", "b13"),
            val("m", "b5"),
            fpr("t", "r64t", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FFWIL",
        &["fa", "im5h", "sp2", "ma5", "r64t"],
        vec![
            gr("b", "fa", Access::Read),
            val("disp", "im5h"),
            val("sp", "sp2"),
            val("ma", "ma5"),
            fpr("t", "r64t", Access::Write),
        ],
    ));
    m.formats.push(fmt(
        "FFWIS",
        &["fa", "im5h", "sp2", "ma5", "r64t"],
        vec![
            gr("b", "fa", Access::Read),
            val("disp", "im5h"),
            val("sp", "sp2"),
            val("ma", "ma5"),
            fpr("t", "r64t", Access::Read),
        ],
    ));
    // @fldstdx/@fldstdi（fldd/fstd。t は 5 ビットのペア指定）。
    m.formats.push(fmt(
        "FFDXL",
        &["fa", "fb", "sp2", "b13", "b5", "fc"],
        vec![
            gr("b", "fa", Access::Read),
            gr("x", "fb", Access::Read),
            val("sp", "sp2"),
            val("scale", "b13"),
            val("m", "b5"),
            fpr("t", "fc", Access::Write),
        ],
    ));
    m.formats.push(fmt(
        "FFDXS",
        &["fa", "fb", "sp2", "b13", "b5", "fc"],
        vec![
            gr("b", "fa", Access::Read),
            gr("x", "fb", Access::Read),
            val("sp", "sp2"),
            val("scale", "b13"),
            val("m", "b5"),
            fpr("t", "fc", Access::Read),
        ],
    ));
    m.formats.push(fmt(
        "FFDIL",
        &["fa", "im5h", "sp2", "ma5", "fc"],
        vec![
            gr("b", "fa", Access::Read),
            val("disp", "im5h"),
            val("sp", "sp2"),
            val("ma", "ma5"),
            fpr("t", "fc", Access::Write),
        ],
    ));
    m.formats.push(fmt(
        "FFDIS",
        &["fa", "im5h", "sp2", "ma5", "fc"],
        vec![
            gr("b", "fa", Access::Read),
            val("disp", "im5h"),
            val("sp", "sp2"),
            val("ma", "ma5"),
            fpr("t", "fc", Access::Read),
        ],
    ));
    // オフセット形式（opcode 0x10-0x1f）。16 ビットの素材をその
    // まま渡す。disp/sp/m の切り分け（expand_16/12a/11a と
    // neg_to_m/pos_to_m/ma2_to_m）は意味論が insn 名で振り分ける。
    m.formats.push(fmt(
        "FOFFL",
        &["fa", "fb", "im16"],
        vec![gr("b", "fa", Access::Read), gr("t", "fb", Access::Write), val("off", "im16")],
    ));
    m.formats.push(fmt(
        "FOFFS",
        &["fa", "fb", "im16"],
        vec![gr("b", "fa", Access::Read), gr("t", "fb", Access::Read), val("off", "im16")],
    ));
    m.formats.push(fmt(
        "FOFFDL",
        &["fa", "fb", "im16"],
        vec![gr("b", "fa", Access::Read), fpr("t", "fb", Access::Write), val("off", "im16")],
    ));
    m.formats.push(fmt(
        "FOFFDS",
        &["fa", "fb", "im16"],
        vec![gr("b", "fa", Access::Read), fpr("t", "fb", Access::Read), val("off", "im16")],
    ));
    // fldw/fstw のオフセット形（0x16/0x17/0x1e/0x1f）。f は
    // rm64（bit1 が上位桁）。offa は assemble_12a の素材で
    // bit2 が a_to_m の m。
    m.formats.push(fmt(
        "FFOWL",
        &["fa", "r64m", "offa", "a2m"],
        vec![
            gr("b", "fa", Access::Read),
            fpr("f", "r64m", Access::Write),
            val("off", "offa"),
            val("m", "a2m"),
        ],
    ));
    m.formats.push(fmt(
        "FFOWS",
        &["fa", "r64m", "offa", "a2m"],
        vec![
            gr("b", "fa", Access::Read),
            fpr("f", "r64m", Access::Read),
            val("off", "offa"),
            val("m", "a2m"),
        ],
    ));
    // fmpyadd/fmpysub。
    m.formats.push(fmt(
        "FMPY",
        &["fa", "fb", "fta", "fra", "fc"],
        vec![
            fpr("rm1", "fa", Access::Read),
            fpr("rm2", "fb", Access::Read),
            fpr("ta", "fta", Access::ReadWrite),
            fpr("ra", "fra", Access::Read),
            fpr("tm", "fc", Access::Write),
        ],
    ));
    // @rrb_cf/@rrb_cdf（cmpb 系。c3 の最下位は cmpb では d_13 と
    // 共有するので生値で渡す）。
    m.formats.push(fmt(
        "FRRB",
        &["fa", "fb", "c3", "bdisp", "n1"],
        vec![
            gr("r2", "fa", Access::Read),
            gr("r1", "fb", Access::Read),
            val("c", "c3"),
            val("disp", "bdisp"),
            val("n", "n1"),
        ],
    ));
    // addb/addbt は r2 を更新するので第1レジスタは ReadWrite。
    m.formats.push(fmt(
        "FADDB",
        &["fa", "fb", "c3", "bdisp", "n1"],
        vec![
            gr("r2", "fa", Access::ReadWrite),
            gr("r1", "fb", Access::Read),
            val("c", "c3"),
            val("disp", "bdisp"),
            val("n", "n1"),
        ],
    ));
    // @rib_cf（addbi/movbi/cmpbi）。
    m.formats.push(fmt(
        "FRIB",
        &["fa", "im5h", "c3", "bdisp", "n1"],
        vec![
            gr("r", "fa", Access::Read),
            val("i", "im5h"),
            val("c", "c3"),
            val("disp", "bdisp"),
            val("n", "n1"),
        ],
    ));
    // addib/addibt は r を更新するので第1レジスタは ReadWrite。
    m.formats.push(fmt(
        "FADDBI",
        &["fa", "im5h", "c3", "bdisp", "n1"],
        vec![
            gr("r", "fa", Access::ReadWrite),
            val("i", "im5h"),
            val("c", "c3"),
            val("disp", "bdisp"),
            val("n", "n1"),
        ],
    ));
    // @rib_cdf（cmpbi_d。c は cmpbid_c の素の 2 ビット、f は
    // bit15）。
    m.formats.push(fmt(
        "FRIBD",
        &["fa", "im5h", "b15", "cc2", "bdisp", "n1"],
        vec![
            gr("r", "fa", Access::Read),
            val("i", "im5h"),
            val("f", "b15"),
            val("c", "cc2"),
            val("disp", "bdisp"),
            val("n", "n1"),
        ],
    ));
    // bb（bit15 が条件、bit13 が PA 2.0 の d）。
    m.formats.push(fmt(
        "FBBS",
        &["fb", "b15", "b13", "bdisp", "n1"],
        vec![
            gr("r", "fb", Access::Read),
            val("c", "b15"),
            val("d", "b13"),
            val("disp", "bdisp"),
            val("n", "n1"),
        ],
    ));
    m.formats.push(fmt(
        "FBBI",
        &["fa", "fb", "b15", "b13", "bdisp", "n1"],
        vec![
            val("p", "fa"),
            gr("r", "fb", Access::Read),
            val("c", "b15"),
            val("d", "b13"),
            val("disp", "bdisp"),
            val("n", "n1"),
        ],
    ));
    // shrp。
    m.formats.push(fmt(
        "FSHS",
        &["fa", "fb", "c3", "b9", "fc"],
        vec![
            gr("r2", "fa", Access::Read),
            gr("r1", "fb", Access::Read),
            val("c", "c3"),
            val("d", "b9"),
            gr("t", "fc", Access::Write),
        ],
    ));
    m.formats.push(fmt(
        "FSHI",
        &["fa", "fb", "c3", "cp5", "fc"],
        vec![
            gr("r2", "fa", Access::Read),
            gr("r1", "fb", Access::Read),
            val("c", "c3"),
            val("cpos", "cp5"),
            gr("t", "fc", Access::Write),
        ],
    ));
    m.formats.push(fmt(
        "FSHID",
        &["fa", "fb", "c3", "cpos6", "fc"],
        vec![
            gr("r2", "fa", Access::Read),
            gr("r1", "fb", Access::Read),
            val("c", "c3"),
            val("cpos", "cpos6"),
            gr("t", "fc", Access::Write),
        ],
    ));
    // extr。
    m.formats.push(fmt(
        "FEXS",
        &["fa", "fb", "c3", "b10", "len5"],
        vec![
            gr("r", "fa", Access::Read),
            gr("t", "fb", Access::Write),
            val("c", "c3"),
            val("se", "b10"),
            val("len", "len5"),
        ],
    ));
    m.formats.push(fmt(
        "FEXSD",
        &["fa", "fb", "c3", "b10", "len6a"],
        vec![
            gr("r", "fa", Access::Read),
            gr("t", "fb", Access::Write),
            val("c", "c3"),
            val("se", "b10"),
            val("len", "len6a"),
        ],
    ));
    m.formats.push(fmt(
        "FEXI",
        &["fa", "fb", "c3", "b10", "cp5", "len5"],
        vec![
            gr("r", "fa", Access::Read),
            gr("t", "fb", Access::Write),
            val("c", "c3"),
            val("se", "b10"),
            val("pos", "cp5"),
            val("len", "len5"),
        ],
    ));
    m.formats.push(fmt(
        "FEXID",
        &["fa", "fb", "c3", "b10", "cpos6", "len6b"],
        vec![
            gr("r", "fa", Access::Read),
            gr("t", "fb", Access::Write),
            val("c", "c3"),
            val("se", "b10"),
            val("pos", "cpos6"),
            val("len", "len6b"),
        ],
    ));
    // dep（t は元値を読んで上書きする）。
    m.formats.push(fmt(
        "FDEPS",
        &["fa", "fb", "c3", "b10", "len5"],
        vec![
            gr("t", "fa", Access::ReadWrite),
            gr("r", "fb", Access::Read),
            val("c", "c3"),
            val("nz", "b10"),
            val("len", "len5"),
        ],
    ));
    m.formats.push(fmt(
        "FDEPSD",
        &["fa", "fb", "c3", "b10", "len6a"],
        vec![
            gr("t", "fa", Access::ReadWrite),
            gr("r", "fb", Access::Read),
            val("c", "c3"),
            val("nz", "b10"),
            val("len", "len6a"),
        ],
    ));
    m.formats.push(fmt(
        "FDEPI",
        &["fa", "fb", "c3", "b10", "cp5", "len5"],
        vec![
            gr("t", "fa", Access::ReadWrite),
            gr("r", "fb", Access::Read),
            val("c", "c3"),
            val("nz", "b10"),
            val("cpos", "cp5"),
            val("len", "len5"),
        ],
    ));
    m.formats.push(fmt(
        "FDEPID",
        &["fa", "fb", "c3", "b10", "cpos6", "len6b"],
        vec![
            gr("t", "fa", Access::ReadWrite),
            gr("r", "fb", Access::Read),
            val("c", "c3"),
            val("nz", "b10"),
            val("cpos", "cpos6"),
            val("len", "len6b"),
        ],
    ));
    // depi（t は元値を読んで上書き。i は im5_16 の素値）。
    m.formats.push(fmt(
        "FDEPIS",
        &["fa", "im5h", "c3", "b10", "b9", "len6a"],
        vec![
            gr("t", "fa", Access::ReadWrite),
            val("i", "im5h"),
            val("c", "c3"),
            val("nz", "b10"),
            val("d", "b9"),
            val("len", "len6a"),
        ],
    ));
    m.formats.push(fmt(
        "FDEPII",
        &["fa", "im5h", "c3", "b10", "cp5", "len5"],
        vec![
            gr("t", "fa", Access::ReadWrite),
            val("i", "im5h"),
            val("c", "c3"),
            val("nz", "b10"),
            val("cpos", "cp5"),
            val("len", "len5"),
        ],
    ));
    m.formats.push(fmt(
        "FDEPIID",
        &["fa", "im5h", "c3", "b10", "cpos6", "len6b"],
        vec![
            gr("t", "fa", Access::ReadWrite),
            val("i", "im5h"),
            val("c", "c3"),
            val("nz", "b10"),
            val("cpos", "cpos6"),
            val("len", "len6b"),
        ],
    ));
    // be/ble（w は assemble_17 の上位 5 ビット、sp は sr3 の素値）。
    m.formats.push(fmt(
        "FBE",
        &["fa", "im5h", "c3", "bdisp", "n1"],
        vec![
            gr("b", "fa", Access::Read),
            val("w", "im5h"),
            val("sp", "c3"),
            val("disp", "bdisp"),
            val("n", "n1"),
        ],
    ));
    // bl/gate（l はリンク先レジスタで Write）。
    m.formats.push(fmt(
        "FBL",
        &["fa", "im5h", "bdisp", "n1"],
        vec![
            gr("l", "fa", Access::Write),
            val("w", "im5h"),
            val("disp", "bdisp"),
            val("n", "n1"),
        ],
    ));
    // bl の長変位形（l=2 固定、assemble_22 の上位 10 ビット）。
    m.formats.push(fmt(
        "FBLL",
        &["w10", "bdisp", "n1"],
        vec![val("w", "w10"), val("disp", "bdisp"), val("n", "n1")],
    ));
    // blr（l はリンク先のレジスタ番号。disp は 0 固定なので
    // オペランドにしない）。
    m.formats.push(fmt(
        "FBLR",
        &["fa", "fb", "n1"],
        vec![
            gr("l", "fa", Access::Write),
            gr("x", "fb", Access::Read),
            val("n", "n1"),
        ],
    ));
    // bv（b は分岐先を持つレジスタ。disp も固定）。
    m.formats.push(fmt(
        "FBV",
        &["fa", "fb", "n1"],
        vec![gr("b", "fa", Access::Read), gr("x", "fb", Access::Read), val("n", "n1")],
    ));
    // bve。
    m.formats.push(fmt(
        "FBVE",
        &["fa", "n1"],
        vec![gr("b", "fa", Access::Read), val("n", "n1")],
    ));
    // FP class 0/1（@f0c_0/@f0c_1/@f0e_d_0/@f0e_dd_1 共通）。
    m.formats.push(fmt(
        "FF01",
        &["fa", "fc"],
        vec![fpr("r", "fa", Access::Read), fpr("t", "fc", Access::Write)],
    ));
    // FP class 2（fcmp。y は cbit、 c は条件）。
    m.formats.push(fmt(
        "FF2",
        &["fa", "fb", "c3", "fc"],
        vec![
            fpr("r1", "fa", Access::Read),
            fpr("r2", "fb", Access::Read),
            val("y", "c3"),
            val("c", "fc"),
        ],
    ));
    // FP class 3（fadd/fsub/fmpy/fdiv）。
    m.formats.push(fmt(
        "FF3",
        &["fa", "fb", "fc"],
        vec![
            fpr("r1", "fa", Access::Read),
            fpr("r2", "fb", Access::Read),
            fpr("t", "fc", Access::Write),
        ],
    ));
    // ftest。
    m.formats.push(fmt(
        "FFTEST",
        &["c3", "fc"],
        vec![val("y", "c3"), val("c", "fc")],
    ));
    // PA 2.0 FP class 0/1（ra64/rt64 の 6 ビット選択）。
    m.formats.push(fmt(
        "FFFE1",
        &["r64a", "r64t"],
        vec![fpr("r", "r64a", Access::Read), fpr("t", "r64t", Access::Write)],
    ));
    m.formats.push(fmt(
        "FFFD1",
        &["r64a", "fc"],
        vec![fpr("r", "r64a", Access::Read), fpr("t", "fc", Access::Write)],
    ));
    m.formats.push(fmt(
        "FFDF1",
        &["fa", "r64t"],
        vec![fpr("r", "fa", Access::Read), fpr("t", "r64t", Access::Write)],
    ));
    // PA 2.0 FP class 2（fcmp_fx）。
    m.formats.push(fmt(
        "FFFE2",
        &["r64a", "r64b", "c3", "fc"],
        vec![
            fpr("r1", "r64a", Access::Read),
            fpr("r2", "r64b", Access::Read),
            val("y", "c3"),
            val("c", "fc"),
        ],
    ));
    // PA 2.0 FP class 3。
    m.formats.push(fmt(
        "FFFE3",
        &["r64a", "r64b", "r64t"],
        vec![
            fpr("r1", "r64a", Access::Read),
            fpr("r2", "r64b", Access::Read),
            fpr("t", "r64t", Access::Write),
        ],
    ));
    // xmpyu（64 ビット選択の乗算。t はペア指定の 5 ビット）。
    m.formats.push(fmt(
        "FXXY",
        &["r64a", "r64b", "fc"],
        vec![
            fpr("r1", "r64a", Access::Read),
            fpr("r2", "r64b", Access::Read),
            fpr("t", "fc", Access::Write),
        ],
    ));
    // fmpyfadd_f（全桁 ra64/rb64/rc64/rt64）。
    m.formats.push(fmt(
        "FFFADF",
        &["r64a", "r64b", "r64c", "b5", "r64t"],
        vec![
            fpr("rm1", "r64a", Access::Read),
            fpr("rm2", "r64b", Access::Read),
            fpr("ra3", "r64c", Access::Read),
            val("neg", "b5"),
            fpr("t", "r64t", Access::Write),
        ],
    ));
    // fmpyfadd_d（ra3 は rc32 の 5 ビット）。
    m.formats.push(fmt(
        "FFFADD",
        &["fa", "fb", "r32c", "b5", "fc"],
        vec![
            fpr("rm1", "fa", Access::Read),
            fpr("rm2", "fb", Access::Read),
            fpr("ra3", "r32c", Access::Read),
            val("neg", "b5"),
            fpr("t", "fc", Access::Write),
        ],
    ));
    // ldil/addil/ldo の即値形。
    m.formats.push(fmt(
        "FLDIL",
        &["fa", "im21"],
        vec![gr("t", "fa", Access::Write), val("i", "im21")],
    ));
    m.formats.push(fmt(
        "FADDIL",
        &["fa", "im21"],
        vec![gr("r", "fa", Access::Read), val("i", "im21")],
    ));

    // 機能述語は isadl の `when` 文法（`&&`・`||`・`!`・括弧）。
    let pred = |feat: &str| -> Pred {
        if feat.is_empty() {
            return Pred::True;
        }
        polyisa_isadl::pred::parse(feat).expect("valid when")
    };
    let mut ins = |name: &str,
                   format: &str,
                   pattern: &str,
                   syntax: &str,
                   feat: &str,
                   wheres: Vec<WhereClause>,
                   timing: &str| {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: pred(feat),
            wheres,
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    };
    let weq = |field: &str, v: u128| WhereClause {
        field: field.to_string(),
        op: WhereOp::Eq,
        rhs: WhereRhs::Lit(v),
    };
    let wne = |field: &str, v: u128| WhereClause {
        field: field.to_string(),
        op: WhereOp::Ne,
        rhs: WhereRhs::Lit(v),
    };

    // ---- System（opcode 0x00）----
    ins(
        "break",
        "FBRK",
        "000000 ..... ..... ... 00000000 .....",
        "break {im5}, {im13}",
        "",
        vec![],
        "system",
    );
    ins(
        "mtsp",
        "FMTSP",
        "000000 ..... ..... ... 11000001 00000",
        "mtsp {r}, {sp}",
        "",
        vec![],
        "system",
    );
    ins(
        "mtctl",
        "FMTCTL",
        "000000 ..... ..... ... 11000010 00000",
        "mtctl {r}, {t}",
        "",
        vec![],
        "system",
    );
    // mtsarcm は PA 2.0 付録C にのみあり、PA1.1 では未割当。
    ins(
        "mtsarcm",
        "F1R",
        "000000 01011 ..... ... 11000110 00000",
        "mtsarcm {r}",
        "pa20",
        vec![],
        "system",
    );
    ins(
        "mtsm",
        "F1R",
        "000000 00000 ..... 000 11000011 00000",
        "mtsm {r}",
        "",
        vec![],
        "system",
    );
    // mfia は PA 2.0 付録C にのみあり、PA1.1 では未割当。
    ins(
        "mfia",
        "F1TW",
        "000000 ..... 00000 ... 10100101 .....",
        "mfia {t}",
        "pa20",
        vec![],
        "system",
    );
    ins(
        "mfsp",
        "FMFSP",
        "000000 ..... 00000 ... 00100101 .....",
        "mfsp {sp}, {t}",
        "",
        vec![],
        "system",
    );
    ins(
        "mfctl",
        "FMFCTL",
        "000000 ..... 00000 ... 01000101 .....",
        "mfctl {r}, {t}",
        "",
        vec![],
        "system",
    );
    // SYNCDMA（bits11:15 = 0x10）はこのパターンが吸収する。
    ins(
        "sync",
        "FNONE",
        "000000 ..... ..... 000 00100000 00000",
        "sync",
        "",
        vec![],
        "system",
    );
    ins(
        "ldsid",
        "FLDSID",
        "000000 ..... ..... .. 0 10000101 .....",
        "ldsid ({b}), {sp}, {t}",
        "",
        vec![],
        "system",
    );
    ins(
        "rsm",
        "FSM",
        "000000 .......... 000 01110011 .....",
        "rsm {i}, {t}",
        "",
        vec![],
        "system",
    );
    ins(
        "ssm",
        "FSM",
        "000000 .......... 000 01101011 .....",
        "ssm {i}, {t}",
        "",
        vec![],
        "system",
    );
    ins(
        "rfi",
        "FNONE",
        "000000 ..... ..... ... 01100000 00000",
        "rfi",
        "",
        vec![],
        "system",
    );
    ins(
        "rfi_r",
        "FNONE",
        "000000 ..... ..... ... 01100101 00000",
        "rfi,r",
        "",
        vec![],
        "system",
    );
    ins(
        "diag",
        "FDIAG",
        "000101 ..........................",
        "diag {i}",
        "",
        vec![],
        "system",
    );

    // ---- Memory Management（opcode 0x01）----
    // fdc の即値形（ext 0xCA）は PA 2.0 付録C にのみあり、
    // PA1.1 では未割当。
    ins(
        "fdc",
        "FNONE",
        "000001 ..... ..... .. 11001010 0 .....",
        "fdc ({b})",
        "pa20",
        vec![],
        "system",
    );
    ins(
        "fdcx",
        "FMMX",
        "000001 ..... ..... .. 01001010 . .....",
        "fdcx {x}({b})",
        "",
        vec![],
        "system",
    );
    ins(
        "fdce",
        "FMMX",
        "000001 ..... ..... .. 01001011 . .....",
        "fdce {x}({b})",
        "",
        vec![],
        "system",
    );
    // instruction MM の s は Figure D-2/C-2 上 3 ビット
    // （bits16:18）なので、pxtlb_s 系と同じ FMMXS を使う。
    ins(
        "fic",
        "FMMXS",
        "000001 ..... ..... ... 0001010 . .....",
        "fic {x}({b})",
        "",
        vec![],
        "system",
    );
    // fic4f（PA 2.0 の fdc/fic 統合形）は PA 2.0 付録C にのみ
    // あり、PA1.1 では未割当。data-MM なので sp は FMMX の
    // 2 ビット。
    ins(
        "fic4f",
        "FMMX",
        "000001 ..... ..... .. 01001111 . 00000",
        "fic {x}({b})",
        "pa20",
        vec![],
        "system",
    );
    ins(
        "fice",
        "FMMXS",
        "000001 ..... ..... ... 0001011 . .....",
        "fice ({b})",
        "",
        vec![],
        "system",
    );
    ins(
        "pdc",
        "FMMX",
        "000001 ..... ..... .. 01001110 . 00000",
        "pdc {x}({b})",
        "",
        vec![],
        "system",
    );
    ins(
        "probe",
        "FPROBE",
        "000001 ..... ..... .. . 100011 . 0 .....",
        "probe ({b}), {ri}, {t}",
        "",
        vec![],
        "system",
    );
    // PA1.x の TLB 挿入命令（PA 2.0 では無効）。
    ins(
        "ixtlbx_d",
        "FIXBX",
        "000001 ..... ..... .. 0100000 . 0 00000",
        "ixtlbx {r}, ({b})",
        "pa11 && !pa20",
        vec![],
        "system",
    );
    ins(
        "ixtlbx_i",
        "FIXBXS",
        "000001 ..... ..... ... 000000 . 0 00000",
        "ixtlbx {r}, ({b})",
        "pa11 && !pa20",
        vec![],
        "system",
    );
    ins(
        "ixtlbt",
        "FITBT",
        "000001 ..... ..... 000 . 100000 0 00000",
        "ixtlbt {r1}, {r2}",
        "pa20",
        vec![],
        "system",
    );
    ins(
        "pxtlb",
        "FMMX",
        "000001 ..... ..... .. 01001000 . .....",
        "pxtlb {x}({b})",
        "",
        vec![],
        "system",
    );
    ins(
        "pxtlb_s",
        "FMMXS",
        "000001 ..... ..... ... 0001000 . .....",
        "pxtlb {x}({b})",
        "",
        vec![],
        "system",
    );
    ins(
        "pxtlb_l",
        "FMMX",
        "000001 ..... ..... .. 01011000 . .....",
        "pxtlb,l {x}({b})",
        "pa20",
        vec![],
        "system",
    );
    ins(
        "pxtlb_ls",
        "FMMXS",
        "000001 ..... ..... ... 0011000 . .....",
        "pxtlb,l {x}({b})",
        "pa20",
        vec![],
        "system",
    );
    ins(
        "pxtlbe",
        "FMMX",
        "000001 ..... ..... .. 01001001 . .....",
        "pxtlbe {x}({b})",
        "",
        vec![],
        "system",
    );
    ins(
        "pxtlbe_s",
        "FMMXS",
        "000001 ..... ..... ... 0001001 . .....",
        "pxtlbe {x}({b})",
        "",
        vec![],
        "system",
    );
    ins(
        "lpa",
        "FLPA",
        "000001 ..... ..... .. 01001101 . .....",
        "lpa {x}({b}), {t}",
        "",
        vec![],
        "system",
    );
    ins(
        "lci",
        "F1TW",
        "000001 ..... ..... .. 01001100 0 .....",
        "lci ({b}), {t}",
        "",
        vec![],
        "system",
    );

    // ---- Arith/Log（opcode 0x02 ほか）----
    for (nm, ext) in [
        ("andcm", "000000"),
        ("and", "001000"),
        ("or", "001001"),
        ("xor", "001010"),
        ("uxor", "001110"),
        ("cmpclr", "100010"),
        ("uaddcm", "100110"),
        ("uaddcm_tc", "100111"),
        ("sub", "010000"),
        ("sub_tsv", "110000"),
        ("sub_tc", "010011"),
        ("sub_tsv_tc", "110011"),
    ] {
        ins(
            nm,
            "FRRCD",
            &format!("000010 ..... ..... .... {ext} . ....."),
            &format!("{nm} {{r2}}, {{r1}}, {{t}}"),
            "",
            vec![],
            "alu",
        );
    }
    ins(
        "ds",
        "FRRC",
        "000010 ..... ..... .... 010001 0 .....",
        "ds {r2}, {r1}, {t}",
        "",
        vec![],
        "alu",
    );
    ins(
        "dcor",
        "FDC",
        "000010 ..... 00000 .... 101110 . .....",
        "dcor {r}, {t}",
        "",
        vec![],
        "alu",
    );
    ins(
        "dcor_i",
        "FDC",
        "000010 ..... 00000 .... 101111 . .....",
        "dcor,i {r}, {t}",
        "",
        vec![],
        "alu",
    );
    // add/sub で sh を持つ形。add_c/sub_b の sh=00 固定と
    // hshladd/hshradd の sh!=0 固定で語を一意に切り分ける。
    for (nm, ext) in [
        ("add", "0110.."),
        ("add_l", "1010.."),
        ("add_tsv", "1110.."),
    ] {
        ins(
            nm,
            "FRRCDS",
            &format!("000010 ..... ..... .... {ext} . ....."),
            &format!("{nm} {{r2}}, {{r1}}, {{t}}"),
            "",
            vec![],
            "alu",
        );
    }
    ins(
        "add_c",
        "FRRCDS",
        "000010 ..... ..... .... 011100 . .....",
        "add,c {r2}, {r1}, {t}",
        "",
        vec![weq("sh", 0)],
        "alu",
    );
    ins(
        "hshladd",
        "FRRSH",
        "000010 ..... ..... 0000 0111.. 0 .....",
        "hshladd {r2}, {r1}, {t}",
        "max1 || max2",
        vec![wne("sh", 0)],
        "alu",
    );
    ins(
        "add_c_tsv",
        "FRRCDS",
        "000010 ..... ..... .... 111100 . .....",
        "add,c,tsv {r2}, {r1}, {t}",
        "",
        vec![weq("sh", 0)],
        "alu",
    );
    ins(
        "sub_b",
        "FRRCDS",
        "000010 ..... ..... .... 010100 . .....",
        "sub,b {r2}, {r1}, {t}",
        "",
        vec![weq("sh", 0)],
        "alu",
    );
    ins(
        "hshradd",
        "FRRSH",
        "000010 ..... ..... 0000 0101.. 0 .....",
        "hshradd {r2}, {r1}, {t}",
        "max1 || max2",
        vec![wne("sh", 0)],
        "alu",
    );
    ins(
        "sub_b_tsv",
        "FRRCDS",
        "000010 ..... ..... .... 110100 . .....",
        "sub,b,tsv {r2}, {r1}, {t}",
        "",
        vec![],
        "alu",
    );

    ins(
        "ldil",
        "FLDIL",
        "001000 ..... .....................",
        "ldil {i}, {t}",
        "",
        vec![],
        "alu",
    );
    ins(
        "addil",
        "FADDIL",
        "001010 ..... .....................",
        "addil {i}, {r}",
        "",
        vec![],
        "alu",
    );
    ins(
        "ldo",
        "FOFFL",
        "001101 ..... ..... ................",
        "ldo {off}({b}), {t}",
        "",
        vec![],
        "alu",
    );

    for (nm, op, o) in [
        ("addi", "101101", "0"),
        ("addi_tsv", "101101", "1"),
        ("addi_tc", "101100", "0"),
        ("addi_tc_tsv", "101100", "1"),
        ("subi", "100101", "0"),
        ("subi_tsv", "100101", "1"),
    ] {
        ins(
            nm,
            "FRRIC",
            &format!("{op} ..... ..... .... {o} ..........."),
            &format!("{nm} {{i}}, {{r}}, {{t}}"),
            "",
            vec![],
            "alu",
        );
    }
    ins(
        "cmpiclr",
        "FRRICD",
        "100100 ..... ..... .... . ...........",
        "cmpiclr {i}, {r}, {t}",
        "",
        vec![],
        "alu",
    );

    // 半語加減算は MAX-1（PA7100LC/PA7300LC）にあり、PA 2.0
    // 付録C Table C-5/C-12 にも掲載があるので max1||max2。
    for (nm, pat) in [
        ("hadd", "00000011 11 0"),
        ("hadd_ss", "00000011 01 0"),
        ("hadd_us", "00000011 00 0"),
        ("havg", "00000010 11 0"),
        ("hsub", "00000001 11 0"),
        ("hsub_ss", "00000001 01 0"),
        ("hsub_us", "00000001 00 0"),
    ] {
        ins(
            nm,
            "FRRR",
            &format!("000010 ..... ..... {pat} ....."),
            &format!("{nm} {{r2}}, {{r1}}, {{t}}"),
            "max1 || max2",
            vec![],
            "alu",
        );
    }
    // MAX-2（PA-8000 系列）。
    ins(
        "hshl",
        "FHS",
        "111110 00000 ..... 100010 .... 0 .....",
        "hshl {r}, {i}, {t}",
        "max2",
        vec![],
        "alu",
    );
    ins(
        "hshr_s",
        "FHSA",
        "111110 ..... 00000 110011 .... 0 .....",
        "hshr,s {r}, {i}, {t}",
        "max2",
        vec![],
        "alu",
    );
    ins(
        "hshr_u",
        "FHSA",
        "111110 ..... 00000 110010 .... 0 .....",
        "hshr,u {r}, {i}, {t}",
        "max2",
        vec![],
        "alu",
    );
    ins(
        "mixh_l",
        "FRRR",
        "111110 ..... ..... 1 00 00100000 .....",
        "mixh,l {r2}, {r1}, {t}",
        "max2",
        vec![],
        "alu",
    );
    ins(
        "mixh_r",
        "FRRR",
        "111110 ..... ..... 1 10 00100000 .....",
        "mixh,r {r2}, {r1}, {t}",
        "max2",
        vec![],
        "alu",
    );
    ins(
        "mixw_l",
        "FRRR",
        "111110 ..... ..... 1 00 00000000 .....",
        "mixw,l {r2}, {r1}, {t}",
        "max2",
        vec![],
        "alu",
    );
    ins(
        "mixw_r",
        "FRRR",
        "111110 ..... ..... 1 10 00000000 .....",
        "mixw,r {r2}, {r1}, {t}",
        "max2",
        vec![],
        "alu",
    );
    // PERMH は MAX-1 にもある（PA 2.0 付録C Table C-5/C-12
    // にも掲載）ので max1||max2。hshl/hshr/mixh/mixw は MAX-2
    // 限定。
    ins(
        "permh",
        "FPERMH",
        "111110 ..... ..... 0 .. 0 .. .. .. 0 .....",
        "permh {r1}, {r2}, {t}",
        "max1 || max2",
        vec![],
        "alu",
    );

    // ---- Index Mem（opcode 0x03）と Copr_w/Copr_dw
    // （0x09/0x0b、仕様用語のコプロセッサ load/store）----
    // size は 0..3 = b/h/w/d。size=3（ext4=3/B。LDD/STD）は
    // PA 2.0 機だけで有効なので、PA 1.1 の表に無い ext4=3/B の
    // 形は pa20 述語付きの別エントリに分け、汎用側は wheres で
    // size!=3 に絞る（SPEC-PARISC-11 付録D Table D-6 には
    // ext4=3/B が無い。SPEC-PARISC-20 付録C Table C-6）。
    ins(
        "ldi",
        "FMIL",
        "000011 ..... ..... .. . 1 .. 00.. ......",
        "ld {t}, {disp}({b})",
        "",
        vec![wne("size", 3)],
        "load",
    );
    ins(
        "ldi_d",
        "FMIL",
        "000011 ..... ..... .. . 1 .. 0011 ......",
        "ldd {t}, {disp}({b})",
        "pa20",
        vec![weq("size", 3)],
        "load",
    );
    ins(
        "ldx",
        "FMIXL",
        "000011 ..... ..... .. . 0 .. 00.. ......",
        "ld {t}, {x}({b})",
        "",
        vec![wne("size", 3)],
        "load",
    );
    ins(
        "ldx_d",
        "FMIXL",
        "000011 ..... ..... .. . 0 .. 0011 ......",
        "ldd {t}, {x}({b})",
        "pa20",
        vec![weq("size", 3)],
        "load",
    );
    ins(
        "sti",
        "FMIS",
        "000011 ..... ..... .. . 1 .. 10.. ......",
        "st {t}, {disp}({b})",
        "",
        vec![wne("size", 3)],
        "store",
    );
    ins(
        "sti_d",
        "FMIS",
        "000011 ..... ..... .. . 1 .. 1011 ......",
        "std {t}, {disp}({b})",
        "pa20",
        vec![weq("size", 3)],
        "store",
    );
    ins(
        "ldcw",
        "FMILC",
        "000011 ..... ..... .. . 1 .. 0111 ......",
        "ldcw {t}, {disp}({b})",
        "",
        vec![],
        "load",
    );
    ins(
        "ldcwx",
        "FMIXC",
        "000011 ..... ..... .. . 0 .. 0111 ......",
        "ldcw {t}, {x}({b})",
        "",
        vec![],
        "load",
    );
    ins(
        "ldcd",
        "FMILC",
        "000011 ..... ..... .. . 1 .. 0101 ......",
        "ldcd {t}, {disp}({b})",
        "pa20",
        vec![],
        "load",
    );
    ins(
        "ldcdx",
        "FMIXC",
        "000011 ..... ..... .. . 0 .. 0101 ......",
        "ldcd {t}, {x}({b})",
        "pa20",
        vec![],
        "load",
    );
    ins(
        "ldaw",
        "FMILC",
        "000011 ..... ..... .. . 1 .. 0110 ......",
        "ldaw {t}, {disp}({b})",
        "",
        vec![],
        "load",
    );
    ins(
        "ldawx",
        "FMIXC",
        "000011 ..... ..... .. . 0 .. 0110 ......",
        "ldaw {t}, {x}({b})",
        "",
        vec![],
        "load",
    );
    ins(
        "ldda",
        "FMILC",
        "000011 ..... ..... .. . 1 .. 0100 ......",
        "ldda {t}, {disp}({b})",
        "pa20",
        vec![],
        "load",
    );
    ins(
        "lddax",
        "FMIXC",
        "000011 ..... ..... .. . 0 .. 0100 ......",
        "ldda {t}, {x}({b})",
        "pa20",
        vec![],
        "load",
    );
    ins(
        "staw",
        "FMISC",
        "000011 ..... ..... .. . 1 .. 1110 ......",
        "staw {t}, {disp}({b})",
        "",
        vec![],
        "store",
    );
    ins(
        "stda",
        "FMISC",
        "000011 ..... ..... .. . 1 .. 1111 ......",
        "stda {t}, {disp}({b})",
        "pa20",
        vec![],
        "store",
    );
    ins(
        "stby",
        "FSTBY",
        "000011 ..... ..... .. . 1 .. 1100 . .....",
        "stby {r}, {disp}({b})",
        "",
        vec![],
        "store",
    );
    ins(
        "stdby",
        "FSTBY",
        "000011 ..... ..... .. . 1 .. 1101 . .....",
        "stdby {r}, {disp}({b})",
        "pa20",
        vec![],
        "store",
    );
    ins(
        "fldwx",
        "FFWXL",
        "001001 ..... ..... .. . 0 .. 000 . . .....",
        "fldw {t}, {x}({b})",
        "",
        vec![],
        "load",
    );
    ins(
        "fldwi",
        "FFWIL",
        "001001 ..... ..... .. . 1 .. 000 . . .....",
        "fldw {t}, {disp}({b})",
        "",
        vec![],
        "load",
    );
    ins(
        "fstwx",
        "FFWXS",
        "001001 ..... ..... .. . 0 .. 100 . . .....",
        "fstw {t}, {x}({b})",
        "",
        vec![],
        "store",
    );
    ins(
        "fstwi",
        "FFWIS",
        "001001 ..... ..... .. . 1 .. 100 . . .....",
        "fstw {t}, {disp}({b})",
        "",
        vec![],
        "store",
    );
    ins(
        "flddx",
        "FFDXL",
        "001011 ..... ..... .. . 0 .. 000 0 . .....",
        "fldd {t}, {x}({b})",
        "",
        vec![],
        "load",
    );
    ins(
        "flddi",
        "FFDIL",
        "001011 ..... ..... .. . 1 .. 000 0 . .....",
        "fldd {t}, {disp}({b})",
        "",
        vec![],
        "load",
    );
    ins(
        "fstd_idx",
        "FFDXS",
        "001011 ..... ..... .. . 0 .. 100 0 . .....",
        "fstd {t}, {x}({b})",
        "",
        vec![],
        "store",
    );
    ins(
        "fstd_im5",
        "FFDIS",
        "001011 ..... ..... .. . 1 .. 100 0 . .....",
        "fstd {t}, {disp}({b})",
        "",
        vec![],
        "store",
    );

    // ---- Offset Mem（opcode 0x10-0x1f）----
    // im16 の解釈: 0x10-0x13/0x18-0x1b/0x0d は expand_16、
    // 0x17/0x1f（10.）は expand_12a + pos_to_m、0x14/0x1c は
    // expand_11a + ma2_to_m。0x16/0x1e/0x17(0..)/0x1f(0..) の
    // FP 形は assemble_12a + a_to_m。
    ins(
        "ldb",
        "FOFFL",
        "010000 ..... ..... .. ..............",
        "ldb {t}, {off}({b})",
        "",
        vec![],
        "load",
    );
    ins(
        "ldh",
        "FOFFL",
        "010001 ..... ..... .. ..............",
        "ldh {t}, {off}({b})",
        "",
        vec![],
        "load",
    );
    ins(
        "ldw",
        "FOFFL",
        "010010 ..... ..... .. ..............",
        "ldw {t}, {off}({b})",
        "",
        vec![],
        "load",
    );
    ins(
        "ldwm",
        "FOFFL",
        "010011 ..... ..... .. ..............",
        "ldwm {t}, {off}({b})",
        "",
        vec![],
        "load",
    );
    ins(
        "ldwm2",
        "FOFFL",
        "010111 ..... ..... .. ...........10.",
        "ldw {t}, {off}({b})",
        "pa20",
        vec![],
        "load",
    );
    ins(
        "stb",
        "FOFFS",
        "011000 ..... ..... .. ..............",
        "stb {t}, {off}({b})",
        "",
        vec![],
        "store",
    );
    ins(
        "sth",
        "FOFFS",
        "011001 ..... ..... .. ..............",
        "sth {t}, {off}({b})",
        "",
        vec![],
        "store",
    );
    ins(
        "stw",
        "FOFFS",
        "011010 ..... ..... .. ..............",
        "stw {t}, {off}({b})",
        "",
        vec![],
        "store",
    );
    ins(
        "stwm",
        "FOFFS",
        "011011 ..... ..... .. ..............",
        "stwm {t}, {off}({b})",
        "",
        vec![],
        "store",
    );
    ins(
        "stwm2",
        "FOFFS",
        "011111 ..... ..... .. ...........10.",
        "stw {t}, {off}({b})",
        "pa20",
        vec![],
        "store",
    );
    ins(
        "ldd",
        "FOFFL",
        "010100 ..... ..... .. ............0.",
        "ldd {t}, {off}({b})",
        "pa20",
        vec![],
        "load",
    );
    ins(
        "fldd",
        "FOFFDL",
        "010100 ..... ..... .. ............1.",
        "fldd {t}, {off}({b})",
        "pa20",
        vec![],
        "load",
    );
    ins(
        "std",
        "FOFFS",
        "011100 ..... ..... .. ............0.",
        "std {t}, {off}({b})",
        "pa20",
        vec![],
        "store",
    );
    ins(
        "fstd",
        "FOFFDS",
        "011100 ..... ..... .. ............1.",
        "fstd {t}, {off}({b})",
        "pa20",
        vec![],
        "store",
    );
    // fldw/fstw のオフセット形（0x16/0x17/0x1e/0x1f の bit29=0
    // 側）は PA 2.0 付録C にのみあり、PA1.1 では未割当。
    ins(
        "fldw_o",
        "FFOWL",
        "010110 ..... ..... ................",
        "fldw {f}, {off}({b})",
        "pa20",
        vec![],
        "load",
    );
    ins(
        "fldw_o0",
        "FFOWL",
        "010111 ..... ..... .............0..",
        "fldw {f}, {off}({b})",
        "pa20",
        vec![],
        "load",
    );
    ins(
        "fstw_o",
        "FFOWS",
        "011110 ..... ..... ................",
        "fstw {f}, {off}({b})",
        "pa20",
        vec![],
        "store",
    );
    ins(
        "fstw_o0",
        "FFOWS",
        "011111 ..... ..... .............0..",
        "fstw {f}, {off}({b})",
        "pa20",
        vec![],
        "store",
    );

    // ---- Floating-point Multiply Add/Sub ----
    ins(
        "fmpyadd_f",
        "FMPY",
        "000110 ..... ..... ..... ..... 1 .....",
        "fmpyadd,f {rm1}, {rm2}, {ta}, {ra}, {tm}",
        "",
        vec![],
        "fp",
    );
    ins(
        "fmpyadd_d",
        "FMPY",
        "000110 ..... ..... ..... ..... 0 .....",
        "fmpyadd,d {rm1}, {rm2}, {ta}, {ra}, {tm}",
        "",
        vec![],
        "fp",
    );
    ins(
        "fmpysub_f",
        "FMPY",
        "100110 ..... ..... ..... ..... 1 .....",
        "fmpysub,f {rm1}, {rm2}, {ta}, {ra}, {tm}",
        "",
        vec![],
        "fp",
    );
    ins(
        "fmpysub_d",
        "FMPY",
        "100110 ..... ..... ..... ..... 0 .....",
        "fmpysub,d {rm1}, {rm2}, {ta}, {ra}, {tm}",
        "",
        vec![],
        "fp",
    );
    ins(
        "fmpyfadd_f",
        "FFFADF",
        "101110 ..... ..... ... . 0 ... . . . .....",
        "fmpyfadd,f {rm1}, {rm2}, {ra3}, {t}",
        "pa20",
        vec![],
        "fp",
    );
    ins(
        "fmpyfadd_d",
        "FFFADD",
        "101110 ..... ..... ... 0 1 ..0 0 0 . .....",
        "fmpyfadd,d {rm1}, {rm2}, {ra3}, {t}",
        "pa20",
        vec![],
        "fp",
    );

    // ---- Conditional Branches ----
    ins(
        "bb_sar",
        "FBBS",
        "110000 00000 ..... . 1 . ........... . .",
        "bb {r}, {disp}",
        "",
        vec![],
        "branch",
    );
    ins(
        "bb_imm",
        "FBBI",
        "110001 ..... ..... . 1 . ........... . .",
        "bb {r}, {p}, {disp}",
        "",
        vec![],
        "branch",
    );
    ins(
        "movb",
        "FRRB",
        "110010 ..... ..... ... ........... . .",
        "movb {r1}, {r2}, {disp}",
        "",
        vec![],
        "branch",
    );
    ins(
        "movbi",
        "FRIB",
        "110011 ..... ..... ... ........... . .",
        "movbi {i}, {r}, {disp}",
        "",
        vec![],
        "branch",
    );
    ins(
        "cmpb",
        "FRRB",
        "100000 ..... ..... ... ........... . .",
        "comb {r1}, {r2}, {disp}",
        "",
        vec![],
        "branch",
    );
    ins(
        "cmpb_f",
        "FRRB",
        "100010 ..... ..... ... ........... . .",
        "combf {r1}, {r2}, {disp}",
        "",
        vec![],
        "branch",
    );
    ins(
        "cmpb_d",
        "FRRB",
        "100111 ..... ..... ... ........... . .",
        "combd {r1}, {r2}, {disp}",
        "pa20",
        vec![],
        "branch",
    );
    ins(
        "cmpb_df",
        "FRRB",
        "101111 ..... ..... ... ........... . .",
        "combf,d {r1}, {r2}, {disp}",
        "pa20",
        vec![],
        "branch",
    );
    ins(
        "cmpbi",
        "FRIB",
        "100001 ..... ..... ... ........... . .",
        "comib {i}, {r}, {disp}",
        "",
        vec![],
        "branch",
    );
    ins(
        "cmpbi_f",
        "FRIB",
        "100011 ..... ..... ... ........... . .",
        "comibf {i}, {r}, {disp}",
        "",
        vec![],
        "branch",
    );
    ins(
        "cmpbi_d",
        "FRIBD",
        "111011 ..... ..... . .. ........... . .",
        "comib,d {i}, {r}, {disp}",
        "pa20",
        vec![],
        "branch",
    );
    ins(
        "addb",
        "FADDB",
        "101000 ..... ..... ... ........... . .",
        "addb {r1}, {r2}, {disp}",
        "",
        vec![],
        "branch",
    );
    ins(
        "addb_f",
        "FADDB",
        "101010 ..... ..... ... ........... . .",
        "addbf {r1}, {r2}, {disp}",
        "",
        vec![],
        "branch",
    );
    ins(
        "addbi",
        "FADDBI",
        "101001 ..... ..... ... ........... . .",
        "addib {i}, {r}, {disp}",
        "",
        vec![],
        "branch",
    );
    ins(
        "addbi_f",
        "FADDBI",
        "101011 ..... ..... ... ........... . .",
        "addibf {i}, {r}, {disp}",
        "",
        vec![],
        "branch",
    );

    // ---- Shift, Extract, Deposit ----
    ins(
        "shrp_sar",
        "FSHS",
        "110100 ..... ..... ... 00 0 . 0000 .....",
        "shrp {r2}, {r1}, {t}",
        "",
        vec![],
        "alu",
    );
    ins(
        "shrp_imm",
        "FSHI",
        "110100 ..... ..... ... 01 0 ..... .....",
        "shrp {r2}, {r1}, {cpos}, {t}",
        "",
        vec![],
        "alu",
    );
    // `0.1`（d=1 側）。`010` は shrp_imm（d=0 形）が取るので
    // 実効は `011` と `001`（cpos6 の最上位が 0/1 の両方を含む）。
    ins(
        "shrp_imm_d",
        "FSHID",
        "110100 ..... ..... ... 0.1 ..... .....",
        "shrpd {r2}, {r1}, {cpos}, {t}",
        "pa20",
        vec![],
        "alu",
    );
    ins(
        "extr_sar",
        "FEXS",
        "110100 ..... ..... ... 10 . 00 000 .....",
        "extr {r}, {len}, {t}",
        "",
        vec![],
        "alu",
    );
    ins(
        "extr_sar_d",
        "FEXSD",
        "110100 ..... ..... ... 10 . 1. 000 .....",
        "extrd {r}, {len}, {t}",
        "pa20",
        vec![],
        "alu",
    );
    ins(
        "extr_imm",
        "FEXI",
        "110100 ..... ..... ... 11 . ..... .....",
        "extr {r}, {pos}, {len}, {t}",
        "",
        vec![],
        "alu",
    );
    ins(
        "extr_imm_d",
        "FEXID",
        "110110 ..... ..... ... .. . ..... .....",
        "extrd {r}, {pos}, {len}, {t}",
        "pa20",
        vec![],
        "alu",
    );
    ins(
        "dep_sar",
        "FDEPS",
        "110101 ..... ..... ... 00 . 00 000 .....",
        "dep {r}, {len}, {t}",
        "",
        vec![],
        "alu",
    );
    ins(
        "dep_sar_d",
        "FDEPSD",
        "110101 ..... ..... ... 00 . 1. 000 .....",
        "depd {r}, {len}, {t}",
        "pa20",
        vec![],
        "alu",
    );
    ins(
        "dep_imm",
        "FDEPI",
        "110101 ..... ..... ... 01 . ..... .....",
        "dep {r}, {cpos}, {len}, {t}",
        "",
        vec![],
        "alu",
    );
    ins(
        "dep_imm_d",
        "FDEPID",
        "111100 ..... ..... ... .. . ..... .....",
        "depd {r}, {cpos}, {len}, {t}",
        "pa20",
        vec![],
        "alu",
    );
    ins(
        "depi_sar",
        "FDEPIS",
        "110101 ..... ..... ... 10 . . . 000 .....",
        "depi {i}, {t}",
        "",
        vec![],
        "alu",
    );
    ins(
        "depi_imm",
        "FDEPII",
        "110101 ..... ..... ... 11 . ..... .....",
        "depi {i}, {cpos}, {len}, {t}",
        "",
        vec![],
        "alu",
    );
    ins(
        "depi_imm_d",
        "FDEPIID",
        "111101 ..... ..... ... .. . ..... .....",
        "depdi {i}, {cpos}, {len}, {t}",
        "pa20",
        vec![],
        "alu",
    );

    // ---- Branch External / Branch ----
    ins(
        "be",
        "FBE",
        "111000 ..... ..... ... ........... . .",
        "be {disp}({b})",
        "",
        vec![],
        "branch",
    );
    ins(
        "ble",
        "FBE",
        "111001 ..... ..... ... ........... . .",
        "ble {disp}({b})",
        "",
        vec![],
        "branch",
    );
    ins(
        "bl",
        "FBL",
        "111010 ..... ..... 000 ........... . .",
        "bl {disp}, {l}",
        "",
        vec![],
        "branch",
    );
    ins(
        "gate",
        "FBL",
        "111010 ..... ..... 001 ........... . .",
        "gate {disp}, {l}",
        "",
        vec![],
        "branch",
    );
    // bl,push と bl の長変位形（ext3=100/101）は PA 2.0 付録C
    // にのみあり、PA1.1 では未割当。
    ins(
        "bl_push",
        "FBL",
        "111010 ..... ..... 100 ........... . .",
        "bl,push {disp}, {l}",
        "pa20",
        vec![],
        "branch",
    );
    ins(
        "bl_long",
        "FBLL",
        "111010 .......... 101 ........... . .",
        "bl {disp}, r2",
        "pa20",
        vec![],
        "branch",
    );
    ins(
        "blr",
        "FBLR",
        "111010 ..... ..... 010 00000000000 . 0",
        "blr {x}, {l}",
        "",
        vec![],
        "branch",
    );
    ins(
        "bv",
        "FBV",
        "111010 ..... ..... 110 00000000000 . 0",
        "bv {x}({b})",
        "",
        vec![],
        "branch",
    );
    ins(
        "bve",
        "FBVE",
        "111010 ..... 00000 110 10000000000 . .",
        "bve ({b})",
        "pa20",
        vec![],
        "branch",
    );
    ins(
        "bve_l",
        "FBVE",
        "111010 ..... 00000 111 10000000000 . .",
        "bve,l ({b})",
        "pa20",
        vec![],
        "branch",
    );

    // ---- FP（opcode 0x0c/0x0e）----
    // 0x0e は PA1.1 にも存在するが L/R 半面選択の意味論が
    // 異なるため、PA 2.0 の 64 レジスタ形のみモデル化する。
    ins(
        "fid_f",
        "FNONE",
        "001100 00000 00000 000 00 000000 00000",
        "fid",
        "",
        vec![],
        "fp",
    );
    // class 0（r,t）。pos21-26 = 00 000 0。
    // fneg/fnegabs（sub 6,7）は PA 2.0 付録C にのみあり、
    // PA1.1 では未割当。
    for (nm, sub, feat) in [
        ("fcpy_f", "010 00", ""),
        ("fabs_f", "011 00", ""),
        ("fsqrt_f", "100 00", ""),
        ("frnd_f", "101 00", ""),
        ("fneg_f", "110 00", "pa20"),
        ("fnegabs_f", "111 00", "pa20"),
        ("fcpy_d", "010 01", ""),
        ("fabs_d", "011 01", ""),
        ("fsqrt_d", "100 01", ""),
        ("frnd_d", "101 01", ""),
        ("fneg_d", "110 01", "pa20"),
        ("fnegabs_d", "111 01", "pa20"),
    ] {
        ins(
            nm,
            "FF01",
            &format!("001100 ..... 00000 {sub} 000000 ....."),
            &format!("{nm} {{r}}, {{t}}"),
            feat,
            vec![],
            "fp",
        );
    }
    // class 0 の PA 2.0 形（r,t は ra64/rt64 の 6 ビット選択）。
    for (nm, sub) in [
        ("fcpy_fw", "010"),
        ("fabs_fw", "011"),
        ("fsqrt_fw", "100"),
        ("frnd_fw", "101"),
        ("fneg_fw", "110"),
        ("fnegabs_fw", "111"),
    ] {
        ins(
            nm,
            "FFFE1",
            &format!("001110 ..... 00000 {sub} 0 0 000 .. 0 ....."),
            &format!("{nm} {{r}}, {{t}}"),
            "pa20",
            vec![],
            "fp",
        );
    }
    for (nm, sub) in [
        ("fcpy_dw", "010"),
        ("fabs_dw", "011"),
        ("fsqrt_dw", "100"),
        ("frnd_dw", "101"),
        ("fneg_dw", "110"),
        ("fnegabs_dw", "111"),
    ] {
        ins(
            nm,
            "FF01",
            &format!("001110 ..... 00000 {sub} 0 1 000 00 0 ....."),
            &format!("{nm} {{r}}, {{t}}"),
            "pa20",
            vec![],
            "fp",
        );
    }
    // class 1（fcnv。形式行 `0C r 0 sub df sf 1 0 0 t` どおり
    // pos14-16 が変換種 sub、pos17-18 が先 fmt の df、
    // pos19-20 が元 fmt の sf、pos21-26 = 01 000 0）。
    // 符号なし・切捨て変換（sub 5,6,7）は PA 2.0 付録C にのみ
    // あり、PA1.1 では未割当。
    for (nm, pat, feat) in [
        ("fcnv_d_f", "000 00 01", ""),
        ("fcnv_f_d", "000 01 00", ""),
        ("fcnv_w_f", "001 00 00", ""),
        ("fcnv_q_f", "001 00 01", ""),
        ("fcnv_w_d", "001 01 00", ""),
        ("fcnv_q_d", "001 01 01", ""),
        ("fcnv_f_w", "010 00 00", ""),
        ("fcnv_d_w", "010 00 01", ""),
        ("fcnv_f_q", "010 01 00", ""),
        ("fcnv_d_q", "010 01 01", ""),
        ("fcnv_t_f_w", "011 00 00", ""),
        ("fcnv_t_d_w", "011 00 01", ""),
        ("fcnv_t_f_q", "011 01 00", ""),
        ("fcnv_t_d_q", "011 01 01", ""),
        ("fcnv_uw_f", "101 00 00", "pa20"),
        ("fcnv_uq_f", "101 00 01", "pa20"),
        ("fcnv_uw_d", "101 01 00", "pa20"),
        ("fcnv_uq_d", "101 01 01", "pa20"),
        ("fcnv_f_uw", "110 00 00", "pa20"),
        ("fcnv_d_uw", "110 00 01", "pa20"),
        ("fcnv_f_uq", "110 01 00", "pa20"),
        ("fcnv_d_uq", "110 01 01", "pa20"),
        ("fcnv_t_f_uw", "111 00 00", "pa20"),
        ("fcnv_t_d_uw", "111 00 01", "pa20"),
        ("fcnv_t_f_uq", "111 01 00", "pa20"),
        ("fcnv_t_d_uq", "111 01 01", "pa20"),
    ] {
        ins(
            nm,
            "FF01",
            &format!("001100 ..... 000 {pat} 010000 ....."),
            &format!("{nm} {{r}}, {{t}}"),
            feat,
            vec![],
            "fp",
        );
    }
    // class 1 の PA 2.0 形。変換元/先の fmt 組合せで末尾の
    // 形式パターンが変わる（ff/df/fd/dd）。sub は pos14-16。
    for (nm, sub, tail, form) in [
        ("fcnv_d_fw", "000", "0001 010 0. 0", "FFDF1"),
        ("fcnv_f_dw", "000", "0100 010 .0 0", "FFFD1"),
        ("fcnv_w_fw", "001", "0000 010 .. 0", "FFFE1"),
        ("fcnv_q_fw", "001", "0001 010 0. 0", "FFDF1"),
        ("fcnv_w_dw", "001", "0100 010 .0 0", "FFFD1"),
        ("fcnv_q_dw", "001", "0101 010 00 0", "FF01"),
        ("fcnv_f_ww", "010", "0000 010 .. 0", "FFFE1"),
        ("fcnv_d_ww", "010", "0001 010 0. 0", "FFDF1"),
        ("fcnv_f_qw", "010", "0100 010 .0 0", "FFFD1"),
        ("fcnv_d_qw", "010", "0101 010 00 0", "FF01"),
        ("fcnv_t_f_ww", "011", "0000 010 .. 0", "FFFE1"),
        ("fcnv_t_d_ww", "011", "0001 010 0. 0", "FFDF1"),
        ("fcnv_t_f_qw", "011", "0100 010 .0 0", "FFFD1"),
        ("fcnv_t_d_qw", "011", "0101 010 00 0", "FF01"),
        ("fcnv_uw_fw", "101", "0000 010 .. 0", "FFFE1"),
        ("fcnv_uq_fw", "101", "0001 010 0. 0", "FFDF1"),
        ("fcnv_uw_dw", "101", "0100 010 .0 0", "FFFD1"),
        ("fcnv_uq_dw", "101", "0101 010 00 0", "FF01"),
        ("fcnv_f_uww", "110", "0000 010 .. 0", "FFFE1"),
        ("fcnv_d_uww", "110", "0001 010 0. 0", "FFDF1"),
        ("fcnv_f_uqw", "110", "0100 010 .0 0", "FFFD1"),
        ("fcnv_d_uqw", "110", "0101 010 00 0", "FF01"),
        ("fcnv_t_f_uww", "111", "0000 010 .. 0", "FFFE1"),
        ("fcnv_t_d_uww", "111", "0001 010 0. 0", "FFDF1"),
        ("fcnv_t_f_uqw", "111", "0100 010 .0 0", "FFFD1"),
        ("fcnv_t_d_uqw", "111", "0101 010 00 0", "FF01"),
    ] {
        ins(
            nm,
            form,
            &format!("001110 ..... 000 {sub} {tail} ....."),
            &format!("{nm} {{r}}, {{t}}"),
            "pa20",
            vec![],
            "fp",
        );
    }
    // class 2。
    ins(
        "ftest",
        "FFTEST",
        "001100 00000 00000 ... 00 10000 1 .....",
        "ftest {y}, {c}",
        "",
        vec![],
        "fp",
    );
    ins(
        "fcmp_f",
        "FF2",
        "001100 ..... ..... ... 00 10000 0 .....",
        "fcmp,f {r1}, {r2}, {c}",
        "",
        vec![],
        "fp",
    );
    ins(
        "fcmp_d",
        "FF2",
        "001100 ..... ..... ... 01 10000 0 .....",
        "fcmp,d {r1}, {r2}, {c}",
        "",
        vec![],
        "fp",
    );
    ins(
        "fcmp_fw",
        "FFFE2",
        "001110 ..... ..... ... .0 100 .00 .....",
        "fcmp,f {r1}, {r2}, {c}",
        "pa20",
        vec![],
        "fp",
    );
    ins(
        "fcmp_dw",
        "FF2",
        "001110 ..... ..... ... 01 100 000 .....",
        "fcmp,d {r1}, {r2}, {c}",
        "pa20",
        vec![],
        "fp",
    );
    // class 3。
    for (nm, sub) in [
        ("fadd_f", "000"),
        ("fsub_f", "001"),
        ("fmpy_f", "010"),
        ("fdiv_f", "011"),
        ("fadd_d", "000"),
        ("fsub_d", "001"),
        ("fmpy_d", "010"),
        ("fdiv_d", "011"),
    ] {
        let fmt2 = if nm.ends_with("_f") { "00" } else { "01" };
        ins(
            nm,
            "FF3",
            &format!("001100 ..... ..... {sub} {fmt2} 110000 ....."),
            &format!("{nm} {{r1}}, {{r2}}, {{t}}"),
            "",
            vec![],
            "fp",
        );
    }
    for (nm, sub) in [
        ("fadd_fw", "000"),
        ("fsub_fw", "001"),
        ("fmpy_fw", "010"),
        ("fdiv_fw", "011"),
    ] {
        ins(
            nm,
            "FFFE3",
            &format!("001110 ..... ..... {sub} .0 110 ..0 ....."),
            &format!("{nm} {{r1}}, {{r2}}, {{t}}"),
            "pa20",
            vec![],
            "fp",
        );
    }
    for (nm, sub) in [
        ("fadd_dw", "000"),
        ("fsub_dw", "001"),
        ("fmpy_dw", "010"),
        ("fdiv_dw", "011"),
    ] {
        ins(
            nm,
            "FF3",
            &format!("001110 ..... ..... {sub} 01 110 000 ....."),
            &format!("{nm} {{r1}}, {{r2}}, {{t}}"),
            "pa20",
            vec![],
            "fp",
        );
    }
    // xmpyu は PA1.1 Table D-20 にもあるので非ゲート。
    ins(
        "xmpyu",
        "FXXY",
        "001110 ..... ..... 010 .0111 .00 .....",
        "xmpyu {r1}, {r2}, {t}",
        "",
        vec![],
        "fp",
    );

    m
}
