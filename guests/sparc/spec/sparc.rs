// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// SPARC の ISADL モデル（段階15）。
//
// 版の範囲は V7、V8、V9 と VIS（1・2）。命令語は 32 ビット固定長。
// 遅延スロットは実行ループが pc/npc で表す。分岐の annul ビットと
// ウィンドウのあふれと不足は OS パーソナリティが担う部分もある。
// V7 は整数の乗除命令を持たず MULScc で乗算段を行う。V8 が整数の
// 乗除命令と STBAR を足す。V9 は 64 ビット化・movcc/movr・cas 系を
// 足し、VIS は V9 のマルチメディア拡張である。
// 出典は SPEC-SPARC-V7 (Solbourne 101482-00)、SPEC-SPARC-V8 (Version 8)、
// SPEC-SPARC-V9 (SAV09R1459912) である。
// Ref: SPEC-SPARC-V7.
// Ref: SPEC-SPARC-V8 (Version 8).
// Ref: SPEC-SPARC-V9.

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// SPARC の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in [
        "alu", "load", "store", "branch", "jump", "call", "misc", "trap", "float", "vis",
    ] {
        m.timing_classes.push(class.to_string());
    }

    // 版ごとの命令集合。後続の版は先行の版の追加で表す。
    // VIS 2 は VIS の追加である。
    // Ref: SPEC-SPARC-V9.
    for (name, implies) in [
        ("v7", &[][..]),
        ("v8", &["v7"][..]),
        ("v9", &["v8"][..]),
        ("vis", &["v9"][..]),
        ("vis2", &["vis"][..]),
    ] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: vec![],
        });
    }

    // 世代ごとの挙動差は挙動パラメータで表す（cpu-models.md の param）。
    m.param(
        "nwindows",
        ParamKind::Int(32),
        "8",
        "レジスタウィンドウの枚数。実装定義で 2 から 32 まで（SPEC-SPARC-V8 §Register Windows）",
    );
    m.param(
        "word64",
        ParamKind::Bool,
        "false",
        "整数レジスタと演算の幅が 64 ビット。V9 のみ true（SPEC-SPARC-V9）",
    );

    // CPU モデル。親チェーンで機能を累積し、モデル差は params で上書きする。
    // v7/v8/v9 は版の骨格モデル。ultrasparc 系と leon3 は実在の実装を表す。
    for (name, parent, add, params) in [
        ("v7", "", &["v7"][..], &[][..]),
        ("v8", "v7", &["v8"][..], &[][..]),
        (
            "v9",
            "v8",
            &["v9"][..],
            &[("word64", "true")][..],
        ),
        ("ultrasparc", "v9", &["vis"][..], &[][..]),
        ("ultrasparc3", "ultrasparc", &["vis2"][..], &[][..]),
        ("leon3", "v8", &[][..], &[][..]),
    ] {
        m.models.push(ModelDef {
            params: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: Vec::new(),
            ident: vec![],
        });
    }

    // 整数レジスタはウィンドウ付きの動的クラス。物理位置は CWP と
    // nwindows から sem が計算する（semantics.md の動的なレジスタ参照）。
    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: true,
        prefix: Some("r".to_string()),
    });
    // 浮動小数点レジスタ f0-31。V7/V8 は 32 ビットの直列、V9 は 64 ビット。
    m.regclasses.push(RegClass {
        name: "fpr".to_string(),
        dynamic: false,
        prefix: Some("f".to_string()),
    });

    for (name, hi, lo) in [
        ("a", 29, 29),
        ("cond", 28, 25),
        ("rd", 29, 25),
        ("op3", 24, 19),
        ("op2", 24, 22),
        ("rs1", 18, 14),
        ("i", 13, 13),
        ("asi", 12, 5),
        ("rs2", 4, 0),
        ("shcnt", 5, 0),
        ("shcnt5", 4, 0),
        ("simm13", 12, 0),
        ("disp22", 21, 0),
        ("imm22", 21, 0),
        ("disp30", 29, 0),
        ("p", 19, 19),
        ("cc", 21, 20),
        ("disp19", 18, 0),
        ("fs", 18, 14),
        ("fd", 29, 25),
        ("opf", 13, 5),
        // MOVcc 系の cond は 17-14 にあり、分岐の cond(28-25) とは
        // 別桁なので別名を使う。
        ("mcond", 17, 14),
        // MOVcc の cc（1 ビット。0=icc, 1=xcc）。MOVfcc の fcc
        // （2 ビット、fcc0-3 の選択）。
        ("xcc", 12, 12),
        ("fcc", 12, 11),
        ("simm11", 10, 0),
        ("rcond", 12, 10),
        ("simm10", 9, 0),
        // MEMBAR の 7 ビットマスク。
        ("mmask", 6, 0),
        // Ticc の 7 ビット即値と V9 Tcc の 8 ビット即値。
        ("simm7", 6, 0),
        ("simm8", 7, 0),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    let gpr = |name: &str, access: Access| Operand {
        name: name.to_string(),
        field: None,
        regclass: Some("gpr".to_string()),
        access,
    };
    let val = |name: &str| Operand {
        name: name.to_string(),
        field: None,
        regclass: None,
        access: Access::Read,
    };

    // CALL 形式（op=01 + disp30）。
    m.formats.push(Format {
        name: "F1CALL".to_string(),
        fields: vec!["disp30".to_string()],
        operands: vec![val("disp30")],
    });
    // SETHI/UNIMP 形式（op=00 + rd + op2 + imm22）。
    m.formats.push(Format {
        name: "F1SETHI".to_string(),
        fields: vec!["rd".to_string(), "imm22".to_string()],
        operands: vec![gpr("rd", Access::Write), val("imm22")],
    });
    // UNIMP 形式（op=00 + 予約 + op2=000 + imm22）。
    m.formats.push(Format {
        name: "F1UNIMP".to_string(),
        fields: vec!["imm22".to_string()],
        operands: vec![val("imm22")],
    });
    // Bicc 形式（op=00 + a + cond + op2=010 + disp22）。
    m.formats.push(Format {
        name: "F2B".to_string(),
        fields: vec!["a".to_string(), "cond".to_string(), "disp22".to_string()],
        operands: vec![val("a"), val("cond"), val("disp22")],
    });
    // F3 レジスタ形（rd 書き込み。整数演算・ロード・jmpl・save/restore）。
    m.formats.push(Format {
        name: "F3R".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "rs2".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
        ],
    });
    // F3 即値形（i=1、simm13）。
    m.formats.push(Format {
        name: "F3I".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "simm13".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            val("simm13"),
        ],
    });
    // F3 ストア・レジスタ形（rd も読み出し。格納元）。
    m.formats.push(Format {
        name: "F3SR".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "rs2".to_string()],
        operands: vec![
            gpr("rd", Access::Read),
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
        ],
    });
    // F3 ストア・即値形。
    m.formats.push(Format {
        name: "F3SI".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "simm13".to_string()],
        operands: vec![
            gpr("rd", Access::Read),
            gpr("rs1", Access::Read),
            val("simm13"),
        ],
    });
    // F3 ASI ロード形（i=0、asi フィールド付き。V8 では特権命令）。
    m.formats.push(Format {
        name: "F3AR".to_string(),
        fields: vec![
            "rd".to_string(),
            "rs1".to_string(),
            "asi".to_string(),
            "rs2".to_string(),
        ],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            val("asi"),
            gpr("rs2", Access::Read),
        ],
    });
    // F3 ASI ストア形（rd も読み出し）。
    m.formats.push(Format {
        name: "F3ASR".to_string(),
        fields: vec![
            "rd".to_string(),
            "rs1".to_string(),
            "asi".to_string(),
            "rs2".to_string(),
        ],
        operands: vec![
            gpr("rd", Access::Read),
            gpr("rs1", Access::Read),
            val("asi"),
            gpr("rs2", Access::Read),
        ],
    });
    // Ticc 形式（rd 桁が cond。rs1 + src2 がトラップ番号）。
    m.formats.push(Format {
        name: "F3T".to_string(),
        fields: vec!["cond".to_string(), "rs1".to_string(), "rs2".to_string()],
        operands: vec![
            val("cond"),
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
        ],
    });
    // Ticc 即値形。
    m.formats.push(Format {
        name: "F3TI".to_string(),
        fields: vec!["cond".to_string(), "rs1".to_string(), "simm13".to_string()],
        operands: vec![
            val("cond"),
            gpr("rs1", Access::Read),
            val("simm13"),
        ],
    });
    // ASR・特権レジスタの読み出し形（rd のみ。rs1 桁が ASR 番号）。
    m.formats.push(Format {
        name: "F3ASRRD".to_string(),
        fields: vec!["rd".to_string()],
        operands: vec![gpr("rd", Access::Write)],
    });
    // ASR・特権レジスタの書き込み・制御形（rd 桁が ASR 番号）。
    // rett もこの形で、実引数は rs1 + src2。
    m.formats.push(Format {
        name: "F3ASWR".to_string(),
        fields: vec!["rs1".to_string(), "rs2".to_string()],
        operands: vec![gpr("rs1", Access::Read), gpr("rs2", Access::Read)],
    });
    // 書き込み・制御の即値形。
    m.formats.push(Format {
        name: "F3ASWI".to_string(),
        fields: vec!["rs1".to_string(), "simm13".to_string()],
        operands: vec![gpr("rs1", Access::Read), val("simm13")],
    });
    // オペランドなし（done/retry/saved/restored/flushw）。
    m.formats.push(Format {
        name: "F3NONE".to_string(),
        fields: vec![],
        operands: vec![],
    });
    // シフト即値形（shcnt5/shcnt6 は同じ位置で幅だけ違う）。
    m.formats.push(Format {
        name: "F3SH".to_string(),
        fields: vec![
            "rd".to_string(),
            "rs1".to_string(),
            "shcnt".to_string(),
        ],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            val("shcnt"),
        ],
    });
    // 32 ビットシフト即値形。量は 5 ビットで bit5 は予約の 0。
    m.formats.push(Format {
        name: "F3SH5".to_string(),
        fields: vec![
            "rd".to_string(),
            "rs1".to_string(),
            "shcnt5".to_string(),
        ],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            val("shcnt5"),
        ],
    });
    // MOVcc レジスタ形（bit18=1、cc は icc/xcc の 1 ビット）。
    m.formats.push(Format {
        name: "F3MCC".to_string(),
        fields: vec![
            "rd".to_string(),
            "mcond".to_string(),
            "xcc".to_string(),
            "rs2".to_string(),
        ],
        operands: vec![
            gpr("rd", Access::Write),
            val("mcond"),
            val("xcc"),
            gpr("rs2", Access::Read),
        ],
    });
    // MOVcc 即値形（simm11）。
    m.formats.push(Format {
        name: "F3MCCI".to_string(),
        fields: vec![
            "rd".to_string(),
            "mcond".to_string(),
            "xcc".to_string(),
            "simm11".to_string(),
        ],
        operands: vec![
            gpr("rd", Access::Write),
            val("mcond"),
            val("xcc"),
            val("simm11"),
        ],
    });
    // MOVfcc レジスタ形（bit18=0、cc は fcc0-3 の 2 ビット）。
    m.formats.push(Format {
        name: "F3MFCC".to_string(),
        fields: vec![
            "rd".to_string(),
            "mcond".to_string(),
            "fcc".to_string(),
            "rs2".to_string(),
        ],
        operands: vec![
            gpr("rd", Access::Write),
            val("mcond"),
            val("fcc"),
            gpr("rs2", Access::Read),
        ],
    });
    // MOVfcc 即値形（simm11）。
    m.formats.push(Format {
        name: "F3MFCCI".to_string(),
        fields: vec![
            "rd".to_string(),
            "mcond".to_string(),
            "fcc".to_string(),
            "simm11".to_string(),
        ],
        operands: vec![
            gpr("rd", Access::Write),
            val("mcond"),
            val("fcc"),
            val("simm11"),
        ],
    });
    // MOVr レジスタ形（rcond で rs1 と 0 を比較する）。
    m.formats.push(Format {
        name: "F3MR".to_string(),
        fields: vec![
            "rd".to_string(),
            "rs1".to_string(),
            "rcond".to_string(),
            "rs2".to_string(),
        ],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            val("rcond"),
            gpr("rs2", Access::Read),
        ],
    });
    // MOVr 即値形（simm10）。
    m.formats.push(Format {
        name: "F3MRI".to_string(),
        fields: vec![
            "rd".to_string(),
            "rs1".to_string(),
            "rcond".to_string(),
            "simm10".to_string(),
        ],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            val("rcond"),
            val("simm10"),
        ],
    });
    // POPC 形（rs1 桁は 0 固定。被演算子は rs2 または simm13）。
    m.formats.push(Format {
        name: "F3POPC".to_string(),
        fields: vec!["rd".to_string(), "rs2".to_string()],
        operands: vec![gpr("rd", Access::Write), gpr("rs2", Access::Read)],
    });
    m.formats.push(Format {
        name: "F3POPCI".to_string(),
        fields: vec!["rd".to_string(), "simm13".to_string()],
        operands: vec![gpr("rd", Access::Write), val("simm13")],
    });
    // rd と rs1 の 2 フィールド形（rdpr。rs1 が特権レジスタ番号）。
    m.formats.push(Format {
        name: "F3RD1".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string()],
        operands: vec![gpr("rd", Access::Write), gpr("rs1", Access::Read)],
    });
    // Ticc の 7 ビット即値形と V9 Tcc の 8 ビット即値形。
    m.formats.push(Format {
        name: "F3TI7".to_string(),
        fields: vec!["cond".to_string(), "rs1".to_string(), "simm7".to_string()],
        operands: vec![val("cond"), gpr("rs1", Access::Read), val("simm7")],
    });
    m.formats.push(Format {
        name: "F3TI8".to_string(),
        fields: vec!["cond".to_string(), "rs1".to_string(), "simm8".to_string()],
        operands: vec![val("cond"), gpr("rs1", Access::Read), val("simm8")],
    });
    // MEMBAR の 7 ビットマスク形。
    m.formats.push(Format {
        name: "F3MB".to_string(),
        fields: vec!["mmask".to_string()],
        operands: vec![val("mmask")],
    });

    // 骨格の命令集合。命令群は SP5 以降で足す。ここでは各形式を
    // 一通りデコードできる組を宣言する。
    // (名前, 形式, パターン, 構文, 分類, 機能)
    // 機能が空でなければ、その feature があるモデルでのみデコードする
    // （V8 の umul/smul/udiv/sdiv は V7 にはない）。
    // Ref: SPEC-SPARC-V8 (Version 8) §Instruction Formats, §Instruction Descriptions.
    let insns: &[(&str, &str, &str, &str, &str, &str)] = &[
        ("call", "F1CALL", "01 ..............................", "call {disp30}", "call", ""),
        ("sethi", "F1SETHI", "00 ..... 100 ......................", "sethi {imm22}, {rd}", "alu", ""),
        ("unimp", "F1UNIMP", "00 00000 000 ......................", "unimp {imm22}", "misc", ""),
        ("bicc", "F2B", "00 . .... 010 ......................", "b{cond} {disp22}", "branch", ""),
        // 整数演算（op=10）。op3 の配置は V8 の命令表どおり。
        ("add", "F3R", "10 ..... 000000 ..... 0 00000000 .....", "add {rs1}, {rs2}, {rd}", "alu", ""),
        ("add_i", "F3I", "10 ..... 000000 ..... 1 .............", "add {rs1}, {simm13}, {rd}", "alu", ""),
        ("addcc", "F3R", "10 ..... 010000 ..... 0 00000000 .....", "addcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("addcc_i", "F3I", "10 ..... 010000 ..... 1 .............", "addcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("addx", "F3R", "10 ..... 001000 ..... 0 00000000 .....", "addx {rs1}, {rs2}, {rd}", "alu", ""),
        ("addx_i", "F3I", "10 ..... 001000 ..... 1 .............", "addx {rs1}, {simm13}, {rd}", "alu", ""),
        ("addxcc", "F3R", "10 ..... 011000 ..... 0 00000000 .....", "addxcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("addxcc_i", "F3I", "10 ..... 011000 ..... 1 .............", "addxcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("and", "F3R", "10 ..... 000001 ..... 0 00000000 .....", "and {rs1}, {rs2}, {rd}", "alu", ""),
        ("and_i", "F3I", "10 ..... 000001 ..... 1 .............", "and {rs1}, {simm13}, {rd}", "alu", ""),
        ("andcc", "F3R", "10 ..... 010001 ..... 0 00000000 .....", "andcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("andcc_i", "F3I", "10 ..... 010001 ..... 1 .............", "andcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("or", "F3R", "10 ..... 000010 ..... 0 00000000 .....", "or {rs1}, {rs2}, {rd}", "alu", ""),
        ("or_i", "F3I", "10 ..... 000010 ..... 1 .............", "or {rs1}, {simm13}, {rd}", "alu", ""),
        ("orcc", "F3R", "10 ..... 010010 ..... 0 00000000 .....", "orcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("orcc_i", "F3I", "10 ..... 010010 ..... 1 .............", "orcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("xor", "F3R", "10 ..... 000011 ..... 0 00000000 .....", "xor {rs1}, {rs2}, {rd}", "alu", ""),
        ("xor_i", "F3I", "10 ..... 000011 ..... 1 .............", "xor {rs1}, {simm13}, {rd}", "alu", ""),
        ("xorcc", "F3R", "10 ..... 010011 ..... 0 00000000 .....", "xorcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("xorcc_i", "F3I", "10 ..... 010011 ..... 1 .............", "xorcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("sub", "F3R", "10 ..... 000100 ..... 0 00000000 .....", "sub {rs1}, {rs2}, {rd}", "alu", ""),
        ("sub_i", "F3I", "10 ..... 000100 ..... 1 .............", "sub {rs1}, {simm13}, {rd}", "alu", ""),
        ("subcc", "F3R", "10 ..... 010100 ..... 0 00000000 .....", "subcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("subcc_i", "F3I", "10 ..... 010100 ..... 1 .............", "subcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("andn", "F3R", "10 ..... 000101 ..... 0 00000000 .....", "andn {rs1}, {rs2}, {rd}", "alu", ""),
        ("andn_i", "F3I", "10 ..... 000101 ..... 1 .............", "andn {rs1}, {simm13}, {rd}", "alu", ""),
        ("andncc", "F3R", "10 ..... 010101 ..... 0 00000000 .....", "andncc {rs1}, {rs2}, {rd}", "alu", ""),
        ("andncc_i", "F3I", "10 ..... 010101 ..... 1 .............", "andncc {rs1}, {simm13}, {rd}", "alu", ""),
        ("orn", "F3R", "10 ..... 000110 ..... 0 00000000 .....", "orn {rs1}, {rs2}, {rd}", "alu", ""),
        ("orn_i", "F3I", "10 ..... 000110 ..... 1 .............", "orn {rs1}, {simm13}, {rd}", "alu", ""),
        ("orncc", "F3R", "10 ..... 010110 ..... 0 00000000 .....", "orncc {rs1}, {rs2}, {rd}", "alu", ""),
        ("orncc_i", "F3I", "10 ..... 010110 ..... 1 .............", "orncc {rs1}, {simm13}, {rd}", "alu", ""),
        ("xnor", "F3R", "10 ..... 000111 ..... 0 00000000 .....", "xnor {rs1}, {rs2}, {rd}", "alu", ""),
        ("xnor_i", "F3I", "10 ..... 000111 ..... 1 .............", "xnor {rs1}, {simm13}, {rd}", "alu", ""),
        ("xnorcc", "F3R", "10 ..... 010111 ..... 0 00000000 .....", "xnorcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("xnorcc_i", "F3I", "10 ..... 010111 ..... 1 .............", "xnorcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("umul", "F3R", "10 ..... 001010 ..... 0 00000000 .....", "umul {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("umul_i", "F3I", "10 ..... 001010 ..... 1 .............", "umul {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("umulcc", "F3R", "10 ..... 011010 ..... 0 00000000 .....", "umulcc {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("umulcc_i", "F3I", "10 ..... 011010 ..... 1 .............", "umulcc {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("smul", "F3R", "10 ..... 001011 ..... 0 00000000 .....", "smul {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("smul_i", "F3I", "10 ..... 001011 ..... 1 .............", "smul {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("smulcc", "F3R", "10 ..... 011011 ..... 0 00000000 .....", "smulcc {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("smulcc_i", "F3I", "10 ..... 011011 ..... 1 .............", "smulcc {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("subx", "F3R", "10 ..... 001100 ..... 0 00000000 .....", "subx {rs1}, {rs2}, {rd}", "alu", ""),
        ("subx_i", "F3I", "10 ..... 001100 ..... 1 .............", "subx {rs1}, {simm13}, {rd}", "alu", ""),
        ("subxcc", "F3R", "10 ..... 011100 ..... 0 00000000 .....", "subxcc {rs1}, {rs2}, {rd}", "alu", ""),
        ("subxcc_i", "F3I", "10 ..... 011100 ..... 1 .............", "subxcc {rs1}, {simm13}, {rd}", "alu", ""),
        ("udiv", "F3R", "10 ..... 001110 ..... 0 00000000 .....", "udiv {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("udiv_i", "F3I", "10 ..... 001110 ..... 1 .............", "udiv {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("udivcc", "F3R", "10 ..... 011110 ..... 0 00000000 .....", "udivcc {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("udivcc_i", "F3I", "10 ..... 011110 ..... 1 .............", "udivcc {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("sdiv", "F3R", "10 ..... 001111 ..... 0 00000000 .....", "sdiv {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("sdiv_i", "F3I", "10 ..... 001111 ..... 1 .............", "sdiv {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("sdivcc", "F3R", "10 ..... 011111 ..... 0 00000000 .....", "sdivcc {rs1}, {rs2}, {rd}", "alu", "v8"),
        ("sdivcc_i", "F3I", "10 ..... 011111 ..... 1 .............", "sdivcc {rs1}, {simm13}, {rd}", "alu", "v8"),
        ("mulscc", "F3R", "10 ..... 100100 ..... 0 00000000 .....", "mulscc {rs1}, {rs2}, {rd}", "alu", ""),
        ("mulscc_i", "F3I", "10 ..... 100100 ..... 1 .............", "mulscc {rs1}, {simm13}, {rd}", "alu", ""),
        // シフト。bit12 は V9 の x 桁（64 ビットシフト）なので 32 ビット
        // 形は 0 に固定する。x 形は sllx/srlx/srax として v9 で登録する。
        ("sll", "F3R", "10 ..... 100101 ..... 0 00000000 .....", "sll {rs1}, {rs2}, {rd}", "alu", ""),
        ("sll_i", "F3SH5", "10 ..... 100101 ..... 1 00000000 .....", "sll {rs1}, {shcnt5}, {rd}", "alu", ""),
        ("srl", "F3R", "10 ..... 100110 ..... 0 00000000 .....", "srl {rs1}, {rs2}, {rd}", "alu", ""),
        ("srl_i", "F3SH5", "10 ..... 100110 ..... 1 00000000 .....", "srl {rs1}, {shcnt5}, {rd}", "alu", ""),
        ("sra", "F3R", "10 ..... 100111 ..... 0 00000000 .....", "sra {rs1}, {rs2}, {rd}", "alu", ""),
        ("sra_i", "F3SH5", "10 ..... 100111 ..... 1 00000000 .....", "sra {rs1}, {shcnt5}, {rd}", "alu", ""),
        ("ld", "F3R", "11 ..... 000000 ..... 0 00000000 .....", "ld [{rs1} + {rs2}], {rd}", "load", ""),
        ("ld_i", "F3I", "11 ..... 000000 ..... 1 .............", "ld [{rs1} + {simm13}], {rd}", "load", ""),
        ("ldub", "F3R", "11 ..... 000001 ..... 0 00000000 .....", "ldub [{rs1} + {rs2}], {rd}", "load", ""),
        ("ldub_i", "F3I", "11 ..... 000001 ..... 1 .............", "ldub [{rs1} + {simm13}], {rd}", "load", ""),
        ("lduh", "F3R", "11 ..... 000010 ..... 0 00000000 .....", "lduh [{rs1} + {rs2}], {rd}", "load", ""),
        ("lduh_i", "F3I", "11 ..... 000010 ..... 1 .............", "lduh [{rs1} + {simm13}], {rd}", "load", ""),
        ("ldd", "F3R", "11 ..... 000011 ..... 0 00000000 .....", "ldd [{rs1} + {rs2}], {rd}", "load", ""),
        ("ldd_i", "F3I", "11 ..... 000011 ..... 1 .............", "ldd [{rs1} + {simm13}], {rd}", "load", ""),
        ("st", "F3SR", "11 ..... 000100 ..... 0 00000000 .....", "st {rd}, [{rs1} + {rs2}]", "store", ""),
        ("st_i", "F3SI", "11 ..... 000100 ..... 1 .............", "st {rd}, [{rs1} + {simm13}]", "store", ""),
        ("stb", "F3SR", "11 ..... 000101 ..... 0 00000000 .....", "stb {rd}, [{rs1} + {rs2}]", "store", ""),
        ("stb_i", "F3SI", "11 ..... 000101 ..... 1 .............", "stb {rd}, [{rs1} + {simm13}]", "store", ""),
        ("sth", "F3SR", "11 ..... 000110 ..... 0 00000000 .....", "sth {rd}, [{rs1} + {rs2}]", "store", ""),
        ("sth_i", "F3SI", "11 ..... 000110 ..... 1 .............", "sth {rd}, [{rs1} + {simm13}]", "store", ""),
        ("std", "F3SR", "11 ..... 000111 ..... 0 00000000 .....", "std {rd}, [{rs1} + {rs2}]", "store", ""),
        ("std_i", "F3SI", "11 ..... 000111 ..... 1 .............", "std {rd}, [{rs1} + {simm13}]", "store", ""),
        ("ldsb", "F3R", "11 ..... 001001 ..... 0 00000000 .....", "ldsb [{rs1} + {rs2}], {rd}", "load", ""),
        ("ldsb_i", "F3I", "11 ..... 001001 ..... 1 .............", "ldsb [{rs1} + {simm13}], {rd}", "load", ""),
        ("ldsh", "F3R", "11 ..... 001010 ..... 0 00000000 .....", "ldsh [{rs1} + {rs2}], {rd}", "load", ""),
        ("ldsh_i", "F3I", "11 ..... 001010 ..... 1 .............", "ldsh [{rs1} + {simm13}], {rd}", "load", ""),
        ("ldstub", "F3R", "11 ..... 001101 ..... 0 00000000 .....", "ldstub [{rs1} + {rs2}], {rd}", "load", ""),
        ("ldstub_i", "F3I", "11 ..... 001101 ..... 1 .............", "ldstub [{rs1} + {simm13}], {rd}", "load", ""),
        ("swap", "F3SR", "11 ..... 001111 ..... 0 00000000 .....", "swap [{rs1} + {rs2}], {rd}", "load", ""),
        ("swap_i", "F3SI", "11 ..... 001111 ..... 1 .............", "swap [{rs1} + {simm13}], {rd}", "load", ""),
        // ASI 指定形（i=0 のみ、asi フィールドを持つ。V8 では特権命令。
        // 特権チェックは SP8 の意味論が行い、アドレス空間の選択は
        // 後続ステップで扱う。ここでは通常の空間へのアクセスに畳む）。
        ("lda", "F3AR", "11 ..... 010000 ..... 0 ........ .....", "lda [{rs1} + {rs2}] {asi}, {rd}", "load", ""),
        ("lduba", "F3AR", "11 ..... 010001 ..... 0 ........ .....", "lduba [{rs1} + {rs2}] {asi}, {rd}", "load", ""),
        ("lduha", "F3AR", "11 ..... 010010 ..... 0 ........ .....", "lduha [{rs1} + {rs2}] {asi}, {rd}", "load", ""),
        ("ldda", "F3AR", "11 ..... 010011 ..... 0 ........ .....", "ldda [{rs1} + {rs2}] {asi}, {rd}", "load", ""),
        ("sta", "F3ASR", "11 ..... 010100 ..... 0 ........ .....", "sta {rd}, [{rs1} + {rs2}] {asi}", "store", ""),
        ("stba", "F3ASR", "11 ..... 010101 ..... 0 ........ .....", "stba {rd}, [{rs1} + {rs2}] {asi}", "store", ""),
        ("stha", "F3ASR", "11 ..... 010110 ..... 0 ........ .....", "stha {rd}, [{rs1} + {rs2}] {asi}", "store", ""),
        ("stda", "F3ASR", "11 ..... 010111 ..... 0 ........ .....", "stda {rd}, [{rs1} + {rs2}] {asi}", "store", ""),
        ("ldsba", "F3AR", "11 ..... 011001 ..... 0 ........ .....", "ldsba [{rs1} + {rs2}] {asi}, {rd}", "load", ""),
        ("ldsha", "F3AR", "11 ..... 011010 ..... 0 ........ .....", "ldsha [{rs1} + {rs2}] {asi}, {rd}", "load", ""),
        ("ldstuba", "F3AR", "11 ..... 011101 ..... 0 ........ .....", "ldstuba [{rs1} + {rs2}] {asi}, {rd}", "load", ""),
        ("swapa", "F3ASR", "11 ..... 011111 ..... 0 ........ .....", "swapa [{rs1} + {rs2}] {asi}, {rd}", "load", ""),
        ("jmpl", "F3R", "10 ..... 111000 ..... 0 00000000 .....", "jmpl {rs1} + {rs2}, {rd}", "jump", ""),
        ("jmpl_i", "F3I", "10 ..... 111000 ..... 1 .............", "jmpl {rs1} + {simm13}, {rd}", "jump", ""),
        ("save", "F3R", "10 ..... 111100 ..... 0 00000000 .....", "save {rs1}, {rs2}, {rd}", "alu", ""),
        ("save_i", "F3I", "10 ..... 111100 ..... 1 .............", "save {rs1}, {simm13}, {rd}", "alu", ""),
        ("restore", "F3R", "10 ..... 111101 ..... 0 00000000 .....", "restore {rs1}, {rs2}, {rd}", "alu", ""),
        ("restore_i", "F3I", "10 ..... 111101 ..... 1 .............", "restore {rs1}, {simm13}, {rd}", "alu", ""),
        // Ticc。rd 桁は cond（4 ビット、bit29 は予約 0）。
        // trap type は 128 + ((rs1 + src2) & 0x7f)。V9 では Tcc で
        // 0x100 + N になる（意味論側でモデル判定する）。
        ("ticc", "F3T", "10 0.... 111010 ..... 0 00000000 .....", "t{cond} {rs1} + {rs2}", "trap", ""),
        ("ticc_i", "F3TI7", "10 0.... 111010 ..... 1 000000 .......", "t{cond} {rs1} + {simm7}", "trap", ""),
        // ユーザ ASR。V8 の %y と、V9 の %ccr・%pc。
        ("rdy", "F3ASRRD", "10 ..... 101000 00000 0 00000000 00000", "rd %y, {rd}", "misc", ""),
        ("wry", "F3ASWR", "10 00000 110000 ..... 0 00000000 .....", "wr {rs1}, {rs2}, %y", "misc", ""),
        ("wry_i", "F3ASWI", "10 00000 110000 ..... 1 .............", "wr {rs1}, {simm13}, %y", "misc", ""),
        ("rdccr", "F3ASRRD", "10 ..... 101000 00010 0 00000000 00000", "rd %ccr, {rd}", "misc", "v9"),
        ("wrccr", "F3ASWR", "10 00010 110000 ..... 0 00000000 .....", "wr {rs1}, {rs2}, %ccr", "misc", "v9"),
        ("wrccr_i", "F3ASWI", "10 00010 110000 ..... 1 .............", "wr {rs1}, {simm13}, %ccr", "misc", "v9"),
        ("rdpc", "F3ASRRD", "10 ..... 101000 00101 0 00000000 00000", "rd %pc, {rd}", "misc", "v9"),
        // V8 の特権命令。ユーザーモードでは privileged_instruction
        // トラップの経路だけを実装する（ウィンドウ制御レジスタや
        // トラップ復帰の実体は扱わない）。rett は遅延スロットを持つが、
        // トラップが先に起きるので実行ループからは通常命令に見える。
        // これらは V9 の saved/restored/return/flushw/rdpr/wrpr と
        // 符号化が衝突するので v9 ではデコードしない。
        ("rdpsr", "F3ASRRD", "10 ..... 101001 00000 0 00000000 00000", "rd %psr, {rd}", "trap", "!v9"),
        ("rdwim", "F3ASRRD", "10 ..... 101010 00000 0 00000000 00000", "rd %wim, {rd}", "trap", "!v9"),
        ("rdtbr", "F3ASRRD", "10 ..... 101011 00000 0 00000000 00000", "rd %tbr, {rd}", "trap", "!v9"),
        ("wrpsr", "F3ASWR", "10 00000 110001 ..... 0 00000000 .....", "wr {rs1}, {rs2}, %psr", "trap", "!v9"),
        ("wrpsr_i", "F3ASWI", "10 00000 110001 ..... 1 .............", "wr {rs1}, {simm13}, %psr", "trap", "!v9"),
        ("wrwim", "F3ASWR", "10 00000 110010 ..... 0 00000000 .....", "wr {rs1}, {rs2}, %wim", "trap", "!v9"),
        ("wrwim_i", "F3ASWI", "10 00000 110010 ..... 1 .............", "wr {rs1}, {simm13}, %wim", "trap", "!v9"),
        ("wrtbr", "F3ASWR", "10 00000 110011 ..... 0 00000000 .....", "wr {rs1}, {rs2}, %tbr", "trap", "!v9"),
        ("wrtbr_i", "F3ASWI", "10 00000 110011 ..... 1 .............", "wr {rs1}, {simm13}, %tbr", "trap", "!v9"),
        ("rett", "F3ASWR", "10 00000 111001 ..... 0 00000000 .....", "rett {rs1} + {rs2}", "trap", "!v9"),
        ("rett_i", "F3ASWI", "10 00000 111001 ..... 1 .............", "rett {rs1} + {simm13}", "trap", "!v9"),
        // ---- V9 追加分 ----
        // 64 ビット乗除。mulx は下位 64 ビット、udivx/sdivx は 64 ビット
        // 被除数（Y は使わない）。V8 の udiv(0x0e)/sdiv(0x0f) とは op3 が
        // 違うので衝突はない。
        ("mulx", "F3R", "10 ..... 001001 ..... 0 00000000 .....", "mulx {rs1}, {rs2}, {rd}", "alu", "v9"),
        ("mulx_i", "F3I", "10 ..... 001001 ..... 1 .............", "mulx {rs1}, {simm13}, {rd}", "alu", "v9"),
        ("udivx", "F3R", "10 ..... 001101 ..... 0 00000000 .....", "udivx {rs1}, {rs2}, {rd}", "alu", "v9"),
        ("udivx_i", "F3I", "10 ..... 001101 ..... 1 .............", "udivx {rs1}, {simm13}, {rd}", "alu", "v9"),
        ("sdivx", "F3R", "10 ..... 101101 ..... 0 00000000 .....", "sdivx {rs1}, {rs2}, {rd}", "alu", "v9"),
        ("sdivx_i", "F3I", "10 ..... 101101 ..... 1 .............", "sdivx {rs1}, {simm13}, {rd}", "alu", "v9"),
        // 64 ビットシフト（bit12 の x 桁が 1）。シフト量はレジスタ形が
        // rs2 の下位 6 ビット、即値形が shcnt6。
        ("sllx", "F3R", "10 ..... 100101 ..... 0 10000000 .....", "sllx {rs1}, {rs2}, {rd}", "alu", "v9"),
        ("sllx_i", "F3SH", "10 ..... 100101 ..... 1 1000000 ......", "sllx {rs1}, {shcnt}, {rd}", "alu", "v9"),
        ("srlx", "F3R", "10 ..... 100110 ..... 0 10000000 .....", "srlx {rs1}, {rs2}, {rd}", "alu", "v9"),
        ("srlx_i", "F3SH", "10 ..... 100110 ..... 1 1000000 ......", "srlx {rs1}, {shcnt}, {rd}", "alu", "v9"),
        ("srax", "F3R", "10 ..... 100111 ..... 0 10000000 .....", "srax {rs1}, {rs2}, {rd}", "alu", "v9"),
        ("srax_i", "F3SH", "10 ..... 100111 ..... 1 1000000 ......", "srax {rs1}, {shcnt}, {rd}", "alu", "v9"),
        // MOVcc（bit18=1: cc は icc=0/xcc=1 の 1 ビット）と MOVfcc
        // （bit18=0: cc は fcc0-3 の 2 ビット）。即値は simm11。
        ("movcc", "F3MCC", "10 ..... 101100 1 .... 0.0000000 .....", "movcc {xcc} {mcond} {rs2} {rd}", "alu", "v9"),
        ("movcc_i", "F3MCCI", "10 ..... 101100 1 .... 1.0 ...........", "movcc {xcc} {mcond} {simm11} {rd}", "alu", "v9"),
        ("movfcc", "F3MFCC", "10 ..... 101100 0 .... 0.. 000000 .....", "movfcc {fcc} {mcond} {rs2} {rd}", "alu", "v9"),
        ("movfcc_i", "F3MFCCI", "10 ..... 101100 0 .... 1.. ...........", "movfcc {fcc} {mcond} {simm11} {rd}", "alu", "v9"),
        // MOVr。rcond で rs1 と 0 を比較して転送する。
        ("movr", "F3MR", "10 ..... 101111 ..... 0 ... 00000 .....", "movr {rs1} {rcond} {rs2} {rd}", "alu", "v9"),
        ("movr_i", "F3MRI", "10 ..... 101111 ..... 1 ... ..........", "movr {rs1} {rcond} {simm10} {rd}", "alu", "v9"),
        // POPC（rs1 桁は 0 固定）。
        ("popc", "F3POPC", "10 ..... 101110 00000 0 00000000 .....", "popc {rs2}, {rd}", "alu", "v9"),
        ("popc_i", "F3POPCI", "10 ..... 101110 00000 1 .............", "popc {simm13}, {rd}", "alu", "v9"),
        // CASA/CASXA（op=11 のロード/ストア空間）。i=0 は ASI 指定、
        // i=1 は %asi レジスタを使う。ユーザーモデルでは通常空間に畳む。
        ("casa", "F3ASR", "11 ..... 111100 ..... 0 ........ .....", "casa [{rs1}] {asi}, {rs2}, {rd}", "load", "v9"),
        ("casa_i", "F3SR", "11 ..... 111100 ..... 1 00000000 .....", "casa [{rs1}] %asi, {rs2}, {rd}", "load", "v9"),
        ("casxa", "F3ASR", "11 ..... 111110 ..... 0 ........ .....", "casxa [{rs1}] {asi}, {rs2}, {rd}", "load", "v9"),
        ("casxa_i", "F3SR", "11 ..... 111110 ..... 1 00000000 .....", "casxa [{rs1}] %asi, {rs2}, {rd}", "load", "v9"),
        // バリアとキャッシュ制御。ユーザーモデルではいずれも no-op。
        ("stbar", "F3NONE", "10 00000 101000 01111 0 00000000 00000", "stbar", "misc", ""),
        ("membar", "F3MB", "10 00000 101000 01111 1 000000 .......", "membar {mmask}", "misc", "v9"),
        ("flush", "F3ASWR", "10 00000 111011 ..... 0 00000000 .....", "flush {rs1} + {rs2}", "misc", ""),
        ("flush_i", "F3ASWI", "10 00000 111011 ..... 1 .............", "flush {rs1} + {simm13}", "misc", ""),
        // V9 のウィンドウ関連。saved/restored は OS の帳尻合わせを
        // 完了させる印でユーザーモデルでは no-op。flushw は仕様上
        // window_flush トラップを起こし得るが、ユーザーモデルでは
        // no-op に畳む（必要になればトラップ経路へ倒す）。
        // allclean 等は特権命令。
        ("saved", "F3NONE", "10 00000 110001 00000 0 00000000 00000", "saved", "misc", "v9"),
        ("restored", "F3NONE", "10 00001 110001 00000 0 00000000 00000", "restored", "misc", "v9"),
        ("allclean", "F3NONE", "10 00010 110001 00000 0 00000000 00000", "allclean", "trap", "v9"),
        ("otherw", "F3NONE", "10 00011 110001 00000 0 00000000 00000", "otherw", "trap", "v9"),
        ("normalw", "F3NONE", "10 00100 110001 00000 0 00000000 00000", "normalw", "trap", "v9"),
        ("invalw", "F3NONE", "10 00101 110001 00000 0 00000000 00000", "invalw", "trap", "v9"),
        ("flushw", "F3NONE", "10 00000 101011 00000 0 00000000 00000", "flushw", "trap", "v9"),
        // V9 の return（rett と同じ op3。非特権で CTI）。
        ("return", "F3ASWR", "10 00000 111001 ..... 0 00000000 .....", "return {rs1} + {rs2}", "branch", "v9"),
        ("return_i", "F3ASWI", "10 00000 111001 ..... 1 .............", "return {rs1} + {simm13}", "branch", "v9"),
        // V9 特権レジスタの rdpr/wrpr（ユーザーモードではトラップ）。
        ("rdpr", "F3RD1", "10 ..... 101010 ..... 0 00000000 00000", "rdpr {rs1}, {rd}", "trap", "v9"),
        ("wrpr", "F3R", "10 ..... 110010 ..... 0 00000000 .....", "wrpr {rs1}, {rs2}, {rd}", "trap", "v9"),
        ("wrpr_i", "F3I", "10 ..... 110010 ..... 1 .............", "wrpr {rs1}, {simm13}, {rd}", "trap", "v9"),
        // V9 Tcc。xcc 形は bit12 の cc 桁が 1（icc 形は ticc と同じ
        // 符号化）。icc の即値形で即値の最上位（bit7）が立つものは
        // V8 の予約桁と重ならないよう別パターンにする（トラップ番号は
        // 7 ビットに折れるので意味は変わらない）。
        ("tcc_i", "F3TI7", "10 0.... 111010 ..... 1 000001 .......", "t{cond} %icc, {rs1} + {simm7}", "trap", "v9"),
        ("tccx", "F3T", "10 0.... 111010 ..... 0 10000000 .....", "t{cond} %xcc, {rs1} + {rs2}", "trap", "v9"),
        ("tccx_i", "F3TI8", "10 0.... 111010 ..... 1 10000 ........", "t{cond} %xcc, {rs1} + {simm8}", "trap", "v9"),
        ("done", "F3NONE", "10 00000 111110 00000 0 00000000 00000", "done", "trap", "v9"),
        ("retry", "F3NONE", "10 00001 111110 00000 0 00000000 00000", "retry", "trap", "v9"),
    ];
    for (name, format, pattern, syntax, timing, feat) in insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: if feat.is_empty() {
                Pred::True
            } else {
                // "&" で連言、"!" で否定を指定する。例 "v8&!v9" は
                // V8 以降だが V9 ではないモデル（V8 専用命令）を表す。
                let terms: Vec<Pred> = feat
                    .split('&')
                    .map(|t| {
                        if let Some(neg) = t.strip_prefix('!') {
                            Pred::Not(Box::new(Pred::Flag(neg.to_string())))
                        } else {
                            Pred::Flag(t.to_string())
                        }
                    })
                    .collect();
                if terms.len() == 1 {
                    terms.into_iter().next().unwrap()
                } else {
                    Pred::All(terms)
                }
            },
            wheres: vec![],
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }
    m
}
