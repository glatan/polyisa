// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// LoongArch の ISADL モデル（段階19）。
//
// LoongArch の基本命令は固定 32 ビット長。語の下位側に
// レジスタ桁（rd[4:0]・rj[9:5]・rk[14:10]）、上位側にオペコードと
// 即値が並ぶ。LA32 の基本語彙は LA64 の部分集合で、`.d`/`du` 系の
// 64 ビット命令は LA64 のみ（`when` で切る）。
// Ref: SPEC-LOONGARCH-RM §1.3（命令長）, Appendix B（符号化表）.
//
// 分岐変位は語内で分割される。BEQZ/BNEZ/BCEQZ/BCNEZ は
// offs[15:0] を [25:10]、offs[20:16] を [4:0] に持ち、B/BL は
// offs[15:0] を [25:10]、offs[25:16] を [9:0] に持つ。いずれも
// 値は 4 バイト単位（下位 2 ビットは常に 0）なので `zfill: 2`。
// Ref: SPEC-LOONGARCH-RM §2.2.4（分岐命令）, Appendix B.
//
// パターンの固定ビットは SPEC-LOONGARCH-RM Appendix B を正本とする。

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// LoongArch の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in [
        "alu", "load", "store", "branch", "system", "fp", "atomic", "misc",
    ] {
        m.timing_classes.push(class.to_string());
    }

    // アーキテクチャの幅。la32 と la64 は排他。`lsx` は
    // Alpine/musl が実際に実行する部分集合だけを実装し、
    // `lasx`/`lbt` は拡張の宣言のみで命令の割当てはない
    // （LA13 の棚卸しを参照）。
    // Ref: SPEC-LOONGARCH-RM §1.2（LA32/LA64）, §1.4（拡張構成）.
    for (name, implies, conflicts) in [
        ("la32", &[][..], &["la64"][..]),
        ("la64", &[][..], &["la32"][..]),
        ("lsx", &[][..], &[][..]),
        ("lasx", &["lsx"][..], &[][..]),
        ("lbt", &[][..], &[][..]),
    ] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: conflicts.iter().map(|s| s.to_string()).collect(),
        });
    }

    // CPU モデル。LA32 系と LA64 系の代表を置く。識別情報
    // （CPUCFG）の値は LA8 で意味論側へ接続する。
    // Ref: SPEC-LOONGARCH-RM §1.2.
    // LA264 は 64 ビットの双発行コア（2K1000LA 資料）で、LA32 系では
    // ない。ベクトル拡張の有無は一次資料の確認待ちで lsx は入れない。
    for (name, parent, add) in [
        ("la32", "", &["la32"][..]),
        ("la132", "la32", &[][..]),
        ("la264", "", &["la64"][..]),
        // LA364（2K2000 系）も 64 ビットコア。LSX を持つ —— 龍芯の
        // 2K2000 製品パラメータに「浮点单元: 128位向量单元」（浮動
        // 小数点ユニット = 128 ビットベクトルユニット）とあり、
        // 128 ビットは LSX（LASX は 256 ビット）を指す。LBT の有無は
        // 不明で入れない。
        // Ref: SPEC-LOONGARCH-2K2000.
        ("la364", "", &["la64", "lsx"][..]),
        // la464 は実機の機能構成（LSX 内蔵）に合わせて `lsx` を
        // 持たせる。la664 は親から継承する。
        // Ref: SPEC-LOONGARCH-RM §1.4（LS464 の標準構成）.
        ("la464", "", &["la64", "lsx", "lasx", "lbt"][..]),
        ("la664", "la464", &["lasx"][..]),
    ] {
        m.models.push(ModelDef {
        timing: None,
        params: Default::default(),
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: vec![],
            ident: vec![],
        });
    }

    // 整数レジスタ r0-r31（r0 は常に 0）、FP レジスタ f0-f31、
    // 条件フラグ FCC0-FCC7、FCSR0-FCSR3。
    // Ref: SPEC-LOONGARCH-RM §2.1, §3.1.
    m.regclasses.push(RegClass {
        name: "gr".to_string(),
        dynamic: false,
        prefix: Some("$r".to_string()),
    });
    m.regclasses.push(RegClass {
        name: "fpr".to_string(),
        dynamic: false,
        prefix: Some("$f".to_string()),
    });
    m.regclasses.push(RegClass {
        name: "fcc".to_string(),
        dynamic: false,
        prefix: Some("$fcc".to_string()),
    });
    m.regclasses.push(RegClass {
        name: "fcsr".to_string(),
        dynamic: false,
        prefix: Some("$fcsr".to_string()),
    });
    // LSX の 128 ビットベクトルレジスタ vr0-vr31。
    // Ref: SPEC-LOONGARCH-RM Vol.2 §1（LSX 概要）.
    m.regclasses.push(RegClass {
        name: "vr".to_string(),
        dynamic: false,
        prefix: Some("$vr".to_string()),
    });

    // 単一範囲の桁。Ref: SPEC-LOONGARCH-RM Appendix B.
    for (name, hi, lo) in [
        ("rd", 4, 0),
        ("rj", 9, 5),
        ("rk", 14, 10),
        ("ra", 19, 15),
        ("cd", 2, 0),
        ("cj", 7, 5),
        ("ca", 17, 15),
        ("cond", 19, 15),
        ("fcsrd", 4, 0),
        ("fcsrj", 9, 5),
        ("si12", 21, 10),
        ("ui12", 21, 10),
        ("si14", 23, 10),
        ("si16", 25, 10),
        ("si20", 24, 5),
        ("ui5", 14, 10),
        ("ui6", 15, 10),
        ("sa2", 16, 15),
        ("sa3", 17, 15),
        ("msbw", 20, 16),
        ("lsbw", 14, 10),
        ("msbd", 21, 16),
        ("lsbd", 15, 10),
        ("code5", 4, 0),
        ("code15", 14, 0),
        ("hint5", 4, 0),
        ("hint15", 14, 0),
        ("level15", 14, 0),
        ("level8", 17, 10),
        ("seq8", 17, 10),
        ("csr", 23, 10),
        ("op5", 4, 0),
        // LSX 系の桁。si13 は VLDI のパターン選択＋即値、si9 は
        // VLDREPL.D の符号つきオフセット、imm8 は VSHUF4I の
        // 選択即値、vidx2/vidx1 は VPICKVE2GR/VINSGR2VR の要素番号。
        // Ref: SPEC-LOONGARCH-RM Vol.2（LSX 命令形式）.
        ("si13", 17, 5),
        // si9 は VLDREPL.D の符号つき要素オフセット [18:10]
        // （Vol.2: VA = GR[rj] + SignExtend(si9 << 3)）。
        ("si9", 18, 10),
        ("imm8", 17, 10),
        ("vidx2", 11, 10),
        ("vidx1", 10, 10),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    // 分割する分岐変位。offs16 は BEQ 系の [25:10]（生の 16 ビット。
    // 4 バイト単位なので意味論で <<2 する。`zfill` を付けると
    // 単一部の Parts が生成コードで二重括弧になり clippy に
    // 引っかかるため Bits とする）、offs21 は BEQZ 系（[4:0] が
    // 上位、[25:10] が下位）、offs26 は B/BL（[9:0] が上位、
    // [25:10] が下位）。後者二つはバイト単位へ直すために
    // 下位 2 ビットを 0 埋めする。
    // Ref: SPEC-LOONGARCH-RM Appendix B.
    m.fields.push(Field {
        name: "offs16".to_string(),
        kind: FieldKind::Bits { hi: 25, lo: 10 },
    });
    m.fields.push(Field {
        name: "offs21".to_string(),
        kind: FieldKind::Parts {
            parts: vec![(4, 0), (25, 10)],
            zfill: 2,
        },
    });
    m.fields.push(Field {
        name: "offs26".to_string(),
        kind: FieldKind::Parts {
            parts: vec![(9, 0), (25, 10)],
            zfill: 2,
        },
    });

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
    let fcc = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("fcc".to_string()),
        access,
    };
    let fcsr = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("fcsr".to_string()),
        access,
    };
    let vr = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("vr".to_string()),
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

    // オペランドなし（ERTN・TLB 系）。
    m.formats.push(fmt("FN0", &[], vec![]));
    // 15 ビットのコード/ヒント/レベル（BREAK・SYSCALL・DBCL・DBAR・IBAR・IDLE）。
    m.formats.push(fmt("FCODE15", &["code15"], vec![val("code", "code15")]));
    m.formats.push(fmt("FHINT15", &["hint15"], vec![val("hint", "hint15")]));
    m.formats.push(fmt("FIDLE", &["level15"], vec![val("level", "level15")]));
    // rd, rj の 2 項（CLO/CLZ/CTO/CTZ・REV*/BITREV/EXT・RDTIME*・
    // CPUCFG・LLACQ/SCREL・IOCSR*）。
    m.formats.push(fmt(
        "FR2",
        &["rj", "rd"],
        vec![gr("rd", "rd", Access::Write), gr("rj", "rj", Access::Read)],
    ));
    // rj, rk の 2 項（ASRTLE/ASRTGT。rd 位置は固定 0）。
    m.formats.push(fmt(
        "FR2JK",
        &["rk", "rj"],
        vec![gr("rj", "rj", Access::Read), gr("rk", "rk", Access::Read)],
    ));
    // fd, fj の FP 2 項。
    m.formats.push(fmt(
        "FF2",
        &["rj", "rd"],
        vec![fpr("fd", "rd", Access::Write), fpr("fj", "rj", Access::Read)],
    ));
    // fd, rj（MOVGR2FR*）。
    m.formats.push(fmt(
        "FG2F",
        &["rj", "rd"],
        vec![fpr("fd", "rd", Access::Write), gr("rj", "rj", Access::Read)],
    ));
    // rd, fj（MOVFR2GR*）。
    m.formats.push(fmt(
        "FF2G",
        &["rj", "rd"],
        vec![gr("rd", "rd", Access::Write), fpr("fj", "rj", Access::Read)],
    ));
    // fcsr, rj（MOVGR2FCSR）。
    m.formats.push(fmt(
        "FG2FCSR",
        &["rj", "fcsrd"],
        vec![fcsr("fcsr", "fcsrd", Access::Write), gr("rj", "rj", Access::Read)],
    ));
    // rd, fcsr（MOVFCSR2GR）。
    m.formats.push(fmt(
        "FFCSR2G",
        &["fcsrj", "rd"],
        vec![gr("rd", "rd", Access::Write), fcsr("fcsr", "fcsrj", Access::Read)],
    ));
    // cd, fj（MOVFR2CF）。
    m.formats.push(fmt(
        "FF2CF",
        &["rj", "cd"],
        vec![fcc("cd", "cd", Access::Write), fpr("fj", "rj", Access::Read)],
    ));
    // fd, cj（MOVCF2FR）。
    m.formats.push(fmt(
        "FCF2F",
        &["cj", "rd"],
        vec![fpr("fd", "rd", Access::Write), fcc("cj", "cj", Access::Read)],
    ));
    // cd, rj（MOVGR2CF）。
    m.formats.push(fmt(
        "FG2CF",
        &["rj", "cd"],
        vec![fcc("cd", "cd", Access::Write), gr("rj", "rj", Access::Read)],
    ));
    // rd, cj（MOVCF2GR）。
    m.formats.push(fmt(
        "FCF2G",
        &["cj", "rd"],
        vec![gr("rd", "rd", Access::Write), fcc("cj", "cj", Access::Read)],
    ));
    // rd, rj, rk の 3 項（整数・LDX/STX・LDGT/STGT・AM*・CRC）。
    m.formats.push(fmt(
        "FR3",
        &["rk", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::Write),
            gr("rj", "rj", Access::Read),
            gr("rk", "rk", Access::Read),
        ],
    ));
    // rd, rj, rk の 3 項（AMCAS・AMSWAP.B/H・SC.Q。構文上は
    // rd, rk, rj の順だが桁は共通）。
    m.formats.push(fmt(
        "FAM3",
        &["rk", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::ReadWrite),
            gr("rk", "rk", Access::Read),
            gr("rj", "rj", Access::Read),
        ],
    ));
    // fd, rj, rk（FLDX/FSTX・FLDGT/FSTGT/FLE 系）。
    m.formats.push(fmt(
        "FR3F",
        &["rk", "rj", "rd"],
        vec![
            fpr("fd", "rd", Access::ReadWrite),
            gr("rj", "rj", Access::Read),
            gr("rk", "rk", Access::Read),
        ],
    ));
    // fd, fj, fk の FP 3 項。
    m.formats.push(fmt(
        "FF3",
        &["rk", "rj", "rd"],
        vec![
            fpr("fd", "rd", Access::Write),
            fpr("fj", "rj", Access::Read),
            fpr("fk", "rk", Access::Read),
        ],
    ));
    // fd, fj, fk, fa の FP 4 項（FMADD 系）。
    m.formats.push(fmt(
        "FF4",
        &["ra", "rk", "rj", "rd"],
        vec![
            fpr("fd", "rd", Access::Write),
            fpr("fj", "rj", Access::Read),
            fpr("fk", "rk", Access::Read),
            fpr("fa", "ra", Access::Read),
        ],
    ));
    // cd, fj, fk（FCMP.cond）。
    m.formats.push(fmt(
        "FFCMP",
        &["cond", "rk", "rj", "cd"],
        vec![
            fcc("cd", "cd", Access::Write),
            fpr("fj", "rj", Access::Read),
            fpr("fk", "rk", Access::Read),
            val("cond", "cond"),
        ],
    ));
    // fd, fj, fk, ca（FSEL）。
    m.formats.push(fmt(
        "FFSEL",
        &["ca", "rk", "rj", "rd"],
        vec![
            fpr("fd", "rd", Access::Write),
            fpr("fj", "rj", Access::Read),
            fpr("fk", "rk", Access::Read),
            fcc("ca", "ca", Access::Read),
        ],
    ));
    // rd, rj, rk, sa2（ALSL・BYTEPICK.W）。
    m.formats.push(fmt(
        "FR3SA2",
        &["sa2", "rk", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::Write),
            gr("rj", "rj", Access::Read),
            gr("rk", "rk", Access::Read),
            val("sa2", "sa2"),
        ],
    ));
    // rd, rj, rk, sa3（BYTEPICK.D）。
    m.formats.push(fmt(
        "FR3SA3",
        &["sa3", "rk", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::Write),
            gr("rj", "rj", Access::Read),
            gr("rk", "rk", Access::Read),
            val("sa3", "sa3"),
        ],
    ));
    // rd, rj, ui5 / rd, rj, ui6（即値シフト・回転）。
    m.formats.push(fmt(
        "FUI5",
        &["ui5", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::Write),
            gr("rj", "rj", Access::Read),
            val("ui5", "ui5"),
        ],
    ));
    m.formats.push(fmt(
        "FUI6",
        &["ui6", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::Write),
            gr("rj", "rj", Access::Read),
            val("ui6", "ui6"),
        ],
    ));
    // rd, rj, msb, lsb（BSTRINS/BSTRPICK）。
    m.formats.push(fmt(
        "FBSTRW",
        &["msbw", "lsbw", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::ReadWrite),
            gr("rj", "rj", Access::Read),
            val("msbw", "msbw"),
            val("lsbw", "lsbw"),
        ],
    ));
    m.formats.push(fmt(
        "FBSTRD",
        &["msbd", "lsbd", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::ReadWrite),
            gr("rj", "rj", Access::Read),
            val("msbd", "msbd"),
            val("lsbd", "lsbd"),
        ],
    ));
    // rd, rj, si12（即値演算・LD/ST si12）。
    m.formats.push(fmt(
        "FSI12",
        &["si12", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::ReadWrite),
            gr("rj", "rj", Access::Read),
            val("si12", "si12"),
        ],
    ));
    // fd, rj, si12（FLD/FST）。
    m.formats.push(fmt(
        "FSI12F",
        &["si12", "rj", "rd"],
        vec![
            fpr("fd", "rd", Access::ReadWrite),
            gr("rj", "rj", Access::Read),
            val("si12", "si12"),
        ],
    ));
    // hint, rj, si12（PRELD）。
    m.formats.push(fmt(
        "FPRELD",
        &["si12", "rj", "hint5"],
        vec![
            val("hint", "hint5"),
            gr("rj", "rj", Access::Read),
            val("si12", "si12"),
        ],
    ));
    // hint, rj, rk（PRELDX）。
    m.formats.push(fmt(
        "FPRELDX",
        &["rk", "rj", "hint5"],
        vec![
            val("hint", "hint5"),
            gr("rj", "rj", Access::Read),
            gr("rk", "rk", Access::Read),
        ],
    ));
    // rd, rj, ui12（ANDI/ORI/XORI）。
    m.formats.push(fmt(
        "FUI12",
        &["ui12", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::Write),
            gr("rj", "rj", Access::Read),
            val("ui12", "ui12"),
        ],
    ));
    // rd, rj, si14（LL/SC・LDPTR/STPTR）。
    m.formats.push(fmt(
        "FSI14",
        &["si14", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::ReadWrite),
            gr("rj", "rj", Access::Read),
            val("si14", "si14"),
        ],
    ));
    // rd, rj, si16（ADDU16I.D）。
    m.formats.push(fmt(
        "FSI16",
        &["si16", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::Write),
            gr("rj", "rj", Access::Read),
            val("si16", "si16"),
        ],
    ));
    // rd, si20（LU12I/LU32I・PC 系即値）。
    m.formats.push(fmt(
        "FSI20",
        &["si20", "rd"],
        vec![gr("rd", "rd", Access::ReadWrite), val("si20", "si20")],
    ));
    // rd, rj, csr（CSRRD/CSRWR/CSRXCHG。CSRRD は rj==0、
    // CSRWR は rj==1 の固定位置として `wheres` で切る）。
    m.formats.push(fmt(
        "FCSR",
        &["csr", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::ReadWrite),
            gr("rj", "rj", Access::Read),
            val("csr", "csr"),
        ],
    ));
    // code, rj, si12（CACOP）。
    m.formats.push(fmt(
        "FCACOP",
        &["si12", "rj", "code5"],
        vec![
            val("code", "code5"),
            gr("rj", "rj", Access::Read),
            val("si12", "si12"),
        ],
    ));
    // rd, rj, level8（LDDIR）。
    m.formats.push(fmt(
        "FLDDIR",
        &["level8", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::Write),
            gr("rj", "rj", Access::Read),
            val("level", "level8"),
        ],
    ));
    // rj, seq8（LDPTE。rd 位置は固定 0）。
    m.formats.push(fmt(
        "FLDPTE",
        &["seq8", "rj"],
        vec![gr("rj", "rj", Access::Read), val("seq", "seq8")],
    ));
    // op, rj, rk（INVTLB）。
    m.formats.push(fmt(
        "FINVTLB",
        &["rk", "rj", "op5"],
        vec![
            val("op", "op5"),
            gr("rj", "rj", Access::Read),
            gr("rk", "rk", Access::Read),
        ],
    ));
    // rj, offs21（BEQZ/BNEZ）。
    m.formats.push(fmt(
        "FBEQZ",
        &["offs21", "rj"],
        vec![gr("rj", "rj", Access::Read), val("offs", "offs21")],
    ));
    // cj, offs21（BCEQZ/BCNEZ）。
    m.formats.push(fmt(
        "FBCEZ",
        &["offs21", "cj"],
        vec![fcc("cj", "cj", Access::Read), val("offs", "offs21")],
    ));
    // rd, rj, offs16（JIRL）。
    m.formats.push(fmt(
        "FJIRL",
        &["offs16", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::Write),
            gr("rj", "rj", Access::Read),
            val("offs", "offs16"),
        ],
    ));
    // offs26（B/BL）。
    m.formats.push(fmt("FB", &["offs26"], vec![val("offs", "offs26")]));
    // rj, rd, offs16（BEQ/BNE/BLT/BGE/BLTU/BGEU）。
    m.formats.push(fmt(
        "FBCOND",
        &["offs16", "rj", "rd"],
        vec![
            gr("rj", "rj", Access::Read),
            gr("rd", "rd", Access::Read),
            val("offs", "offs16"),
        ],
    ));

    // ---- LSX 用フォーマット。Ref: SPEC-LOONGARCH-RM Vol.2.
    // vd, vj, vk の 3 項（要素演算・VILVL・VSHUF.H/W/D 等）。
    m.formats.push(fmt(
        "FV3R",
        &["rk", "rj", "rd"],
        vec![
            vr("vd", "rd", Access::Write),
            vr("vj", "rj", Access::Read),
            vr("vk", "rk", Access::Read),
        ],
    ));
    // vd, vj, vk, va の 4 項（VSHUF.B）。
    m.formats.push(fmt(
        "FV4R",
        &["ra", "rk", "rj", "rd"],
        vec![
            vr("vd", "rd", Access::Write),
            vr("vj", "rj", Access::Read),
            vr("vk", "rk", Access::Read),
            vr("va", "ra", Access::Read),
        ],
    ));
    // vd, vj の 2 項（VREPLGR2VR 系・VEXT*/VPCNT*）。
    m.formats.push(fmt(
        "FV2R",
        &["rj", "rd"],
        vec![vr("vd", "rd", Access::Write), vr("vj", "rj", Access::Read)],
    ));
    // vd, rj の 2 項（VREPLGR2VR。rj は汎用レジスタ）。
    m.formats.push(fmt(
        "FVRG2",
        &["rj", "rd"],
        vec![vr("vd", "rd", Access::Write), gr("rj", "rj", Access::Read)],
    ));
    // vd, vj, ui5（VSRLLI/VSRLI/VADDI/VSUBI 系）。
    m.formats.push(fmt(
        "FVUI5",
        &["ui5", "rj", "rd"],
        vec![
            vr("vd", "rd", Access::Write),
            vr("vj", "rj", Access::Read),
            val("ui5", "ui5"),
        ],
    ));
    // vd, vj, ui6（VBITREVI.D・VSLLI.D/VSRLLI.D 系）。
    m.formats.push(fmt(
        "FVUI6",
        &["ui6", "rj", "rd"],
        vec![
            vr("vd", "rd", Access::Write),
            vr("vj", "rj", Access::Read),
            val("ui6", "ui6"),
        ],
    ));
    // vd, rj, si12（VLD/VST）。
    m.formats.push(fmt(
        "FVLD",
        &["si12", "rj", "rd"],
        vec![
            vr("vd", "rd", Access::ReadWrite),
            gr("rj", "rj", Access::Read),
            val("si12", "si12"),
        ],
    ));
    // vd, rj, rk（VLDX/VSTX）。
    m.formats.push(fmt(
        "FVLDX",
        &["rk", "rj", "rd"],
        vec![
            vr("vd", "rd", Access::ReadWrite),
            gr("rj", "rj", Access::Read),
            gr("rk", "rk", Access::Read),
        ],
    ));
    // vd, rj, si9（VLDREPL.D。si9 は符号つきで、意味論で
    // 要素幅 8 倍にスケールする）。
    m.formats.push(fmt(
        "FVLDREPL",
        &["si9", "rj", "rd"],
        vec![
            vr("vd", "rd", Access::Write),
            gr("rj", "rj", Access::Read),
            val("si9", "si9"),
        ],
    ));
    // vd, vj, imm8（VSHUF4I.*）。
    m.formats.push(fmt(
        "FVSHUF4I",
        &["imm8", "rj", "rd"],
        vec![
            vr("vd", "rd", Access::Write),
            vr("vj", "rj", Access::Read),
            val("imm8", "imm8"),
        ],
    ));
    // rd, vj, vidx2（VPICKVE2GR.W 等、2 ビット要素番号）。
    m.formats.push(fmt(
        "FVPICK2",
        &["vidx2", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::Write),
            vr("vj", "rj", Access::Read),
            val("vidx2", "vidx2"),
        ],
    ));
    // rd, vj, vidx1（VPICKVE2GR.DU、1 ビット要素番号）。
    m.formats.push(fmt(
        "FVPICK1",
        &["vidx1", "rj", "rd"],
        vec![
            gr("rd", "rd", Access::Write),
            vr("vj", "rj", Access::Read),
            val("vidx1", "vidx1"),
        ],
    ));
    // vd, rj, vidx2（VINSGR2VR.W。挿入なので vd は読み書き）。
    m.formats.push(fmt(
        "FVINS2",
        &["vidx2", "rj", "rd"],
        vec![
            vr("vd", "rd", Access::ReadWrite),
            gr("rj", "rj", Access::Read),
            val("vidx2", "vidx2"),
        ],
    ));
    // cd, vj（VSETNEZ.V/VSETEQZ.V）。
    m.formats.push(fmt(
        "FVCD",
        &["rj", "cd"],
        vec![fcc("cd", "cd", Access::Write), vr("vj", "rj", Access::Read)],
    ));
    // vd, si13（VLDI）。
    m.formats.push(fmt(
        "FVLDI",
        &["si13", "rd"],
        vec![vr("vd", "rd", Access::Write), val("si13", "si13")],
    ));

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
    let base = || Pred::True;
    let f_la64 = || Pred::Flag("la64".to_string());
    let f_lsx = || Pred::Flag("lsx".to_string());

    // ---- ユーザモード全語彙 + 特権命令の符号化（LA3）。
    // LA32 必須の部分集合は SPEC-LOONGARCH-RM 表 2 に従い、
    // 表にない命令（.d 系・LDX/STX・AM*・CRC 等）は la64 に
    // 切る。FLDX/FSTX/FLD{GT,LE}/FST{GT,LE}.{S/D} だけが
    // LA64 専用の FP 命令で、他の FP 命令は LA32/LA64 共通。
    // Ref: SPEC-LOONGARCH-RM §2.1（LA32 部分集合）,
    // §3.4（LA64 専用 FP メモリ命令）, Appendix B.
    for (name, format, pattern, when, syntax, timing) in [

        // 2R 変換・計数・読み出し（CLO/CLZ/CTO/CTZ・REV*/
        // BITREV/EXT・RDTIME・CPUCFG）。Ref: §2.2.5, §2.2.10.
        ("clo_w", "FR2", "0000000000000000000100..........", base(), "clo.w {rd}, {rj}", "alu"),
        ("clz_w", "FR2", "0000000000000000000101..........", base(), "clz.w {rd}, {rj}", "alu"),
        ("cto_w", "FR2", "0000000000000000000110..........", base(), "cto.w {rd}, {rj}", "alu"),
        ("ctz_w", "FR2", "0000000000000000000111..........", base(), "ctz.w {rd}, {rj}", "alu"),
        ("clo_d", "FR2", "0000000000000000001000..........", f_la64(), "clo.d {rd}, {rj}", "alu"),
        ("clz_d", "FR2", "0000000000000000001001..........", f_la64(), "clz.d {rd}, {rj}", "alu"),
        ("cto_d", "FR2", "0000000000000000001010..........", f_la64(), "cto.d {rd}, {rj}", "alu"),
        ("ctz_d", "FR2", "0000000000000000001011..........", f_la64(), "ctz.d {rd}, {rj}", "alu"),
        ("revb_2h", "FR2", "0000000000000000001100..........", base(), "revb.2h {rd}, {rj}", "alu"),
        ("revb_4h", "FR2", "0000000000000000001101..........", f_la64(), "revb.4h {rd}, {rj}", "alu"),
        ("revb_2w", "FR2", "0000000000000000001110..........", f_la64(), "revb.2w {rd}, {rj}", "alu"),
        ("revb_d", "FR2", "0000000000000000001111..........", f_la64(), "revb.d {rd}, {rj}", "alu"),
        ("revh_2w", "FR2", "0000000000000000010000..........", f_la64(), "revh.2w {rd}, {rj}", "alu"),
        ("revh_d", "FR2", "0000000000000000010001..........", f_la64(), "revh.d {rd}, {rj}", "alu"),
        ("bitrev_4b", "FR2", "0000000000000000010010..........", base(), "bitrev.4b {rd}, {rj}", "alu"),
        ("bitrev_8b", "FR2", "0000000000000000010011..........", f_la64(), "bitrev.8b {rd}, {rj}", "alu"),
        ("bitrev_w", "FR2", "0000000000000000010100..........", base(), "bitrev.w {rd}, {rj}", "alu"),
        ("bitrev_d", "FR2", "0000000000000000010101..........", f_la64(), "bitrev.d {rd}, {rj}", "alu"),
        ("ext_w_h", "FR2", "0000000000000000010110..........", base(), "ext.w.h {rd}, {rj}", "alu"),
        ("ext_w_b", "FR2", "0000000000000000010111..........", base(), "ext.w.b {rd}, {rj}", "alu"),
        ("rdtimel_w", "FR2", "0000000000000000011000..........", base(), "rdtimel.w {rd}, {rj}", "system"),
        ("rdtimeh_w", "FR2", "0000000000000000011001..........", base(), "rdtimeh.w {rd}, {rj}", "system"),
        ("rdtime_d", "FR2", "0000000000000000011010..........", f_la64(), "rdtime.d {rd}, {rj}", "system"),
        ("cpucfg", "FR2", "0000000000000000011011..........", base(), "cpucfg {rd}, {rj}", "system"),

        // アサート。Ref: §2.2.11.
        ("asrtle_d", "FR2JK", "00000000000000010..........00000", f_la64(), "asrtle.d {rj}, {rk}", "system"),
        ("asrtgt_d", "FR2JK", "00000000000000011..........00000", f_la64(), "asrtgt.d {rj}, {rk}", "system"),

        // ALSL・BYTEPICK（sa2/sa3 付き 3 項）。Ref: §2.2.1.3, §2.2.5.3.
        ("alsl_w", "FR3SA2", "000000000000010.................", base(), "alsl.w {rd}, {rj}, {rk}, {sa2}", "alu"),
        ("alsl_wu", "FR3SA2", "000000000000011.................", f_la64(), "alsl.wu {rd}, {rj}, {rk}, {sa2}", "alu"),
        ("bytepick_w", "FR3SA2", "000000000000100.................", base(), "bytepick.w {rd}, {rj}, {rk}, {sa2}", "alu"),
        ("bytepick_d", "FR3SA3", "00000000000011..................", f_la64(), "bytepick.d {rd}, {rj}, {rk}, {sa3}", "alu"),

        // 3 項の整数演算・比較・論理・シフト・乗除。Ref: §2.2.1-2.2.3.
        ("add_w", "FR3", "00000000000100000...............", base(), "add.w {rd}, {rj}, {rk}", "alu"),
        ("add_d", "FR3", "00000000000100001...............", f_la64(), "add.d {rd}, {rj}, {rk}", "alu"),
        ("sub_w", "FR3", "00000000000100010...............", base(), "sub.w {rd}, {rj}, {rk}", "alu"),
        ("sub_d", "FR3", "00000000000100011...............", f_la64(), "sub.d {rd}, {rj}, {rk}", "alu"),
        ("slt", "FR3", "00000000000100100...............", base(), "slt {rd}, {rj}, {rk}", "alu"),
        ("sltu", "FR3", "00000000000100101...............", base(), "sltu {rd}, {rj}, {rk}", "alu"),
        ("maskeqz", "FR3", "00000000000100110...............", base(), "maskeqz {rd}, {rj}, {rk}", "alu"),
        ("masknez", "FR3", "00000000000100111...............", base(), "masknez {rd}, {rj}, {rk}", "alu"),
        ("nor", "FR3", "00000000000101000...............", base(), "nor {rd}, {rj}, {rk}", "alu"),
        ("and", "FR3", "00000000000101001...............", base(), "and {rd}, {rj}, {rk}", "alu"),
        ("or", "FR3", "00000000000101010...............", base(), "or {rd}, {rj}, {rk}", "alu"),
        ("xor", "FR3", "00000000000101011...............", base(), "xor {rd}, {rj}, {rk}", "alu"),
        ("orn", "FR3", "00000000000101100...............", base(), "orn {rd}, {rj}, {rk}", "alu"),
        ("andn", "FR3", "00000000000101101...............", base(), "andn {rd}, {rj}, {rk}", "alu"),
        ("sll_w", "FR3", "00000000000101110...............", base(), "sll.w {rd}, {rj}, {rk}", "alu"),
        ("srl_w", "FR3", "00000000000101111...............", base(), "srl.w {rd}, {rj}, {rk}", "alu"),
        ("sra_w", "FR3", "00000000000110000...............", base(), "sra.w {rd}, {rj}, {rk}", "alu"),
        ("sll_d", "FR3", "00000000000110001...............", f_la64(), "sll.d {rd}, {rj}, {rk}", "alu"),
        ("srl_d", "FR3", "00000000000110010...............", f_la64(), "srl.d {rd}, {rj}, {rk}", "alu"),
        ("sra_d", "FR3", "00000000000110011...............", f_la64(), "sra.d {rd}, {rj}, {rk}", "alu"),
        ("rotr_w", "FR3", "00000000000110110...............", base(), "rotr.w {rd}, {rj}, {rk}", "alu"),
        ("rotr_d", "FR3", "00000000000110111...............", f_la64(), "rotr.d {rd}, {rj}, {rk}", "alu"),
        ("mul_w", "FR3", "00000000000111000...............", base(), "mul.w {rd}, {rj}, {rk}", "alu"),
        ("mulh_w", "FR3", "00000000000111001...............", base(), "mulh.w {rd}, {rj}, {rk}", "alu"),
        ("mulh_wu", "FR3", "00000000000111010...............", base(), "mulh.wu {rd}, {rj}, {rk}", "alu"),
        ("mul_d", "FR3", "00000000000111011...............", f_la64(), "mul.d {rd}, {rj}, {rk}", "alu"),
        ("mulh_d", "FR3", "00000000000111100...............", f_la64(), "mulh.d {rd}, {rj}, {rk}", "alu"),
        ("mulh_du", "FR3", "00000000000111101...............", f_la64(), "mulh.du {rd}, {rj}, {rk}", "alu"),
        ("mulw_d_w", "FR3", "00000000000111110...............", f_la64(), "mulw.d.w {rd}, {rj}, {rk}", "alu"),
        ("mulw_d_wu", "FR3", "00000000000111111...............", f_la64(), "mulw.d.wu {rd}, {rj}, {rk}", "alu"),
        ("div_w", "FR3", "00000000001000000...............", base(), "div.w {rd}, {rj}, {rk}", "alu"),
        ("mod_w", "FR3", "00000000001000001...............", base(), "mod.w {rd}, {rj}, {rk}", "alu"),
        ("div_wu", "FR3", "00000000001000010...............", base(), "div.wu {rd}, {rj}, {rk}", "alu"),
        ("mod_wu", "FR3", "00000000001000011...............", base(), "mod.wu {rd}, {rj}, {rk}", "alu"),
        ("div_d", "FR3", "00000000001000100...............", f_la64(), "div.d {rd}, {rj}, {rk}", "alu"),
        ("mod_d", "FR3", "00000000001000101...............", f_la64(), "mod.d {rd}, {rj}, {rk}", "alu"),
        ("div_du", "FR3", "00000000001000110...............", f_la64(), "div.du {rd}, {rj}, {rk}", "alu"),
        ("mod_du", "FR3", "00000000001000111...............", f_la64(), "mod.du {rd}, {rj}, {rk}", "alu"),

        // CRC 検査。Ref: §2.2.9.
        ("crc_w_b_w", "FR3", "00000000001001000...............", f_la64(), "crc.w.b.w {rd}, {rj}, {rk}", "alu"),
        ("crc_w_h_w", "FR3", "00000000001001001...............", f_la64(), "crc.w.h.w {rd}, {rj}, {rk}", "alu"),
        ("crc_w_w_w", "FR3", "00000000001001010...............", f_la64(), "crc.w.w.w {rd}, {rj}, {rk}", "alu"),
        ("crc_w_d_w", "FR3", "00000000001001011...............", f_la64(), "crc.w.d.w {rd}, {rj}, {rk}", "alu"),
        ("crcc_w_b_w", "FR3", "00000000001001100...............", f_la64(), "crcc.w.b.w {rd}, {rj}, {rk}", "alu"),
        ("crcc_w_h_w", "FR3", "00000000001001101...............", f_la64(), "crcc.w.h.w {rd}, {rj}, {rk}", "alu"),
        ("crcc_w_w_w", "FR3", "00000000001001110...............", f_la64(), "crcc.w.w.w {rd}, {rj}, {rk}", "alu"),
        ("crcc_w_d_w", "FR3", "00000000001001111...............", f_la64(), "crcc.w.d.w {rd}, {rj}, {rk}", "alu"),

        // 例外・システム呼出の発行点。Ref: §2.2.12.
        ("break", "FCODE15", "00000000001010100...............", base(), "break {code}", "system"),
        ("dbcl", "FCODE15", "00000000001010101...............", base(), "dbcl {code}", "system"),
        ("syscall", "FCODE15", "00000000001010110...............", base(), "syscall {code}", "system"),

        // ALSL.D（sa2 付き、LA64）。Ref: §2.2.1.3.
        ("alsl_d", "FR3SA2", "000000000010110.................", f_la64(), "alsl.d {rd}, {rj}, {rk}, {sa2}", "alu"),

        // 即値シフト・回転。Ref: §2.2.2.
        ("slli_w", "FUI5", "00000000010000001...............", base(), "slli.w {rd}, {rj}, {ui5}", "alu"),
        ("slli_d", "FUI6", "0000000001000001................", f_la64(), "slli.d {rd}, {rj}, {ui6}", "alu"),
        ("srli_w", "FUI5", "00000000010001001...............", base(), "srli.w {rd}, {rj}, {ui5}", "alu"),
        ("srli_d", "FUI6", "0000000001000101................", f_la64(), "srli.d {rd}, {rj}, {ui6}", "alu"),
        ("srai_w", "FUI5", "00000000010010001...............", base(), "srai.w {rd}, {rj}, {ui5}", "alu"),
        ("srai_d", "FUI6", "0000000001001001................", f_la64(), "srai.d {rd}, {rj}, {ui6}", "alu"),
        ("rotri_w", "FUI5", "00000000010011001...............", base(), "rotri.w {rd}, {rj}, {ui5}", "alu"),
        ("rotri_d", "FUI6", "0000000001001101................", f_la64(), "rotri.d {rd}, {rj}, {ui6}", "alu"),

        // ビット列の挿入・取出し。Ref: §2.2.5.5.
        ("bstrins_w", "FBSTRW", "00000000011.....0...............", base(), "bstrins.w {rd}, {rj}, {msbw}, {lsbw}", "alu"),
        ("bstrpick_w", "FBSTRW", "00000000011.....1...............", base(), "bstrpick.w {rd}, {rj}, {msbw}, {lsbw}", "alu"),
        ("bstrins_d", "FBSTRD", "0000000010......................", f_la64(), "bstrins.d {rd}, {rj}, {msbd}, {lsbd}", "alu"),
        ("bstrpick_d", "FBSTRD", "0000000011......................", f_la64(), "bstrpick.d {rd}, {rj}, {msbd}, {lsbd}", "alu"),

        // FP 基本演算（FF3 系）。Ref: §3.2.1-3.2.2.
        ("fadd_s", "FF3", "00000001000000001...............", base(), "fadd.s {fd}, {fj}, {fk}", "fp"),
        ("fadd_d", "FF3", "00000001000000010...............", base(), "fadd.d {fd}, {fj}, {fk}", "fp"),
        ("fsub_s", "FF3", "00000001000000101...............", base(), "fsub.s {fd}, {fj}, {fk}", "fp"),
        ("fsub_d", "FF3", "00000001000000110...............", base(), "fsub.d {fd}, {fj}, {fk}", "fp"),
        ("fmul_s", "FF3", "00000001000001001...............", base(), "fmul.s {fd}, {fj}, {fk}", "fp"),
        ("fmul_d", "FF3", "00000001000001010...............", base(), "fmul.d {fd}, {fj}, {fk}", "fp"),
        ("fdiv_s", "FF3", "00000001000001101...............", base(), "fdiv.s {fd}, {fj}, {fk}", "fp"),
        ("fdiv_d", "FF3", "00000001000001110...............", base(), "fdiv.d {fd}, {fj}, {fk}", "fp"),
        ("fmax_s", "FF3", "00000001000010001...............", base(), "fmax.s {fd}, {fj}, {fk}", "fp"),
        ("fmax_d", "FF3", "00000001000010010...............", base(), "fmax.d {fd}, {fj}, {fk}", "fp"),
        ("fmin_s", "FF3", "00000001000010101...............", base(), "fmin.s {fd}, {fj}, {fk}", "fp"),
        ("fmin_d", "FF3", "00000001000010110...............", base(), "fmin.d {fd}, {fj}, {fk}", "fp"),
        ("fmaxa_s", "FF3", "00000001000011001...............", base(), "fmaxa.s {fd}, {fj}, {fk}", "fp"),
        ("fmaxa_d", "FF3", "00000001000011010...............", base(), "fmaxa.d {fd}, {fj}, {fk}", "fp"),
        ("fmina_s", "FF3", "00000001000011101...............", base(), "fmina.s {fd}, {fj}, {fk}", "fp"),
        ("fmina_d", "FF3", "00000001000011110...............", base(), "fmina.d {fd}, {fj}, {fk}", "fp"),
        ("fscaleb_s", "FF3", "00000001000100001...............", base(), "fscaleb.s {fd}, {fj}, {fk}", "fp"),
        ("fscaleb_d", "FF3", "00000001000100010...............", base(), "fscaleb.d {fd}, {fj}, {fk}", "fp"),
        ("fcopysign_s", "FF3", "00000001000100101...............", base(), "fcopysign.s {fd}, {fj}, {fk}", "fp"),
        ("fcopysign_d", "FF3", "00000001000100110...............", base(), "fcopysign.d {fd}, {fj}, {fk}", "fp"),

        // FP 2 項の写像・関数（FF2 系）。Ref: §3.2.3, §3.2.7.
        ("fabs_s", "FF2", "0000000100010100000001..........", base(), "fabs.s {fd}, {fj}", "fp"),
        ("fabs_d", "FF2", "0000000100010100000010..........", base(), "fabs.d {fd}, {fj}", "fp"),
        ("fneg_s", "FF2", "0000000100010100000101..........", base(), "fneg.s {fd}, {fj}", "fp"),
        ("fneg_d", "FF2", "0000000100010100000110..........", base(), "fneg.d {fd}, {fj}", "fp"),
        ("flogb_s", "FF2", "0000000100010100001001..........", base(), "flogb.s {fd}, {fj}", "fp"),
        ("flogb_d", "FF2", "0000000100010100001010..........", base(), "flogb.d {fd}, {fj}", "fp"),
        ("fclass_s", "FF2", "0000000100010100001101..........", base(), "fclass.s {fd}, {fj}", "fp"),
        ("fclass_d", "FF2", "0000000100010100001110..........", base(), "fclass.d {fd}, {fj}", "fp"),
        ("fsqrt_s", "FF2", "0000000100010100010001..........", base(), "fsqrt.s {fd}, {fj}", "fp"),
        ("fsqrt_d", "FF2", "0000000100010100010010..........", base(), "fsqrt.d {fd}, {fj}", "fp"),
        ("frecip_s", "FF2", "0000000100010100010101..........", base(), "frecip.s {fd}, {fj}", "fp"),
        ("frecip_d", "FF2", "0000000100010100010110..........", base(), "frecip.d {fd}, {fj}", "fp"),
        ("frsqrt_s", "FF2", "0000000100010100011001..........", base(), "frsqrt.s {fd}, {fj}", "fp"),
        ("frsqrt_d", "FF2", "0000000100010100011010..........", base(), "frsqrt.d {fd}, {fj}", "fp"),
        ("frecipe_s", "FF2", "0000000100010100011101..........", base(), "frecipe.s {fd}, {fj}", "fp"),
        ("frecipe_d", "FF2", "0000000100010100011110..........", base(), "frecipe.d {fd}, {fj}", "fp"),
        ("frsqrte_s", "FF2", "0000000100010100100001..........", base(), "frsqrte.s {fd}, {fj}", "fp"),
        ("frsqrte_d", "FF2", "0000000100010100100010..........", base(), "frsqrte.d {fd}, {fj}", "fp"),
        ("fmov_s", "FF2", "0000000100010100100101..........", base(), "fmov.s {fd}, {fj}", "fp"),
        ("fmov_d", "FF2", "0000000100010100100110..........", base(), "fmov.d {fd}, {fj}", "fp"),

        // GR/FR/FCC/FCSR 間の移動。Ref: §3.4.4, §3.4.5.
        ("movgr2fr_w", "FG2F", "0000000100010100101001..........", base(), "movgr2fr.w {fd}, {rj}", "fp"),
        ("movgr2fr_d", "FG2F", "0000000100010100101010..........", f_la64(), "movgr2fr.d {fd}, {rj}", "fp"),
        ("movgr2frh_w", "FG2F", "0000000100010100101011..........", base(), "movgr2frh.w {fd}, {rj}", "fp"),
        ("movfr2gr_s", "FF2G", "0000000100010100101101..........", base(), "movfr2gr.s {rd}, {fj}", "fp"),
        ("movfr2gr_d", "FF2G", "0000000100010100101110..........", f_la64(), "movfr2gr.d {rd}, {fj}", "fp"),
        ("movfrh2gr_s", "FF2G", "0000000100010100101111..........", base(), "movfrh2gr.s {rd}, {fj}", "fp"),
        ("movgr2fcsr", "FG2FCSR", "0000000100010100110000..........", base(), "movgr2fcsr {fcsr}, {rj}", "fp"),
        ("movfcsr2gr", "FFCSR2G", "0000000100010100110010..........", base(), "movfcsr2gr {rd}, {fcsr}", "fp"),
        ("movfr2cf", "FF2CF", "0000000100010100110100.....00...", base(), "movfr2cf {cd}, {fj}", "fp"),
        ("movcf2fr", "FCF2F", "000000010001010011010100........", base(), "movcf2fr {fd}, {cj}", "fp"),
        ("movgr2cf", "FG2CF", "0000000100010100110110.....00...", base(), "movgr2cf {cd}, {rj}", "fp"),
        ("movcf2gr", "FCF2G", "000000010001010011011100........", base(), "movcf2gr {rd}, {cj}", "fp"),

        // FP 変換・整数化。Ref: §3.4.1-3.4.3.
        ("fcvt_s_d", "FF2", "0000000100011001000110..........", base(), "fcvt.s.d {fd}, {fj}", "fp"),
        ("fcvt_d_s", "FF2", "0000000100011001001001..........", base(), "fcvt.d.s {fd}, {fj}", "fp"),
        ("ftintrm_w_s", "FF2", "0000000100011010000001..........", base(), "ftintrm.w.s {fd}, {fj}", "fp"),
        ("ftintrm_w_d", "FF2", "0000000100011010000010..........", base(), "ftintrm.w.d {fd}, {fj}", "fp"),
        ("ftintrm_l_s", "FF2", "0000000100011010001001..........", base(), "ftintrm.l.s {fd}, {fj}", "fp"),
        ("ftintrm_l_d", "FF2", "0000000100011010001010..........", base(), "ftintrm.l.d {fd}, {fj}", "fp"),
        ("ftintrp_w_s", "FF2", "0000000100011010010001..........", base(), "ftintrp.w.s {fd}, {fj}", "fp"),
        ("ftintrp_w_d", "FF2", "0000000100011010010010..........", base(), "ftintrp.w.d {fd}, {fj}", "fp"),
        ("ftintrp_l_s", "FF2", "0000000100011010011001..........", base(), "ftintrp.l.s {fd}, {fj}", "fp"),
        ("ftintrp_l_d", "FF2", "0000000100011010011010..........", base(), "ftintrp.l.d {fd}, {fj}", "fp"),
        ("ftintrz_w_s", "FF2", "0000000100011010100001..........", base(), "ftintrz.w.s {fd}, {fj}", "fp"),
        ("ftintrz_w_d", "FF2", "0000000100011010100010..........", base(), "ftintrz.w.d {fd}, {fj}", "fp"),
        ("ftintrz_l_s", "FF2", "0000000100011010101001..........", base(), "ftintrz.l.s {fd}, {fj}", "fp"),
        ("ftintrz_l_d", "FF2", "0000000100011010101010..........", base(), "ftintrz.l.d {fd}, {fj}", "fp"),
        ("ftintrne_w_s", "FF2", "0000000100011010110001..........", base(), "ftintrne.w.s {fd}, {fj}", "fp"),
        ("ftintrne_w_d", "FF2", "0000000100011010110010..........", base(), "ftintrne.w.d {fd}, {fj}", "fp"),
        ("ftintrne_l_s", "FF2", "0000000100011010111001..........", base(), "ftintrne.l.s {fd}, {fj}", "fp"),
        ("ftintrne_l_d", "FF2", "0000000100011010111010..........", base(), "ftintrne.l.d {fd}, {fj}", "fp"),
        ("ftint_w_s", "FF2", "0000000100011011000001..........", base(), "ftint.w.s {fd}, {fj}", "fp"),
        ("ftint_w_d", "FF2", "0000000100011011000010..........", base(), "ftint.w.d {fd}, {fj}", "fp"),
        ("ftint_l_s", "FF2", "0000000100011011001001..........", base(), "ftint.l.s {fd}, {fj}", "fp"),
        ("ftint_l_d", "FF2", "0000000100011011001010..........", base(), "ftint.l.d {fd}, {fj}", "fp"),
        ("ffint_s_w", "FF2", "0000000100011101000100..........", base(), "ffint.s.w {fd}, {fj}", "fp"),
        ("ffint_s_l", "FF2", "0000000100011101000110..........", base(), "ffint.s.l {fd}, {fj}", "fp"),
        ("ffint_d_w", "FF2", "0000000100011101001000..........", base(), "ffint.d.w {fd}, {fj}", "fp"),
        ("ffint_d_l", "FF2", "0000000100011101001010..........", base(), "ffint.d.l {fd}, {fj}", "fp"),
        ("frint_s", "FF2", "0000000100011110010001..........", base(), "frint.s {fd}, {fj}", "fp"),
        ("frint_d", "FF2", "0000000100011110010010..........", base(), "frint.d {fd}, {fj}", "fp"),

        // 即値の算術・論理・上位即値。Ref: §2.2.1, §2.2.5.8.
        ("slti", "FSI12", "0000001000......................", base(), "slti {rd}, {rj}, {si12}", "alu"),
        ("sltui", "FSI12", "0000001001......................", base(), "sltui {rd}, {rj}, {si12}", "alu"),
        ("addi_w", "FSI12", "0000001010......................", base(), "addi.w {rd}, {rj}, {si12}", "alu"),
        ("addi_d", "FSI12", "0000001011......................", f_la64(), "addi.d {rd}, {rj}, {si12}", "alu"),
        ("lu52i_d", "FSI12", "0000001100......................", f_la64(), "lu52i.d {rd}, {rj}, {si12}", "alu"),
        ("andi", "FUI12", "0000001101......................", base(), "andi {rd}, {rj}, {ui12}", "alu"),
        ("ori", "FUI12", "0000001110......................", base(), "ori {rd}, {rj}, {ui12}", "alu"),
        ("xori", "FUI12", "0000001111......................", base(), "xori {rd}, {rj}, {ui12}", "alu"),

        // キャッシュ操作・ページ走査・IOCSR・TLB・ERTN・
        // IDLE・INVTLB（特権命令の符号化）。Ref: §4.4, §4.5.
        ("cacop", "FCACOP", "0000011000......................", base(), "cacop {code}, {rj}, {si12}", "system"),
        ("lddir", "FLDDIR", "00000110010000..................", base(), "lddir {rd}, {rj}, {level}", "system"),
        ("ldpte", "FLDPTE", "00000110010001.............00000", base(), "ldpte {rj}, {seq}", "system"),
        ("iocsrrd_b", "FR2", "0000011001001000000000..........", base(), "iocsrrd.b {rd}, {rj}", "system"),
        ("iocsrrd_h", "FR2", "0000011001001000000001..........", base(), "iocsrrd.h {rd}, {rj}", "system"),
        ("iocsrrd_w", "FR2", "0000011001001000000010..........", base(), "iocsrrd.w {rd}, {rj}", "system"),
        ("iocsrrd_d", "FR2", "0000011001001000000011..........", f_la64(), "iocsrrd.d {rd}, {rj}", "system"),
        ("iocsrwr_b", "FR2", "0000011001001000000100..........", base(), "iocsrwr.b {rd}, {rj}", "system"),
        ("iocsrwr_h", "FR2", "0000011001001000000101..........", base(), "iocsrwr.h {rd}, {rj}", "system"),
        ("iocsrwr_w", "FR2", "0000011001001000000110..........", base(), "iocsrwr.w {rd}, {rj}", "system"),
        ("iocsrwr_d", "FR2", "0000011001001000000111..........", f_la64(), "iocsrwr.d {rd}, {rj}", "system"),
        ("tlbclr", "FN0", "00000110010010000010000000000000", base(), "tlbclr", "system"),
        ("tlbflush", "FN0", "00000110010010000010010000000000", base(), "tlbflush", "system"),
        ("tlbsrch", "FN0", "00000110010010000010100000000000", base(), "tlbsrch", "system"),
        ("tlbrd", "FN0", "00000110010010000010110000000000", base(), "tlbrd", "system"),
        ("tlbwr", "FN0", "00000110010010000011000000000000", base(), "tlbwr", "system"),
        ("tlbfill", "FN0", "00000110010010000011010000000000", base(), "tlbfill", "system"),
        ("ertn", "FN0", "00000110010010000011100000000000", base(), "ertn", "system"),
        ("idle", "FIDLE", "00000110010010001...............", base(), "idle {level}", "system"),
        ("invtlb", "FINVTLB", "00000110010010010...............", base(), "invtlb {op}, {rj}, {rk}", "system"),

        // FP 融合演算（FF4 系）。Ref: §3.3.
        ("fmadd_s", "FF4", "000010000001....................", base(), "fmadd.s {fd}, {fj}, {fk}, {fa}", "fp"),
        ("fmadd_d", "FF4", "000010000010....................", base(), "fmadd.d {fd}, {fj}, {fk}, {fa}", "fp"),
        ("fmsub_s", "FF4", "000010000101....................", base(), "fmsub.s {fd}, {fj}, {fk}, {fa}", "fp"),
        ("fmsub_d", "FF4", "000010000110....................", base(), "fmsub.d {fd}, {fj}, {fk}, {fa}", "fp"),
        ("fnmadd_s", "FF4", "000010001001....................", base(), "fnmadd.s {fd}, {fj}, {fk}, {fa}", "fp"),
        ("fnmadd_d", "FF4", "000010001010....................", base(), "fnmadd.d {fd}, {fj}, {fk}, {fa}", "fp"),
        ("fnmsub_s", "FF4", "000010001101....................", base(), "fnmsub.s {fd}, {fj}, {fk}, {fa}", "fp"),
        ("fnmsub_d", "FF4", "000010001110....................", base(), "fnmsub.d {fd}, {fj}, {fk}, {fa}", "fp"),

        // FP 比較と選択。Ref: §3.2.2, §3.4.6.
        ("fcmp_cond_s", "FFCMP", "000011000001...............00...", base(), "fcmp.cond.s {cd}, {fj}, {fk}", "fp"),
        ("fcmp_cond_d", "FFCMP", "000011000010...............00...", base(), "fcmp.cond.d {cd}, {fj}, {fk}", "fp"),
        ("fsel", "FFSEL", "00001101000000..................", base(), "fsel {fd}, {fj}, {fk}, {ca}", "fp"),

        // 16/20 ビット即値と PC 相対即値。Ref: §2.2.1.4, §2.2.1.8.
        ("addu16i_d", "FSI16", "000100..........................", f_la64(), "addu16i.d {rd}, {rj}, {si16}", "alu"),
        ("lu12i_w", "FSI20", "0001010.........................", base(), "lu12i.w {rd}, {si20}", "alu"),
        ("lu32i_d", "FSI20", "0001011.........................", f_la64(), "lu32i.d {rd}, {si20}", "alu"),
        ("pcaddi", "FSI20", "0001100.........................", base(), "pcaddi {rd}, {si20}", "alu"),
        ("pcalau12i", "FSI20", "0001101.........................", base(), "pcalau12i {rd}, {si20}", "alu"),
        ("pcaddu12i", "FSI20", "0001110.........................", base(), "pcaddu12i {rd}, {si20}", "alu"),
        ("pcaddu18i", "FSI20", "0001111.........................", f_la64(), "pcaddu18i {rd}, {si20}", "alu"),

        // LL/SC・LDPTR/STPTR（si14）。Ref: §2.2.7.4, §2.2.6.3.
        ("ll_w", "FSI14", "00100000........................", base(), "ll.w {rd}, {rj}, {si14}", "atomic"),
        ("sc_w", "FSI14", "00100001........................", base(), "sc.w {rd}, {rj}, {si14}", "atomic"),
        ("ll_d", "FSI14", "00100010........................", f_la64(), "ll.d {rd}, {rj}, {si14}", "atomic"),
        ("sc_d", "FSI14", "00100011........................", f_la64(), "sc.d {rd}, {rj}, {si14}", "atomic"),
        ("ldptr_w", "FSI14", "00100100........................", f_la64(), "ldptr.w {rd}, {rj}, {si14}", "load"),
        ("stptr_w", "FSI14", "00100101........................", f_la64(), "stptr.w {rd}, {rj}, {si14}", "store"),
        ("ldptr_d", "FSI14", "00100110........................", f_la64(), "ldptr.d {rd}, {rj}, {si14}", "load"),
        ("stptr_d", "FSI14", "00100111........................", f_la64(), "stptr.d {rd}, {rj}, {si14}", "store"),

        // LD/ST・FLD/FST・PRELD（si12）。Ref: §2.2.6, §3.4.1.
        ("ld_b", "FSI12", "0010100000......................", base(), "ld.b {rd}, {rj}, {si12}", "load"),
        ("ld_h", "FSI12", "0010100001......................", base(), "ld.h {rd}, {rj}, {si12}", "load"),
        ("ld_w", "FSI12", "0010100010......................", base(), "ld.w {rd}, {rj}, {si12}", "load"),
        ("ld_d", "FSI12", "0010100011......................", f_la64(), "ld.d {rd}, {rj}, {si12}", "load"),
        ("st_b", "FSI12", "0010100100......................", base(), "st.b {rd}, {rj}, {si12}", "store"),
        ("st_h", "FSI12", "0010100101......................", base(), "st.h {rd}, {rj}, {si12}", "store"),
        ("st_w", "FSI12", "0010100110......................", base(), "st.w {rd}, {rj}, {si12}", "store"),
        ("st_d", "FSI12", "0010100111......................", f_la64(), "st.d {rd}, {rj}, {si12}", "store"),
        ("ld_bu", "FSI12", "0010101000......................", base(), "ld.bu {rd}, {rj}, {si12}", "load"),
        ("ld_hu", "FSI12", "0010101001......................", base(), "ld.hu {rd}, {rj}, {si12}", "load"),
        ("ld_wu", "FSI12", "0010101010......................", f_la64(), "ld.wu {rd}, {rj}, {si12}", "load"),
        ("preld", "FPRELD", "0010101011......................", base(), "preld {hint}, {rj}, {si12}", "load"),
        ("fld_s", "FSI12F", "0010101100......................", base(), "fld.s {fd}, {rj}, {si12}", "load"),
        ("fst_s", "FSI12F", "0010101101......................", base(), "fst.s {fd}, {rj}, {si12}", "store"),
        ("fld_d", "FSI12F", "0010101110......................", base(), "fld.d {fd}, {rj}, {si12}", "load"),
        ("fst_d", "FSI12F", "0010101111......................", base(), "fst.d {fd}, {rj}, {si12}", "store"),

        // 指標付き LDX/STX・FLDX/FSTX・PRELDX。Ref: §2.2.6.2, §3.4.2.
        ("ldx_b", "FR3", "00111000000000000...............", f_la64(), "ldx.b {rd}, {rj}, {rk}", "load"),
        ("ldx_h", "FR3", "00111000000001000...............", f_la64(), "ldx.h {rd}, {rj}, {rk}", "load"),
        ("ldx_w", "FR3", "00111000000010000...............", f_la64(), "ldx.w {rd}, {rj}, {rk}", "load"),
        ("ldx_d", "FR3", "00111000000011000...............", f_la64(), "ldx.d {rd}, {rj}, {rk}", "load"),
        ("stx_b", "FR3", "00111000000100000...............", f_la64(), "stx.b {rd}, {rj}, {rk}", "store"),
        ("stx_h", "FR3", "00111000000101000...............", f_la64(), "stx.h {rd}, {rj}, {rk}", "store"),
        ("stx_w", "FR3", "00111000000110000...............", f_la64(), "stx.w {rd}, {rj}, {rk}", "store"),
        ("stx_d", "FR3", "00111000000111000...............", f_la64(), "stx.d {rd}, {rj}, {rk}", "store"),
        ("ldx_bu", "FR3", "00111000001000000...............", f_la64(), "ldx.bu {rd}, {rj}, {rk}", "load"),
        ("ldx_hu", "FR3", "00111000001001000...............", f_la64(), "ldx.hu {rd}, {rj}, {rk}", "load"),
        ("ldx_wu", "FR3", "00111000001010000...............", f_la64(), "ldx.wu {rd}, {rj}, {rk}", "load"),
        ("preldx", "FPRELDX", "00111000001011000...............", f_la64(), "preldx {hint}, {rj}, {rk}", "load"),
        ("fldx_s", "FR3F", "00111000001100000...............", f_la64(), "fldx.s {fd}, {rj}, {rk}", "load"),
        ("fldx_d", "FR3F", "00111000001101000...............", f_la64(), "fldx.d {fd}, {rj}, {rk}", "load"),
        ("fstx_s", "FR3F", "00111000001110000...............", f_la64(), "fstx.s {fd}, {rj}, {rk}", "store"),
        ("fstx_d", "FR3F", "00111000001111000...............", f_la64(), "fstx.d {fd}, {rj}, {rk}", "store"),

        // SC.Q・LLACQ/SCREL・AMCAS。Ref: §2.2.7.3-2.2.7.6.
        ("sc_q", "FAM3", "00111000010101110...............", f_la64(), "sc.q {rd}, {rk}, {rj}", "atomic"),
        ("llacq_w", "FR2", "0011100001010111100000..........", f_la64(), "llacq.w {rd}, {rj}", "atomic"),
        ("screl_w", "FR2", "0011100001010111100001..........", f_la64(), "screl.w {rd}, {rj}", "atomic"),
        ("llacq_d", "FR2", "0011100001010111100010..........", f_la64(), "llacq.d {rd}, {rj}", "atomic"),
        ("screl_d", "FR2", "0011100001010111100011..........", f_la64(), "screl.d {rd}, {rj}", "atomic"),
        ("amcas_b", "FAM3", "00111000010110000...............", f_la64(), "amcas.b {rd}, {rk}, {rj}", "atomic"),
        ("amcas_h", "FAM3", "00111000010110001...............", f_la64(), "amcas.h {rd}, {rk}, {rj}", "atomic"),
        ("amcas_w", "FAM3", "00111000010110010...............", f_la64(), "amcas.w {rd}, {rk}, {rj}", "atomic"),
        ("amcas_d", "FAM3", "00111000010110011...............", f_la64(), "amcas.d {rd}, {rk}, {rj}", "atomic"),
        ("amcas_db_b", "FAM3", "00111000010110100...............", f_la64(), "amcas_db.b {rd}, {rk}, {rj}", "atomic"),
        ("amcas_db_h", "FAM3", "00111000010110101...............", f_la64(), "amcas_db.h {rd}, {rk}, {rj}", "atomic"),
        ("amcas_db_w", "FAM3", "00111000010110110...............", f_la64(), "amcas_db.w {rd}, {rk}, {rj}", "atomic"),
        ("amcas_db_d", "FAM3", "00111000010110111...............", f_la64(), "amcas_db.d {rd}, {rk}, {rj}", "atomic"),

        // AM*{SWAP/ADD}.B/H。Ref: §2.2.7.2.
        ("amswap_b", "FAM3", "00111000010111000...............", f_la64(), "amswap.b {rd}, {rk}, {rj}", "atomic"),
        ("amswap_h", "FAM3", "00111000010111001...............", f_la64(), "amswap.h {rd}, {rk}, {rj}", "atomic"),
        ("amadd_b", "FAM3", "00111000010111010...............", f_la64(), "amadd.b {rd}, {rk}, {rj}", "atomic"),
        ("amadd_h", "FAM3", "00111000010111011...............", f_la64(), "amadd.h {rd}, {rk}, {rj}", "atomic"),
        ("amswap_db_b", "FAM3", "00111000010111100...............", f_la64(), "amswap_db.b {rd}, {rk}, {rj}", "atomic"),
        ("amswap_db_h", "FAM3", "00111000010111101...............", f_la64(), "amswap_db.h {rd}, {rk}, {rj}", "atomic"),
        ("amadd_db_b", "FAM3", "00111000010111110...............", f_la64(), "amadd_db.b {rd}, {rk}, {rj}", "atomic"),
        ("amadd_db_h", "FAM3", "00111000010111111...............", f_la64(), "amadd_db.h {rd}, {rk}, {rj}", "atomic"),

        // AM*.W/D（交換・加算・論理・最大最小）。Ref: §2.2.7.1.
        ("amswap_w", "FR3", "00111000011000000...............", f_la64(), "amswap.w {rd}, {rj}, {rk}", "atomic"),
        ("amswap_d", "FR3", "00111000011000001...............", f_la64(), "amswap.d {rd}, {rj}, {rk}", "atomic"),
        ("amadd_w", "FR3", "00111000011000010...............", f_la64(), "amadd.w {rd}, {rj}, {rk}", "atomic"),
        ("amadd_d", "FR3", "00111000011000011...............", f_la64(), "amadd.d {rd}, {rj}, {rk}", "atomic"),
        ("amand_w", "FR3", "00111000011000100...............", f_la64(), "amand.w {rd}, {rj}, {rk}", "atomic"),
        ("amand_d", "FR3", "00111000011000101...............", f_la64(), "amand.d {rd}, {rj}, {rk}", "atomic"),
        ("amor_w", "FR3", "00111000011000110...............", f_la64(), "amor.w {rd}, {rj}, {rk}", "atomic"),
        ("amor_d", "FR3", "00111000011000111...............", f_la64(), "amor.d {rd}, {rj}, {rk}", "atomic"),
        ("amxor_w", "FR3", "00111000011001000...............", f_la64(), "amxor.w {rd}, {rj}, {rk}", "atomic"),
        ("amxor_d", "FR3", "00111000011001001...............", f_la64(), "amxor.d {rd}, {rj}, {rk}", "atomic"),
        ("ammax_w", "FR3", "00111000011001010...............", f_la64(), "ammax.w {rd}, {rj}, {rk}", "atomic"),
        ("ammax_d", "FR3", "00111000011001011...............", f_la64(), "ammax.d {rd}, {rj}, {rk}", "atomic"),
        ("ammin_w", "FR3", "00111000011001100...............", f_la64(), "ammin.w {rd}, {rj}, {rk}", "atomic"),
        ("ammin_d", "FR3", "00111000011001101...............", f_la64(), "ammin.d {rd}, {rj}, {rk}", "atomic"),
        ("ammax_wu", "FR3", "00111000011001110...............", f_la64(), "ammax.wu {rd}, {rj}, {rk}", "atomic"),
        ("ammax_du", "FR3", "00111000011001111...............", f_la64(), "ammax.du {rd}, {rj}, {rk}", "atomic"),
        ("ammin_wu", "FR3", "00111000011010000...............", f_la64(), "ammin.wu {rd}, {rj}, {rk}", "atomic"),
        ("ammin_du", "FR3", "00111000011010001...............", f_la64(), "ammin.du {rd}, {rj}, {rk}", "atomic"),
        ("amswap_db_w", "FR3", "00111000011010010...............", f_la64(), "amswap_db.w {rd}, {rj}, {rk}", "atomic"),
        ("amswap_db_d", "FR3", "00111000011010011...............", f_la64(), "amswap_db.d {rd}, {rj}, {rk}", "atomic"),
        ("amadd_db_w", "FR3", "00111000011010100...............", f_la64(), "amadd_db.w {rd}, {rj}, {rk}", "atomic"),
        ("amadd_db_d", "FR3", "00111000011010101...............", f_la64(), "amadd_db.d {rd}, {rj}, {rk}", "atomic"),
        ("amand_db_w", "FR3", "00111000011010110...............", f_la64(), "amand_db.w {rd}, {rj}, {rk}", "atomic"),
        ("amand_db_d", "FR3", "00111000011010111...............", f_la64(), "amand_db.d {rd}, {rj}, {rk}", "atomic"),
        ("amor_db_w", "FR3", "00111000011011000...............", f_la64(), "amor_db.w {rd}, {rj}, {rk}", "atomic"),
        ("amor_db_d", "FR3", "00111000011011001...............", f_la64(), "amor_db.d {rd}, {rj}, {rk}", "atomic"),
        ("amxor_db_w", "FR3", "00111000011011010...............", f_la64(), "amxor_db.w {rd}, {rj}, {rk}", "atomic"),
        ("amxor_db_d", "FR3", "00111000011011011...............", f_la64(), "amxor_db.d {rd}, {rj}, {rk}", "atomic"),
        ("ammax_db_w", "FR3", "00111000011011100...............", f_la64(), "ammax_db.w {rd}, {rj}, {rk}", "atomic"),
        ("ammax_db_d", "FR3", "00111000011011101...............", f_la64(), "ammax_db.d {rd}, {rj}, {rk}", "atomic"),
        ("ammin_db_w", "FR3", "00111000011011110...............", f_la64(), "ammin_db.w {rd}, {rj}, {rk}", "atomic"),
        ("ammin_db_d", "FR3", "00111000011011111...............", f_la64(), "ammin_db.d {rd}, {rj}, {rk}", "atomic"),
        ("ammax_db_wu", "FR3", "00111000011100000...............", f_la64(), "ammax_db.wu {rd}, {rj}, {rk}", "atomic"),
        ("ammax_db_du", "FR3", "00111000011100001...............", f_la64(), "ammax_db.du {rd}, {rj}, {rk}", "atomic"),
        ("ammin_db_wu", "FR3", "00111000011100010...............", f_la64(), "ammin_db.wu {rd}, {rj}, {rk}", "atomic"),
        ("ammin_db_du", "FR3", "00111000011100011...............", f_la64(), "ammin_db.du {rd}, {rj}, {rk}", "atomic"),

        // バリア。Ref: §2.2.8.
        ("dbar", "FHINT15", "00111000011100100...............", base(), "dbar {hint}", "system"),
        ("ibar", "FHINT15", "00111000011100101...............", base(), "ibar {hint}", "system"),

        // GT/LE のアドレス空間アクセス。Ref: §2.2.6.4, §3.4.3.
        ("fldgt_s", "FR3F", "00111000011101000...............", f_la64(), "fldgt.s {fd}, {rj}, {rk}", "load"),
        ("fldgt_d", "FR3F", "00111000011101001...............", f_la64(), "fldgt.d {fd}, {rj}, {rk}", "load"),
        ("fldle_s", "FR3F", "00111000011101010...............", f_la64(), "fldle.s {fd}, {rj}, {rk}", "load"),
        ("fldle_d", "FR3F", "00111000011101011...............", f_la64(), "fldle.d {fd}, {rj}, {rk}", "load"),
        ("fstgt_s", "FR3F", "00111000011101100...............", f_la64(), "fstgt.s {fd}, {rj}, {rk}", "store"),
        ("fstgt_d", "FR3F", "00111000011101101...............", f_la64(), "fstgt.d {fd}, {rj}, {rk}", "store"),
        ("fstle_s", "FR3F", "00111000011101110...............", f_la64(), "fstle.s {fd}, {rj}, {rk}", "store"),
        ("fstle_d", "FR3F", "00111000011101111...............", f_la64(), "fstle.d {fd}, {rj}, {rk}", "store"),
        ("ldgt_b", "FR3", "00111000011110000...............", f_la64(), "ldgt.b {rd}, {rj}, {rk}", "atomic"),
        ("ldgt_h", "FR3", "00111000011110001...............", f_la64(), "ldgt.h {rd}, {rj}, {rk}", "atomic"),
        ("ldgt_w", "FR3", "00111000011110010...............", f_la64(), "ldgt.w {rd}, {rj}, {rk}", "atomic"),
        ("ldgt_d", "FR3", "00111000011110011...............", f_la64(), "ldgt.d {rd}, {rj}, {rk}", "atomic"),
        ("ldle_b", "FR3", "00111000011110100...............", f_la64(), "ldle.b {rd}, {rj}, {rk}", "atomic"),
        ("ldle_h", "FR3", "00111000011110101...............", f_la64(), "ldle.h {rd}, {rj}, {rk}", "atomic"),
        ("ldle_w", "FR3", "00111000011110110...............", f_la64(), "ldle.w {rd}, {rj}, {rk}", "atomic"),
        ("ldle_d", "FR3", "00111000011110111...............", f_la64(), "ldle.d {rd}, {rj}, {rk}", "atomic"),
        ("stgt_b", "FR3", "00111000011111000...............", f_la64(), "stgt.b {rd}, {rj}, {rk}", "store"),
        ("stgt_h", "FR3", "00111000011111001...............", f_la64(), "stgt.h {rd}, {rj}, {rk}", "store"),
        ("stgt_w", "FR3", "00111000011111010...............", f_la64(), "stgt.w {rd}, {rj}, {rk}", "store"),
        ("stgt_d", "FR3", "00111000011111011...............", f_la64(), "stgt.d {rd}, {rj}, {rk}", "store"),
        ("stle_b", "FR3", "00111000011111100...............", f_la64(), "stle.b {rd}, {rj}, {rk}", "store"),
        ("stle_h", "FR3", "00111000011111101...............", f_la64(), "stle.h {rd}, {rj}, {rk}", "store"),
        ("stle_w", "FR3", "00111000011111110...............", f_la64(), "stle.w {rd}, {rj}, {rk}", "store"),
        ("stle_d", "FR3", "00111000011111111...............", f_la64(), "stle.d {rd}, {rj}, {rk}", "store"),

        // 分岐（BEQZ/BNEZ・BCEQZ/BCNEZ・JIRL・B/BL・
        // BEQ/BNE/BLT/BGE/BLTU/BGEU）。Ref: §2.2.4, §3.4.7.
        ("beqz", "FBEQZ", "010000..........................", base(), "beqz {rj}, {offs}", "branch"),
        ("bnez", "FBEQZ", "010001..........................", base(), "bnez {rj}, {offs}", "branch"),
        ("bceqz", "FBCEZ", "010010................00........", base(), "bceqz {cj}, {offs}", "branch"),
        ("bcnez", "FBCEZ", "010010................01........", base(), "bcnez {cj}, {offs}", "branch"),
        ("jirl", "FJIRL", "010011..........................", base(), "jirl {rd}, {rj}, {offs}", "branch"),
        ("b", "FB", "010100..........................", base(), "b {offs}", "branch"),
        ("bl", "FB", "010101..........................", base(), "bl {offs}", "branch"),
        ("beq", "FBCOND", "010110..........................", base(), "beq {rj}, {rd}, {offs}", "branch"),
        ("bne", "FBCOND", "010111..........................", base(), "bne {rj}, {rd}, {offs}", "branch"),
        ("blt", "FBCOND", "011000..........................", base(), "blt {rj}, {rd}, {offs}", "branch"),
        ("bge", "FBCOND", "011001..........................", base(), "bge {rj}, {rd}, {offs}", "branch"),
        ("bltu", "FBCOND", "011010..........................", base(), "bltu {rj}, {rd}, {offs}", "branch"),
        ("bgeu", "FBCOND", "011011..........................", base(), "bgeu {rj}, {rd}, {offs}", "branch"),

    ] {
        m.insns.push(ins(name, format, pattern, when, syntax, timing));
    }

    // ---- LSX の部分集合（LA13）。Alpine 3.24 の musl/BusyBox が
    // 実際に実行する命令に限定して実装する。完全な LSX 語彙は
    // 膨大なため、ここにない LSX 命令は未実装エラーとして
    // 可視化する（宣言のみの語彙テーブルは持たない）。
    // Ref: SPEC-LOONGARCH-RM Vol.2（LSX）, Appendix B.
    for (name, format, pattern, when, syntax, timing) in [
        // ベクトル load/store。
        ("vld", "FVLD", "0010110000......................", f_lsx(), "vld {vd}, {rj}, {si12}", "alu"),
        ("vst", "FVLD", "0010110001......................", f_lsx(), "vst {vd}, {rj}, {si12}", "alu"),
        ("vldx", "FVLDX", "00111000110100000...............", f_lsx(), "vldx {vd}, {rj}, {rk}", "alu"),
        ("vstx", "FVLDX", "00111000110100010...............", f_lsx(), "vstx {vd}, {rj}, {rk}", "alu"),
        // 要素幅でスケール済みオフセットの全要素複写 load（.d のみ）。
        ("vldrepl_d", "FVLDREPL", "0011000000010...................", f_lsx(), "vldrepl.d {vd}, {rj}, {si9}", "alu"),
        // 汎用レジスタの全要素複写。
        ("vreplgr2vr_w", "FVRG2", "0111001010011111000010..........", f_lsx(), "vreplgr2vr.w {vd}, {rj}", "alu"),
        ("vreplgr2vr_d", "FVRG2", "0111001010011111000011..........", f_lsx(), "vreplgr2vr.d {vd}, {rj}", "alu"),
        // 要素 ⇔ 汎用レジスタの転送。
        ("vpickve2gr_w", "FVPICK2", "01110010111011111110............", f_lsx(), "vpickve2gr.w {rd}, {vj}, {vidx2}", "alu"),
        ("vpickve2gr_du", "FVPICK1", "011100101111001111110...........", f_lsx(), "vpickve2gr.du {rd}, {vj}, {vidx1}", "alu"),
        ("vinsgr2vr_w", "FVINS2", "01110010111010111110............", f_lsx(), "vinsgr2vr.w {vd}, {rj}, {vidx2}", "alu"),
        // 要素ごとの popcount と全要素非零判定（FCC への書き出し）。
        ("vpcnt_w", "FV2R", "0111001010011100001010..........", f_lsx(), "vpcnt.w {vd}, {vj}", "alu"),
        ("vsetnez_v", "FVCD", "0111001010011100100111..........", f_lsx(), "vsetnez.v {cd}, {vj}", "alu"),
        // 要素シフト。
        ("vsrli_w", "FVUI5", "01110011001100001...............", f_lsx(), "vsrli.w {vd}, {vj}, {ui5}", "alu"),
        ("vslli_w", "FVUI5", "01110011001011001...............", f_lsx(), "vslli.w {vd}, {vj}, {ui5}", "alu"),
        // シャッフル・インタリーブ・拡張。
        ("vshuf_w", "FV3R", "01110001011110110...............", f_lsx(), "vshuf.w {vd}, {vj}, {vk}", "alu"),
        ("vshuf_b", "FV4R", "000011010101....................", f_lsx(), "vshuf.b {vd}, {vj}, {vk}, {va}", "alu"),
        ("vshuf4i_b", "FVSHUF4I", "01110011100100..................", f_lsx(), "vshuf4i.b {vd}, {vj}, {imm8}", "alu"),
        ("vilvl_b", "FV3R", "01110001000110100...............", f_lsx(), "vilvl.b {vd}, {vj}, {vk}", "alu"),
        ("vilvl_h", "FV3R", "01110001000110101...............", f_lsx(), "vilvl.h {vd}, {vj}, {vk}", "alu"),
        ("vexth_wu_hu", "FV2R", "0111001010011110111101..........", f_lsx(), "vexth.wu.hu {vd}, {vj}", "alu"),
        ("vexth_hu_bu", "FV2R", "0111001010011110111100..........", f_lsx(), "vexth.hu.bu {vd}, {vj}", "alu"),
        // ビット反転＋回転・要素即値・パターン即値ロード。
        ("vbitrevi_d", "FVUI6", "0111001100011001................", f_lsx(), "vbitrevi.d {vd}, {vj}, {ui6}", "alu"),
        ("vsubi_du", "FVUI5", "01110010100011011...............", f_lsx(), "vsubi.du {vd}, {vj}, {ui5}", "alu"),
        ("vldi", "FVLDI", "01110011111000..................", f_lsx(), "vldi {vd}, {si13}", "alu"),
        // 要素演算（.d/.w 中心の最小集合）。
        ("vseq_w", "FV3R", "01110000000000010...............", f_lsx(), "vseq.w {vd}, {vj}, {vk}", "alu"),
        ("vadd_d", "FV3R", "01110000000010111...............", f_lsx(), "vadd.d {vd}, {vj}, {vk}", "alu"),
        ("vsub_d", "FV3R", "01110000000011011...............", f_lsx(), "vsub.d {vd}, {vj}, {vk}", "alu"),
        // 128 ビット幅の bitwise。
        ("vxor_v", "FV3R", "01110001001001110...............", f_lsx(), "vxor.v {vd}, {vj}, {vk}", "alu"),
        ("vor_v", "FV3R", "01110001001001101...............", f_lsx(), "vor.v {vd}, {vj}, {vk}", "alu"),
        ("vand_v", "FV3R", "01110001001001100...............", f_lsx(), "vand.v {vd}, {vj}, {vk}", "alu"),
        ("vnor_v", "FV3R", "01110001001001111...............", f_lsx(), "vnor.v {vd}, {vj}, {vk}", "alu"),
    ] {
        m.insns.push(ins(name, format, pattern, when, syntax, timing));
    }

    // CSRRD/CSRWR/CSRXCHG は上位 `00000100` と csr 桁・rd 桁を
    // 共有し、rj[9:5] で切り分ける（0: CSRRD、1: CSRWR、それ以外:
    // CSRXCHG）。Ref: SPEC-LOONGARCH-RM §4.1.7, Appendix B.
    for (name, op, rhs, syntax) in [
        ("csrrd", WhereOp::Eq, 0u128, "csrrd {rd}, {csr}"),
        ("csrwr", WhereOp::Eq, 1u128, "csrwr {rd}, {csr}"),
        ("csrxchg", WhereOp::Ne, 0u128, "csrxchg {rd}, {rj}, {csr}"),
    ] {
        let mut i = ins(
            name,
            "FCSR",
            "00000100........................",
            base(),
            syntax,
            "system",
        );
        i.wheres.push(WhereClause {
            field: "rj".to_string(),
            op,
            rhs: WhereRhs::Lit(rhs),
        });
        // CSRXCHG は rj!=0 かつ rj!=1。
        if name == "csrxchg" {
            i.wheres.push(WhereClause {
                field: "rj".to_string(),
                op: WhereOp::Ne,
                rhs: WhereRhs::Lit(1),
            });
        }
        m.insns.push(i);
    }

    m
}
