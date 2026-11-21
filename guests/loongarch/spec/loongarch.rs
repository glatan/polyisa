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

    // アーキテクチャの幅。la32 と la64 は排他。`lsx`/`lasx`/`lbt` は
    // 拡張の宣言のみで、命令の割当ては LA13 で棚卸す。
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
    for (name, parent, add) in [
        ("la32", "", &["la32"][..]),
        ("la264", "la32", &[][..]),
        ("la464", "", &["la64"][..]),
        ("la664", "la464", &[][..]),
    ] {
        m.models.push(ModelDef {
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

    // ---- 骨格語彙（LA2）。LA3 で全語彙に拡張する。
    // Ref: SPEC-LOONGARCH-RM Appendix B.
    for (name, format, pattern, when, syntax, timing) in [
        // 基本算術。
        ("add_w", "FR3", "00000000000100000...............", base(), "add.w {rd}, {rj}, {rk}", "alu"),
        ("add_d", "FR3", "00000000000100001...............", f_la64(), "add.d {rd}, {rj}, {rk}", "alu"),
        ("sub_w", "FR3", "00000000000100010...............", base(), "sub.w {rd}, {rj}, {rk}", "alu"),
        ("sub_d", "FR3", "00000000000100011...............", f_la64(), "sub.d {rd}, {rj}, {rk}", "alu"),
        ("or", "FR3", "00000000000101010...............", base(), "or {rd}, {rj}, {rk}", "alu"),
        ("addi_w", "FSI12", "0000001010......................", base(), "addi.w {rd}, {rj}, {si12}", "alu"),
        ("addi_d", "FSI12", "0000001011......................", f_la64(), "addi.d {rd}, {rj}, {si12}", "alu"),
        ("lu12i_w", "FSI20", "0001010.........................", base(), "lu12i.w {rd}, {si20}", "alu"),
        // load/store。
        ("ld_w", "FSI12", "0010100010......................", base(), "ld.w {rd}, {rj}, {si12}", "load"),
        ("st_w", "FSI12", "0010100110......................", base(), "st.w {rd}, {rj}, {si12}", "store"),
        ("ld_d", "FSI12", "0010100011......................", f_la64(), "ld.d {rd}, {rj}, {si12}", "load"),
        ("st_d", "FSI12", "0010100111......................", f_la64(), "st.d {rd}, {rj}, {si12}", "store"),
        // 分岐。
        ("beq", "FBCOND", "010110..........................", base(), "beq {rj}, {rd}, {offs}", "branch"),
        ("bne", "FBCOND", "010111..........................", base(), "bne {rj}, {rd}, {offs}", "branch"),
        ("b", "FB", "010100..........................", base(), "b {offs}", "branch"),
        ("bl", "FB", "010101..........................", base(), "bl {offs}", "branch"),
        ("jirl", "FJIRL", "010011..........................", base(), "jirl {rd}, {rj}, {offs}", "branch"),
        ("beqz", "FBEQZ", "010000..........................", base(), "beqz {rj}, {offs}", "branch"),
        // システム。
        ("break", "FCODE15", "00000000001010100...............", base(), "break {code}", "system"),
        ("syscall", "FCODE15", "00000000001010110...............", base(), "syscall {code}", "system"),
        ("ertn", "FN0", "00000110010010000011100000000000", base(), "ertn", "system"),
        ("cpucfg", "FR2", "0000000000000000011011..........", base(), "cpucfg {rd}, {rj}", "system"),
        // FP 最小構成。
        ("fadd_s", "FF3", "00000001000000001...............", base(), "fadd.s {fd}, {fj}, {fk}", "fp"),
        ("fadd_d", "FF3", "00000001000000010...............", base(), "fadd.d {fd}, {fj}, {fk}", "fp"),
        ("fmov_s", "FF2", "0000000100010100100101..........", base(), "fmov.s {fd}, {fj}", "fp"),
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
