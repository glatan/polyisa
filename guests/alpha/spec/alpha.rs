// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Alpha AXP の ISADL モデル（段階16）。
//
// 命令語は 32 ビット固定長で、opcode（31-26）の下に形式が決まる。
// OPERATE 系はレジスタ形（bit12=0）と 8 ビットリテラル形
// （bit12=1、桁 20-13 が即値）を併せ持つ。浮動小数点演算の
// function 桁（15-5）の上位 5 ビットは丸めモードとトラップ
// 修飾子であり、命令ごとの宣言ではなくワイルドカードで受けて
// `fpfn` オペランドが意味論に渡す。ただし cvtst 系は修飾子の
// 位置に別の op が埋まるので、同じ fn[5:0] を持つ cvtts とは
// `wheres` で切り分ける。
// 出典は SPEC-ALPHA-ARM である。
// Ref: SPEC-ALPHA-ARM.

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// Alpha の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in [
        "alu", "load", "store", "branch", "jump", "pal", "fp", "misc",
    ] {
        m.timing_classes.push(class.to_string());
    }

    // 命令集合拡張。BWX はバイト/ワードの転送と符号拡張、FIX は
    // 平方根と整数-FP 転送、CIX はカウント、MVI はマルチメディア。
    // ev5/ev56/ev7 は世代固有の追加命令を区別する旗で、後続世代は
    // 先行の旗を含む。
    // Ref: SPEC-ALPHA-ARM.
    for (name, implies) in [
        ("ev5", &[][..]),
        ("ev56", &["ev5"][..]),
        ("ev7", &["ev56"][..]),
        ("bwx", &[][..]),
        ("fix", &[][..]),
        ("cix", &[][..]),
        ("mvi", &[][..]),
    ] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: vec![],
        });
    }

    // CPU モデル。21164PC（PCA56、EV56）が BWX と MVI を、21264
    // （EV6）以降が FIX と CIX を足す（SPEC-ALPHA-ARM Appendix の
    // AMASK 対応）。
    for (name, parent, add) in [
        ("21064", "", &[][..]),
        ("21164", "21064", &["ev5"][..]),
        ("21164pc", "21164", &["ev56", "bwx", "mvi"][..]),
        ("21264", "21164", &["ev56", "bwx", "fix", "cix", "mvi"][..]),
        ("21264a", "21264", &[][..]),
        ("21364", "21264a", &["ev7"][..]),
    ] {
        m.models.push(ModelDef {
        timing: None,
        params: Default::default(),
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: Vec::new(),
            ident: vec![],
        });
    }

    // 整数レジスタ r0-31（r31 は常に 0）と FP レジスタ f0-31。
    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: false,
        prefix: Some("r".to_string()),
    });
    m.regclasses.push(RegClass {
        name: "fpr".to_string(),
        dynamic: false,
        prefix: Some("f".to_string()),
    });

    for (name, hi, lo) in [
        ("ra", 25, 21),
        ("rb", 20, 16),
        ("rc", 4, 0),
        ("fa", 25, 21),
        ("fb", 20, 16),
        ("fc", 4, 0),
        ("lit8", 20, 13),
        ("disp16", 15, 0),
        ("disp21", 20, 0),
        ("hint14", 13, 0),
        ("mfunc", 15, 0),
        ("palfn", 25, 0),
        // FP 演算の function 桁（丸め/トラップ修飾子を含む）。
        ("fpfn", 15, 5),
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
    let fpr = |name: &str, access: Access| Operand {
        name: name.to_string(),
        field: None,
        regclass: Some("fpr".to_string()),
        access,
    };
    let val = |name: &str| Operand {
        name: name.to_string(),
        field: None,
        regclass: None,
        access: Access::Read,
    };
    let fmt = |name: &str, fields: &[&str], operands: Vec<Operand>| Format {
        name: name.to_string(),
        fields: fields.iter().map(|s| s.to_string()).collect(),
        operands,
    };

    // CALL_PAL 形式（opcode=0 + func）。
    m.formats
        .push(fmt("FPAL", &["palfn"], vec![val("palfn")]));
    // 整数分岐（ra を読む。br/bsr だけは戻りアドレスを書く）。
    m.formats.push(fmt(
        "FBRR",
        &["ra", "disp21"],
        vec![gpr("ra", Access::Read), val("disp21")],
    ));
    m.formats.push(fmt(
        "FBRW",
        &["ra", "disp21"],
        vec![gpr("ra", Access::Write), val("disp21")],
    ));
    // FP 分岐（fa を読む）。
    m.formats.push(fmt(
        "FFB",
        &["fa", "disp21"],
        vec![fpr("fa", Access::Read), val("disp21")],
    ));
    // MEMORY 形式（整数 load/store と FP load/store）。
    m.formats.push(fmt(
        "FMLD",
        &["ra", "rb", "disp16"],
        vec![
            gpr("ra", Access::Write),
            gpr("rb", Access::Read),
            val("disp16"),
        ],
    ));
    m.formats.push(fmt(
        "FMST",
        &["ra", "rb", "disp16"],
        vec![
            gpr("ra", Access::Read),
            gpr("rb", Access::Read),
            val("disp16"),
        ],
    ));
    // 条件付き store（ra は格納値であり、成否フラグでも書き戻す）。
    m.formats.push(fmt(
        "FMSTC",
        &["ra", "rb", "disp16"],
        vec![
            gpr("ra", Access::ReadWrite),
            gpr("rb", Access::Read),
            val("disp16"),
        ],
    ));
    m.formats.push(fmt(
        "FFLD",
        &["fa", "rb", "disp16"],
        vec![
            fpr("fa", Access::Write),
            gpr("rb", Access::Read),
            val("disp16"),
        ],
    ));
    m.formats.push(fmt(
        "FFST",
        &["fa", "rb", "disp16"],
        vec![
            fpr("fa", Access::Read),
            gpr("rb", Access::Read),
            val("disp16"),
        ],
    ));
    // JMP 形式（ra 書き込み + rb 読み + 14 ビットヒント）。
    m.formats.push(fmt(
        "FMBR",
        &["ra", "rb", "hint14"],
        vec![
            gpr("ra", Access::Write),
            gpr("rb", Access::Read),
            val("hint14"),
        ],
    ));
    // ret 形式（ra 桁はヒントで、ハードは書き込まない）。
    m.formats.push(fmt(
        "FRET",
        &["rb", "hint14"],
        vec![gpr("rb", Access::Read), val("hint14")],
    ));
    // MISC 形式（opcode 0x18。mb 系はレジスタを使わない）。
    m.formats
        .push(fmt("FMFCN", &["mfunc"], vec![val("mfunc")]));
    // MISC 形式のうち rb を読むもの（fetch/ecb/wh64 系）。
    m.formats.push(fmt(
        "FMFCR",
        &["rb", "mfunc"],
        vec![gpr("rb", Access::Read), val("mfunc")],
    ));
    // MISC 形式のうち ra を書くもの（rpcc/rc/rs）。
    m.formats.push(fmt(
        "FMFCW",
        &["ra", "mfunc"],
        vec![gpr("ra", Access::Write), val("mfunc")],
    ));
    // 整数 OPERATE レジスタ形 / リテラル形。
    m.formats.push(fmt(
        "FOPR",
        &["ra", "rb", "rc"],
        vec![
            gpr("ra", Access::Read),
            gpr("rb", Access::Read),
            gpr("rc", Access::Write),
        ],
    ));
    m.formats.push(fmt(
        "FOPL",
        &["ra", "lit8", "rc"],
        vec![
            gpr("ra", Access::Read),
            val("lit8"),
            gpr("rc", Access::Write),
        ],
    ));
    // 1 入力の整数 OPERATE（ra 桁は符号化上 31 にする約束だが
    // ハードは読まないのでワイルドカードで受ける）。
    m.formats.push(fmt(
        "FOPRZ",
        &["rb", "rc"],
        vec![gpr("rb", Access::Read), gpr("rc", Access::Write)],
    ));
    m.formats.push(fmt(
        "FOPLZ",
        &["lit8", "rc"],
        vec![val("lit8"), gpr("rc", Access::Write)],
    ));
    // implver（リテラル形専用。書き先だけがオペランド）。
    m.formats
        .push(fmt("FIMPV", &["rc"], vec![gpr("rc", Access::Write)]));
    // FP OPERATE 3 項形（修飾子なしの固定 function）。
    m.formats.push(fmt(
        "FFP3",
        &["fa", "fb", "fc"],
        vec![
            fpr("fa", Access::Read),
            fpr("fb", Access::Read),
            fpr("fc", Access::Write),
        ],
    ));
    // FP OPERATE 3 項形（修飾子付き。fpfn で値を渡す）。
    m.formats.push(fmt(
        "FFP3Q",
        &["fa", "fb", "fc", "fpfn"],
        vec![
            fpr("fa", Access::Read),
            fpr("fb", Access::Read),
            fpr("fc", Access::Write),
            val("fpfn"),
        ],
    ));
    // FP OPERATE 2 項形（fa 桁は読まないのでワイルドカード）。
    m.formats.push(fmt(
        "FFP2",
        &["fb", "fc"],
        vec![fpr("fb", Access::Read), fpr("fc", Access::Write)],
    ));
    m.formats.push(fmt(
        "FFP2Q",
        &["fb", "fc", "fpfn"],
        vec![
            fpr("fb", Access::Read),
            fpr("fc", Access::Write),
            val("fpfn"),
        ],
    ));
    // 整数→FP 転送（itofs/itoff/itoft）。
    m.formats.push(fmt(
        "FITF",
        &["ra", "fc"],
        vec![gpr("ra", Access::Read), fpr("fc", Access::Write)],
    ));
    // FP→整数転送（ftois/ftoit）。
    m.formats.push(fmt(
        "FFTI",
        &["fa", "rc"],
        vec![fpr("fa", Access::Read), gpr("rc", Access::Write)],
    ));

    let pred = |feat: &str| -> Pred {
        if feat.is_empty() {
            return Pred::True;
        }
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
    let weq = |v: u128| WhereClause {
        field: "fpfn".to_string(),
        op: WhereOp::Eq,
        rhs: WhereRhs::Lit(v),
    };
    let wne = |v: u128| WhereClause {
        field: "fpfn".to_string(),
        op: WhereOp::Ne,
        rhs: WhereRhs::Lit(v),
    };

    // CALL_PAL と PAL 予約オペコード（0x00/0x19/0x1B/0x1D/0x1E/0x1F）。
    ins(
        "call_pal",
        "FPAL",
        "000000 ..........................",
        "call_pal {palfn}",
        "",
        vec![],
        "pal",
    );
    for (nm, op) in [
        ("pal19", "011001"),
        ("pal1b", "011011"),
        ("pal1d", "011101"),
        ("pal1e", "011110"),
        ("pal1f", "011111"),
    ] {
        ins(
            nm,
            "FPAL",
            &format!("{op} .........................."),
            &format!("{nm} {{palfn}}"),
            "",
            vec![],
            "pal",
        );
    }

    // MEMORY 形式（整数 load）。
    for (nm, op, feat) in [
        ("lda", "001000", ""),
        ("ldah", "001001", ""),
        ("ldbu", "001010", "bwx"),
        ("ldq_u", "001011", ""),
        ("ldwu", "001100", "bwx"),
        ("ldl", "101000", ""),
        ("ldq", "101001", ""),
        ("ldl_l", "101010", ""),
        ("ldq_l", "101011", ""),
    ] {
        ins(
            nm,
            "FMLD",
            &format!("{op} ..... ..... ................"),
            &format!("{nm} {{ra}}, {{disp16}}({{rb}})"),
            feat,
            vec![],
            "load",
        );
    }
    // MEMORY 形式（整数 store）。条件付き store は ra を読み書きする。
    for (nm, op, feat) in [
        ("stw", "001101", "bwx"),
        ("stb", "001110", "bwx"),
        ("stq_u", "001111", ""),
        ("stl", "101100", ""),
        ("stq", "101101", ""),
    ] {
        ins(
            nm,
            "FMST",
            &format!("{op} ..... ..... ................"),
            &format!("{nm} {{ra}}, {{disp16}}({{rb}})"),
            feat,
            vec![],
            "store",
        );
    }
    for (nm, op) in [("stl_c", "101110"), ("stq_c", "101111")] {
        ins(
            nm,
            "FMSTC",
            &format!("{op} ..... ..... ................"),
            &format!("{nm} {{ra}}, {{disp16}}({{rb}})"),
            "",
            vec![],
            "store",
        );
    }
    // MEMORY 形式（FP load/store）。
    for (nm, op) in [
        ("ldf", "100000"),
        ("ldg", "100001"),
        ("lds", "100010"),
        ("ldt", "100011"),
    ] {
        ins(
            nm,
            "FFLD",
            &format!("{op} ..... ..... ................"),
            &format!("{nm} {{fa}}, {{disp16}}({{rb}})"),
            "",
            vec![],
            "load",
        );
    }
    for (nm, op) in [
        ("stf", "100100"),
        ("stg", "100101"),
        ("sts", "100110"),
        ("stt", "100111"),
    ] {
        ins(
            nm,
            "FFST",
            &format!("{op} ..... ..... ................"),
            &format!("{nm} {{fa}}, {{disp16}}({{rb}})"),
            "",
            vec![],
            "store",
        );
    }

    // BRANCH 形式。br/bsr は戻りアドレスを ra に書き、条件分岐は
    // ra（整数）や fa（FP）を読む。
    for (nm, op) in [("br", "110000"), ("bsr", "110100")] {
        ins(
            nm,
            "FBRW",
            &format!("{op} ..... ....................."),
            &format!("{nm} {{ra}}, {{disp21}}"),
            "",
            vec![],
            "branch",
        );
    }
    for (nm, op) in [
        ("blbc", "111000"),
        ("beq", "111001"),
        ("blt", "111010"),
        ("ble", "111011"),
        ("blbs", "111100"),
        ("bne", "111101"),
        ("bge", "111110"),
        ("bgt", "111111"),
    ] {
        ins(
            nm,
            "FBRR",
            &format!("{op} ..... ....................."),
            &format!("{nm} {{ra}}, {{disp21}}"),
            "",
            vec![],
            "branch",
        );
    }
    for (nm, op) in [
        ("fbeq", "110001"),
        ("fblt", "110010"),
        ("fble", "110011"),
        ("fbne", "110101"),
        ("fbge", "110110"),
        ("fbgt", "110111"),
    ] {
        ins(
            nm,
            "FFB",
            &format!("{op} ..... ....................."),
            &format!("{nm} {{fa}}, {{disp21}}"),
            "",
            vec![],
            "branch",
        );
    }

    // JMP 形式（bits15-14 がサブ形式: 00=jmp 01=jsr 11=jcr）。
    for (nm, h) in [("jmp", "00"), ("jsr", "01"), ("jsr_coroutine", "11")] {
        ins(
            nm,
            "FMBR",
            &format!("011010 ..... ..... {h} .............."),
            &format!("{nm} {{ra}}, ({{rb}})"),
            "",
            vec![],
            "jump",
        );
    }
    // ret は ra 桁を書かない（桁の値はリターン予測ヒント）。
    ins(
        "ret",
        "FRET",
        "011010 ..... ..... 10 ..............",
        "ret ({rb}), {hint14}",
        "",
        vec![],
        "jump",
    );

    // MISC 形式（opcode 0x18。function は桁 15-0）。レジスタを
    // 使わないもの・rb を読むもの・ra を書くものに分かれ、wmb は
    // EV5、ecb/wh64 は EV56、wh64en は EV7 の追加である。
    for (nm, f, syntax, feat) in [
        ("trapb", "0000000000000000", "trapb", ""),
        ("excb", "0000010000000000", "excb", ""),
        ("mb", "0100000000000000", "mb", ""),
        ("wmb", "0100010000000000", "wmb", "ev5"),
    ] {
        ins(
            nm,
            "FMFCN",
            &format!("011000 ..... ..... {f}"),
            syntax,
            feat,
            vec![],
            "misc",
        );
    }
    for (nm, f, syntax, feat) in [
        ("fetch", "1000000000000000", "fetch ({rb})", ""),
        ("fetch_m", "1010000000000000", "fetch_m ({rb})", ""),
        ("ecb", "1110100000000000", "ecb ({rb})", "ev56"),
        ("wh64", "1111100000000000", "wh64 ({rb})", "ev56"),
        ("wh64en", "1111110000000000", "wh64en ({rb})", "ev7"),
    ] {
        ins(
            nm,
            "FMFCR",
            &format!("011000 ..... ..... {f}"),
            syntax,
            feat,
            vec![],
            "misc",
        );
    }
    for (nm, f, syntax) in [
        ("rpcc", "1100000000000000", "rpcc {ra}"),
        ("rc", "1110000000000000", "rc {ra}"),
        ("rs", "1111000000000000", "rs {ra}"),
    ] {
        ins(
            nm,
            "FMFCW",
            &format!("011000 ..... ..... {f}"),
            syntax,
            "",
            vec![],
            "misc",
        );
    }

    // 整数 OPERATE。各行はレジスタ形（bit12=0）とリテラル形
    // （bit12=1、桁 20-13 が 8 ビット即値）を並べる。
    for (op, table) in [
        (
            "010000",
            &[
                ("addl", "0000000", ""),
                ("s4addl", "0000010", ""),
                ("subl", "0001001", ""),
                ("s4subl", "0001011", ""),
                ("cmpbge", "0001111", ""),
                ("s8addl", "0010010", ""),
                ("s8subl", "0011011", ""),
                ("cmpult", "0011101", ""),
                ("addq", "0100000", ""),
                ("s4addq", "0100010", ""),
                ("subq", "0101001", ""),
                ("s4subq", "0101011", ""),
                ("cmpeq", "0101101", ""),
                ("s8addq", "0110010", ""),
                ("s8subq", "0111011", ""),
                ("cmpule", "0111101", ""),
                ("addl_v", "1000000", ""),
                ("subl_v", "1001001", ""),
                ("cmplt", "1001101", ""),
                ("addq_v", "1100000", ""),
                ("subq_v", "1101001", ""),
                ("cmple", "1101101", ""),
            ][..],
        ),
        (
            "010001",
            &[
                ("and", "0000000", ""),
                ("bic", "0001000", ""),
                ("cmovlbs", "0010100", ""),
                ("cmovlbc", "0010110", ""),
                ("bis", "0100000", ""),
                ("cmoveq", "0100100", ""),
                ("cmovne", "0100110", ""),
                ("ornot", "0101000", ""),
                ("xor", "1000000", ""),
                ("cmovlt", "1000100", ""),
                ("cmovge", "1000110", ""),
                ("eqv", "1001000", ""),
                ("cmovle", "1100100", ""),
                ("cmovgt", "1100110", ""),
            ][..],
        ),
        (
            "010010",
            &[
                ("mskbl", "0000010", ""),
                ("extbl", "0000110", ""),
                ("insbl", "0001011", ""),
                ("mskwl", "0010010", ""),
                ("extwl", "0010110", ""),
                ("inswl", "0011011", ""),
                ("mskll", "0100010", ""),
                ("extll", "0100110", ""),
                ("insll", "0101011", ""),
                ("zap", "0110000", ""),
                ("zapnot", "0110001", ""),
                ("mskql", "0110010", ""),
                ("srl", "0110100", ""),
                ("extql", "0110110", ""),
                ("sll", "0111001", ""),
                ("insql", "0111011", ""),
                ("sra", "0111100", ""),
                ("mskwh", "1010010", ""),
                ("inswh", "1010111", ""),
                ("extwh", "1011010", ""),
                ("msklh", "1100010", ""),
                ("inslh", "1100111", ""),
                ("extlh", "1101010", ""),
                ("mskqh", "1110010", ""),
                ("insqh", "1110111", ""),
                ("extqh", "1111010", ""),
            ][..],
        ),
        (
            "010011",
            &[
                ("mull", "0000000", ""),
                ("mulq", "0100000", ""),
                ("umulh", "0110000", ""),
                ("mull_v", "1000000", ""),
                ("mulq_v", "1100000", ""),
            ][..],
        ),
    ] {
        for (nm, f, feat) in table {
            ins(
                nm,
                "FOPR",
                &format!("{op} ..... ..... 000 0 {f} ....."),
                &format!("{nm} {{ra}}, {{rb}}, {{rc}}"),
                feat,
                vec![],
                "alu",
            );
            ins(
                &format!("{nm}_i"),
                "FOPL",
                &format!("{op} ..... ........ 1 {f} ....."),
                &format!("{nm} {{ra}}, {{lit8}}, {{rc}}"),
                feat,
                vec![],
                "alu",
            );
        }
    }

    // opcode 0x1C の整数側（拡張機能群）。1 入力形は ra 桁を読まない。
    for (nm, f, feat) in [
        ("sextb", "0000000", "bwx"),
        ("sextw", "0000001", "bwx"),
        ("ctpop", "0110000", "cix"),
        ("ctlz", "0110010", "cix"),
        ("cttz", "0110011", "cix"),
        ("unpkbw", "0110100", "mvi"),
        ("unpkbl", "0110101", "mvi"),
        ("pkwb", "0110110", "mvi"),
        ("pklb", "0110111", "mvi"),
    ] {
        ins(
            nm,
            "FOPRZ",
            &format!("011100 ..... ..... 000 0 {f} ....."),
            &format!("{nm} {{rb}}, {{rc}}"),
            feat,
            vec![],
            "alu",
        );
    }
    // sextb/sextw のリテラル形。ARM §4.6.5 が
    // `SEXTx #b.ib,Rc.wq !Operate format` を明示するので受理する。
    // Ref: SPEC-ALPHA-ARM §4.6.5.
    for (nm, f) in [("sextb", "0000000"), ("sextw", "0000001")] {
        ins(
            &format!("{nm}_i"),
            "FOPLZ",
            &format!("011100 ..... ........ 1 {f} ....."),
            &format!("{nm} {{lit8}}, {{rc}}"),
            "bwx",
            vec![],
            "alu",
        );
    }
    ins(
        "perr",
        "FOPR",
        "011100 ..... ..... 000 0 0110001 .....",
        "perr {ra}, {rb}, {rc}",
        "mvi",
        vec![],
        "alu",
    );
    for (nm, f) in [
        ("minsb8", "0111000"),
        ("minsw4", "0111001"),
        ("minub8", "0111010"),
        ("minuw4", "0111011"),
        ("maxub8", "0111100"),
        ("maxuw4", "0111101"),
        ("maxsb8", "0111110"),
        ("maxsw4", "0111111"),
    ] {
        ins(
            nm,
            "FOPR",
            &format!("011100 ..... ..... 000 0 {f} ....."),
            &format!("{nm} {{ra}}, {{rb}}, {{rc}}"),
            "mvi",
            vec![],
            "alu",
        );
        ins(
            &format!("{nm}_i"),
            "FOPL",
            &format!("011100 ..... ........ 1 {f} ....."),
            &format!("{nm} {{ra}}, {{lit8}}, {{rc}}"),
            "mvi",
            vec![],
            "alu",
        );
    }

    // amask（機能マスクを読む）と implver（実装世代を読む）。
    ins(
        "amask",
        "FOPRZ",
        "010001 ..... ..... 000 0 1100001 .....",
        "amask {rb}, {rc}",
        "",
        vec![],
        "misc",
    );
    ins(
        "amask_i",
        "FOPLZ",
        "010001 ..... ........ 1 1100001 .....",
        "amask {lit8}, {rc}",
        "",
        vec![],
        "misc",
    );
    ins(
        "implver",
        "FIMPV",
        "010001 11111 00000001 1 1101100 .....",
        "implver {rc}",
        "",
        vec![],
        "misc",
    );

    // 浮動小数点 OPERATE。fn[10:6]（丸めモードとトラップ修飾子）は
    // ワイルドカードで受け、fn[5:0] が基本 op。
    for (nm, f) in [
        ("itofs", "00000000100"),
        ("itoff", "00000010100"),
        ("itoft", "00000100100"),
    ] {
        ins(
            nm,
            "FITF",
            &format!("010100 ..... ..... {f} ....."),
            &format!("{nm} {{ra}}, {{fc}}"),
            "fix",
            vec![],
            "fp",
        );
    }
    for (nm, b) in [
        ("sqrtf", "001010"),
        ("sqrts", "001011"),
        ("sqrtg", "101010"),
        ("sqrtt", "101011"),
    ] {
        ins(
            nm,
            "FFP2Q",
            &format!("010100 ..... ..... .....{b} ....."),
            &format!("{nm} {{fb}}, {{fc}}"),
            "fix",
            vec![],
            "fp",
        );
    }
    // VAX 浮動小数点（opcode 0x15）。
    for (nm, b) in [
        ("addf", "000000"),
        ("subf", "000001"),
        ("mulf", "000010"),
        ("divf", "000011"),
        ("addg", "100000"),
        ("subg", "100001"),
        ("mulg", "100010"),
        ("divg", "100011"),
        ("cmpgeq", "100101"),
        ("cmpglt", "100110"),
        ("cmpgle", "100111"),
    ] {
        ins(
            nm,
            "FFP3Q",
            &format!("010101 ..... ..... .....{b} ....."),
            &format!("{nm} {{fa}}, {{fb}}, {{fc}}"),
            "",
            vec![],
            "fp",
        );
    }
    for (nm, b) in [
        ("cvtdg", "011110"),
        ("cvtgf", "101100"),
        ("cvtgd", "101101"),
        ("cvtgq", "101111"),
        ("cvtqf", "111100"),
        ("cvtqg", "111110"),
    ] {
        ins(
            nm,
            "FFP2Q",
            &format!("010101 ..... ..... .....{b} ....."),
            &format!("{nm} {{fb}}, {{fc}}"),
            "",
            vec![],
            "fp",
        );
    }
    // IEEE 浮動小数点（opcode 0x16）。cvtst/cvtst_s は cvtts の
    // 修飾子桁に op が埋まる特別形で、wheres で切り分ける。
    ins(
        "cvtst",
        "FFP2Q",
        "010110 ..... ..... .1010101100 .....",
        "cvtst {fb}, {fc}",
        "",
        vec![weq(0x2AC)],
        "fp",
    );
    ins(
        "cvtst_s",
        "FFP2Q",
        "010110 ..... ..... .1010101100 .....",
        "cvtst/s {fb}, {fc}",
        "",
        vec![weq(0x6AC)],
        "fp",
    );
    for (nm, b) in [
        ("adds", "000000"),
        ("subs", "000001"),
        ("muls", "000010"),
        ("divs", "000011"),
        ("addt", "100000"),
        ("subt", "100001"),
        ("mult", "100010"),
        ("divt", "100011"),
        ("cmptun", "100100"),
        ("cmpteq", "100101"),
        ("cmptlt", "100110"),
        ("cmptle", "100111"),
    ] {
        ins(
            nm,
            "FFP3Q",
            &format!("010110 ..... ..... .....{b} ....."),
            &format!("{nm} {{fa}}, {{fb}}, {{fc}}"),
            "",
            vec![],
            "fp",
        );
    }
    for (nm, b, wheres) in [
        ("cvtts", "101100", vec![wne(0x2AC), wne(0x6AC)]),
        ("cvttq", "101111", vec![]),
        ("cvtqs", "111100", vec![]),
        ("cvtqt", "111110", vec![]),
    ] {
        ins(
            nm,
            "FFP2Q",
            &format!("010110 ..... ..... .....{b} ....."),
            &format!("{nm} {{fb}}, {{fc}}"),
            "",
            wheres,
            "fp",
        );
    }
    // opcode 0x17（修飾子のない FP 演算と fcmov・fpcr 転送）。
    ins(
        "cvtlq",
        "FFP2",
        "010111 ..... ..... 00000010000 .....",
        "cvtlq {fb}, {fc}",
        "",
        vec![],
        "fp",
    );
    for (nm, f) in [
        ("cpys", "00000100000"),
        ("cpysn", "00000100001"),
        ("cpyse", "00000100010"),
        ("mt_fpcr", "00000100100"),
        ("mf_fpcr", "00000100101"),
        ("fcmoveq", "00000101010"),
        ("fcmovne", "00000101011"),
        ("fcmovlt", "00000101100"),
        ("fcmovge", "00000101101"),
        ("fcmovle", "00000101110"),
        ("fcmovgt", "00000101111"),
    ] {
        ins(
            nm,
            "FFP3",
            &format!("010111 ..... ..... {f} ....."),
            &format!("{nm} {{fa}}, {{fb}}, {{fc}}"),
            "",
            vec![],
            "fp",
        );
    }
    ins(
        "cvtql",
        "FFP2Q",
        "010111 ..... ..... .....110000 .....",
        "cvtql {fb}, {fc}",
        "",
        vec![],
        "fp",
    );
    // FP→整数転送（opcode 0x1C の FP 側。FIX 拡張）。
    for (nm, f) in [("ftoit", "00001110000"), ("ftois", "00001111000")] {
        ins(
            nm,
            "FFTI",
            &format!("011100 ..... ..... {f} ....."),
            &format!("{nm} {{fa}}, {{rc}}"),
            "fix",
            vec![],
            "fp",
        );
    }

    m
}
