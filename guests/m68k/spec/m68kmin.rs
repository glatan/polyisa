// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// m68k 最小の ISADL モデル（段階14）。
//
// 宣言する命令は、16ビット固定の実符号化（nop/reset/rts/rtr/rte/illegal）、
// EA フィールドを持つ move/movea/moveq（C1）、算術・比較（C2）、
// 論理・単項（C3）、シフト/ローテート（C4）、ビット操作（C5）、
// 分岐・復帰（C6）、scc/dbcc（C7）、lea/pea/link/unlk（C8）、exg/swap/ext（C9）。
// EA モードの解釈と拡張語の消費は `src/ea.rs`、意味論は `src/sem.rs`。
// 出典は SPEC-M68K-PRM (M68000PM/AD Rev 1) である。
// Ref: SPEC-M68K-PRM (Rev 1).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// m68k 最小の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["misc", "ctrl"] {
        m.timing_classes.push(class.to_string());
    }

    // 世代ごとの命令集合。68010 以降は先行世代の追加で表す。
    // 68040/68060 で OS 補完へ回る命令群は、世代機能の implies からは
    // 除けない（閉包で再付与される）ので、粒状の独立機能か
    // `when` の `!m68040` 形で表す。モデル確定時に決める。
    // Ref: SPEC-M68K-PRM (Rev 1).
    for (name, implies) in [
        ("m68000", &[][..]),
        ("m68010", &["m68000"][..]),
        ("m68020", &["m68010"][..]),
        ("m68030", &["m68020"][..]),
        ("m68040", &["m68030"][..]),
        ("m68060", &["m68040"][..]),
    ] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: vec![],
        });
    }
    for (name, parent, add) in [
        ("generic", "", &["m68000"][..]),
        ("i68000", "generic", &[][..]),
    ] {
        m.models.push(ModelDef {
            params: vec![],
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: Vec::new(),
            ident: vec![],
        });
    }

    m.regclasses.push(RegClass {
        name: "dreg".to_string(),
        dynamic: false,
        prefix: Some("d".to_string()),
    });
    m.regclasses.push(RegClass {
        name: "areg".to_string(),
        dynamic: false,
        prefix: Some("a".to_string()),
    });

    // EA フィールド。source は bits[5:3]/[2:0]、destination は
    // bits[8:6]/[11:9]。値の評価と拡張語消費は ea.rs が担う。
    // Ref: SPEC-M68K-PRM (Rev 1) §Effective Addressing.
    for (name, hi, lo) in [
        ("sreg", 2u32, 0u32),
        ("smode", 5, 3),
        ("dmode", 8, 6),
        ("dreg", 11, 9),
        ("qimm", 7, 0),
        // C2: 算術・比較系のフィールド。emode/ereg は EA、qsz はサイズ。
        // bits 11-9 のクイック即値・cmpm 宛先レジスタは dreg を再利用する。
        ("emode", 5, 3),
        ("ereg", 2, 0),
        ("qsz", 7, 6),
        // C4: シフト系。dir は方向、sop はレジスタ形の i+op（bits5-3）。
        ("dir", 8, 8),
        ("sop", 5, 3),
        // C6: 分岐系。cc は条件コード、disp は 8 ビット変位。
        ("cc", 11, 8),
        ("disp", 7, 0),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    // F0: 16ビット固定・オペランドなし（拡張語も伴わない命令）。
    m.formats.push(Format {
        name: "F0".to_string(),
        fields: vec![],
        operands: vec![],
    });
    // E2: move/movea の2EA形式。
    m.formats.push(Format {
        name: "E2".to_string(),
        fields: vec![
            "sreg".to_string(),
            "smode".to_string(),
            "dmode".to_string(),
            "dreg".to_string(),
        ],
        operands: vec![],
    });
    // Q: moveq のクイック即値形式。
    m.formats.push(Format {
        name: "Q".to_string(),
        fields: vec!["dreg".to_string(), "qimm".to_string()],
        operands: vec![],
    });
    // AE: レジスタ・サイズ・EA（add/sub/cmp 系。方向・宛先 An は
    // パターンの bit8/opm が決める）。
    m.formats.push(Format {
        name: "AE".to_string(),
        fields: vec![
            "dreg".to_string(),
            "qsz".to_string(),
            "emode".to_string(),
            "ereg".to_string(),
        ],
        operands: vec![],
    });
    // QE: クイック即値・サイズ・EA（addq/subq 系）。
    m.formats.push(Format {
        name: "QE".to_string(),
        fields: vec![
            "dreg".to_string(),
            "qsz".to_string(),
            "emode".to_string(),
            "ereg".to_string(),
        ],
        operands: vec![],
    });
    // IE: サイズ・EA（即値系。即値は拡張語が持つ）。
    m.formats.push(Format {
        name: "IE".to_string(),
        fields: vec!["qsz".to_string(), "emode".to_string(), "ereg".to_string()],
        operands: vec![],
    });
    // CM: cmpm のレジスタ2つとサイズ。emode は固定値だが、EOR
    // 宣言時の排他検証に使うので宣言する。
    m.formats.push(Format {
        name: "CM".to_string(),
        fields: vec![
            "dreg".to_string(),
            "qsz".to_string(),
            "emode".to_string(),
            "sreg".to_string(),
        ],
        operands: vec![],
    });
    // SR: レジスタシフト。bits[11:9] はカウント/レジスタ、sop は
    // i(bit5)+op(bits4-3)、ereg は宛先 Dn。
    m.formats.push(Format {
        name: "SR".to_string(),
        fields: vec![
            "dreg".to_string(),
            "dir".to_string(),
            "qsz".to_string(),
            "sop".to_string(),
            "ereg".to_string(),
        ],
        operands: vec![],
    });
    // SM: メモリシフト（word・カウント1固定）。bits[11:9] は演算種別。
    m.formats.push(Format {
        name: "SM".to_string(),
        fields: vec![
            "dreg".to_string(),
            "dir".to_string(),
            "emode".to_string(),
            "ereg".to_string(),
        ],
        operands: vec![],
    });

    // BE: ビット操作。レジスタ形は bits[11:9] がソース Dn、
    // 即値形は拡張語がビット番号で bits[11:8] は 1000 固定。
    m.formats.push(Format {
        name: "BE".to_string(),
        fields: vec!["dreg".to_string(), "emode".to_string(), "ereg".to_string()],
        operands: vec![],
    });
    // BR: 相対分岐。cc は条件（0=T,1=F,2〜15=Bcc）、disp は 8bit
    // 変位（0 は 16bit 拡張語を示す）。
    m.formats.push(Format {
        name: "BR".to_string(),
        fields: vec!["cc".to_string(), "disp".to_string()],
        operands: vec![],
    });
    // JF: jmp/jsr/pea の制御 EA。
    m.formats.push(Format {
        name: "JF".to_string(),
        fields: vec!["emode".to_string(), "ereg".to_string()],
        operands: vec![],
    });
    // SC: scc/dbcc。emode=1 が dbcc（Dn+変位語）の空間。
    m.formats.push(Format {
        name: "SC".to_string(),
        fields: vec!["cc".to_string(), "emode".to_string(), "ereg".to_string()],
        operands: vec![],
    });
    // LF: lea の宛先 An と制御 EA。
    m.formats.push(Format {
        name: "LF".to_string(),
        fields: vec!["dreg".to_string(), "emode".to_string(), "ereg".to_string()],
        operands: vec![],
    });
    // LK: link/unlk の対象 An、swap/ext の対象 Dn。
    m.formats.push(Format {
        name: "LK".to_string(),
        fields: vec!["ereg".to_string()],
        operands: vec![],
    });
    // XG: exg の2レジスタ。
    m.formats.push(Format {
        name: "XG".to_string(),
        fields: vec!["dreg".to_string(), "ereg".to_string()],
        operands: vec![],
    });

    // (名前, パターン, 構文, 分類)
    // いずれも拡張語を伴わない16ビット固定の実符号化。
    // Ref: SPEC-M68K-PRM (Rev 1).
    let insns: &[(&str, &str, &str, &str)] = &[
        ("nop", "0100111001110001", "nop", "misc"),
        ("reset", "0100111001110000", "reset", "ctrl"),
        ("rte", "0100111001110011", "rte", "ctrl"),
        ("rts", "0100111001110101", "rts", "ctrl"),
        ("rtr", "0100111001110111", "rtr", "ctrl"),
    ];
    for (name, pattern, syntax, timing) in insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: "F0".to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: vec![],
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }
    // illegal の符号化は tst のパターン空間（`..` が bits[7:6]=11 を
    // 含む）に内包される。qsz（bits[7:6]）が 3 であることを where で
    // 示して tst（qsz != 3）との排他を証明する。
    m.insns.push(Insn {
        name: "illegal".to_string(),
        format: "F0".to_string(),
        pattern: Pattern::parse("0100101011111100").expect("valid pattern"),
        when: Pred::True,
        wheres: vec![WhereClause {
            field: "qsz".to_string(),
            op: WhereOp::Eq,
            rhs: WhereRhs::Lit(3),
        }],
        syntax: "illegal".to_string(),
        timing: "misc".to_string(),
    });

    // movea は move.w/move.l の宛先 An 直と同じ符号化を持つので、
    // where で dmode==1（An 直）を宣言して排他を示す。move.b は
    // byte の An 直が未割当なので source/destination 両方で An を
    // 弾く。Ref: SPEC-M68K-PRM (Rev 1) §MOVE/MOVEA.
    type Cond = (&'static str, WhereOp, u128);
    type EaDecl = (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static [Cond],
    );
    let ea_insns: &[EaDecl] = &[
        (
            "movea_l",
            "E2",
            "0010 ... 001 ......",
            "movea.l",
            &[("dmode", WhereOp::Eq, 1)],
        ),
        (
            "movea_w",
            "E2",
            "0011 ... 001 ......",
            "movea.w",
            &[("dmode", WhereOp::Eq, 1)],
        ),
        (
            "move_b",
            "E2",
            "0001 ............",
            "move.b",
            &[("dmode", WhereOp::Ne, 1), ("smode", WhereOp::Ne, 1)],
        ),
        (
            "move_w",
            "E2",
            "0011 ............",
            "move.w",
            &[("dmode", WhereOp::Ne, 1)],
        ),
        (
            "move_l",
            "E2",
            "0010 ............",
            "move.l",
            &[("dmode", WhereOp::Ne, 1)],
        ),
    ];
    for (name, format, pattern, syntax, wheres) in ea_insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: wheres
                .iter()
                .map(|(field, op, rhs)| WhereClause {
                    field: field.to_string(),
                    op: *op,
                    rhs: WhereRhs::Lit(*rhs),
                })
                .collect(),
            syntax: syntax.to_string(),
            timing: "misc".to_string(),
        });
    }
    // C2: 算術・比較系。opm（bits[8:6]、bit8+qsz）が方向・サイズ・
    // An 宛てを決める。bit8=1 の空間は ADDX（emode 0/1）・
    // ADDA.L（opm 7）と分かれるので、*_dn は emode/qsz を where で
    // 弾き、*_a_l は qsz==3 を where で示す（将来の ADDX 宣言との
    // 排他検証のため）。addq/subq の qsz==3 は Scc/DBcc の空間。
    // Ref: SPEC-M68K-PRM (Rev 1) §ADD/SUB/CMP.
    let arith: &[EaDecl] = &[
        ("add", "AE", "1101 ... 0 .. ......", "add", &[]),
        (
            "add_dn",
            "AE",
            "1101 ... 1 .. ......",
            "add",
            &[("emode", WhereOp::Ne, 0), ("emode", WhereOp::Ne, 1), ("qsz", WhereOp::Ne, 3)],
        ),
        (
            "adda_l",
            "AE",
            "1101 ... 111 ......",
            "adda.l",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        ("sub", "AE", "1001 ... 0 .. ......", "sub", &[]),
        (
            "sub_dn",
            "AE",
            "1001 ... 1 .. ......",
            "sub",
            &[("emode", WhereOp::Ne, 0), ("emode", WhereOp::Ne, 1), ("qsz", WhereOp::Ne, 3)],
        ),
        (
            "suba_l",
            "AE",
            "1001 ... 111 ......",
            "suba.l",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        ("cmp", "AE", "1011 ... 0 .. ......", "cmp", &[]),
        (
            "cmpa_l",
            "AE",
            "1011 ... 111 ......",
            "cmpa.l",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        (
            "cmpm",
            "CM",
            "1011 ... 1 .. 001 ...",
            "cmpm",
            &[("qsz", WhereOp::Ne, 3), ("emode", WhereOp::Eq, 1)],
        ),
        (
            "addq",
            "QE",
            "0101 ... 0 .. ......",
            "addq",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        (
            "subq",
            "QE",
            "0101 ... 1 .. ......",
            "subq",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        (
            "addi",
            "IE",
            "0000 0110 .. ......",
            "addi",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        (
            "subi",
            "IE",
            "0000 0100 .. ......",
            "subi",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        (
            "cmpi",
            "IE",
            "0000 1100 .. ......",
            "cmpi",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        // C3: 論理系。or/and の Dn→ea 方向はサイズごとに別宣言:
        // or.b は SBCD（emode 0 と 1 の両方を占める）の空間を、
        // or.w/l は An 直のみ避ける。and.b は ABCD、and.w/l は EXG
        // （それぞれ emode 0/1）を避ける。eor は cmpm・cmpa と
        // 排他になるよう emode/qsz で絞る。
        // Ref: SPEC-M68K-PRM (Rev 1) §OR/AND/EOR.
        ("or", "AE", "1000 ... 0 .. ......", "or", &[("qsz", WhereOp::Ne, 3)]),
        (
            "or_b_dn",
            "AE",
            "1000 ... 1 00 ......",
            "or",
            &[("emode", WhereOp::Ne, 0), ("emode", WhereOp::Ne, 1)],
        ),
        (
            "or_w_dn",
            "AE",
            "1000 ... 1 01 ......",
            "or",
            &[("emode", WhereOp::Ne, 1)],
        ),
        (
            "or_l_dn",
            "AE",
            "1000 ... 1 10 ......",
            "or",
            &[("emode", WhereOp::Ne, 1)],
        ),
        (
            "and",
            "AE",
            "1100 ... 0 .. ......",
            "and",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        (
            "and_b_dn",
            "AE",
            "1100 ... 1 00 ......",
            "and",
            &[("emode", WhereOp::Ne, 0), ("emode", WhereOp::Ne, 1)],
        ),
        (
            "and_w_dn",
            "AE",
            "1100 ... 1 01 ......",
            "and",
            &[("emode", WhereOp::Ne, 0), ("emode", WhereOp::Ne, 1)],
        ),
        (
            "and_l_dn",
            "AE",
            "1100 ... 1 10 ......",
            "and",
            &[("emode", WhereOp::Ne, 1)],
        ),
        (
            "eor",
            "AE",
            "1011 ... 1 .. ......",
            "eor",
            &[("qsz", WhereOp::Ne, 3), ("emode", WhereOp::Ne, 1)],
        ),
        // 即値論理系。EA フィールドが #imm（emode7 ereg4）のとき
        // to CCR/to SR の特殊符号化になる（意味論側で振り分け）。
        ("ori", "IE", "0000 0000 .. ......", "ori", &[("qsz", WhereOp::Ne, 3)]),
        (
            "andi",
            "IE",
            "0000 0010 .. ......",
            "andi",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        (
            "eori",
            "IE",
            "0000 1010 .. ......",
            "eori",
            &[("qsz", WhereOp::Ne, 3)],
        ),
        // 単項系。qsz=3 は tas・move to/from sr の空間として残す。
        ("not", "IE", "0100 0110 .. ......", "not", &[("qsz", WhereOp::Ne, 3)]),
        ("clr", "IE", "0100 0010 .. ......", "clr", &[("qsz", WhereOp::Ne, 3)]),
        ("tst", "IE", "0100 1010 .. ......", "tst", &[("qsz", WhereOp::Ne, 3)]),
        // C4: シフト/ローテート。レジスタ形は qsz!=3（qsz=3 はメモリ
        // 形の空間）。メモリ形は bits[11:9] が演算種別・bit8 が方向・
        // word・カウント1固定。
        // Ref: SPEC-M68K-PRM (Rev 1) §ASL/ASR/LSL/LSR/ROL/ROR/ROXL/ROXR.
        ("asr", "SR", "1110 ... 0 .. .00 ...", "asr", &[("qsz", WhereOp::Ne, 3)]),
        ("asl", "SR", "1110 ... 1 .. .00 ...", "asl", &[("qsz", WhereOp::Ne, 3)]),
        ("lsr", "SR", "1110 ... 0 .. .01 ...", "lsr", &[("qsz", WhereOp::Ne, 3)]),
        ("lsl", "SR", "1110 ... 1 .. .01 ...", "lsl", &[("qsz", WhereOp::Ne, 3)]),
        ("roxr", "SR", "1110 ... 0 .. .10 ...", "roxr", &[("qsz", WhereOp::Ne, 3)]),
        ("roxl", "SR", "1110 ... 1 .. .10 ...", "roxl", &[("qsz", WhereOp::Ne, 3)]),
        ("ror", "SR", "1110 ... 0 .. .11 ...", "ror", &[("qsz", WhereOp::Ne, 3)]),
        ("rol", "SR", "1110 ... 1 .. .11 ...", "rol", &[("qsz", WhereOp::Ne, 3)]),
        (
            "asr_m",
            "SM",
            "1110 000 0 11 ......",
            "asr",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        (
            "asl_m",
            "SM",
            "1110 000 1 11 ......",
            "asl",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        (
            "lsr_m",
            "SM",
            "1110 001 0 11 ......",
            "lsr",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        (
            "lsl_m",
            "SM",
            "1110 001 1 11 ......",
            "lsl",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        (
            "roxr_m",
            "SM",
            "1110 010 0 11 ......",
            "roxr",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        (
            "roxl_m",
            "SM",
            "1110 010 1 11 ......",
            "roxl",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        (
            "ror_m",
            "SM",
            "1110 011 0 11 ......",
            "ror",
            &[("qsz", WhereOp::Eq, 3)],
        ),
        (
            "rol_m",
            "SM",
            "1110 011 1 11 ......",
            "rol",
            &[("qsz", WhereOp::Eq, 3)],
        ),

        // C5: ビット操作。レジスタ形は bit8=1 + op(bits7-6)、emode=1
        // は MOVEP の空間として残す。即値形は 0000 1000 + op で
        // 拡張語がビット番号。
        // Ref: SPEC-M68K-PRM (Rev 1) §BTST/BCHG/BCLR/BSET.
        (
            "btst",
            "BE",
            "0000 ... 1 00 ......",
            "btst",
            &[("emode", WhereOp::Ne, 1)],
        ),
        (
            "bchg",
            "BE",
            "0000 ... 1 01 ......",
            "bchg",
            &[("emode", WhereOp::Ne, 1)],
        ),
        (
            "bclr",
            "BE",
            "0000 ... 1 10 ......",
            "bclr",
            &[("emode", WhereOp::Ne, 1)],
        ),
        (
            "bset",
            "BE",
            "0000 ... 1 11 ......",
            "bset",
            &[("emode", WhereOp::Ne, 1)],
        ),
        ("btst_i", "BE", "0000 1000 00 ......", "btst", &[]),
        ("bchg_i", "BE", "0000 1000 01 ......", "bchg", &[]),
        ("bclr_i", "BE", "0000 1000 10 ......", "bclr", &[]),
        ("bset_i", "BE", "0000 1000 11 ......", "bset", &[]),
        // C6: 分岐。disp8=0 は 16bit 変位の拡張語を読む（0xFF は
        // byte 変位 -1。32bit 変位は 020 以降）。jmp/jsr の EA は
        // 制御モードのみ。
        // Ref: SPEC-M68K-PRM (Rev 1) §BRA/BSR/Bcc/JMP/JSR.
        ("bra", "BR", "0110 0000 ........", "bra", &[("cc", WhereOp::Eq, 0)]),
        ("bsr", "BR", "0110 0001 ........", "bsr", &[("cc", WhereOp::Eq, 1)]),
        (
            "bcc",
            "BR",
            "0110 .... ........",
            "bcc",
            &[("cc", WhereOp::Ne, 0), ("cc", WhereOp::Ne, 1)],
        ),
        ("jmp", "JF", "0100 1110 11 ......", "jmp", &[]),
        ("jsr", "JF", "0100 1110 10 ......", "jsr", &[]),
        // C7: scc/dbcc。scc は emode!=1（emode=1 が dbcc の空間）。
        // Ref: SPEC-M68K-PRM (Rev 1) §Scc/DBcc.
        (
            "scc",
            "SC",
            "0101 .... 11 ......",
            "scc",
            &[("emode", WhereOp::Ne, 1), ("qsz", WhereOp::Eq, 3)],
        ),
        (
            "dbcc",
            "SC",
            "0101 .... 11 001 ...",
            "dbcc",
            &[("emode", WhereOp::Eq, 1), ("qsz", WhereOp::Eq, 3)],
        ),
         // C8: 制御 EA → An / スタックフレーム。
        // lea: 0100 rrr 1 11 ea。pea: 0100 1000 01 ea。
        // pea の emode=0 は swap（0100 1000 0100 0ddd、C9）の空間。
        // emode=1（0x4848-4F）は 68000 では illegal で pea→ベクタ4 が
        // 実機と一致するので残す。
        // Ref: SPEC-M68K-PRM (Rev 1) §LEA/PEA/LINK/UNLK.
        ("lea", "LF", "0100 ... 1 11 ......", "lea", &[]),
        (
            "pea",
            "JF",
            "0100 1000 01 ......",
            "pea",
            &[("emode", WhereOp::Ne, 0)],
        ),
        ("link", "LK", "0100 1110 0101 0...", "link", &[]),
        ("unlk", "LK", "0100 1110 0101 1...", "unlk", &[]),
         // C9: 交換・拡張。
        // exg は and.w/l dn→ea が予約した空間（dd/aa は qsz=1 の
        // emode 0/1、da は qsz=2 の emode=1）。
        // Ref: SPEC-M68K-PRM (Rev 1) §EXG/SWAP/EXT.
        (
            "exg_dd",
            "XG",
            "1100 ... 1 0100 0...",
            "exg",
            &[("emode", WhereOp::Eq, 0)],
        ),
        (
            "exg_aa",
            "XG",
            "1100 ... 1 0100 1...",
            "exg",
            &[("emode", WhereOp::Eq, 1)],
        ),
        (
            "exg_da",
            "XG",
            "1100 ... 1 1000 1...",
            "exg",
            &[("emode", WhereOp::Eq, 1)],
        ),
        // swap は pea が予約した emode=0（0100 1000 0100 0ddd）。
        (
            "swap",
            "LK",
            "0100 1000 0100 0...",
            "swap",
            &[("emode", WhereOp::Eq, 0)],
        ),
        // ext.w/ext.l は 0100 1000 1x 空間の emode=0
        // （残りは movem、C10）。
        (
            "ext_w",
            "LK",
            "0100 1000 1000 0...",
            "ext",
            &[("emode", WhereOp::Eq, 0)],
        ),
        (
            "ext_l",
            "LK",
            "0100 1000 1100 0...",
            "ext",
            &[("emode", WhereOp::Eq, 0)],
        ),
    ];
    for (name, format, pattern, syntax, wheres) in arith {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: wheres
                .iter()
                .map(|(field, op, rhs)| WhereClause {
                    field: field.to_string(),
                    op: *op,
                    rhs: WhereRhs::Lit(*rhs),
                })
                .collect(),
            syntax: syntax.to_string(),
            // 分岐系は ctrl、それ以外は misc（サイクルモデルは S14-2）。
            timing: if matches!(*name, "bra" | "bsr" | "bcc" | "dbcc" | "jmp" | "jsr") {
                "ctrl"
            } else {
                "misc"
            }
            .to_string(),
        });
    }
    m.insns.push(Insn {
        name: "moveq".to_string(),
        format: "Q".to_string(),
        pattern: Pattern::parse("0111 ... 0 ........").expect("valid pattern"),
        when: Pred::True,
        wheres: vec![],
        syntax: "moveq".to_string(),
        timing: "misc".to_string(),
    });
    m
}
