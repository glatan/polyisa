// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// OpenRISC の ISADL モデル（段階20）。
//
// OpenRISC 1000 の命令は固定 32 ビット長。語の上位 6 ビット [31:26]
// が主オペコードで、レジスタ桁は D[25:21]・A[20:16]・B[15:11]、
// 即値は I/K[15:0]・N[25:0]・L[5:0]。ストア系と l.mtspr は 16 ビット
// 即値が [25:21] と [10:0] に割れる分割即値形式。
// 正本は SPEC-OPENRISC-1000 §5.3 の命令一覧（付録の機械語表）で、
// 本文中の形式図と齟齬がある箇所（l.movhi の K 桁など）は機械語表の
// 桁配置を採る。
// Ref: SPEC-OPENRISC-1000 §5（Instruction Set）, Appendix
// "Instruction set listing"（機械語表）.
//
// 遅延スロットの有無は CPUCFGR[ND] が示す実装選択肢（§16.4）。
// ND=0 は分岐成立に 1 命令の遅延スロットが伴う。本モデルは機能旗
// `dslot` で表し、既定モデルは Linux ユーザ空間前提の遅延あり。
// Ref: SPEC-OPENRISC-1000 §16.4（CPUCFGR）, §6（例外と DSX）.

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// OpenRISC の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "load", "store", "branch", "system", "fp", "mac", "misc"] {
        m.timing_classes.push(class.to_string());
    }

    // 機能旗。
    // - `dslot`: CPUCFGR[ND]=0 の構成。分岐・ジャンプ成立で 1 命令の
    //   遅延スロットを実行する。Linux ユーザ空間の既定。
    // - `fpu`: ORFPX32（単精度 FP 拡張、lf.*.s 語彙）。
    // - `f64a32`: ORFPX64A32（32 ビット機上の倍精度 FP、GPR ペアの
    //   lf.*.d 語彙）。`fpu` を含意する。
    // - `orb64`: ORBIS64（64 ビット整数・l.ld/l.sd 等）。宣言のみで
    //   命令の割当てはない（対象 ABI は 32 ビット）。
    // - `orvdx`: ORVDX64（ベクトル拡張、lv.*）。宣言のみ・実装対象外。
    // Ref: SPEC-OPENRISC-1000 §5.1（命令部分集合）, §16.4（CPUCFGR）.
    let features: &[(&str, &[&str], &[&str])] = &[
        ("dslot", &[], &[]),
        ("fpu", &[], &[]),
        ("f64a32", &["fpu"], &[]),
        ("orb64", &[], &[]),
        ("orvdx", &[], &[]),
    ];
    for &(name, implies, conflicts) in features {
        m.features.push(Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: conflicts.iter().map(|s| s.to_string()).collect(),
        });
    }

    // CPU モデル。or1k Linux ユーザ空間が対象の 32 ビット系。
    // mor1kx は FPU 有りの構成を代表として載せる（実機は合成時
    // オプションだが、配布物実行には FP を通せる方が都合が良い）。
    // Ref: SPEC-OPENRISC-1000 §16（実装差の識別レジスタ）.
    for (name, parent, add) in [
        ("or1200", "", &["dslot"][..]),
        ("mor1kx", "or1200", &["fpu"][..]),
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

    // 汎用レジスタ r0-r31。r0 は常に 0 を返し、書き込みは捨てる
    // 実装選択をとる（§4.1 の「R0 should always hold a zero value.
    // It is the responsibility of software to initialize it.」に対し、
    // 実機（or1200/mor1kx）と同じハードワイヤ解釈を選ぶ）。
    // Ref: SPEC-OPENRISC-1000 §4.1（GPR）.
    m.regclasses.push(RegClass {
        name: "gr".to_string(),
        dynamic: false,
        prefix: Some("r".to_string()),
    });

    // 桁。機械語表（付録）の配置が正本。
    // Ref: SPEC-OPENRISC-1000 Appendix "Instruction set listing".
    for (name, hi, lo) in [
        ("d", 25, 21),  // 宛先レジスタ
        ("a", 20, 16),  // ソースレジスタ A
        ("b", 15, 11),  // ソースレジスタ B
        ("i16", 15, 0), // 符号拡張する 16 ビット即値（I）
        ("k16", 15, 0), // ゼロ拡張する 16 ビット即値（K）
        ("n26", 25, 0), // 分岐・ジャンプ変位（4 バイト単位。sext<<2）
        ("ni21", 20, 0), // l.adrp の 21 ビット即値
        ("l6", 5, 0),   // シフト量 L
        ("l5", 10, 5),  // l.cust5 の L 桁（独自位置）
        ("k5", 4, 0),   // l.cust5 の K 桁（独自位置）
        ("oo3", 10, 8), // ORFPX64A32 のレジスタペアオフセット
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }
    // ストア系・l.mtspr の分割即値。I[15:11] が [25:21]、
    // I[10:0] が [10:0] に割れる。
    // Ref: SPEC-OPENRISC-1000 §5.3（l.sw/l.swa/l.mtspr 各行）.
    m.fields.push(Field {
        name: "sk16".to_string(),
        kind: FieldKind::Parts {
            parts: vec![(25, 21), (10, 0)],
            zfill: 0,
        },
    });

    let gr = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("gr".to_string()),
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

    // オペランドなし（l.msync/l.psync/l.csync/l.rfe/l.cust{1,2,3,4,6,7,8}）。
    m.formats.push(fmt("FN0", &[], vec![]));
    // K 即値のみ（l.nop/l.sys/l.trap）。
    m.formats.push(fmt("FK16", &["k16"], vec![val("k", "k16")]));
    // 分岐・ジャンプ変位（l.j/l.jal/l.bf/l.bnf）。
    m.formats.push(fmt("FN26", &["n26"], vec![val("n", "n26")]));
    // l.adrp の D,NI。
    m.formats.push(fmt(
        "FADRP",
        &["ni21", "d"],
        vec![gr("d", "d", Access::Write), val("ni", "ni21")],
    ));
    // l.movhi の D,K。
    m.formats.push(fmt(
        "FDK",
        &["k16", "d"],
        vec![gr("d", "d", Access::Write), val("k", "k16")],
    ));
    // D のみ（l.macrc）。
    m.formats.push(fmt("FD", &["d"], vec![gr("d", "d", Access::Write)]));
    // rB のみ（l.jr/l.jalr）。
    m.formats.push(fmt("FB", &["b"], vec![gr("b", "b", Access::Read)]));
    // rA, I（l.maci・l.sf*i 即値比較）。
    m.formats.push(fmt(
        "FAI",
        &["i16", "a"],
        vec![gr("a", "a", Access::Read), val("i", "i16")],
    ));
    // rD, rA, I（即値演算・ロード系）。
    m.formats.push(fmt(
        "FDAI",
        &["i16", "a", "d"],
        vec![
            gr("d", "d", Access::Write),
            gr("a", "a", Access::Read),
            val("i", "i16"),
        ],
    ));
    // rD, rA, K（ゼロ拡張即値・l.mfspr）。
    m.formats.push(fmt(
        "FDAK",
        &["k16", "a", "d"],
        vec![
            gr("d", "d", Access::Write),
            gr("a", "a", Access::Read),
            val("k", "k16"),
        ],
    ));
    // rD, rA, rB（3 項 ALU・l.sf* レジスタ比較は FDAB を共有しない。
    // 比較は rD を持たないので別形式 FAB で表す）。
    m.formats.push(fmt(
        "FDAB",
        &["b", "a", "d"],
        vec![
            gr("d", "d", Access::Write),
            gr("a", "a", Access::Read),
            gr("b", "b", Access::Read),
        ],
    ));
    // rA, rB（l.sf* 比較・l.mac/l.macu/l.msb/l.msbu・lf.sf*.s・
    // lf.madd.s。宛先は暗黙の SR[F]・MACHI:MACLO・FPMADD）。
    m.formats.push(fmt(
        "FAB",
        &["b", "a"],
        vec![gr("a", "a", Access::Read), gr("b", "b", Access::Read)],
    ));
    // rD, rA, L（即値シフト・回転）。
    m.formats.push(fmt(
        "FDAL",
        &["l6", "a", "d"],
        vec![
            gr("d", "d", Access::Write),
            gr("a", "a", Access::Read),
            val("l", "l6"),
        ],
    ));
    // 分割即値ストア（l.sd/l.sw/l.sb/l.sh/l.swa）。構文は I(rA),rB。
    m.formats.push(fmt(
        "FSTORE",
        &["b", "a", "sk16"],
        vec![
            val("i", "sk16"),
            gr("a", "a", Access::Read),
            gr("b", "b", Access::Read),
        ],
    ));
    // l.mtspr rA,rB,K（K は分割即値）。
    m.formats.push(fmt(
        "FMTSPR",
        &["b", "a", "sk16"],
        vec![
            gr("a", "a", Access::Read),
            gr("b", "b", Access::Read),
            val("k", "sk16"),
        ],
    ));
    // l.cust5 rD,rA,rB,L,K（実装定義の予約。解読のみ）。
    m.formats.push(fmt(
        "FCUST5",
        &["k5", "l5", "b", "a", "d"],
        vec![
            gr("d", "d", Access::Read),
            gr("a", "a", Access::Read),
            gr("b", "b", Access::Read),
            val("l", "l5"),
            val("k", "k5"),
        ],
    ));
    // ---- ORFPX32/64A32 ----
    // rD, rA, rB（lf.add.s 等の 2 項演算。単精度は GPR 保持）。
    m.formats.push(fmt(
        "FFDAB",
        &["b", "a", "d"],
        vec![
            gr("d", "d", Access::Write),
            gr("a", "a", Access::Read),
            gr("b", "b", Access::Read),
        ],
    ));
    // rD, rA（lf.itof.s/lf.ftoi.s）。
    m.formats.push(fmt(
        "FFDA",
        &["a", "d"],
        vec![gr("d", "d", Access::Write), gr("a", "a", Access::Read)],
    ));
    // rA, rB, OO（lf.sf*.d・lf.madd.d。OO はペアオフセット）。
    m.formats.push(fmt(
        "FFABO",
        &["b", "a", "oo3"],
        vec![
            gr("a", "a", Access::Read),
            gr("b", "b", Access::Read),
            val("oo", "oo3"),
        ],
    ));
    // rD, rA, rB, OO（lf.add.d 等）。
    m.formats.push(fmt(
        "FFDABO",
        &["b", "a", "d", "oo3"],
        vec![
            gr("d", "d", Access::Write),
            gr("a", "a", Access::Read),
            gr("b", "b", Access::Read),
            val("oo", "oo3"),
        ],
    ));
    // rD, rA, OO（lf.stod.d/lf.dtos.d/lf.itof.d/lf.ftoi.d）。
    m.formats.push(fmt(
        "FFDAO",
        &["a", "d", "oo3"],
        vec![
            gr("d", "d", Access::Write),
            gr("a", "a", Access::Read),
            val("oo", "oo3"),
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
    let f_fpu = || Pred::Flag("fpu".to_string());
    let f_f64a32 = || Pred::Flag("f64a32".to_string());

    // ---- ORBIS32 語彙（付録の機械語表が正本）。----
    // OR2 の骨格として代表形式のみ登録する。残りの語彙は OR3 で補完する。
    // Ref: SPEC-OPENRISC-1000 §5.3, Appendix "Instruction set listing".
    for (name, format, pattern, when, syntax, timing) in [
        // 制御転送（遅延スロットの枠組みの検証用）。
        ("l_j", "FN26", "000000..........................", base(), "l.j {n}", "branch"),
        ("l_jal", "FN26", "000001..........................", base(), "l.jal {n}", "branch"),
        ("l_bnf", "FN26", "000011..........................", base(), "l.bnf {n}", "branch"),
        ("l_bf", "FN26", "000100..........................", base(), "l.bf {n}", "branch"),
        // 定数形成と NOP（実行ループの最小検査用）。
        ("l_movhi", "FDK", "000110.........0................", base(), "l.movhi {d}, {k}", "alu"),
        ("l_nop", "FK16", "00010101........................", base(), "l.nop {k}", "misc"),
        // 即値演算と 3 項演算の代表。
        ("l_addi", "FDAI", "100111..........................", base(), "l.addi {d}, {a}, {i}", "alu"),
        ("l_add", "FDAB", "111000................00....0000", base(), "l.add {d}, {a}, {b}", "alu"),
        ("l_or", "FDAB", "111000................00....0100", base(), "l.or {d}, {a}, {b}", "alu"),
        // システム呼出の発行点。
        ("l_sys", "FK16", "0010000000000000................", base(), "l.sys {k}", "system"),
    ] {
        m.insns.push(ins(name, format, pattern, when, syntax, timing));
    }
    let _ = (f_fpu, f_f64a32);

    m
}
