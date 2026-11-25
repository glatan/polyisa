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
        timing: None,
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
    // Ref: SPEC-OPENRISC-1000 §5.3, Appendix "Instruction set listing".
    for (name, format, pattern, when, syntax, timing) in [
        // 制御転送・PC 相対。
        ("l_j", "FN26", "000000..........................", base(), "l.j {n}", "branch"),
        ("l_jal", "FN26", "000001..........................", base(), "l.jal {n}", "branch"),
        ("l_adrp", "FADRP", "000010..........................", base(), "l.adrp {d}, {ni}", "alu"),
        ("l_bnf", "FN26", "000011..........................", base(), "l.bnf {n}", "branch"),
        ("l_bf", "FN26", "000100..........................", base(), "l.bf {n}", "branch"),
        ("l_nop", "FK16", "00010101........................", base(), "l.nop {k}", "misc"),
        ("l_jr", "FB", "010001..........................", base(), "l.jr {b}", "branch"),
        ("l_jalr", "FB", "010010..........................", base(), "l.jalr {b}", "branch"),
        // 定数形成・MAC 読み出し（同じ上位 6 ビットで bit16 が識別）。
        ("l_movhi", "FDK", "000110.........0................", base(), "l.movhi {d}, {k}", "alu"),
        ("l_macrc", "FD", "000110.........10000000000000000", base(), "l.macrc {d}", "mac"),
        // システム・同期。
        ("l_sys", "FK16", "0010000000000000................", base(), "l.sys {k}", "system"),
        ("l_trap", "FK16", "0010000100000000................", base(), "l.trap {k}", "system"),
        ("l_msync", "FN0", "00100010000000000000000000000000", base(), "l.msync", "system"),
        ("l_psync", "FN0", "00100010100000000000000000000000", base(), "l.psync", "system"),
        ("l_csync", "FN0", "00100011000000000000000000000000", base(), "l.csync", "system"),
        ("l_rfe", "FN0", "001001..........................", base(), "l.rfe", "system"),
        // MAC 即値積和。
        ("l_maci", "FAI", "010011..........................", base(), "l.maci {a}, {i}", "mac"),
        // ロード（l.lf/l.lwa）と ORBIS64 の l.ld（宣言のみの orb64 機能）。
        ("l_lf", "FDAI", "011010..........................", f_fpu(), "l.lf {d}, {i}({a})", "load"),
        ("l_lwa", "FDAI", "011011..........................", base(), "l.lwa {d}, {i}({a})", "load"),
        ("l_ld", "FDAI", "100000..........................", Pred::Flag("orb64".to_string()), "l.ld {d}, {i}({a})", "load"),
        ("l_lwz", "FDAI", "100001..........................", base(), "l.lwz {d}, {i}({a})", "load"),
        ("l_lws", "FDAI", "100010..........................", base(), "l.lws {d}, {i}({a})", "load"),
        ("l_lbz", "FDAI", "100011..........................", base(), "l.lbz {d}, {i}({a})", "load"),
        ("l_lbs", "FDAI", "100100..........................", base(), "l.lbs {d}, {i}({a})", "load"),
        ("l_lhz", "FDAI", "100101..........................", base(), "l.lhz {d}, {i}({a})", "load"),
        ("l_lhs", "FDAI", "100110..........................", base(), "l.lhs {d}, {i}({a})", "load"),
        // 即値演算（I は符号拡張、K はゼロ拡張）。
        ("l_addi", "FDAI", "100111..........................", base(), "l.addi {d}, {a}, {i}", "alu"),
        ("l_addic", "FDAI", "101000..........................", base(), "l.addic {d}, {a}, {i}", "alu"),
        ("l_andi", "FDAK", "101001..........................", base(), "l.andi {d}, {a}, {k}", "alu"),
        ("l_ori", "FDAK", "101010..........................", base(), "l.ori {d}, {a}, {k}", "alu"),
        ("l_xori", "FDAI", "101011..........................", base(), "l.xori {d}, {a}, {i}", "alu"),
        ("l_muli", "FDAI", "101100..........................", base(), "l.muli {d}, {a}, {i}", "alu"),
        ("l_mfspr", "FDAK", "101101..........................", base(), "l.mfspr {d}, {a}, {k}", "system"),
        // 即値シフト・回転（[7:6] が副演算）。
        ("l_slli", "FDAL", "101110..................00......", base(), "l.slli {d}, {a}, {l}", "alu"),
        ("l_srli", "FDAL", "101110..................01......", base(), "l.srli {d}, {a}, {l}", "alu"),
        ("l_srai", "FDAL", "101110..................10......", base(), "l.srai {d}, {a}, {l}", "alu"),
        ("l_rori", "FDAL", "101110..................11......", base(), "l.rori {d}, {a}, {l}", "alu"),
        // 即値比較（[25:21] が条件副演算）。
        ("l_sfeqi", "FAI", "10111100000.....................", base(), "l.sfeqi {a}, {i}", "alu"),
        ("l_sfnei", "FAI", "10111100001.....................", base(), "l.sfnei {a}, {i}", "alu"),
        ("l_sfgtui", "FAI", "10111100010.....................", base(), "l.sfgtui {a}, {i}", "alu"),
        ("l_sfgeui", "FAI", "10111100011.....................", base(), "l.sfgeui {a}, {i}", "alu"),
        ("l_sfltui", "FAI", "10111100100.....................", base(), "l.sfltui {a}, {i}", "alu"),
        ("l_sfleui", "FAI", "10111100101.....................", base(), "l.sfleui {a}, {i}", "alu"),
        ("l_sfgtsi", "FAI", "10111101010.....................", base(), "l.sfgtsi {a}, {i}", "alu"),
        ("l_sfgesi", "FAI", "10111101011.....................", base(), "l.sfgesi {a}, {i}", "alu"),
        ("l_sfltsi", "FAI", "10111101100.....................", base(), "l.sfltsi {a}, {i}", "alu"),
        ("l_sflesi", "FAI", "10111101101.....................", base(), "l.sflesi {a}, {i}", "alu"),
        // SPR 書き込み（分割即値）。
        ("l_mtspr", "FMTSPR", "110000..........................", base(), "l.mtspr {a}, {b}, {k}", "system"),
        // MAC（[3:0] が副演算）。
        ("l_mac", "FAB", "110001......................0001", base(), "l.mac {a}, {b}", "mac"),
        ("l_msb", "FAB", "110001......................0010", base(), "l.msb {a}, {b}", "mac"),
        ("l_macu", "FAB", "110001......................0011", base(), "l.macu {a}, {b}", "mac"),
        ("l_msbu", "FAB", "110001......................0100", base(), "l.msbu {a}, {b}", "mac"),
        // ストア（分割即値）。l.sd は ORBIS64。
        ("l_swa", "FSTORE", "110011..........................", base(), "l.swa {i}({a}), {b}", "store"),
        ("l_sd", "FSTORE", "110100..........................", Pred::Flag("orb64".to_string()), "l.sd {i}({a}), {b}", "store"),
        ("l_sw", "FSTORE", "110101..........................", base(), "l.sw {i}({a}), {b}", "store"),
        ("l_sb", "FSTORE", "110110..........................", base(), "l.sb {i}({a}), {b}", "store"),
        ("l_sh", "FSTORE", "110111..........................", base(), "l.sh {i}({a}), {b}", "store"),
        // 0x38 主演算群。符号拡張（ext*）・ff1/fl1。
        ("l_exths", "FDAB", "111000................0000..1100", base(), "l.exths {d}, {a}", "alu"),
        ("l_extws", "FDAB", "111000................0000..1101", base(), "l.extws {d}, {a}", "alu"),
        ("l_extbs", "FDAB", "111000................0001..1100", base(), "l.extbs {d}, {a}", "alu"),
        ("l_extwz", "FDAB", "111000................0001..1101", base(), "l.extwz {d}, {a}", "alu"),
        ("l_exthz", "FDAB", "111000................0010..1100", base(), "l.exthz {d}, {a}", "alu"),
        ("l_extbz", "FDAB", "111000................0011..1100", base(), "l.extbz {d}, {a}", "alu"),
        ("l_ff1", "FDAB", "111000................00....1111", base(), "l.ff1 {d}, {a}", "alu"),
        ("l_fl1", "FDAB", "111000................01....1111", base(), "l.fl1 {d}, {a}", "alu"),
        // 整数 3 項演算・条件ムーブ。
        ("l_add", "FDAB", "111000................00....0000", base(), "l.add {d}, {a}, {b}", "alu"),
        ("l_addc", "FDAB", "111000................00....0001", base(), "l.addc {d}, {a}, {b}", "alu"),
        ("l_sub", "FDAB", "111000................00....0010", base(), "l.sub {d}, {a}, {b}", "alu"),
        ("l_and", "FDAB", "111000................00....0011", base(), "l.and {d}, {a}, {b}", "alu"),
        ("l_or", "FDAB", "111000................00....0100", base(), "l.or {d}, {a}, {b}", "alu"),
        ("l_xor", "FDAB", "111000................00....0101", base(), "l.xor {d}, {a}, {b}", "alu"),
        ("l_cmov", "FDAB", "111000................00....1110", base(), "l.cmov {d}, {a}, {b}", "alu"),
        // レジスタシフト・回転（[9:6] が副演算）。
        ("l_sll", "FDAB", "111000................0000..1000", base(), "l.sll {d}, {a}, {b}", "alu"),
        ("l_srl", "FDAB", "111000................0001..1000", base(), "l.srl {d}, {a}, {b}", "alu"),
        ("l_sra", "FDAB", "111000................0010..1000", base(), "l.sra {d}, {a}, {b}", "alu"),
        ("l_ror", "FDAB", "111000................0011..1000", base(), "l.ror {d}, {a}, {b}", "alu"),
        // 乗除（[9:8]=11、[3:0] が副演算）。
        ("l_mul", "FDAB", "111000................11....0110", base(), "l.mul {d}, {a}, {b}", "alu"),
        ("l_muld", "FAB", "111000................11....0111", base(), "l.muld {a}, {b}", "mac"),
        ("l_div", "FDAB", "111000................11....1001", base(), "l.div {d}, {a}, {b}", "alu"),
        ("l_divu", "FDAB", "111000................11....1010", base(), "l.divu {d}, {a}, {b}", "alu"),
        ("l_mulu", "FDAB", "111000................11....1011", base(), "l.mulu {d}, {a}, {b}", "alu"),
        ("l_muldu", "FAB", "111000................11....1100", base(), "l.muldu {a}, {b}", "mac"),
        // レジスタ比較（[25:21] が条件副演算）。
        ("l_sfeq", "FAB", "11100100000.....................", base(), "l.sfeq {a}, {b}", "alu"),
        ("l_sfne", "FAB", "11100100001.....................", base(), "l.sfne {a}, {b}", "alu"),
        ("l_sfgtu", "FAB", "11100100010.....................", base(), "l.sfgtu {a}, {b}", "alu"),
        ("l_sfgeu", "FAB", "11100100011.....................", base(), "l.sfgeu {a}, {b}", "alu"),
        ("l_sfltu", "FAB", "11100100100.....................", base(), "l.sfltu {a}, {b}", "alu"),
        ("l_sfleu", "FAB", "11100100101.....................", base(), "l.sfleu {a}, {b}", "alu"),
        ("l_sfgts", "FAB", "11100101010.....................", base(), "l.sfgts {a}, {b}", "alu"),
        ("l_sfges", "FAB", "11100101011.....................", base(), "l_sfges {a}, {b}", "alu"),
        ("l_sflts", "FAB", "11100101100.....................", base(), "l_sflts {a}, {b}", "alu"),
        ("l_sfles", "FAB", "11100101101.....................", base(), "l_sfles {a}, {b}", "alu"),
        // カスタム命令の予約（実装定義。語彙として宣言し、意味論は
        // 未実装として Undefined を上げる）。
        ("l_cust1", "FN0", "011100..........................", base(), "l.cust1", "misc"),
        ("l_cust2", "FN0", "011101..........................", base(), "l.cust2", "misc"),
        ("l_cust3", "FN0", "011110..........................", base(), "l.cust3", "misc"),
        ("l_cust4", "FN0", "011111..........................", base(), "l.cust4", "misc"),
        ("l_cust5", "FCUST5", "111100..........................", base(), "l.cust5 {d}, {a}, {b}, {l}, {k}", "misc"),
        ("l_cust6", "FN0", "111101..........................", base(), "l.cust6", "misc"),
        ("l_cust7", "FN0", "111110..........................", base(), "l.cust7", "misc"),
        ("l_cust8", "FN0", "111111..........................", base(), "l.cust8", "misc"),
        // ---- ORFPX32（fpu）。単精度は GPR のビットイメージ ----
        ("lf_add_s", "FFDAB", "110010..................00000000", f_fpu(), "lf.add.s {d}, {a}, {b}", "fp"),
        ("lf_sub_s", "FFDAB", "110010..................00000001", f_fpu(), "lf.sub.s {d}, {a}, {b}", "fp"),
        ("lf_mul_s", "FFDAB", "110010..................00000010", f_fpu(), "lf.mul.s {d}, {a}, {b}", "fp"),
        ("lf_div_s", "FFDAB", "110010..................00000011", f_fpu(), "lf.div.s {d}, {a}, {b}", "fp"),
        ("lf_itof_s", "FFDA", "110010..........00000...00000100", f_fpu(), "lf.itof.s {d}, {a}", "fp"),
        ("lf_ftoi_s", "FFDA", "110010..........00000...00000101", f_fpu(), "lf.ftoi.s {d}, {a}", "fp"),
        ("lf_madd_s", "FAB", "110010..................00000111", f_fpu(), "lf.madd.s {a}, {b}", "fp"),
        ("lf_sfeq_s", "FAB", "110010..................00001000", f_fpu(), "lf.sfeq.s {a}, {b}", "fp"),
        ("lf_sfne_s", "FAB", "110010..................00001001", f_fpu(), "lf.sfne.s {a}, {b}", "fp"),
        ("lf_sfgt_s", "FAB", "110010..................00001010", f_fpu(), "lf.sfgt.s {a}, {b}", "fp"),
        ("lf_sfge_s", "FAB", "110010..................00001011", f_fpu(), "lf.sfge.s {a}, {b}", "fp"),
        ("lf_sflt_s", "FAB", "110010..................00001100", f_fpu(), "lf.sflt.s {a}, {b}", "fp"),
        ("lf_sfle_s", "FAB", "110010..................00001101", f_fpu(), "lf.sfle.s {a}, {b}", "fp"),
        ("lf_sfueq_s", "FAB", "110010..................00101000", f_fpu(), "lf.sfueq.s {a}, {b}", "fp"),
        ("lf_sfune_s", "FAB", "110010..................00101001", f_fpu(), "lf.sfune.s {a}, {b}", "fp"),
        ("lf_sfugt_s", "FAB", "110010..................00101010", f_fpu(), "lf.sfugt.s {a}, {b}", "fp"),
        ("lf_sfuge_s", "FAB", "110010..................00101011", f_fpu(), "lf.sfuge.s {a}, {b}", "fp"),
        ("lf_sfult_s", "FAB", "110010..................00101100", f_fpu(), "lf.sfult.s {a}, {b}", "fp"),
        ("lf_sfule_s", "FAB", "110010..................00101101", f_fpu(), "lf.sfule.s {a}, {b}", "fp"),
        ("lf_sfun_s", "FAB", "110010..................00101110", f_fpu(), "lf.sfun.s {a}, {b}", "fp"),
        ("lf_cust1_s", "FFABO", "110010..................1101....", f_fpu(), "lf.cust1.s {a}, {b}, {oo}", "fp"),
        // ---- ORFPX64A32（f64a32）。GPR ペアの倍精度 ----
        ("lf_add_d", "FFDABO", "110010..................00010000", f_f64a32(), "lf.add.d {d}, {a}, {b}, {oo}", "fp"),
        ("lf_sub_d", "FFDABO", "110010..................00010001", f_f64a32(), "lf.sub.d {d}, {a}, {b}, {oo}", "fp"),
        ("lf_mul_d", "FFDABO", "110010..................00010010", f_f64a32(), "lf.mul.d {d}, {a}, {b}, {oo}", "fp"),
        ("lf_div_d", "FFDABO", "110010..................00010011", f_f64a32(), "lf.div.d {d}, {a}, {b}, {oo}", "fp"),
        ("lf_itof_d", "FFDAO", "110010..........00000...00010100", f_f64a32(), "lf.itof.d {d}, {a}, {oo}", "fp"),
        ("lf_ftoi_d", "FFDAO", "110010..........00000...00010101", f_f64a32(), "lf.ftoi.d {d}, {a}, {oo}", "fp"),
        ("lf_madd_d", "FFABO", "110010..................00010111", f_f64a32(), "lf.madd.d {a}, {b}, {oo}", "fp"),
        ("lf_sfeq_d", "FFABO", "110010..................00011000", f_f64a32(), "lf.sfeq.d {a}, {b}, {oo}", "fp"),
        ("lf_sfne_d", "FFABO", "110010..................00011001", f_f64a32(), "lf.sfne.d {a}, {b}, {oo}", "fp"),
        ("lf_sfgt_d", "FFABO", "110010..................00011010", f_f64a32(), "lf.sfgt.d {a}, {b}, {oo}", "fp"),
        ("lf_sfge_d", "FFABO", "110010..................00011011", f_f64a32(), "lf.sfge.d {a}, {b}, {oo}", "fp"),
        ("lf_sflt_d", "FFABO", "110010..................00011100", f_f64a32(), "lf.sflt.d {a}, {b}, {oo}", "fp"),
        ("lf_sfle_d", "FFABO", "110010..................00011101", f_f64a32(), "lf.sfle.d {a}, {b}, {oo}", "fp"),
        ("lf_sfueq_d", "FFABO", "110010..................00111000", f_f64a32(), "lf.sfueq.d {a}, {b}, {oo}", "fp"),
        ("lf_sfune_d", "FFABO", "110010..................00111001", f_f64a32(), "lf.sfune.d {a}, {b}, {oo}", "fp"),
        ("lf_sfugt_d", "FFABO", "110010..................00111010", f_f64a32(), "lf.sfugt.d {a}, {b}, {oo}", "fp"),
        ("lf_sfuge_d", "FFABO", "110010..................00111011", f_f64a32(), "lf.sfuge.d {a}, {b}, {oo}", "fp"),
        ("lf_sfult_d", "FFABO", "110010..................00111100", f_f64a32(), "lf.sfult.d {a}, {b}, {oo}", "fp"),
        ("lf_sfule_d", "FFABO", "110010..................00111101", f_f64a32(), "lf.sfule.d {a}, {b}, {oo}", "fp"),
        ("lf_sfun_d", "FFABO", "110010..................00111110", f_f64a32(), "lf.sfun.d {a}, {b}, {oo}", "fp"),
        ("lf_stod_d", "FFDAO", "110010..................00110100", f_f64a32(), "lf.stod.d {d}, {a}, {oo}", "fp"),
        ("lf_dtos_d", "FFDAO", "110010..................00110101", f_f64a32(), "lf.dtos.d {d}, {a}, {oo}", "fp"),
        ("lf_cust1_d", "FFABO", "110010..................1110....", f_f64a32(), "lf.cust1.d {a}, {b}, {oo}", "fp"),
    ] {
        m.insns.push(ins(name, format, pattern, when, syntax, timing));
    }

    m
}
