// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// RV64I の ISADL モデル。
//
// 出典は下記の資料の版 20250508 である。各命令の節番号は
// 将来の `.isadl` 構文解析で付ける。ここでは事実（符号化）のみを記述する。
// Ref: SPEC-RISCV-UNPRIV (20250508).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// RV64I の検査済みモデルを作る。RV32I 共通 37 件のうちシフト 3 件は RV64 版で置き換える。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in [
        "alu", "load", "store", "branch", "jump", "system", "mult", "div", "atomic", "csr",
        "falu_s", "falu_d", "fsj", "fcmp", "fminmax", "fcvt", "fdiv_s", "fdiv_d", "fsqrt_s",
        "fsqrt_d", "fload", "fstore",
    ] {
        m.timing_classes.push(class.to_string());
    }

    // 機能と汎用CPUモデル。RVA22U64相当のRV64GCを汎用とする。
    // m/a/f/d/c/zicsr/zifencei は命令の when にも接続し、モデルの
    // 機能集合で利用可否が変わるようにする。
    // Ref: SPEC-RISCV-UNPRIV (20250508), SPEC-RISCV-PROFILES (RVA23 v1.0).
    for (name, implies, conflicts) in [
        ("rv64", &[][..], &["rv32"][..]),
        ("rv32", &[][..], &["rv64"][..]),
        ("m", &[][..], &[][..]),
        ("a", &[][..], &[][..]),
        ("f", &[][..], &[][..]),
        ("d", &["f"][..], &[][..]),
        ("c", &[][..], &[][..]),
        ("zicsr", &[][..], &[][..]),
        ("zifencei", &[][..], &[][..]),
        ("zba", &[][..], &[][..]),
        ("zbb", &[][..], &[][..]),
        ("zbc", &[][..], &[][..]),
        ("zbs", &[][..], &[][..]),
        // RVA22/23 で必須化される拡張。命令はいずれも未実装で、
        // カバレッジ表にゼロ件で見える。カウンタ系（Zicntr/Zihpm）・
        // PMA 系（Ziccif 等）・データ独立レイテンシ（Zkt）のように
        // 命令の可否に関わらないものは旗に立てない。
        ("zihintpause", &[][..], &[][..]),
        ("zicbom", &[][..], &[][..]),
        ("zicbop", &[][..], &[][..]),
        ("zicboz", &[][..], &[][..]),
        ("zfhmin", &[][..], &[][..]),
        ("v", &[][..], &[][..]),
        ("zvfhmin", &["v"][..], &[][..]),
        ("zvbb", &["v"][..], &[][..]),
        ("zicond", &[][..], &[][..]),
        ("zimop", &[][..], &[][..]),
        ("zcmop", &["zimop"][..], &[][..]),
        ("zcb", &["c"][..], &[][..]),
        ("zfa", &[][..], &[][..]),
        ("zawrs", &[][..], &[][..]),
    ] {
        m.features.push(polyisa_isadl::model::Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: conflicts.iter().map(|s| s.to_string()).collect(),
        });
    }
    m.models.push(polyisa_isadl::model::ModelDef {
        timing: None,
        params: vec![],
        name: "rv64gc".to_string(),
        parent: String::new(),
        add_features: ["rv64", "m", "a", "f", "d", "c", "zicsr", "zifencei"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        remove_features: Vec::new(),
        ident: vec![],
    });
    m.models.push(polyisa_isadl::model::ModelDef {
        timing: None,
        params: vec![],
        name: "rv64imac".to_string(),
        parent: "rv64gc".to_string(),
        add_features: Vec::new(),
        remove_features: ["f", "d"].iter().map(|s| s.to_string()).collect(),
        ident: vec![],
    });
    // SiFive U74。ISA は RV64GC_Zba_Zbb_Sscofpmf（Sscofpmf の命令は
    // タイミング上の観測点がないため機能にも立てない）。
    // Zba/Zbb の命令自体は未実装で、機能ビットの宣言のみ。
    // Ref: SPEC-SIFIVE-U74 §4.4.1 Table 11.
    m.models.push(polyisa_isadl::model::ModelDef {
        timing: Some(polyisa_isadl::model::ModelTiming {
            fidelity: "approx_uncalibrated".to_string(),
            engine: "inorder".to_string(),
            table: "sifive_u74".to_string(),
        }),
        params: vec![],
        name: "sifive_u74".to_string(),
        parent: "rv64gc".to_string(),
        add_features: ["zba", "zbb"].iter().map(|s| s.to_string()).collect(),
        remove_features: Vec::new(),
        ident: vec![],
    });

    // 基本プロファイル。整数系は Zicsr・Zifencei を含めない純粋な
    // 拡張列とし、rv64imac・rv64gc は従来どおり CSR を含む構成と
    // して残す（rv64gc が先頭で既定）。
    // Ref: SPEC-RISCV-UNPRIV (20250508) の拡張命名。
    for (name, parent, add) in [
        ("rv32i", "", &["rv32"][..]),
        ("rv32im", "rv32i", &["m"][..]),
        ("rv32ima", "rv32im", &["a"][..]),
        ("rv32imac", "rv32ima", &["c"][..]),
        ("rv32gc", "rv32imac", &["f", "d", "zicsr", "zifencei"][..]),
        ("rv64i", "", &["rv64"][..]),
        ("rv64im", "rv64i", &["m"][..]),
        ("rv64ima", "rv64im", &["a"][..]),
        // SiFive E31。RV32IMAC に CSR 類を備えた実機構成。
        ("sifive_e31", "rv32imac", &["zicsr", "zifencei"][..]),
        // RVA20U64 プロファイル。必須は RV64GC+Zba+Zbb+Zbs（Zicntr/
        // Zihpm のカウンタ類は命令の可否に関わらないため旗に立てない）。
        // Zba/Zbb/Zbs の命令自体は未実装。
        // Ref: SPEC-RISCV-PROFILES (RVA23 v1.0) の収録表。
        ("rva20u64", "rv64gc", &["zba", "zbb", "zbs"][..]),
        // RVA22 は RVA20 にキャッシュブロック操作・半精度・pause
        // ヒントを足す。RVA23 はベクトルを必須化し Zicond・Zimop・
        // Zfa・Zawrs 等を足す。いずれの拡張命令も未実装。
        // Ref: SPEC-RISCV-PROFILES (RVA23 v1.0).
        (
            "rva22u64",
            "rva20u64",
            &["zihintpause", "zicbom", "zicbop", "zicboz", "zfhmin"][..],
        ),
        (
            "rva23u64",
            "rva22u64",
            &[
                "v", "zvfhmin", "zvbb", "zicond", "zimop", "zcmop", "zcb",
                "zfa", "zawrs",
            ][..],
        ),
    ] {
        m.models.push(polyisa_isadl::model::ModelDef {
        timing: None,
        params: vec![],
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: Vec::new(),
            ident: vec![],
        });
    }

    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: false,
        prefix: Some("x".to_string()),
    });

    for (name, hi, lo) in [
        ("rd", 11, 7),
        ("rs1", 19, 15),
        ("rs2", 24, 20),
        ("funct3", 14, 12),
        // 圧縮命令のレジスタ位置。CR形式で使う。
        ("cr_rs1", 11, 7),
        ("cr_rs2", 6, 2),
        // 積和融合命令の第4オペランド。R4形式で使う。
        ("rs3", 31, 27),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }
    // 即値フィールド。形式ごとに配置が違うので別名にし、オペランド
    // 側は構文中の名前（imm/csr/uimm）からリンクする。
    // Ref: SPEC-RISCV-UNPRIV (20250508) §2.3.
    m.fields.push(Field {
        name: "imm_i".to_string(),
        kind: FieldKind::Bits { hi: 31, lo: 20 },
    });
    m.fields.push(Field {
        name: "imm_u".to_string(),
        kind: FieldKind::Bits { hi: 31, lo: 12 },
    });
    m.fields.push(Field {
        name: "imm_s".to_string(),
        kind: FieldKind::Parts {
            parts: vec![(31, 25), (11, 7)],
            zfill: 0,
        },
    });
    m.fields.push(Field {
        name: "imm_b".to_string(),
        kind: FieldKind::Parts {
            parts: vec![(31, 31), (7, 7), (30, 25), (11, 8)],
            zfill: 1,
        },
    });
    m.fields.push(Field {
        name: "imm_j".to_string(),
        kind: FieldKind::Parts {
            parts: vec![(31, 31), (19, 12), (20, 20), (30, 21)],
            zfill: 1,
        },
    });

    let gpr = |name: &str, access: Access| Operand {
        name: name.to_string(),
        field: None,
        regclass: Some("gpr".to_string()),
        access,
    };
    let imm = |name: &str, field: &str| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: None,
        access: Access::Read,
    };
    m.formats.push(Format {
        name: "R".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "rs2".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
        ],
    });
    m.formats.push(Format {
        name: "I".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "imm_i".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            imm("imm", "imm_i"),
        ],
    });
    // CSR 命令は I の即値領域を CSR 番号として読む（csrrw 系）。即値版は
    // rs1 の位置を uimm として読む（csrrwi 系）。
    m.formats.push(Format {
        name: "C".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "imm_i".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            imm("csr", "imm_i"),
            gpr("rs1", Access::Read),
        ],
    });
    m.formats.push(Format {
        name: "CI".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "imm_i".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            imm("csr", "imm_i"),
            imm("uimm", "rs1"),
        ],
    });
    m.formats.push(Format {
        name: "S".to_string(),
        fields: vec!["rs1".to_string(), "rs2".to_string(), "imm_s".to_string()],
        operands: vec![
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
            imm("imm", "imm_s"),
        ],
    });
    m.formats.push(Format {
        name: "B".to_string(),
        fields: vec!["rs1".to_string(), "rs2".to_string(), "imm_b".to_string()],
        operands: vec![
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
            imm("imm", "imm_b"),
        ],
    });
    m.formats.push(Format {
        name: "U".to_string(),
        fields: vec!["rd".to_string(), "imm_u".to_string()],
        operands: vec![gpr("rd", Access::Write), imm("imm", "imm_u")],
    });
    m.formats.push(Format {
        name: "J".to_string(),
        fields: vec!["rd".to_string(), "imm_j".to_string()],
        operands: vec![gpr("rd", Access::Write), imm("imm", "imm_j")],
    });
    // CR（圧縮レジスタ形式。JR群の where 判定と operand 取り出しに使う）。
    m.formats.push(Format {
        name: "CR".to_string(),
        fields: vec!["cr_rs1".to_string(), "cr_rs2".to_string()],
        operands: vec![
            gpr("cr_rs1", Access::ReadWrite),
            gpr("cr_rs2", Access::Read),
        ],
    });
    // R4（積和融合形式。第4オペランド rs3 を持つ）。
    m.formats.push(Format {
        name: "R4".to_string(),
        fields: vec![
            "rs3".to_string(),
            "rs2".to_string(),
            "rs1".to_string(),
            "rd".to_string(),
        ],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
            gpr("rs3", Access::Read),
        ],
    });

    // (名前, 形式, パターン, 構文, 分類)
    let insns: &[(&str, &str, &str, &str, &str)] = &[
        // U/J/分岐
        ("lui", "U", ".................... ..... 0110111", "lui {rd}, {imm}", "alu"),
        ("auipc", "U", ".................... ..... 0010111", "auipc {rd}, {imm}", "alu"),
        ("jal", "J", ".................... ..... 1101111", "jal {rd}, {imm}", "jump"),
        ("jalr", "I", "............ ..... 000 ..... 1100111", "jalr {rd}, {rs1}, {imm}", "jump"),
        ("beq", "B", "....... ..... ..... 000 ..... 1100011", "beq {rs1}, {rs2}, {imm}", "branch"),
        ("bne", "B", "....... ..... ..... 001 ..... 1100011", "bne {rs1}, {rs2}, {imm}", "branch"),
        ("blt", "B", "....... ..... ..... 100 ..... 1100011", "blt {rs1}, {rs2}, {imm}", "branch"),
        ("bge", "B", "....... ..... ..... 101 ..... 1100011", "bge {rs1}, {rs2}, {imm}", "branch"),
        ("bltu", "B", "....... ..... ..... 110 ..... 1100011", "bltu {rs1}, {rs2}, {imm}", "branch"),
        ("bgeu", "B", "....... ..... ..... 111 ..... 1100011", "bgeu {rs1}, {rs2}, {imm}", "branch"),
        // ロード・ストア
        ("lb", "I", "............ ..... 000 ..... 0000011", "lb {rd}, {imm}({rs1})", "load"),
        ("lh", "I", "............ ..... 001 ..... 0000011", "lh {rd}, {imm}({rs1})", "load"),
        ("lw", "I", "............ ..... 010 ..... 0000011", "lw {rd}, {imm}({rs1})", "load"),
        ("ld", "I", "............ ..... 011 ..... 0000011", "ld {rd}, {imm}({rs1})", "load"),
        ("lbu", "I", "............ ..... 100 ..... 0000011", "lbu {rd}, {imm}({rs1})", "load"),
        ("lhu", "I", "............ ..... 101 ..... 0000011", "lhu {rd}, {imm}({rs1})", "load"),
        ("lwu", "I", "............ ..... 110 ..... 0000011", "lwu {rd}, {imm}({rs1})", "load"),
        ("sb", "S", "....... ..... ..... 000 ..... 0100011", "sb {rs2}, {imm}({rs1})", "store"),
        ("sh", "S", "....... ..... ..... 001 ..... 0100011", "sh {rs2}, {imm}({rs1})", "store"),
        ("sw", "S", "....... ..... ..... 010 ..... 0100011", "sw {rs2}, {imm}({rs1})", "store"),
        ("sd", "S", "....... ..... ..... 011 ..... 0100011", "sd {rs2}, {imm}({rs1})", "store"),
        // OP-IMM
        ("addi", "I", "............ ..... 000 ..... 0010011", "addi {rd}, {rs1}, {imm}", "alu"),
        ("slti", "I", "............ ..... 010 ..... 0010011", "slti {rd}, {rs1}, {imm}", "alu"),
        ("sltiu", "I", "............ ..... 011 ..... 0010011", "sltiu {rd}, {rs1}, {imm}", "alu"),
        ("xori", "I", "............ ..... 100 ..... 0010011", "xori {rd}, {rs1}, {imm}", "alu"),
        ("ori", "I", "............ ..... 110 ..... 0010011", "ori {rd}, {rs1}, {imm}", "alu"),
        ("andi", "I", "............ ..... 111 ..... 0010011", "andi {rd}, {rs1}, {imm}", "alu"),
        ("slli", "I", "000000 ...... ..... 001 ..... 0010011", "slli {rd}, {rs1}, {imm}", "alu"),
        ("srli", "I", "000000 ...... ..... 101 ..... 0010011", "srli {rd}, {rs1}, {imm}", "alu"),
        ("srai", "I", "010000 ...... ..... 101 ..... 0010011", "srai {rd}, {rs1}, {imm}", "alu"),
        // OP-IMM-32
        ("addiw", "I", "............ ..... 000 ..... 0011011", "addiw {rd}, {rs1}, {imm}", "alu"),
        ("slliw", "I", "0000000 ..... ..... 001 ..... 0011011", "slliw {rd}, {rs1}, {imm}", "alu"),
        ("srliw", "I", "0000000 ..... ..... 101 ..... 0011011", "srliw {rd}, {rs1}, {imm}", "alu"),
        ("sraiw", "I", "0100000 ..... ..... 101 ..... 0011011", "sraiw {rd}, {rs1}, {imm}", "alu"),
        // OP
        ("add", "R", "0000000 ..... ..... 000 ..... 0110011", "add {rd}, {rs1}, {rs2}", "alu"),
        ("sub", "R", "0100000 ..... ..... 000 ..... 0110011", "sub {rd}, {rs1}, {rs2}", "alu"),
        ("sll", "R", "0000000 ..... ..... 001 ..... 0110011", "sll {rd}, {rs1}, {rs2}", "alu"),
        ("slt", "R", "0000000 ..... ..... 010 ..... 0110011", "slt {rd}, {rs1}, {rs2}", "alu"),
        ("sltu", "R", "0000000 ..... ..... 011 ..... 0110011", "sltu {rd}, {rs1}, {rs2}", "alu"),
        ("xor", "R", "0000000 ..... ..... 100 ..... 0110011", "xor {rd}, {rs1}, {rs2}", "alu"),
        ("srl", "R", "0000000 ..... ..... 101 ..... 0110011", "srl {rd}, {rs1}, {rs2}", "alu"),
        ("sra", "R", "0100000 ..... ..... 101 ..... 0110011", "sra {rd}, {rs1}, {rs2}", "alu"),
        ("or", "R", "0000000 ..... ..... 110 ..... 0110011", "or {rd}, {rs1}, {rs2}", "alu"),
        ("and", "R", "0000000 ..... ..... 111 ..... 0110011", "and {rd}, {rs1}, {rs2}", "alu"),
        // Zicond（条件ゼロ化）
        ("czero_eqz", "R", "0000111 ..... ..... 101 ..... 0110011", "czero.eqz {rd}, {rs1}, {rs2}", "alu"),
        ("czero_nez", "R", "0000111 ..... ..... 111 ..... 0110011", "czero.nez {rd}, {rs1}, {rs2}", "alu"),
        // Zimop（将来拡張へ再定義される予約演算。既定では rd へ 0 を書く）
        ("mop_r0", "R", "100000011100 ..... 100 ..... 1110011", "mop.r.0 {rd}, {rs1}", "alu"),
        ("mop_r1", "R", "100000011101 ..... 100 ..... 1110011", "mop.r.1 {rd}, {rs1}", "alu"),
        ("mop_r2", "R", "100000011110 ..... 100 ..... 1110011", "mop.r.2 {rd}, {rs1}", "alu"),
        ("mop_r3", "R", "100000011111 ..... 100 ..... 1110011", "mop.r.3 {rd}, {rs1}", "alu"),
        ("mop_r4", "R", "100001011100 ..... 100 ..... 1110011", "mop.r.4 {rd}, {rs1}", "alu"),
        ("mop_r5", "R", "100001011101 ..... 100 ..... 1110011", "mop.r.5 {rd}, {rs1}", "alu"),
        ("mop_r6", "R", "100001011110 ..... 100 ..... 1110011", "mop.r.6 {rd}, {rs1}", "alu"),
        ("mop_r7", "R", "100001011111 ..... 100 ..... 1110011", "mop.r.7 {rd}, {rs1}", "alu"),
        ("mop_r8", "R", "100010011100 ..... 100 ..... 1110011", "mop.r.8 {rd}, {rs1}", "alu"),
        ("mop_r9", "R", "100010011101 ..... 100 ..... 1110011", "mop.r.9 {rd}, {rs1}", "alu"),
        ("mop_r10", "R", "100010011110 ..... 100 ..... 1110011", "mop.r.10 {rd}, {rs1}", "alu"),
        ("mop_r11", "R", "100010011111 ..... 100 ..... 1110011", "mop.r.11 {rd}, {rs1}", "alu"),
        ("mop_r12", "R", "100011011100 ..... 100 ..... 1110011", "mop.r.12 {rd}, {rs1}", "alu"),
        ("mop_r13", "R", "100011011101 ..... 100 ..... 1110011", "mop.r.13 {rd}, {rs1}", "alu"),
        ("mop_r14", "R", "100011011110 ..... 100 ..... 1110011", "mop.r.14 {rd}, {rs1}", "alu"),
        ("mop_r15", "R", "100011011111 ..... 100 ..... 1110011", "mop.r.15 {rd}, {rs1}", "alu"),
        ("mop_r16", "R", "110000011100 ..... 100 ..... 1110011", "mop.r.16 {rd}, {rs1}", "alu"),
        ("mop_r17", "R", "110000011101 ..... 100 ..... 1110011", "mop.r.17 {rd}, {rs1}", "alu"),
        ("mop_r18", "R", "110000011110 ..... 100 ..... 1110011", "mop.r.18 {rd}, {rs1}", "alu"),
        ("mop_r19", "R", "110000011111 ..... 100 ..... 1110011", "mop.r.19 {rd}, {rs1}", "alu"),
        ("mop_r20", "R", "110001011100 ..... 100 ..... 1110011", "mop.r.20 {rd}, {rs1}", "alu"),
        ("mop_r21", "R", "110001011101 ..... 100 ..... 1110011", "mop.r.21 {rd}, {rs1}", "alu"),
        ("mop_r22", "R", "110001011110 ..... 100 ..... 1110011", "mop.r.22 {rd}, {rs1}", "alu"),
        ("mop_r23", "R", "110001011111 ..... 100 ..... 1110011", "mop.r.23 {rd}, {rs1}", "alu"),
        ("mop_r24", "R", "110010011100 ..... 100 ..... 1110011", "mop.r.24 {rd}, {rs1}", "alu"),
        ("mop_r25", "R", "110010011101 ..... 100 ..... 1110011", "mop.r.25 {rd}, {rs1}", "alu"),
        ("mop_r26", "R", "110010011110 ..... 100 ..... 1110011", "mop.r.26 {rd}, {rs1}", "alu"),
        ("mop_r27", "R", "110010011111 ..... 100 ..... 1110011", "mop.r.27 {rd}, {rs1}", "alu"),
        ("mop_r28", "R", "110011011100 ..... 100 ..... 1110011", "mop.r.28 {rd}, {rs1}", "alu"),
        ("mop_r29", "R", "110011011101 ..... 100 ..... 1110011", "mop.r.29 {rd}, {rs1}", "alu"),
        ("mop_r30", "R", "110011011110 ..... 100 ..... 1110011", "mop.r.30 {rd}, {rs1}", "alu"),
        ("mop_r31", "R", "110011011111 ..... 100 ..... 1110011", "mop.r.31 {rd}, {rs1}", "alu"),
        ("mop_rr0", "R", "1000001 ..... ..... 100 ..... 1110011", "mop.rr.0 {rd}, {rs1}, {rs2}", "alu"),
        ("mop_rr1", "R", "1000011 ..... ..... 100 ..... 1110011", "mop.rr.1 {rd}, {rs1}, {rs2}", "alu"),
        ("mop_rr2", "R", "1000101 ..... ..... 100 ..... 1110011", "mop.rr.2 {rd}, {rs1}, {rs2}", "alu"),
        ("mop_rr3", "R", "1000111 ..... ..... 100 ..... 1110011", "mop.rr.3 {rd}, {rs1}, {rs2}", "alu"),
        ("mop_rr4", "R", "1100001 ..... ..... 100 ..... 1110011", "mop.rr.4 {rd}, {rs1}, {rs2}", "alu"),
        ("mop_rr5", "R", "1100011 ..... ..... 100 ..... 1110011", "mop.rr.5 {rd}, {rs1}, {rs2}", "alu"),
        ("mop_rr6", "R", "1100101 ..... ..... 100 ..... 1110011", "mop.rr.6 {rd}, {rs1}, {rs2}", "alu"),
        ("mop_rr7", "R", "1100111 ..... ..... 100 ..... 1110011", "mop.rr.7 {rd}, {rs1}, {rs2}", "alu"),
        // Zba（アドレス加算・上位ゼロ拡張シフト）
        ("add_uw", "R", "0000100 ..... ..... 000 ..... 0111011", "add.uw {rd}, {rs1}, {rs2}", "alu"),
        ("sh1add", "R", "0010000 ..... ..... 010 ..... 0110011", "sh1add {rd}, {rs1}, {rs2}", "alu"),
        ("sh2add", "R", "0010000 ..... ..... 100 ..... 0110011", "sh2add {rd}, {rs1}, {rs2}", "alu"),
        ("sh3add", "R", "0010000 ..... ..... 110 ..... 0110011", "sh3add {rd}, {rs1}, {rs2}", "alu"),
        ("sh1add_uw", "R", "0010000 ..... ..... 010 ..... 0111011", "sh1add.uw {rd}, {rs1}, {rs2}", "alu"),
        ("sh2add_uw", "R", "0010000 ..... ..... 100 ..... 0111011", "sh2add.uw {rd}, {rs1}, {rs2}", "alu"),
        ("sh3add_uw", "R", "0010000 ..... ..... 110 ..... 0111011", "sh3add.uw {rd}, {rs1}, {rs2}", "alu"),
        ("slli_uw", "I", "000010 ...... ..... 001 ..... 0011011", "slli.uw {rd}, {rs1}, {imm}", "alu"),
        // Zbb（論理・カウント・最小最大・回転・バイト操作）
        ("andn", "R", "0100000 ..... ..... 111 ..... 0110011", "andn {rd}, {rs1}, {rs2}", "alu"),
        ("orn", "R", "0100000 ..... ..... 110 ..... 0110011", "orn {rd}, {rs1}, {rs2}", "alu"),
        ("xnor", "R", "0100000 ..... ..... 100 ..... 0110011", "xnor {rd}, {rs1}, {rs2}", "alu"),
        ("clz", "R", "0110000 00000 ..... 001 ..... 0010011", "clz {rd}, {rs1}", "alu"),
        ("clzw", "R", "0110000 00000 ..... 001 ..... 0011011", "clzw {rd}, {rs1}", "alu"),
        ("ctz", "R", "0110000 00001 ..... 001 ..... 0010011", "ctz {rd}, {rs1}", "alu"),
        ("ctzw", "R", "0110000 00001 ..... 001 ..... 0011011", "ctzw {rd}, {rs1}", "alu"),
        ("cpop", "R", "0110000 00010 ..... 001 ..... 0010011", "cpop {rd}, {rs1}", "alu"),
        ("cpopw", "R", "0110000 00010 ..... 001 ..... 0011011", "cpopw {rd}, {rs1}", "alu"),
        ("max", "R", "0000101 ..... ..... 110 ..... 0110011", "max {rd}, {rs1}, {rs2}", "alu"),
        ("maxu", "R", "0000101 ..... ..... 111 ..... 0110011", "maxu {rd}, {rs1}, {rs2}", "alu"),
        ("min", "R", "0000101 ..... ..... 100 ..... 0110011", "min {rd}, {rs1}, {rs2}", "alu"),
        ("minu", "R", "0000101 ..... ..... 101 ..... 0110011", "minu {rd}, {rs1}, {rs2}", "alu"),
        ("rol", "R", "0110000 ..... ..... 001 ..... 0110011", "rol {rd}, {rs1}, {rs2}", "alu"),
        ("rolw", "R", "0110000 ..... ..... 001 ..... 0111011", "rolw {rd}, {rs1}, {rs2}", "alu"),
        ("ror", "R", "0110000 ..... ..... 101 ..... 0110011", "ror {rd}, {rs1}, {rs2}", "alu"),
        ("rorw", "R", "0110000 ..... ..... 101 ..... 0111011", "rorw {rd}, {rs1}, {rs2}", "alu"),
        ("rori", "I", "011000 ...... ..... 101 ..... 0010011", "rori {rd}, {rs1}, {imm}", "alu"),
        ("roriw", "I", "011000 ...... ..... 101 ..... 0011011", "roriw {rd}, {rs1}, {imm}", "alu"),
        ("orc_b", "R", "0010100 00111 ..... 101 ..... 0010011", "orc.b {rd}, {rs1}", "alu"),
        ("rev8", "R", "0110101 11000 ..... 101 ..... 0010011", "rev8 {rd}, {rs1}", "alu"),
        ("sext_b", "R", "0110000 00100 ..... 001 ..... 0010011", "sext.b {rd}, {rs1}", "alu"),
        ("sext_h", "R", "0110000 00101 ..... 001 ..... 0010011", "sext.h {rd}, {rs1}", "alu"),
        ("zext_h", "R", "0000100 00000 ..... 100 ..... 0111011", "zext.h {rd}, {rs1}", "alu"),
        // Zbc（キャリーレス乗算）
        ("clmul", "R", "0000101 ..... ..... 001 ..... 0110011", "clmul {rd}, {rs1}, {rs2}", "alu"),
        ("clmulh", "R", "0000101 ..... ..... 011 ..... 0110011", "clmulh {rd}, {rs1}, {rs2}", "alu"),
        ("clmulr", "R", "0000101 ..... ..... 010 ..... 0110011", "clmulr {rd}, {rs1}, {rs2}", "alu"),
        // Zbs（単一ビット操作）
        ("bclr", "R", "0100100 ..... ..... 001 ..... 0110011", "bclr {rd}, {rs1}, {rs2}", "alu"),
        ("bclri", "I", "010010 ...... ..... 001 ..... 0010011", "bclri {rd}, {rs1}, {imm}", "alu"),
        ("bext", "R", "0100100 ..... ..... 101 ..... 0110011", "bext {rd}, {rs1}, {rs2}", "alu"),
        ("bexti", "I", "010010 ...... ..... 101 ..... 0010011", "bexti {rd}, {rs1}, {imm}", "alu"),
        ("binv", "R", "0110100 ..... ..... 001 ..... 0110011", "binv {rd}, {rs1}, {rs2}", "alu"),
        ("binvi", "I", "011010 ...... ..... 001 ..... 0010011", "binvi {rd}, {rs1}, {imm}", "alu"),
        ("bset", "R", "0010100 ..... ..... 001 ..... 0110011", "bset {rd}, {rs1}, {rs2}", "alu"),
        ("bseti", "I", "001010 ...... ..... 001 ..... 0010011", "bseti {rd}, {rs1}, {imm}", "alu"),
        // OP-32
        ("addw", "R", "0000000 ..... ..... 000 ..... 0111011", "addw {rd}, {rs1}, {rs2}", "alu"),
        ("subw", "R", "0100000 ..... ..... 000 ..... 0111011", "subw {rd}, {rs1}, {rs2}", "alu"),
        ("sllw", "R", "0000000 ..... ..... 001 ..... 0111011", "sllw {rd}, {rs1}, {rs2}", "alu"),
        ("srlw", "R", "0000000 ..... ..... 101 ..... 0111011", "srlw {rd}, {rs1}, {rs2}", "alu"),
        ("sraw", "R", "0100000 ..... ..... 101 ..... 0111011", "sraw {rd}, {rs1}, {rs2}", "alu"),
        // SYSTEM。fence の fm/pred/succ と rd/rs1 を問わず同じ命令として
        // 扱う。予約・ヒント形も単一ハートの意味論では順序付けだけなので、
        // 意味論は共通の no-op で足りる。
        ("fence", "I", "............ ..... 000 ..... 0001111", "fence", "system"),
        ("fence_i", "I", "............ ..... 001 ..... 0001111", "fence.i", "system"),
        ("ecall", "I", "000000000000 ..... 000 ..... 1110011", "ecall", "system"),
        ("ebreak", "I", "000000000001 ..... 000 ..... 1110011", "ebreak", "system"),
        // M（乗除算。funct7=0000001）
        ("mul", "R", "0000001 ..... ..... 000 ..... 0110011", "mul {rd}, {rs1}, {rs2}", "mult"),
        ("mulh", "R", "0000001 ..... ..... 001 ..... 0110011", "mulh {rd}, {rs1}, {rs2}", "mult"),
        ("mulhsu", "R", "0000001 ..... ..... 010 ..... 0110011", "mulhsu {rd}, {rs1}, {rs2}", "mult"),
        ("mulhu", "R", "0000001 ..... ..... 011 ..... 0110011", "mulhu {rd}, {rs1}, {rs2}", "mult"),
        ("div", "R", "0000001 ..... ..... 100 ..... 0110011", "div {rd}, {rs1}, {rs2}", "div"),
        ("divu", "R", "0000001 ..... ..... 101 ..... 0110011", "divu {rd}, {rs1}, {rs2}", "div"),
        ("rem", "R", "0000001 ..... ..... 110 ..... 0110011", "rem {rd}, {rs1}, {rs2}", "div"),
        ("remu", "R", "0000001 ..... ..... 111 ..... 0110011", "remu {rd}, {rs1}, {rs2}", "div"),
        ("mulw", "R", "0000001 ..... ..... 000 ..... 0111011", "mulw {rd}, {rs1}, {rs2}", "mult"),
        ("divw", "R", "0000001 ..... ..... 100 ..... 0111011", "divw {rd}, {rs1}, {rs2}", "div"),
        ("divuw", "R", "0000001 ..... ..... 101 ..... 0111011", "divuw {rd}, {rs1}, {rs2}", "div"),
        ("remw", "R", "0000001 ..... ..... 110 ..... 0111011", "remw {rd}, {rs1}, {rs2}", "div"),
        ("remuw", "R", "0000001 ..... ..... 111 ..... 0111011", "remuw {rd}, {rs1}, {rs2}", "div"),
        // SYSTEM の CSR 系（Zicsr）
        ("csrrw", "C", "............ ..... 001 ..... 1110011", "csrrw {rd}, {csr}, {rs1}", "csr"),
        ("csrrs", "C", "............ ..... 010 ..... 1110011", "csrrs {rd}, {csr}, {rs1}", "csr"),
        ("csrrc", "C", "............ ..... 011 ..... 1110011", "csrrc {rd}, {csr}, {rs1}", "csr"),
        ("csrrwi", "CI", "............ ..... 101 ..... 1110011", "csrrwi {rd}, {csr}, {uimm}", "csr"),
        ("csrrsi", "CI", "............ ..... 110 ..... 1110011", "csrrsi {rd}, {csr}, {uimm}", "csr"),
        ("csrrci", "CI", "............ ..... 111 ..... 1110011", "csrrci {rd}, {csr}, {uimm}", "csr"),
        // A（不可分操作。aq/rl は単一ホストスレッドでは不可分性に影響しない
        // ため無視する。Ref: SPEC-RISCV-UNPRIV (20250508) §A。）
        ("lr_w", "I", "00010..00000 ..... 010 ..... 0101111", "lr_w {rd}, ({rs1})", "atomic"),
        ("lr_d", "I", "00010..00000 ..... 011 ..... 0101111", "lr_d {rd}, ({rs1})", "atomic"),
        ("sc_w", "R", "00011.. ..... ..... 010 ..... 0101111", "sc_w {rd}, {rs1}, {rs2}", "atomic"),
        ("sc_d", "R", "00011.. ..... ..... 011 ..... 0101111", "sc_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amoswap_w", "R", "00001.. ..... ..... 010 ..... 0101111", "amoswap_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amoadd_w", "R", "00000.. ..... ..... 010 ..... 0101111", "amoadd_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amoxor_w", "R", "00100.. ..... ..... 010 ..... 0101111", "amoxor_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amoand_w", "R", "01100.. ..... ..... 010 ..... 0101111", "amoand_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amoor_w", "R", "01000.. ..... ..... 010 ..... 0101111", "amoor_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amomin_w", "R", "10000.. ..... ..... 010 ..... 0101111", "amomin_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amomax_w", "R", "10100.. ..... ..... 010 ..... 0101111", "amomax_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amominu_w", "R", "11000.. ..... ..... 010 ..... 0101111", "amominu_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amomaxu_w", "R", "11100.. ..... ..... 010 ..... 0101111", "amomaxu_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amoswap_d", "R", "00001.. ..... ..... 011 ..... 0101111", "amoswap_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amoadd_d", "R", "00000.. ..... ..... 011 ..... 0101111", "amoadd_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amoxor_d", "R", "00100.. ..... ..... 011 ..... 0101111", "amoxor_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amoand_d", "R", "01100.. ..... ..... 011 ..... 0101111", "amoand_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amoor_d", "R", "01000.. ..... ..... 011 ..... 0101111", "amoor_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amomin_d", "R", "10000.. ..... ..... 011 ..... 0101111", "amomin_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amomax_d", "R", "10100.. ..... ..... 011 ..... 0101111", "amomax_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amominu_d", "R", "11000.. ..... ..... 011 ..... 0101111", "amominu_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amomaxu_d", "R", "11100.. ..... ..... 011 ..... 0101111", "amomaxu_d {rd}, {rs1}, {rs2}", "atomic"),
        // F（単精度浮動小数点。fmt=00。rm は RNE 固定で無視する）
        ("flw", "I", "............ ..... 010 ..... 0000111", "flw {rd}, {imm}({rs1})", "fload"),
        ("fsw", "S", "....... ..... ..... 010 ..... 0100111", "fsw {rs2}, {imm}({rs1})", "fstore"),
        ("fadd_s", "R", "0000000 ..... ..... ... ..... 1010011", "fadd.s {rd}, {rs1}, {rs2}", "falu_s"),
        ("fsub_s", "R", "0000100 ..... ..... ... ..... 1010011", "fsub.s {rd}, {rs1}, {rs2}", "falu_s"),
        ("fmul_s", "R", "0001000 ..... ..... ... ..... 1010011", "fmul.s {rd}, {rs1}, {rs2}", "falu_s"),
        ("fdiv_s", "R", "0001100 ..... ..... ... ..... 1010011", "fdiv.s {rd}, {rs1}, {rs2}", "fdiv_s"),
        // 積和融合（R4形式。funct2 で単精度/倍精度を区別する。rm は RNE 固定）
        ("fmadd_s", "R4", "..... 00 ..... ..... ... ..... 1000011", "fmadd.s {rd}, {rs1}, {rs2}, {rs3}", "falu_s"),
        ("fmsub_s", "R4", "..... 00 ..... ..... ... ..... 1000111", "fmsub.s {rd}, {rs1}, {rs2}, {rs3}", "falu_s"),
        ("fnmsub_s", "R4", "..... 00 ..... ..... ... ..... 1001011", "fnmsub.s {rd}, {rs1}, {rs2}, {rs3}", "falu_s"),
        ("fnmadd_s", "R4", "..... 00 ..... ..... ... ..... 1001111", "fnmadd.s {rd}, {rs1}, {rs2}, {rs3}", "falu_s"),
        ("fmadd_d", "R4", "..... 01 ..... ..... ... ..... 1000011", "fmadd.d {rd}, {rs1}, {rs2}, {rs3}", "falu_d"),
        ("fmsub_d", "R4", "..... 01 ..... ..... ... ..... 1000111", "fmsub.d {rd}, {rs1}, {rs2}, {rs3}", "falu_d"),
        ("fnmsub_d", "R4", "..... 01 ..... ..... ... ..... 1001011", "fnmsub.d {rd}, {rs1}, {rs2}, {rs3}", "falu_d"),
        ("fnmadd_d", "R4", "..... 01 ..... ..... ... ..... 1001111", "fnmadd.d {rd}, {rs1}, {rs2}, {rs3}", "falu_d"),
        ("fsqrt_s", "R", "0101100 00000 ..... ... ..... 1010011", "fsqrt.s {rd}, {rs1}", "fsqrt_s"),
        ("fsgnj_s", "R", "0010000 ..... ..... 000 ..... 1010011", "fsgnj.s {rd}, {rs1}, {rs2}", "fsj"),
        ("fsgnjn_s", "R", "0010000 ..... ..... 001 ..... 1010011", "fsgnjn.s {rd}, {rs1}, {rs2}", "fsj"),
        ("fsgnjx_s", "R", "0010000 ..... ..... 010 ..... 1010011", "fsgnjx.s {rd}, {rs1}, {rs2}", "fsj"),
        ("fmin_s", "R", "0010100 ..... ..... 000 ..... 1010011", "fmin.s {rd}, {rs1}, {rs2}", "fminmax"),
        ("fmax_s", "R", "0010100 ..... ..... 001 ..... 1010011", "fmax.s {rd}, {rs1}, {rs2}", "fminmax"),
        ("fcvt_w_s", "R", "1100000 00000 ..... ... ..... 1010011", "fcvt.w.s {rd}, {rs1}", "fcvt"),
        ("fcvt_wu_s", "R", "1100000 00001 ..... ... ..... 1010011", "fcvt.wu.s {rd}, {rs1}", "fcvt"),
        ("fcvt_l_s", "R", "1100000 00010 ..... ... ..... 1010011", "fcvt.l.s {rd}, {rs1}", "fcvt"),
        ("fcvt_lu_s", "R", "1100000 00011 ..... ... ..... 1010011", "fcvt.lu.s {rd}, {rs1}", "fcvt"),
        ("fmv_x_w", "R", "1110000 00000 ..... 000 ..... 1010011", "fmv.x.w {rd}, {rs1}", "fsj"),
        ("fclass_s", "R", "1110000 00000 ..... 001 ..... 1010011", "fclass.s {rd}, {rs1}", "fcmp"),
        ("feq_s", "R", "1010000 ..... ..... 010 ..... 1010011", "feq.s {rd}, {rs1}, {rs2}", "fcmp"),
        ("flt_s", "R", "1010000 ..... ..... 001 ..... 1010011", "flt.s {rd}, {rs1}, {rs2}", "fcmp"),
        ("fle_s", "R", "1010000 ..... ..... 000 ..... 1010011", "fle.s {rd}, {rs1}, {rs2}", "fcmp"),
        ("fcvt_s_w", "R", "1101000 00000 ..... ... ..... 1010011", "fcvt.s.w {rd}, {rs1}", "fcvt"),
        ("fcvt_s_wu", "R", "1101000 00001 ..... ... ..... 1010011", "fcvt.s.wu {rd}, {rs1}", "fcvt"),
        ("fcvt_s_l", "R", "1101000 00010 ..... ... ..... 1010011", "fcvt.s.l {rd}, {rs1}", "fcvt"),
        ("fcvt_s_lu", "R", "1101000 00011 ..... ... ..... 1010011", "fcvt.s.lu {rd}, {rs1}", "fcvt"),
        ("fmv_w_x", "R", "1111000 00000 ..... 000 ..... 1010011", "fmv.w.x {rd}, {rs1}", "fsj"),
        // D（倍精度浮動小数点。fmt=01）
        ("fld", "I", "............ ..... 011 ..... 0000111", "fld {rd}, {imm}({rs1})", "fload"),
        ("fsd", "S", "....... ..... ..... 011 ..... 0100111", "fsd {rs2}, {imm}({rs1})", "fstore"),
        ("fadd_d", "R", "0000001 ..... ..... ... ..... 1010011", "fadd.d {rd}, {rs1}, {rs2}", "falu_d"),
        ("fsub_d", "R", "0000101 ..... ..... ... ..... 1010011", "fsub.d {rd}, {rs1}, {rs2}", "falu_d"),
        ("fmul_d", "R", "0001001 ..... ..... ... ..... 1010011", "fmul.d {rd}, {rs1}, {rs2}", "falu_d"),
        ("fdiv_d", "R", "0001101 ..... ..... ... ..... 1010011", "fdiv.d {rd}, {rs1}, {rs2}", "fdiv_d"),
        ("fsqrt_d", "R", "0101101 00000 ..... ... ..... 1010011", "fsqrt.d {rd}, {rs1}", "fsqrt_d"),
        ("fsgnj_d", "R", "0010001 ..... ..... 000 ..... 1010011", "fsgnj.d {rd}, {rs1}, {rs2}", "fsj"),
        ("fsgnjn_d", "R", "0010001 ..... ..... 001 ..... 1010011", "fsgnjn.d {rd}, {rs1}, {rs2}", "fsj"),
        ("fsgnjx_d", "R", "0010001 ..... ..... 010 ..... 1010011", "fsgnjx.d {rd}, {rs1}, {rs2}", "fsj"),
        ("fmin_d", "R", "0010101 ..... ..... 000 ..... 1010011", "fmin.d {rd}, {rs1}, {rs2}", "fminmax"),
        ("fmax_d", "R", "0010101 ..... ..... 001 ..... 1010011", "fmax.d {rd}, {rs1}, {rs2}", "fminmax"),
        ("fcvt_w_d", "R", "1100001 00000 ..... ... ..... 1010011", "fcvt.w.d {rd}, {rs1}", "fcvt"),
        ("fcvt_wu_d", "R", "1100001 00001 ..... ... ..... 1010011", "fcvt.wu.d {rd}, {rs1}", "fcvt"),
        ("fcvt_l_d", "R", "1100001 00010 ..... ... ..... 1010011", "fcvt.l.d {rd}, {rs1}", "fcvt"),
        ("fcvt_lu_d", "R", "1100001 00011 ..... ... ..... 1010011", "fcvt.lu.d {rd}, {rs1}", "fcvt"),
        ("fmv_x_d", "R", "1110001 00000 ..... 000 ..... 1010011", "fmv.x.d {rd}, {rs1}", "fsj"),
        ("fclass_d", "R", "1110001 00000 ..... 001 ..... 1010011", "fclass.d {rd}, {rs1}", "fcmp"),
        ("feq_d", "R", "1010001 ..... ..... 010 ..... 1010011", "feq.d {rd}, {rs1}, {rs2}", "fcmp"),
        ("flt_d", "R", "1010001 ..... ..... 001 ..... 1010011", "flt.d {rd}, {rs1}, {rs2}", "fcmp"),
        ("fle_d", "R", "1010001 ..... ..... 000 ..... 1010011", "fle.d {rd}, {rs1}, {rs2}", "fcmp"),
        ("fcvt_d_w", "R", "1101001 00000 ..... ... ..... 1010011", "fcvt.d.w {rd}, {rs1}", "fcvt"),
        ("fcvt_d_wu", "R", "1101001 00001 ..... ... ..... 1010011", "fcvt.d.wu {rd}, {rs1}", "fcvt"),
        ("fcvt_d_l", "R", "1101001 00010 ..... ... ..... 1010011", "fcvt.d.l {rd}, {rs1}", "fcvt"),
        ("fcvt_d_lu", "R", "1101001 00011 ..... ... ..... 1010011", "fcvt.d.lu {rd}, {rs1}", "fcvt"),
        ("fmv_d_x", "R", "1111001 00000 ..... 000 ..... 1010011", "fmv.d.x {rd}, {rs1}", "fsj"),
        ("fcvt_s_d", "R", "0100000 00001 ..... ... ..... 1010011", "fcvt.s.d {rd}, {rs1}", "fcvt"),
        ("fcvt_d_s", "R", "0100001 00000 ..... ... ..... 1010011", "fcvt.d.s {rd}, {rs1}", "fcvt"),
        // C（圧縮。16ビット。funct3とop下位2ビットで区別できる衝突なし subset）
        // Ref: SPEC-RISCV-UNPRIV (20250508) §C.
        ("c_addi4spn", "R", "000 ........ ... 00", "c.addi4spn {rd}, {imm}", "alu"),
        // Zcb。CL 形式の byte/half アクセス。bit6/bit5 の固定値で
        // 符号拡張の有無と即値位置を分ける。
        ("c_lbu", "R", "100 0 00 ... . . ... 00", "c.lbu {rd}, {imm}({rs1})", "load"),
        ("c_lhu", "R", "100 0 01 ... 0 . ... 00", "c.lhu {rd}, {imm}({rs1})", "load"),
        ("c_lh", "R", "100 0 01 ... 1 . ... 00", "c.lh {rd}, {imm}({rs1})", "load"),
        ("c_sb", "R", "100 0 10 ... . . ... 00", "c.sb {rs2}, {imm}({rs1})", "store"),
        ("c_sh", "R", "100 0 11 ... 0 . ... 00", "c.sh {rs2}, {imm}({rs1})", "store"),
        // Zcb の単項形と乗算形。bits6:2 が 24〜29 の単項形は
        // rd'=rs1' として同じレジスタを更新する。
        ("c_zext_b", "R", "100 1 11 ... 11000 01", "c.zext.b {rd}", "alu"),
        ("c_sext_b", "R", "100 1 11 ... 11001 01", "c.sext.b {rd}", "alu"),
        ("c_zext_h", "R", "100 1 11 ... 11010 01", "c.zext.h {rd}", "alu"),
        ("c_sext_h", "R", "100 1 11 ... 11011 01", "c.sext.h {rd}", "alu"),
        ("c_zext_w", "R", "100 1 11 ... 11100 01", "c.zext.w {rd}", "alu"),
        ("c_not", "R", "100 1 11 ... 11101 01", "c.not {rd}", "alu"),
        ("c_mul", "R", "100 1 11 ... 10 ... 01", "c.mul {rd}, {rs2}", "alu"),
        ("c_fld", "R", "001 ........ ... 00", "c.fld {rd}, {imm}({rs1})", "fload"),
        ("c_fsd", "R", "101 ........ ... 00", "c.fsd {rs2}, {imm}({rs1})", "fstore"),
        ("c_lw", "R", "010 ........ ... 00", "c.lw {rd}, {imm}({rs1})", "load"),
        ("c_ld", "R", "011 ........ ... 00", "c.ld {rd}, {imm}({rs1})", "load"),
        ("c_sw", "R", "110 ........ ... 00", "c.sw {rs2}, {imm}({rs1})", "store"),
        ("c_sd", "R", "111 ........ ... 00", "c.sd {rs2}, {imm}({rs1})", "store"),
        ("c_addi", "R", "000 ........ ... 01", "c.addi {rd}, {imm}", "alu"),
        ("c_addiw", "R", "001 ........ ... 01", "c.addiw {rd}, {imm}", "alu"),
        ("c_li", "R", "010 ........ ... 01", "c.li {rd}, {imm}", "alu"),
        ("c_lui_addi16sp", "R", "011 ........ ... 01", "c.lui/addi16sp {rd}, {imm}", "alu"),
        ("c_srli", "R", "100 . 00 ... ..... 01", "c.srli {rd}, {imm}", "alu"),
        ("c_srai", "R", "100 . 01 ... ..... 01", "c.srai {rd}, {imm}", "alu"),
        ("c_andi", "R", "100 . 10 ... ..... 01", "c.andi {rd}, {imm}", "alu"),
        ("c_sub", "R", "100 0 11 ... 00 ... 01", "c.sub {rd}, {rs2}", "alu"),
        ("c_xor", "R", "100 0 11 ... 01 ... 01", "c.xor {rd}, {rs2}", "alu"),
        ("c_or", "R", "100 0 11 ... 10 ... 01", "c.or {rd}, {rs2}", "alu"),
        ("c_and", "R", "100 0 11 ... 11 ... 01", "c.and {rd}, {rs2}", "alu"),
        ("c_subw", "R", "100 1 11 ... 00 ... 01", "c.subw {rd}, {rs2}", "alu"),
        ("c_addw", "R", "100 1 11 ... 01 ... 01", "c.addw {rd}, {rs2}", "alu"),
        ("c_j", "R", "101 ........ ... 01", "c.j {imm}", "jump"),
        ("c_beqz", "R", "110 ........ ... 01", "c.beqz {rs1}, {imm}", "branch"),
        ("c_bnez", "R", "111 ........ ... 01", "c.bnez {rs1}, {imm}", "branch"),
        ("c_slli", "R", "000 ........ ... 10", "c.slli {rd}, {imm}", "alu"),
        ("c_lwsp", "R", "010 ........ ... 10", "c.lwsp {rd}, {imm}", "load"),
        ("c_ldsp", "R", "011 ........ ... 10", "c.ldsp {rd}, {imm}", "load"),
        ("c_fldsp", "R", "001 ........ ... 10", "c.fldsp {rd}, {imm}", "fload"),
        ("c_fsdsp", "R", "101 ........ ... 10", "c.fsdsp {rs2}, {imm}", "fstore"),
        ("c_swsp", "R", "110 ........ ... 10", "c.swsp {rs2}, {imm}", "store"),
        ("c_sdsp", "R", "111 ........ ... 10", "c.sdsp {rs2}, {imm}", "store"),
    ];
    let flag = |name: &str| Pred::Flag(name.to_string());
    let pred_of = |reqs: &[&str]| match reqs {
        [] => Pred::True,
        [one] => flag(one),
        many => Pred::All(many.iter().map(|f| flag(f)).collect()),
    };
    let is_double = |name: &str| {
        (name.starts_with("fcvt_d_") || name.ends_with("_d"))
            || matches!(
                name,
                "fld" | "fsd" | "fmv_d_x" | "fcvt_d_s" | "c_fld" | "c_fsd" | "c_fldsp" | "c_fsdsp"
            )
    };
    for (name, format, pattern, syntax, timing) in insns {
        let mut reqs = Vec::new();
        if matches!(*timing, "mult" | "div") {
            reqs.push("m");
        }
        if matches!(
            *name,
            "add_uw" | "sh1add" | "sh2add" | "sh3add" | "sh1add_uw" | "sh2add_uw" | "sh3add_uw" | "slli_uw"
        ) {
            reqs.push("zba");
        }
        if matches!(
            *name,
            "andn" | "orn" | "xnor" | "clz" | "clzw" | "ctz" | "ctzw" | "cpop" | "cpopw"
                | "max" | "maxu" | "min" | "minu" | "rol" | "rolw" | "ror" | "rorw" | "rori" | "roriw"
                | "orc_b" | "rev8" | "sext_b" | "sext_h" | "zext_h"
        ) {
            reqs.push("zbb");
        }
        if matches!(*name, "clmul" | "clmulh" | "clmulr") {
            reqs.push("zbc");
        }
        if matches!(*name, "bclr" | "bclri" | "bext" | "bexti" | "binv" | "binvi" | "bset" | "bseti") {
            reqs.push("zbs");
        }
        if name.starts_with("mop_") {
            reqs.push("zimop");
        }
        if name.starts_with("czero_") {
            reqs.push("zicond");
        }
        if matches!(
            *name,
            "c_lbu"
                | "c_lhu"
                | "c_lh"
                | "c_sb"
                | "c_sh"
                | "c_zext_b"
                | "c_zext_h"
                | "c_not"
        ) {
            reqs.push("zcb");
        }
        if matches!(*name, "c_sext_b" | "c_sext_h") {
            reqs.push("zcb");
            reqs.push("zbb");
        }
        if *name == "c_zext_w" {
            reqs.push("zcb");
            reqs.push("zba");
        }
        if *name == "c_mul" {
            reqs.push("zcb");
            reqs.push("m");
        }
        if *timing == "atomic" {
            reqs.push("a");
        }
        if *timing == "csr" {
            reqs.push("zicsr");
        }
        if *name == "fence_i" {
            reqs.push("zifencei");
        }
        if timing.starts_with('f') {
            reqs.push(if is_double(name) { "d" } else { "f" });
        }
        if name.starts_with("c_") {
            reqs.push("c");
        }
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: pred_of(&reqs),
            wheres: vec![],
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }
    // RV32のC.JALはRV64のC.ADDIWと同じ符号化。whenで区別し、
    // 生成デコーダ（decode_model）がモデルで解決する（ADR-0006）。
    // Ref: SPEC-RISCV-UNPRIV (20250508) §C.
    m.insns.push(Insn {
        name: "c_jal".to_string(),
        format: "R".to_string(),
        pattern: Pattern::parse("001 ........ ... 01").expect("valid pattern"),
        when: Pred::All(vec![
            Pred::Flag("rv32".to_string()),
            Pred::Flag("c".to_string()),
        ]),
        wheres: vec![],
        syntax: "c.jal {imm}".to_string(),
        timing: "jump".to_string(),
    });
    // JR群（funct3=100・op=10）。レジスタ値で区別するため where で受ける。
    // Ref: SPEC-RISCV-UNPRIV (20250508) §C.
    let cr = |op: WhereOp, field: &str, value: u128| WhereClause {
        field: field.to_string(),
        op,
        rhs: WhereRhs::Lit(value),
    };
    for (name, bit12, wheres, syntax, timing) in [
        (
            "c_jr",
            '0',
            vec![cr(WhereOp::Ne, "cr_rs1", 0), cr(WhereOp::Eq, "cr_rs2", 0)],
            "c.jr {rs1}",
            "jump",
        ),
        (
            "c_mv",
            '0',
            // rd=x0 の HINT も同じ符号化で、実行影響はない。
            vec![cr(WhereOp::Ne, "cr_rs2", 0)],
            "c.mv {rd}, {rs2}",
            "alu",
        ),
        (
            "c_jalr",
            '1',
            vec![cr(WhereOp::Ne, "cr_rs1", 0), cr(WhereOp::Eq, "cr_rs2", 0)],
            "c.jalr {rs1}",
            "jump",
        ),
        (
            "c_add",
            '1',
            // rd=x0 の HINT も同じ符号化で、実行影響はない。
            vec![cr(WhereOp::Ne, "cr_rs2", 0)],
            "c.add {rd}, {rs2}",
            "alu",
        ),
        (
            "c_ebreak",
            '1',
            vec![cr(WhereOp::Eq, "cr_rs1", 0), cr(WhereOp::Eq, "cr_rs2", 0)],
            "c.ebreak",
            "system",
        ),
    ] {
        m.insns.push(Insn {
            name: name.to_string(),
            format: "CR".to_string(),
            pattern: Pattern::parse(&format!("100 {bit12} ..... ..... 10"))
                .expect("valid pattern"),
            when: Pred::Flag("c".to_string()),
            wheres,
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }
    // RV32の単精度ロードストア（RV64の倍精度と同符号化）。whenで区別する。
    // Ref: SPEC-RISCV-UNPRIV (20250508) §C.
    for (name, pattern, syntax, timing) in [
        ("c_flw", "011 ........ ... 00", "c.flw {rd}, {imm}({rs1})", "fload"),
        ("c_fsw", "111 ........ ... 00", "c.fsw {rs2}, {imm}({rs1})", "fstore"),
        ("c_flwsp", "011 ........ ... 10", "c.flwsp {rd}, {imm}", "fload"),
        ("c_fswsp", "111 ........ ... 10", "c.fswsp {rs2}, {imm}", "fstore"),
    ] {
        m.insns.push(Insn {
            name: name.to_string(),
            format: "R".to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::All(vec![
                Pred::Flag("rv32".to_string()),
                Pred::Flag("c".to_string()),
                Pred::Flag("f".to_string()),
            ]),
            wheres: vec![],
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }
    // RV64限定命令にrv64注記を付ける。生成デコーダ（decode_model）が
    // モデルで解決する（ADR-0006）。
    // Ref: SPEC-RISCV-UNPRIV (20250508).
    for insn in m.insns.iter_mut() {
        let rv64_only = matches!(
            insn.name.as_str(),
            "ld" | "lwu"
                | "sd" | "addiw"
                | "slliw" | "srliw"
                | "sraiw" | "addw"
                | "subw" | "sllw"
                | "srlw" | "sraw"
                | "mulw" | "divw"
                | "divuw" | "remw"
                | "remuw" | "lr_d"
                | "sc_d" | "amoswap_d"
                | "amoadd_d" | "amoxor_d"
                | "amoand_d" | "amoor_d"
                | "amomin_d" | "amomax_d"
                | "amominu_d" | "amomaxu_d"
                | "c_ld" | "c_sd"
                | "c_addiw" | "c_ldsp"
                | "c_zext_w" | "add_uw"
                | "sh1add_uw" | "sh2add_uw"
                | "sh3add_uw" | "slli_uw"
                | "clzw" | "ctzw"
                | "cpopw" | "rolw"
                | "rorw" | "roriw"
                | "rev8" | "zext_h"
                | "rori" | "bclri"
                | "bexti" | "binvi"
                | "bseti"
                | "c_sdsp"
                | "fcvt_l_s" | "fcvt_lu_s"
                | "fcvt_s_l" | "fcvt_s_lu"
                | "fcvt_l_d" | "fcvt_lu_d"
                | "fcvt_d_l" | "fcvt_d_lu"
                | "fmv_x_d" | "fmv_d_x"
        );
        if rv64_only {
            insn.when = if insn.when == Pred::True {
                Pred::Flag("rv64".to_string())
            } else {
                Pred::All(vec![
                    insn.when.clone(),
                    Pred::Flag("rv64".to_string()),
                ])
            };
        }
    }
    m
}
