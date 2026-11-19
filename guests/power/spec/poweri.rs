// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Power ISA（64 ビット・ELFv2・ユーザーモード）の ISADL モデル。
//
// 試作の粗分類は「主オペコード（bits[31:26]）」で分け、細かい命令
// （XO フィールドや補助ビット）の振り分けは意味論側（`sem` の各
// エントリ）が行う。ARM の試作と同じ構造である。
// 出典は SPEC-POWER-ISA（Power ISA v3.1C）である。
// Ref: SPEC-POWER-ISA (v3.1C).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// Power の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in [
        "alu", "load", "store", "branch", "mult", "div", "system", "fp", "vsx", "cr",
    ] {
        m.timing_classes.push(class.to_string());
    }

    // 機能と CPU モデル。ppc64le ユーザーモードの必須集合を generic に持つ。
    // Ref: SPEC-POWER-ISA (v3.1C), SPEC-POWER-ABI (ELFv2 r1.5).
    for name in ["fp", "altivec", "vsx"] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: vec![],
            conflicts: vec![],
        });
    }
    m.models.push(ModelDef {
            params: vec![],
        name: "generic".to_string(),
        parent: String::new(),
        add_features: ["fp", "altivec", "vsx"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        remove_features: Vec::new(),
        ident: vec![],
    });

    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: false,
        prefix: Some("r".to_string()),
    });

    // 形式。オペランドのメタデータのみ（解読はパターンの仕事）。
    m.formats.push(Format {
        name: "FN".to_string(),
        fields: vec![],
        operands: vec![],
    });

    // (名前, 形式, パターン, 構文, 分類)。パターンは 6 ビットの主
    // オペコードだけを固定し、XO・拡張ビットは意味論が読む。
    // 数値は Power ISA Book I/II/III のオペコード表に従う。
    // Ref: SPEC-POWER-ISA (v3.1C).
    let insns: &[(&str, u8, &str)] = &[
        ("tdi", 2, "system"),
        ("twi", 3, "system"),
        ("x4", 4, "vsx"), // AltiVec/VMX・VA/VX 形式のベクタ命令群。
        ("mulli", 7, "mult"),
        ("subfic", 8, "alu"),
        ("cmpli", 10, "alu"),
        ("cmpwi", 11, "alu"),
        ("addic", 12, "alu"),
        ("addic_rc", 13, "alu"),
        ("addi", 14, "alu"),
        ("addis", 15, "alu"),
        ("bc", 16, "branch"),
        ("sc", 17, "system"),
        ("b", 18, "branch"),
        ("x19", 19, "branch"), // bclr/bcctr/cr論理/isync 等。
        ("rlwimi", 20, "alu"),
        ("rlwinm", 21, "alu"),
        ("rlwnm", 23, "alu"),
        ("ori", 24, "alu"),
        ("oris", 25, "alu"),
        ("xori", 26, "alu"),
        ("xoris", 27, "alu"),
        ("andi_rc", 28, "alu"),
        ("andis_rc", 29, "alu"),
        ("x30", 30, "alu"),  // rldicl/rldicr/rldic/rldimi（MD 形式）。
        ("x31", 31, "alu"),  // X 形式の整数・ロードストア・予約・SPR 群。
        ("lwz", 32, "load"),
        ("lwzu", 33, "load"),
        ("lbz", 34, "load"),
        ("lbzu", 35, "load"),
        ("stw", 36, "store"),
        ("stwu", 37, "store"),
        ("stb", 38, "store"),
        ("stbu", 39, "store"),
        ("lhz", 40, "load"),
        ("lhzu", 41, "load"),
        ("lha", 42, "load"),
        ("lhau", 43, "load"),
        ("sth", 44, "store"),
        ("sthu", 45, "store"),
        ("lmw", 46, "load"),
        ("stmw", 47, "store"),
        ("lfs", 48, "load"),
        ("lfsu", 49, "load"),
        ("lfd", 50, "load"),
        ("lfdu", 51, "load"),
        ("stfs", 52, "store"),
        ("stfsu", 53, "store"),
        ("stfd", 54, "store"),
        ("stfdu", 55, "store"),
        ("x56", 56, "load"),  // lq（DQ 形式の 128 ビットロード）。
        ("x58", 58, "load"),  // ld/ldu/lwa（DS 形式）。
        ("x59", 59, "fp"),    // 単精度 FP と lfiwax/stfiwx 等。
        ("x60", 60, "vsx"),   // VSX の XX 形式（xsadddp/xxlor 等）。
        ("x61", 61, "vsx"),   // lxv/stxv（DQ 形式の 128 ビット VSX）。
        ("x62", 62, "store"), // std/stdu（DS 形式）。
        ("x63", 63, "fp"),    // 倍精度 FP と fmadd/fctid/mffs 等。
    ];

    for (name, op, timing) in insns {
        let pattern = format!("{op:06b} {}", ".".repeat(26));
        m.insns.push(Insn {
            name: name.to_string(),
            format: "FN".to_string(),
            pattern: Pattern::parse(&pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: vec![],
            syntax: name.to_string(),
            timing: timing.to_string(),
        });
    }
    m
}
