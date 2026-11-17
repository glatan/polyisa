// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// ARM（AArch32・ARM 状態）の命令集合。Thumb/Thumb-2 は対象外。
//
// A32 の解読は大きな符号化領域で分ける試作の粗分類である。
// 各 Insn は「領域」を表し、細かい命令の振り分けは意味論側
// （`sem` の各エントリ）が追加の固定ビットで行う。
//
// - cond(bits[31:28])=1111 は ARMv7 以降の無条件領域で、条件付き領域と
//   ビットが重なる。領域を両立させるため、条件付きの各 Insn は
//   `where cond != 15`、無条件領域の Insn は `where cond == 15` を持つ。
// - 1111 空間のうち 000x/001x/011x（NEON 等）と 100x（SRS/RFE/CPS）は
//   試作では未対応で、decode は None を返す。
// 出典は SPEC-ARM-ARM-A（Arm ARM A32）である。
// Ref: SPEC-ARM-ARM-A (Arm ARM A32, 2024-09)。

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// ARM の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "load", "store", "branch", "mult", "system", "fp"] {
        m.timing_classes.push(class.to_string());
    }

    // ARMv7-A で増えた命令群（MOVW/MOVT/BFI/BFC/UBFX/SBFX/UBFX 等の
    // メディア命令とハードウェア除算）。意味論側は常に受け付けるが、
    // モデル選択の名付け用に旗だけ持つ。
    m.features.push(Feature {
        name: "v7".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    m.models.push(ModelDef {
            params: vec![],
        name: "armv5".to_string(),
        parent: String::new(),
        add_features: vec![],
        remove_features: vec![],
        ident: vec![],
    });
    m.models.push(ModelDef {
            params: vec![],
        name: "armv7".to_string(),
        parent: String::new(),
        add_features: vec!["v7".to_string()],
        remove_features: vec![],
        ident: vec![],
    });

    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: false,
    });

    // `where` の参照用に cond をフィールドとして持つ（形式には入れない）。
    m.fields.push(Field {
        name: "cond".to_string(),
        kind: FieldKind::Bits { hi: 31, lo: 28 },
    });

    // 語全体を一括りにする形式。オペランドの切り出しは意味論が行う。
    m.formats.push(Format {
        name: "FW".to_string(),
        fields: vec![],
        operands: vec![],
    });

    let cond_field = "cond".to_string();
    let not_al = WhereClause {
        field: cond_field.clone(),
        op: WhereOp::Ne,
        rhs: WhereRhs::Lit(15),
    };
    let is_al = WhereClause {
        field: cond_field,
        op: WhereOp::Eq,
        rhs: WhereRhs::Lit(15),
    };

    // (名前, パターン, 分類)。構文は領域名のまま（試作の粗分類）。
    // Ref: SPEC-ARM-ARM-A (Arm ARM A32, 2024-09) の解読表。
    let insns: &[(&str, &str, &str)] = &[
        // データ処理（即値）。MOVW/MOVT・MSR 即値・ヒントもこの領域。
        ("dp_imm", ".... 001. .... .... .... .... .... ....", "alu"),
        // データ処理（レジスタ・即値シフト）。bit4=0 の MRS/MSR/半積算もここ。
        ("dp_reg", ".... 000. .... .... .... .... ...0 ....", "alu"),
        // データ処理（レジスタ・レジスタシフト）。BX/BLX/CLZ/BKPT/QADD 系もここ。
        ("dp_sreg", ".... 000. .... .... .... .... 0..1 ....", "alu"),
        // MUL/MLA/UMAAL/MLS（bits[24:23]=00, bits[7:4]=1001）。
        ("mul", ".... 0000 0... .... .... .... 1001 ....", "mult"),
        // 長積算 UMULL/UMLAL/SMULL/SMLAL。
        ("mull", ".... 0000 1... .... .... .... 1001 ....", "mult"),
        // SWP/SWPB。
        ("swp", ".... 0001 0... .... .... .... 1001 ....", "store"),
        // 排他的ロード/ストア（LDREX/STREX とバイト・ハーフ・ダブル）。
        ("excl", ".... 0001 1... .... .... .... 1001 ....", "load"),
        // 追加ロード/ストア（半・符号・ダブル）の SH=01/11 面。
        ("els_h", ".... 000. .... .... .... .... 1.11 ....", "load"),
        // 追加ロード/ストアの SH=10 面（LDRSB/LDRD）。
        ("els_d", ".... 000. .... .... .... .... 1101 ....", "load"),
        // 単一ロード/ストア（即値オフセット・T 形式を含む）。
        ("ls_imm", ".... 010. .... .... .... .... .... ....", "load"),
        // 単一ロード/ストア（レジスタオフセット）。
        ("ls_reg", ".... 011. .... .... .... .... ...0 ....", "load"),
        // メディア命令（拡張・飽和・ビットフィールド・並列・SEL・REV 等）。
        ("media", ".... 011. .... .... .... .... ...1 ....", "alu"),
        // ブロック転送 LDM/STM（PUSH/POP を含む）。
        ("ldm_stm", ".... 100. .... .... .... .... .... ....", "load"),
        // B。
        ("b", ".... 1010 .... .... .... .... .... ....", "branch"),
        // BL。
        ("bl", ".... 1011 .... .... .... .... .... ....", "branch"),
        // コプロセッサのロード/ストア（VLDR/VSTR/VLDM/VSTM・MCRR/MRRC）。
        ("cp_ls", ".... 110. .... .... .... .... .... ....", "fp"),
        // コプロセッサのデータ操作と転送（VFP 演算・VMOV・MCR/MRC/CDP）。
        ("cp_dp", ".... 1110 .... .... .... .... .... ....", "fp"),
        // スーパーバイザコール。
        ("svc", ".... 1111 .... .... .... .... .... ....", "system"),
    ];
    for (name, pattern, timing) in insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: "FW".to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: vec![not_al.clone()],
            syntax: name.to_string(),
            timing: timing.to_string(),
        });
    }

    // ---- 無条件領域（cond=1111）----
    // Ref: SPEC-ARM-ARM-A (Arm ARM A32, 2024-09)。
    let uncond: &[(&str, &str, &str)] = &[
        // BLX 即値（ARM→Thumb。Thumb 切替は未対応だが符号化は持つ）。
        ("blx_imm", "1111 101. .... .... .... .... .... ....", "branch"),
        // PLD/PLI・DMB/DSB/ISB・CLREX 等のヒント領域。
        ("uncond_hint", "1111 010. .... .... .... .... .... ....", "system"),
        // LDC2/STC2（コプロセッサのロード/ストアの拡張形式）。
        ("cp2_ls", "1111 110. .... .... .... .... .... ....", "fp"),
        // CDP2/MCR2/MRC2 と 1111-1111 の領域。
        ("cp2_dp", "1111 111. .... .... .... .... .... ....", "fp"),
    ];
    for (name, pattern, timing) in uncond {
        m.insns.push(Insn {
            name: name.to_string(),
            format: "FW".to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: vec![is_al.clone()],
            syntax: name.to_string(),
            timing: timing.to_string(),
        });
    }

    m
}
