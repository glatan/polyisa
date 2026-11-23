// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PDP-11 の骨格検査（段階24・PD2）。16 ビット語のデコードと
//! CPU モデル宣言・機能旗・挙動パラメータの形を見る。
//! 出典は SPEC-PDP11-ARCH83 ほかである。

use polyisa_guest_pdp11::*;

/// 16 ビット命令語のデコード（既定モデル）。
fn dec(w: u16) -> Option<Insn> {
    decode(u128::from(w), 16)
}

/// モデルの機能集合でのデコード。
fn dec_m(w: u16, model: &str) -> Option<Insn> {
    decode_model_ex(u128::from(w), 16, false, model_feats(model))
}

#[test]
fn decode_double_operand() {
    // 01SSDD mov・06SSDD add・16SSDD sub。
    assert_eq!(dec(0o010001), Some(Insn::Mov)); // mov r0, r1
    assert_eq!(dec(0o110377), Some(Insn::Movb)); // movb @#0,-(pc) 相当
    assert_eq!(dec(0o064723), Some(Insn::Add));
    assert_eq!(dec(0o160001), Some(Insn::Sub));
    assert_eq!(dec(0o020001), Some(Insn::Cmp));
    assert_eq!(dec(0o050001), Some(Insn::Bis));
}

#[test]
fn decode_single_operand_and_control() {
    assert_eq!(dec(0o005000), Some(Insn::Clr)); // clr r0
    assert_eq!(dec(0o005737), Some(Insn::Tst)); // tst @#…
    assert_eq!(dec(0o000100), Some(Insn::Jmp));
    assert_eq!(dec(0o000300), Some(Insn::Swab));
    assert_eq!(dec(0o000240), Some(Insn::Nop));
    assert_eq!(dec(0o000000), Some(Insn::Halt));
    assert_eq!(dec(0o000001), Some(Insn::Wait));
    assert_eq!(dec(0o000002), Some(Insn::Rti));
    assert_eq!(dec(0o000200), Some(Insn::Rts)); // rts r0
}

#[test]
fn decode_branch_and_traps() {
    assert_eq!(dec(0o000400), Some(Insn::Br));
    assert_eq!(dec(0o001001), Some(Insn::Bne));
    assert_eq!(dec(0o103777), Some(Insn::Bcs));
    assert_eq!(dec(0o104000), Some(Insn::Emt));
    assert_eq!(dec(0o104400), Some(Insn::Trap));
    assert_eq!(dec(0o077501), Some(Insn::Sob)); // sob r2, …
}

#[test]
fn decode_gated_by_features() {
    // 既定モデル（pdp11_03）は EIS を持たないので 070RSS は解けない。
    assert_eq!(dec(0o070000), None); // mul r0, r0
    assert_eq!(dec_m(0o070000, "pdp11_70"), Some(Insn::Mul));
    // FIS も旗が要る（+fis で足した集合で解ける）。
    assert_eq!(dec(0o075002), None); // fadd r2
    let feats = model_feats("pdp11_03") | FEAT_FIS;
    assert_eq!(
        decode_model_ex(0o075002, 16, false, feats),
        Some(Insn::Fadd)
    );
    // MMU 命令と MTPS/MFPS・SPL・MFPT・J-11 命令。
    assert_eq!(dec_m(0o006500, "pdp11_70"), Some(Insn::Mfpi));
    assert_eq!(dec(0o006500), None);
    assert_eq!(dec_m(0o106400, "pdp11_03"), Some(Insn::Mtps));
    assert_eq!(dec_m(0o106400, "pdp11_70"), None);
    assert_eq!(dec_m(0o000230, "pdp11_70"), Some(Insn::Spl));
    assert_eq!(dec_m(0o000007, "pdp11_23"), Some(Insn::Mfpt));
    assert_eq!(dec_m(0o007000, "pdp11_73"), Some(Insn::Csm));
    assert_eq!(dec_m(0o007200, "pdp11_73"), Some(Insn::Tstset));
    assert_eq!(dec_m(0o007300, "pdp11_73"), Some(Insn::Wrtlck));
}

#[test]
fn insn_count() {
    // 二重 12 + 単一語 20 + 単一バイト 16 + JSR/RTS/SOB 3 + EIS/XOR 5
    // + FIS 4 + 分岐 15 + EMT/TRAP 2 + MARK/SPL 2 + 固定語 19。
    assert_eq!(INSNS.len(), 98);
}

#[test]
fn cpu_models() {
    for n in [
        "pdp11_03", "pdp11_04", "pdp11_34", "pdp11_44", "pdp11_60", "pdp11_70", "pdp11_23",
        "pdp11_24", "pdp11_73", "pdp11_83", "pdp11_93", "t11",
    ] {
        assert!(MODELS.contains(&n), "{n}");
    }
    for f in [
        "eis",
        "fis",
        "fp11",
        "cis",
        "mmu",
        "id_split",
        "sm",
        "dual_regset",
        "mtps",
        "mfpt",
        "spl",
        "csm",
        "tstset_wrtlck",
    ] {
        assert!(FEATURES.contains(&f), "{f}");
    }
    // 11/70: EIS・MMU・分離 I/D・スーパーバイザ・第2レジスタセット。
    let f70 = model_feats("pdp11_70");
    assert_eq!(
        f70 & (FEAT_EIS | FEAT_MMU | FEAT_ID_SPLIT | FEAT_SM | FEAT_DUAL_REGSET | FEAT_SPL),
        FEAT_EIS | FEAT_MMU | FEAT_ID_SPLIT | FEAT_SM | FEAT_DUAL_REGSET | FEAT_SPL
    );
    assert_eq!(f70 & (FEAT_MTPS | FEAT_FP11), 0);
    // 11/03: MTPS/MFPS のみ。
    let f03 = model_feats("pdp11_03");
    assert_eq!(f03, FEAT_MTPS);
    // J-11: EIS・FP11 標準、CSM・TSTSET/WRTLCK を持つ。FIS は排他。
    let f73 = model_feats("pdp11_73");
    assert_ne!(
        f73 & (FEAT_EIS | FEAT_FP11 | FEAT_CSM | FEAT_TSTSET_WRTLCK),
        0
    );
    assert_eq!(f73 & FEAT_FIS, 0);
    // 親チェーン: 11/83/93 は 11/73 の機能を継ぐ、11/24 は 23 に
    // tstset_wrtlck を足す。
    assert_eq!(model_feats("pdp11_83"), f73);
    assert_eq!(
        model_feats("pdp11_24"),
        model_feats("pdp11_23") | FEAT_TSTSET_WRTLCK
    );
    // implies: csm→sm→mmu、id_split→mmu。
    assert_ne!(f73 & FEAT_MMU, 0);
}

#[test]
fn model_params_resolve() {
    let p03 = model_params("pdp11_03");
    assert!(!p03.odd_addr_trap);
    assert!(!p03.psw_mapped);
    assert_eq!(p03.jmp_reg_trap, JMP_REG_TRAP_VEC004);
    let p70 = model_params("pdp11_70");
    assert!(p70.odd_addr_trap);
    assert!(p70.psw_mapped);
    assert_eq!(p70.jmp_reg_trap, JMP_REG_TRAP_VEC004);
    // パラメータも親チェーンで継承される。
    let p83 = model_params("pdp11_83");
    assert_eq!(p83, model_params("pdp11_73"));
}

#[test]
fn disasm_word_spot() {
    assert_eq!(disasm_word(0o010001, 16).as_deref(), Some("mov"));
    assert_eq!(disasm_word(0o000240, 16).as_deref(), Some("nop"));
}
