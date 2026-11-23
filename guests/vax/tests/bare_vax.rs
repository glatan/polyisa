// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAX の骨格検査（段階23・VX2）。オペコード空間（1/2 バイト語）の
//! デコードと、CPU モデル宣言・機能旗・挙動パラメータの形を見る。
//! 命令単位の実行検査は VX4 以降でこのファイルに足す。
//! 出典は SPEC-VAX-ARM と SPEC-VAX-MICROVAX である。

use polyisa_guest_vax::*;

/// 1 バイトオペコード語のデコード。
fn dec1(b: u8) -> Option<Insn> {
    decode(u128::from(b), 8)
}

/// 2 バイトオペコード語（接頭 + 次のバイト。語はフェッチ順に
/// 下位ビットから詰める）のデコード。
fn dec2(prefix: u8, op2: u8) -> Option<Insn> {
    decode(u128::from(prefix) | u128::from(op2) << 8, 16)
}

#[test]
fn decode_one_byte_opcodes() {
    assert_eq!(dec1(0x00), Some(Insn::Halt));
    assert_eq!(dec1(0x01), Some(Insn::Nop));
    assert_eq!(dec1(0x02), Some(Insn::Rei));
    assert_eq!(dec1(0x03), Some(Insn::Bpt));
    assert_eq!(dec1(0x04), Some(Insn::Ret));
    assert_eq!(dec1(0x05), Some(Insn::Rsb));
    assert_eq!(dec1(0x06), Some(Insn::Ldpctx));
    assert_eq!(dec1(0x07), Some(Insn::Svpctx));
    // 未宣言の語と、接頭だけの語は命令にならない。
    assert_eq!(dec1(0x08), None);
    assert_eq!(dec1(0xfd), None);
    assert_eq!(dec1(0xfe), None);
    assert_eq!(dec1(0xff), None);
}

#[test]
fn decode_two_byte_opcodes() {
    assert_eq!(dec2(0xfd, 0xff), Some(Insn::Bugw));
    assert_eq!(dec2(0xfe, 0xff), Some(Insn::Bugl));
    // 接頭の違う同じ第 2 バイトは別の語。
    assert_eq!(dec2(0xff, 0xff), None);
    // 8 ビット語としては 2 バイト語の空間に入らない。
    assert_eq!(decode(0xfffd, 8), None);
}

#[test]
fn feature_flags() {
    for f in [
        "decimal",
        "hfp",
        "string_ext",
        "string_cmp",
        "crc",
        "editpc",
        "compat",
    ] {
        assert!(FEATURES.contains(&f), "{f}");
    }
}

#[test]
fn cpu_models() {
    for name in ["vax11_780", "microvax2", "ka660", "nvax"] {
        assert!(MODELS.contains(&name), "{name}");
    }
    // フル VAX は全機能を持つ。
    let full = model_feats("vax11_780");
    assert_ne!(full & FEAT_DECIMAL, 0);
    assert_ne!(full & FEAT_HFP, 0);
    assert_ne!(full & FEAT_STRING_EXT, 0);
    assert_ne!(full & FEAT_STRING_CMP, 0);
    assert_ne!(full & FEAT_CRC, 0);
    assert_ne!(full & FEAT_EDITPC, 0);
    // KA660 は実装しない群を削り、string_cmp の 6 個は実装する。
    let ka660 = model_feats("ka660");
    assert_eq!(ka660 & FEAT_DECIMAL, 0);
    assert_eq!(ka660 & FEAT_HFP, 0);
    assert_eq!(ka660 & FEAT_STRING_EXT, 0);
    assert_eq!(ka660 & FEAT_CRC, 0);
    assert_eq!(ka660 & FEAT_EDITPC, 0);
    assert_eq!(ka660 & FEAT_COMPAT, 0);
    assert_ne!(ka660 & FEAT_STRING_CMP, 0);
    // KA630 は string_cmp も補完対象。
    let ka630 = model_feats("microvax2");
    assert_eq!(ka630 & FEAT_STRING_CMP, 0);
    // NVAX は compat 以外を持つ。
    let nvax = model_feats("nvax");
    assert_ne!(nvax & FEAT_DECIMAL, 0);
    assert_eq!(nvax & FEAT_COMPAT, 0);
}

#[test]
fn cpu_model_params() {
    // KA660 は DV をハードが扱わない。それ以外は扱う。
    assert!(!model_params("ka660").dv_hw);
    assert!(model_params("vax11_780").dv_hw);
    assert!(model_params("microvax2").dv_hw);
    // 補完経路の配送は既定で実行側のトラップハンドラ。
    assert_eq!(DEFAULT_PARAMS.emul_dispatch, EMUL_DISPATCH_HOOK);
    assert_eq!(model_params("ka660").emul_dispatch, EMUL_DISPATCH_HOOK);
}
